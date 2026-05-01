import { BadRequestException, Injectable, OnModuleInit } from '@nestjs/common';
import { PinoLogger } from '@novu/application-generic';
import { OrganizationRepository, UserRepository } from '@novu/dal';
import { AuthProviderEnum, MemberRoleEnum, normalizeEmail } from '@novu/shared';
import * as crypto from 'crypto';
import { CreateOrganizationCommand } from '../../organization/usecases/create-organization/create-organization.command';
import { CreateOrganization } from '../../organization/usecases/create-organization/create-organization.usecase';
import { AddMemberCommand } from '../../organization/usecases/membership/add-member/add-member.command';
import { AddMember } from '../../organization/usecases/membership/add-member/add-member.usecase';
import { AuthService } from './auth.service';

export interface IOidcUserProfile {
  sub: string;
  email: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
}

export interface IOidcAuthorizeResult {
  url: string;
  state: string;
}

export interface IOidcCallbackResult {
  token: string;
  newUser: boolean;
}

const DEFAULT_OIDC_PROVIDER_NAME = 'OIDC';
const DEFAULT_OIDC_SCOPES = 'openid profile email groups';
const STATE_TTL_MS = 5 * 60 * 1000;

interface CachedClient {
  // The dynamically imported openid-client `Client` instance. Loosely typed to
  // avoid leaking ESM-only types into our CommonJS build surface.
  client: any;
  fetchedAt: number;
}

@Injectable()
export class OidcService implements OnModuleInit {
  private clientPromise: Promise<CachedClient> | null = null;
  private stateStore = new Map<string, { createdAt: number; redirectAfterLogin?: string }>();

  constructor(
    private readonly userRepository: UserRepository,
    private readonly organizationRepository: OrganizationRepository,
    private readonly authService: AuthService,
    private readonly createOrganization: CreateOrganization,
    private readonly addMember: AddMember,
    private readonly logger: PinoLogger
  ) {
    this.logger.setContext(this.constructor.name);
  }

  onModuleInit() {
    if (!OidcService.isEnabled()) return;
    // Pre-warm discovery so the first user request doesn't pay the cost.
    this.getClient().catch((err) => {
      this.logger.warn({ err: err?.message }, 'OIDC discovery pre-warm failed; will retry lazily');
      this.clientPromise = null;
    });
  }

  static isEnabled(): boolean {
    return process.env.IS_OIDC_ENABLED === 'true';
  }

  static isOidcOnly(): boolean {
    return process.env.IS_OIDC_ONLY === 'true';
  }

  static getProviderDisplayName(): string {
    return process.env.OIDC_PROVIDER_NAME || DEFAULT_OIDC_PROVIDER_NAME;
  }

  private getRequiredEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
      throw new BadRequestException(`OIDC misconfigured: missing ${name}`);
    }
    return value;
  }

  private async getClient(): Promise<CachedClient> {
    if (this.clientPromise) return this.clientPromise;

    this.clientPromise = (async () => {
      // openid-client v5 ships as ESM; use dynamic import so this file stays CJS-friendly.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { Issuer } = await import('openid-client');

      const issuerUrl = this.getRequiredEnv('OIDC_ISSUER');
      const clientId = this.getRequiredEnv('OIDC_CLIENT_ID');
      const clientSecret = this.getRequiredEnv('OIDC_CLIENT_SECRET');
      const redirectUri = this.getRequiredEnv('OIDC_REDIRECT_URI');

      const issuer = await Issuer.discover(issuerUrl);
      const client = new issuer.Client({
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uris: [redirectUri],
        response_types: ['code'],
      });

      return { client, fetchedAt: Date.now() };
    })();

    try {
      return await this.clientPromise;
    } catch (err) {
      this.clientPromise = null;
      throw err;
    }
  }

  private getScopes(): string {
    return process.env.OIDC_SCOPES || DEFAULT_OIDC_SCOPES;
  }

  private storeState(state: string, redirectAfterLogin?: string) {
    this.gcStateStore();
    this.stateStore.set(state, { createdAt: Date.now(), redirectAfterLogin });
  }

  private consumeState(state: string): { redirectAfterLogin?: string } | null {
    this.gcStateStore();
    const entry = this.stateStore.get(state);
    if (!entry) return null;
    this.stateStore.delete(state);
    return { redirectAfterLogin: entry.redirectAfterLogin };
  }

  private gcStateStore() {
    const now = Date.now();
    for (const [state, entry] of this.stateStore.entries()) {
      if (now - entry.createdAt > STATE_TTL_MS) {
        this.stateStore.delete(state);
      }
    }
  }

  async authorize(redirectAfterLogin?: string): Promise<IOidcAuthorizeResult> {
    const { client } = await this.getClient();

    const state = crypto.randomBytes(32).toString('hex');
    this.storeState(state, redirectAfterLogin);

    const url = client.authorizationUrl({
      scope: this.getScopes(),
      state,
    });

    return { url, state };
  }

  async handleCallback(query: Record<string, string | string[] | undefined>): Promise<IOidcCallbackResult> {
    const { client } = await this.getClient();

    const state = typeof query.state === 'string' ? query.state : undefined;
    if (!state) throw new BadRequestException('Missing OIDC state parameter');

    const stateEntry = this.consumeState(state);
    if (!stateEntry) throw new BadRequestException('Invalid or expired OIDC state');

    const redirectUri = this.getRequiredEnv('OIDC_REDIRECT_URI');
    const params = client.callbackParams({ url: redirectUri, method: 'GET', body: query });

    const tokenSet = await client.callback(redirectUri, params, { state });
    const userinfo = (await client.userinfo(tokenSet.access_token as string)) as IOidcUserProfile;

    if (!userinfo.email) {
      throw new BadRequestException('OIDC provider did not return an email claim');
    }

    const profile = this.toNovuProfile(userinfo);
    const accessToken = tokenSet.access_token || '';
    const refreshToken = tokenSet.refresh_token || '';

    const result = await this.authService.authenticate(
      AuthProviderEnum.OIDC,
      accessToken,
      refreshToken,
      profile,
      userinfo.sub
    );

    if (result.newUser) {
      await this.ensureUserHasOrganization(profile.email, profile.name || profile.login || profile.email);
    }

    return result;
  }

  private toNovuProfile(userinfo: IOidcUserProfile) {
    const fullName =
      userinfo.name ||
      [userinfo.given_name, userinfo.family_name].filter(Boolean).join(' ').trim() ||
      userinfo.email;

    return {
      id: userinfo.sub,
      login: userinfo.email,
      email: userinfo.email,
      name: fullName,
      avatar_url: userinfo.picture || '',
    };
  }

  private async ensureUserHasOrganization(email: string, displayName: string) {
    const normalized = normalizeEmail(email);
    const user = await this.userRepository.findByEmail(normalized);
    if (!user) return;

    const existing = await this.organizationRepository.findUserActiveOrganizations(user._id);
    if (existing && existing.length > 0) return;

    const configuredOrgId = process.env.OIDC_DEFAULT_ORGANIZATION_ID;
    if (configuredOrgId) {
      const configuredOrg = await this.organizationRepository.findById(configuredOrgId);
      if (configuredOrg) {
        await this.addMember.execute(
          AddMemberCommand.create({
            organizationId: configuredOrg._id,
            userId: user._id,
            roles: [MemberRoleEnum.OSS_ADMIN],
          })
        );
        return;
      }
      this.logger.warn(
        { configuredOrgId },
        'OIDC_DEFAULT_ORGANIZATION_ID set but org not found; falling back to creating a new org'
      );
    }

    await this.createOrganization.execute(
      CreateOrganizationCommand.create({
        userId: user._id,
        name: displayName,
      })
    );
  }
}
