import * as crypto from 'node:crypto';
import { BadRequestException, Injectable, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { decryptApiKey, PinoLogger } from '@novu/application-generic';
import { EnvironmentRepository, OrganizationRepository, UserRepository } from '@novu/dal';
import { AuthProviderEnum, EnvironmentEnum, MemberRoleEnum, normalizeEmail } from '@novu/shared';
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

export interface IOidcBootstrapRequest {
  clientId: string;
  clientSecret: string;
  grantType: string;
}

export interface IOidcBootstrapResult {
  apiKey: string;
  applicationIdentifier: string;
  environmentId: string;
  environmentName: string;
  organizationId: string;
}

const DEFAULT_OIDC_PROVIDER_NAME = 'OIDC';
const DEFAULT_OIDC_SCOPES = 'openid profile email groups';
const STATE_TTL_MS = 5 * 60 * 1000;

interface CachedClient {
  client: OidcClient;
  fetchedAt: number;
}

type OidcMetadata = Record<string, unknown>;

interface OidcTokenSet {
  access_token?: string;
  refresh_token?: string;
}

interface OidcClient {
  authorizationUrl(params: Record<string, string>): string;
  callbackParams(input: unknown): Record<string, unknown>;
  callback(redirectUri: string, params: Record<string, unknown>, checks: { state: string }): Promise<OidcTokenSet>;
  userinfo(accessToken: string): Promise<IOidcUserProfile>;
  grant(params: Record<string, string>): Promise<unknown>;
}

interface OidcIssuer {
  metadata: OidcMetadata;
  Client: new (config: Record<string, unknown>) => OidcClient;
}

interface OidcIssuerConstructor {
  discover(issuerUrl: string): Promise<OidcIssuer>;
  new (metadata: OidcMetadata): OidcIssuer;
}

const BACKCHANNEL_ENDPOINTS = [
  'token_endpoint',
  'jwks_uri',
  'userinfo_endpoint',
  'introspection_endpoint',
  'revocation_endpoint',
];

@Injectable()
export class OidcService implements OnModuleInit {
  private clientPromise: Promise<CachedClient> | null = null;
  private stateStore = new Map<string, { createdAt: number; redirectAfterLogin?: string }>();

  constructor(
    private readonly userRepository: UserRepository,
    private readonly organizationRepository: OrganizationRepository,
    private readonly environmentRepository: EnvironmentRepository,
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

      const issuer = await this.discoverIssuer(Issuer, issuerUrl);
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

  async mintBootstrapContext(body: IOidcBootstrapRequest): Promise<IOidcBootstrapResult> {
    if (!OidcService.isEnabled()) {
      throw new BadRequestException('OIDC is not enabled');
    }
    if (body.grantType !== 'client_credentials') {
      throw new BadRequestException('grantType must be client_credentials');
    }

    const expectedClientId = this.getRequiredEnv('OIDC_BOOTSTRAP_CLIENT_ID');
    const expectedClientSecret = this.getRequiredEnv('OIDC_BOOTSTRAP_CLIENT_SECRET');
    if (
      !this.safeEquals(body.clientId, expectedClientId) ||
      !this.safeEquals(body.clientSecret, expectedClientSecret)
    ) {
      throw new UnauthorizedException('Invalid bootstrap client credentials');
    }

    await this.assertClientCredentialsGrant(body.clientId, body.clientSecret);

    const email = normalizeEmail(this.getRequiredEnv('OIDC_BOOTSTRAP_USER_EMAIL'));
    const organizationName = this.getRequiredEnv('OIDC_BOOTSTRAP_ORGANIZATION_NAME');
    const profile = {
      id: `client:${body.clientId}`,
      login: email,
      email,
      name: organizationName,
      avatar_url: '',
    };

    const result = await this.authService.authenticate(AuthProviderEnum.OIDC, '', '', profile, profile.id);
    if (result.newUser) {
      await this.ensureUserHasOrganization(email, organizationName);
    }

    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      throw new BadRequestException('Bootstrap user was not created');
    }

    let organizations = await this.organizationRepository.findUserActiveOrganizations(user._id);
    if (!organizations || organizations.length === 0) {
      await this.ensureUserHasOrganization(email, organizationName);
      organizations = await this.organizationRepository.findUserActiveOrganizations(user._id);
    }
    const organization = organizations?.[0];
    if (!organization) {
      throw new BadRequestException('Bootstrap organization was not created');
    }

    const environments = await this.environmentRepository.findOrganizationEnvironments(organization._id);
    const environment =
      environments.find((candidate) => candidate.name === EnvironmentEnum.PRODUCTION) ||
      environments.find((candidate) => candidate.name === EnvironmentEnum.DEVELOPMENT) ||
      environments[0];
    if (!environment) {
      throw new BadRequestException('Bootstrap organization has no environment');
    }

    const apiKeys = await this.environmentRepository.getApiKeys(environment._id);
    const apiKey = apiKeys[0]?.key ? decryptApiKey(apiKeys[0].key) : '';
    if (!apiKey) {
      throw new BadRequestException(`Bootstrap environment ${environment._id} has no API key`);
    }

    return {
      apiKey,
      applicationIdentifier: environment.identifier,
      environmentId: environment._id,
      environmentName: environment.name,
      organizationId: organization._id,
    };
  }

  private async assertClientCredentialsGrant(clientId: string, clientSecret: string): Promise<void> {
    const { Issuer } = await import('openid-client');
    const issuer = await this.discoverIssuer(Issuer, this.getRequiredEnv('OIDC_ISSUER'));
    const client = new issuer.Client({
      client_id: clientId,
      client_secret: clientSecret,
    });

    await client.grant({
      grant_type: 'client_credentials',
      scope: 'openid',
    });
  }

  private async discoverIssuer(Issuer: unknown, issuerUrl: string): Promise<OidcIssuer> {
    const issuerConstructor = Issuer as OidcIssuerConstructor;
    const issuer = await issuerConstructor.discover(issuerUrl);
    const backchannelBaseUrl = this.getRequiredEnv('OIDC_BACKCHANNEL_BASE_URL');
    return new issuerConstructor(this.rewriteBackchannelMetadata(issuer.metadata, backchannelBaseUrl));
  }

  private rewriteBackchannelMetadata(metadata: OidcMetadata, backchannelBaseUrl: string): OidcMetadata {
    const issuerUrl = this.parseUrlValue(metadata.issuer);
    if (!issuerUrl) {
      return metadata;
    }

    return BACKCHANNEL_ENDPOINTS.reduce(
      (next, key) => {
        const endpoint = this.rewriteIssuerEndpoint(next[key], issuerUrl, backchannelBaseUrl);
        if (endpoint) {
          next[key] = endpoint;
        }

        return next;
      },
      { ...metadata }
    );
  }

  private rewriteIssuerEndpoint(rawEndpoint: unknown, issuerUrl: URL, backchannelBaseUrl: string): string | undefined {
    const endpointUrl = this.parseUrlValue(rawEndpoint);
    if (!endpointUrl || endpointUrl.origin !== issuerUrl.origin) {
      return undefined;
    }

    const issuerPath = issuerUrl.pathname.replace(/\/$/, '');
    if (issuerPath && endpointUrl.pathname !== issuerPath && !endpointUrl.pathname.startsWith(`${issuerPath}/`)) {
      return undefined;
    }

    const suffix = issuerPath ? endpointUrl.pathname.slice(issuerPath.length) || '/' : endpointUrl.pathname;
    const baseUrl = new URL(backchannelBaseUrl);
    const basePath = baseUrl.pathname.replace(/\/$/, '');
    const suffixPath = suffix.startsWith('/') ? suffix : `/${suffix}`;
    baseUrl.pathname = `${basePath}${suffixPath}`.replace(/\/{2,}/g, '/');
    baseUrl.search = endpointUrl.search;
    baseUrl.hash = '';

    return baseUrl.toString();
  }

  private parseUrlValue(value: unknown): URL | undefined {
    if (typeof value !== 'string' || !value) {
      return undefined;
    }

    try {
      return new URL(value);
    } catch {
      return undefined;
    }
  }

  private safeEquals(a: string, b: string): boolean {
    const left = Buffer.from(a || '');
    const right = Buffer.from(b || '');
    if (left.length !== right.length) return false;

    return crypto.timingSafeEqual(left, right);
  }

  private toNovuProfile(userinfo: IOidcUserProfile) {
    const fullName =
      userinfo.name || [userinfo.given_name, userinfo.family_name].filter(Boolean).join(' ').trim() || userinfo.email;

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
