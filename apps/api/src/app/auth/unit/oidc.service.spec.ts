import { encryptApiKey } from '@novu/application-generic';
import { expect } from 'chai';
import sinon from 'sinon';
import { OidcService } from '../services/oidc.service';

describe('OidcService', () => {
  describe('static config helpers', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      process.env.IS_OIDC_ENABLED = originalEnv.IS_OIDC_ENABLED;
      process.env.IS_OIDC_ONLY = originalEnv.IS_OIDC_ONLY;
      process.env.OIDC_PROVIDER_NAME = originalEnv.OIDC_PROVIDER_NAME;
    });

    it('isEnabled is true only when IS_OIDC_ENABLED is exactly "true"', () => {
      (process.env as Record<string, string>).IS_OIDC_ENABLED = 'true';
      expect(OidcService.isEnabled()).to.equal(true);
      (process.env as Record<string, string>).IS_OIDC_ENABLED = 'false';
      expect(OidcService.isEnabled()).to.equal(false);
      (process.env as Record<string, string>).IS_OIDC_ENABLED = '1';
      expect(OidcService.isEnabled()).to.equal(false);
    });

    it('isOidcOnly is true only when IS_OIDC_ONLY is exactly "true"', () => {
      (process.env as Record<string, string>).IS_OIDC_ONLY = 'true';
      expect(OidcService.isOidcOnly()).to.equal(true);
      (process.env as Record<string, string>).IS_OIDC_ONLY = 'yes';
      expect(OidcService.isOidcOnly()).to.equal(false);
    });

    it('getProviderDisplayName falls back to "OIDC" when env unset', () => {
      delete (process.env as Record<string, string>).OIDC_PROVIDER_NAME;
      expect(OidcService.getProviderDisplayName()).to.equal('OIDC');
      (process.env as Record<string, string>).OIDC_PROVIDER_NAME = 'Ameide SSO';
      expect(OidcService.getProviderDisplayName()).to.equal('Ameide SSO');
    });
  });

  describe('toNovuProfile (private mapping)', () => {
    // Drive the private toNovuProfile via a thin proxy that exposes it for tests.
    // Casting is acceptable here — we only ever exercise the pure mapper.
    const callMapper = (userinfo: Record<string, unknown>) => {
      // @ts-expect-error - access private for test
      return OidcService.prototype.toNovuProfile.call({}, userinfo);
    };

    it('maps an OIDC userinfo blob with full claims', () => {
      const profile = callMapper({
        sub: 'kc-1234',
        email: 'jane@ameide.io',
        name: 'Jane Q Doe',
        given_name: 'Jane',
        family_name: 'Doe',
        picture: 'https://cdn/jane.png',
      });

      expect(profile).to.deep.equal({
        id: 'kc-1234',
        login: 'jane@ameide.io',
        email: 'jane@ameide.io',
        name: 'Jane Q Doe',
        avatar_url: 'https://cdn/jane.png',
      });
    });

    it('falls back to given_name + family_name when name claim is absent', () => {
      const profile = callMapper({
        sub: 'kc-2',
        email: 'a@b.com',
        given_name: 'A',
        family_name: 'B',
      });

      expect(profile.name).to.equal('A B');
      expect(profile.avatar_url).to.equal('');
    });

    it('falls back to email when no name claims are present', () => {
      const profile = callMapper({ sub: 'kc-3', email: 'lone@x.io' });
      expect(profile.name).to.equal('lone@x.io');
      expect(profile.id).to.equal('kc-3');
      expect(profile.login).to.equal('lone@x.io');
    });
  });

  describe('OIDC backchannel metadata rewrite', () => {
    const rewrite = (metadata: Record<string, unknown>, backchannelBaseUrl: string) => {
      // @ts-expect-error - access private for focused contract test
      return OidcService.prototype.rewriteBackchannelMetadata.call(
        Object.create(OidcService.prototype),
        metadata,
        backchannelBaseUrl
      );
    };

    it('rewrites backend endpoints to the required Keycloak backchannel base URL', () => {
      const metadata = rewrite(
        {
          issuer: 'https://auth.example/realms/ameide',
          authorization_endpoint: 'https://auth.example/realms/ameide/protocol/openid-connect/auth',
          end_session_endpoint: 'https://auth.example/realms/ameide/protocol/openid-connect/logout',
          token_endpoint: 'https://auth.example/realms/ameide/protocol/openid-connect/token',
          jwks_uri: 'https://auth.example/realms/ameide/protocol/openid-connect/certs',
          userinfo_endpoint: 'https://auth.example/realms/ameide/protocol/openid-connect/userinfo',
          introspection_endpoint: 'https://auth.example/realms/ameide/protocol/openid-connect/token/introspect',
          revocation_endpoint: 'https://auth.example/realms/ameide/protocol/openid-connect/revoke',
        },
        'http://keycloak.keycloak-instance.svc.cluster.local:8080/realms/ameide'
      );

      expect(metadata).to.include({
        issuer: 'https://auth.example/realms/ameide',
        authorization_endpoint: 'https://auth.example/realms/ameide/protocol/openid-connect/auth',
        end_session_endpoint: 'https://auth.example/realms/ameide/protocol/openid-connect/logout',
        token_endpoint:
          'http://keycloak.keycloak-instance.svc.cluster.local:8080/realms/ameide/protocol/openid-connect/token',
        jwks_uri:
          'http://keycloak.keycloak-instance.svc.cluster.local:8080/realms/ameide/protocol/openid-connect/certs',
        userinfo_endpoint:
          'http://keycloak.keycloak-instance.svc.cluster.local:8080/realms/ameide/protocol/openid-connect/userinfo',
        introspection_endpoint:
          'http://keycloak.keycloak-instance.svc.cluster.local:8080/realms/ameide/protocol/openid-connect/token/introspect',
        revocation_endpoint:
          'http://keycloak.keycloak-instance.svc.cluster.local:8080/realms/ameide/protocol/openid-connect/revoke',
      });
    });

    it('preserves endpoints outside the configured issuer', () => {
      const metadata = rewrite(
        {
          issuer: 'https://auth.example/realms/ameide',
          token_endpoint: 'https://token.example/oauth/token',
        },
        'http://keycloak.keycloak-instance.svc.cluster.local:8080/realms/ameide/'
      );

      expect(metadata.token_endpoint).to.equal('https://token.example/oauth/token');
    });
  });

  describe('mintBootstrapContext', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      process.env = { ...originalEnv };
      sinon.restore();
    });

    it('creates the bootstrap organization and returns the production API key', async () => {
      process.env.IS_OIDC_ENABLED = 'true';
      process.env.OIDC_ISSUER = 'https://auth.example/realms/ameide';
      process.env.OIDC_BOOTSTRAP_CLIENT_ID = 'notifications-bootstrap';
      process.env.OIDC_BOOTSTRAP_CLIENT_SECRET = 'secret';
      process.env.OIDC_BOOTSTRAP_USER_EMAIL = 'notifications-bootstrap@ameide.internal';
      process.env.OIDC_BOOTSTRAP_ORGANIZATION_NAME = 'Ameide Notifications';
      process.env.STORE_ENCRYPTION_KEY = '12345678901234567890123456789012';

      const user = { _id: 'user-1' };
      const org = { _id: 'org-1' };
      const dev = { _id: 'env-dev', name: 'Development', identifier: 'dev-ident' };
      const prod = { _id: 'env-prod', name: 'Production', identifier: 'prod-ident' };
      const userRepository = { findByEmail: sinon.stub().resolves(user) };
      const organizationRepository = {
        findUserActiveOrganizations: sinon.stub(),
      };
      organizationRepository.findUserActiveOrganizations.onFirstCall().resolves([]);
      organizationRepository.findUserActiveOrganizations.onSecondCall().resolves([org]);
      organizationRepository.findUserActiveOrganizations.onThirdCall().resolves([org]);
      const environmentRepository = {
        findOrganizationEnvironments: sinon.stub().resolves([dev, prod]),
        getApiKeys: sinon.stub().resolves([{ key: encryptApiKey('production-api-key') }]),
      };
      const authService = { authenticate: sinon.stub().resolves({ newUser: true, token: 'unused' }) };
      const createOrganization = { execute: sinon.stub().resolves(org) };
      const addMember = { execute: sinon.stub() };
      const logger = { setContext: sinon.stub(), warn: sinon.stub() };
      const service = new OidcService(
        userRepository as any,
        organizationRepository as any,
        environmentRepository as any,
        authService as any,
        createOrganization as any,
        addMember as any,
        logger as any
      );
      sinon.stub(service as any, 'assertClientCredentialsGrant').resolves();

      const result = await service.mintBootstrapContext({
        clientId: 'notifications-bootstrap',
        clientSecret: 'secret',
        grantType: 'client_credentials',
      });

      expect(result).to.deep.equal({
        apiKey: 'production-api-key',
        applicationIdentifier: 'prod-ident',
        environmentId: 'env-prod',
        environmentName: 'Production',
        organizationId: 'org-1',
      });
      expect(createOrganization.execute.calledOnce).to.equal(true);
      expect(environmentRepository.getApiKeys.calledWith('env-prod')).to.equal(true);
    });

    it('rejects credentials that do not match the configured bootstrap client', async () => {
      process.env.IS_OIDC_ENABLED = 'true';
      process.env.OIDC_BOOTSTRAP_CLIENT_ID = 'notifications-bootstrap';
      process.env.OIDC_BOOTSTRAP_CLIENT_SECRET = 'secret';

      const service = new OidcService(
        {} as any,
        {} as any,
        {} as any,
        {} as any,
        {} as any,
        {} as any,
        { setContext: sinon.stub() } as any
      );

      try {
        await service.mintBootstrapContext({
          clientId: 'notifications-bootstrap',
          clientSecret: 'wrong',
          grantType: 'client_credentials',
        });
        throw new Error('expected mintBootstrapContext to reject');
      } catch (err) {
        expect((err as Error).message).to.equal('Invalid bootstrap client credentials');
      }
    });
  });
});
