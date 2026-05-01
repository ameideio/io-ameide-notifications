import { expect } from 'chai';
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
});
