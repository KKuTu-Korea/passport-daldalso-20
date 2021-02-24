import passport from 'passport';
import * as passportOAuth2 from 'passport-oauth2';

export interface StrategyOptions extends passportOAuth2.StrategyOptions {
  client_id: string;
  redirect_uri: string;
}

export interface Profile extends passport.Profile {
  provider: 'daldalso';
  id: string;
  displayName: string | null;
  account: string | null;
  libra: {
    level: number;
    prev: number;
    next: number;
  } | null;
  foveon: number | null;
  profile: {
    image: string;
    text: string;
  } | null;
  _raw: string;
  _json: any;
}

export const buildOptions = (options: StrategyOptions) => {
  options.authorizationURL = 'https://daldal.so/oauth/authorize';
  options.tokenURL = 'https://daldal.so/oauth/token';
  options.state = true;
  return options;
};

/**
 * `Strategy` class.
 *
 * The Daldalso authentication strategy authenticates requests by delegating to
 * Daldalso using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts a `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientId`       your Daldalso application's client id
 *   - `clientSecret`   your Daldalso application's client secret
 *   - `callbackURL`    URL to which Daldalso will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     passport.use(new DaldalsoStrategy({
 *         clientId: 'abcdefgh-1234-hijk-5678-a1b2c3d4e5f6',
 *         clientSecret: 'shhh-its-a-secret',
 *         callbackURL: 'https://example.kr/auth/daldalso/callback',
 *       },
 *       (accessToken, refreshToken, profile, cb) => {
 *         User.findOrCreate(..., (err, user) => {
 *           cb(err, user);
 *         });
 *       },
 *     ));
 *
 * @class
 * @param {object} options
 * @param {function} verify
 * @access public
 */
export class Strategy extends passportOAuth2.Strategy {
  constructor(options: StrategyOptions, verify: passportOAuth2.VerifyFunction) {
    super(buildOptions(options), verify);
    this.name = 'daldalso';
    this._oauth2.setAccessTokenName('access_token');
    this._oauth2.useAuthorizationHeaderforGET(true);
  }

  /**
   * Retrieve user profile from Daldalso.
   *
   * This method constructs a normalized profile, with the following properties:
   *
   *   - `provider`         always set to `daldalso`
   *   - `id`
   *   - `displayName`
   *   - `account`
   *   - `libra`
   *   - `foveon`
   *   - `profile`
   *   - `_raw`
   *   - `_json`
   * 
   * @param {string} accessToken
   * @param {function} done
   * @access protected
   */
  userProfile(
    accessToken: string,
    done: (err?: Error | null, profile?: any) => void,
  ): void {
    this._oauth2.get(
      'https://daldal.so/oauth/api/me',
      accessToken,
      (err, result: string) => {
        if (err) {
          return done(new Error(JSON.stringify(err)));
        }

        try {
          const json = JSON.parse(result);

          const profile: Profile = {
            provider: 'daldalso',
            id: json.key,
            displayName: json.name ?? null,
            account: json.account ?? null,
            libra: json.libra ?? null,
            foveon: json.foveon ?? null,
            profile: json.profile ?? null,
            _raw: result,
            _json: json,
          };

          return done(null, profile);
        } catch (e) {
          return done(e);
        }
      },
    );
  }
}

export default Strategy;
