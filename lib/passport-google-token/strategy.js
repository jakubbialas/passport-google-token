/**
 * Module dependencies.
 */
var passport = require('passport-strategy');
var util = require('util');
var google = require('googleapis');
var OAuth2 = google.auth.OAuth2;

/**
 * `Strategy` constructor.
 *
 * The Google authentication strategy authenticates requests by delegating to
 * Google using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Google application's client id
 *
 * Examples:
 *
 *     passport.use(new GoogleTokenStrategy({
 *         clientID: '123-456-789',
 *       },
 *       function(profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function GoogleTokenStrategy(options, verify) {
    passport.Strategy.call(this);
    this.name = 'google-token';

    options = options || {};

    this.client = new OAuth2(
        options.clientID,
        '',
        ''
    );

    this._verify = verify;
    if (!this._verify) {
        throw new TypeError('GoogleTokenStrategy requires a verify callback');
    }
}
util.inherits(GoogleTokenStrategy, passport.Strategy);

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
GoogleTokenStrategy.prototype.authenticate = function(req, options) {
    options = options || {};
    var self = this;

    if (req.query && req.query.error) {
        return this.fail();
    }

    if (!req.body) {
        return this.fail();
    }

    var idToken = req.body.id_token || req.query.id_token || req.headers.id_token;

    self._verifyToken(idToken, function(err, profile) {
        if (err) { return self.fail(err); };

        function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
        }

        if (self._passReqToCallback) {
            self._verify(req, profile, verified);
        } else {
            self._verify(profile, verified);
        }
    });
}

GoogleTokenStrategy.prototype._verifyToken = function(idToken, done) {
    var self = this;

    self.client.verifyIdToken(idToken, self.client._clientId, function(err, login) {
        if (err) {
            return done(err);
        }
        var payload = login.getPayload();
        var userid = payload['sub'];

        var profile = {provider: 'google'};
        profile.id = payload.sub;
        profile.email = payload.email;
        profile.emailVerified = payload.email_verified;
        profile.displayName = payload.name;
        profile.name = { familyName: payload.family_name,
                          givenName: payload.given_name };
        profile.picture = payload.picture;
        profile.locale = payload.locale;
        profile._json = payload;

        done(null, profile);
    });
}

/**
 * Expose `GoogleTokenStrategy`.
 */
module.exports = GoogleTokenStrategy;
