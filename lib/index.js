var _ = require('underscore');
var controller = require('./controller');
var errors = require('restberry-errors');
var modules = require('restberry-modules');
var LocalStrategy = require('passport-local').Strategy;
var logger = require('restberry-logger');
var utils = require('restberry-utils');

var DEFAULT_PASSWORD_MIN_LENGTH = 8;
var DEFAULT_SCHEMA = {
    email: {type: String, required: true, unique: true, lowercase: true},
    password: {
        type: {
            encrypted: {type: String},
            salt: {type: String},
        },
        hidden: true,
    },
};
var LOGIN_PATH = '/login';

function RestberryAuthLocal() {
    this.passwordMinLength = DEFAULT_PASSWORD_MIN_LENGTH;
    this.schema = DEFAULT_SCHEMA;
};

RestberryAuthLocal.prototype.__proto__ = modules.auth.prototype;

RestberryAuthLocal.prototype.authenticate = function(user, plainText) {
    var password = user.get('password');
    if (password) {
        var encrypted = password.encrypted;
        var salt = password.salt;
        if (encrypted && salt) {
            return this.encryptPassword(plainText, salt) === encrypted;
        } else {
            return new Error('This user has been corrupt, contact admin!');
        }
    }
    return false;
};

RestberryAuthLocal.prototype.config = function(config) {
    if (!config)  config = {};
    if (config.passwordMinLength) {
        this.passwordMinLength = config.passwordMinLength;
    }
    if (config.additionalFields) {
        this.schema = _.extend(this.schema, config.additionalFields);
    }
    return this;
};

RestberryAuthLocal.prototype.enable = function(next) {
    var self = this;
    self.passport.use(new LocalStrategy({
        usernameField: 'email',
    }, function(email, password, next) {
        logger.info('SESSION', 'authenticate', email);
        var query = {email: email};
        var User = self.restberry.auth.getUser();
        User.findOne(query, function(user) {
            var auth = self.authenticate(user, password);
            if (_.isBoolean(auth)) {
                if (auth) {
                    next(null, user);
                } else {
                    next(new Error('Invalid email or password.'));
                }
            } else {
                next(auth);
            }
        }, function(err) {
            next(new Error('Invalid email or password.'));
        });
    }));
    next(self.schema);
};

RestberryAuthLocal.prototype.encryptPassword = function(password, salt) {
    if (password) {
        try {
            return utils.sha1encrypt(salt, password);
        } catch (e) {
            // Do nothing...
        }
    }
};

RestberryAuthLocal.prototype.saltAndEncryptPassword = function(password) {
    var salt = utils.makeSalt();
    var encrypted = this.encryptPassword(password, salt);
    return {
        salt: salt,
        encrypted: encrypted,
    };
};

RestberryAuthLocal.prototype.setupRoutes = function() {
    var self = this;
    var User = self.restberry.auth.getUser();
    User.routes.addCustomRoute({
        _controller: controller.login,
        isLoginRequired: false,
        method: 'POST',
        path: LOGIN_PATH,
        preAction: function(req, res, next) {
            self.passport.authenticate('local', function(err, user, info) {
                if (user) {
                    self.passport.authenticate('local')(req, res, next);
                } else {
                    self.restberry.onError(errors.BadRequestMissingField, {
                        property: 'password',
                        modelName: 'User',
                    });
                }
            })(req, res, next);
        },
    });
};

RestberryAuthLocal.prototype.setupUser = function(User) {
    var self = this;
    User.preSave(function(next) {
        var p = this.get('password');
        if (_.isString(p)) {
            if (p.length < self.passwordMinLength) {
                var msg = 'Invalid password, needs to be at lest ' +
                          self.passwordMinLength + ' characters long';
                next(new Error(msg));
            } else {
                this.set('password', self.saltAndEncryptPassword(p));
                next();
            }
        } else {
            next();
        }
    });
    return User;
};

module.exports = exports = new RestberryAuthLocal;
