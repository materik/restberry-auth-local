var errors = require('restberry-errors');
var controller = require('./controller');
var LocalStrategy = require('passport-local').Strategy;
var logger = require('restberry-logger');
var utils = require('restberry-utils');


var PASSWORD_MIN_LEN = 8;
var DEFAULT_SCHEMA = {
    email: {type: String, required: true, unique: true, lowercase: true},
    _password: {
        type: {
            encrypted: {type: String},
            salt: {type: String},
        },
        hidden: true,
    },
};

function LocalAuth() {
    this.passport = null;
    this.passwordMinLength = PASSWORD_MIN_LEN;
    this.restberry = null;
    this.schema = DEFAULT_SCHEMA;
};

LocalAuth.prototype.use = function(config, next) {
    var self = this;
    if (!config)  config = {};
    if (config.passwordMinLength) {
        self.passwordMinLength = config.passwordMinLength;
    }
    if (config.additionalFields) {
        self.schema = utils.mergeDicts(self.schema, config.additionalFields);
    }
    self.passport.use(new LocalStrategy({
        usernameField: 'email',
    }, function(email, password, next) {
        logger.info('SESSION', 'authenticate', email);
        var query = {email: email};
        self.restberry.auth.User.model.findOne(query, function(err, user) {
            if (err) {
                next(new Error(err));
            } else if (!user || !self.authenticate(user, password)) {
                err = {
                    message: 'Invalid email or password.',
                    title: 'Authentication Error',
                };
                next(new Error(err));
            } else {
                next(null, user);
            }
        });
    }));
    next(self.schema);
};

LocalAuth.prototype.authenticate = function(user, plainText) {
    if (user._password) {
        var encrypted = user._password.encrypted;
        var salt = user._password.salt;
        return this.encryptPassword(plainText, salt) === encrypted;
    }
    return false;
};

LocalAuth.prototype.encryptPassword = function(password, salt) {
    if (password) {
        try {
            return utils.sha1encrypt(salt, password);
        } catch (e) {
            // Do nothing...
        }
    }
    return;
};

LocalAuth.prototype.setupSchema = function(schema) {
    var self = this;
    schema
        .pre('save', function(next) {
            var p = this._password;
            if (p && p.salt && p.salt.length &&
                p.encrypted && p.encrypted.length) {
                next();
            } else {
                var msg = 'Invalid password, needs to be at lest ' +
                          self.passwordMinLength + ' characters long';
                next(new Error(msg));
            };
        })
        .virtual('password')
            .set(function(password) {
                this._password = {};
                if (password && password.length >= self.passwordMinLength) {
                    var salt = utils.makeSalt();
                    this._password.salt = salt;
                    var encrypted = self.encryptPassword(password, salt);
                    this._password.encrypted = encrypted;
                }
            });
    return schema;
};

LocalAuth.prototype.setupRoutes = function() {
    var self = this;
    var User = self.restberry.auth.User;
    User.routes
        .addCustom({
            controller: controller.login,
            method: 'POST',
            path: '/login',
            preAction: self.passport.authenticate('local'),
        })
        .addCustom({
            controller: controller.logout,
            path: '/logout',
        });
};

module.exports = exports = new LocalAuth;
