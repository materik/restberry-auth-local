var _ = require('underscore');
var errors = require('restberry-errors');
var controller = require('./controller');
var modules = require('restberry-modules');
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

function RestberryAuthLocal() {
    this.passwordMinLength = PASSWORD_MIN_LEN;
    this.schema = DEFAULT_SCHEMA;
};

RestberryAuthLocal.prototype.__proto__ = modules.auth.prototype;

RestberryAuthLocal.prototype.authenticate = function(user, plainText) {
    var data = user.getData();
    if (data && data._password) {
        var encrypted = data._password.encrypted;
        var salt = data._password.salt;
        return this.encryptPassword(plainText, salt) === encrypted;
    }
    return false;
};

RestberryAuthLocal.prototype.use = function(next) {
    var self = this;
    self.passport.use(new LocalStrategy({
        usernameField: 'email',
    }, function(email, password, next) {
        logger.info('SESSION', 'authenticate', email);
        var query = {email: email};
        var User = self.restberry.auth.getUser();
        User._findOne(query, function(err, _obj) {
            var user = User.obj(_obj);
            if (err) {
                next(new Error(err));
            } else if (!self.authenticate(user, password)) {
                next(new Error('Invalid email or password.'));
            } else {
                next(null, user);
            }
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

RestberryAuthLocal.prototype.setupRoutes = function() {
    var self = this;
    var User = self.restberry.model('User');
    User.routes
        .addCustom({
            _controller: controller.login,
            loginRequired: false,
            method: 'POST',
            path: '/login',
            preAction: self.passport.authenticate('local'),
        })
        .addCustom({
            _controller: controller.logout,
            loginRequired: false,
            path: '/logout',
        });
};

RestberryAuthLocal.prototype.setupSchema = function(schema) {
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

module.exports = exports = new RestberryAuthLocal;
