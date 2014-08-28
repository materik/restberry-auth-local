var LocalStrategy = require('passport-local').Strategy;
var logger = require('restberry-logger');
var utils = require('restberry-utils');

var PASSWORD_MIN_LEN = 8;
var DEFAULT_SCHEMA = {
    username: {type: String, required: true, unique: true},
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
    },
    password: {
        encrypted: {type: String},
        salt: {type: String},
    },
};

function LocalAuth(auth, passport) {
    this.auth = auth;
    this.schema = DEFAULT_SCHEMA;
    this.passport = passport;
    this.passwordMinLength = PASSWORD_MIN_LEN;
};

LocalAuth.prototype._setup = function() {
    var self = this;
    self.passport.use(new LocalStrategy(function(username, password, next) {
        logger.log('SESSION', 'authenticate', username);
        var query = {username: username};
        self.auth.user.findOne(query, function(err, user) {
            if (err) {
                // TODO(materik):
                console.log(err)
                //_throwerrors(err, next);
            } else if (!user || !user.authenticate(password)) {
                // TODO(materik):
                err = {
                    title: 'Authentication Error',
                    message: 'Invalid username or password.',
                };
                console.log(err)
                //_throwerrors(err, next);
            } else {
                next(null, user);
            }
        });
    }));
};

LocalAuth.prototype.use = function(config, next) {
    if (config.passwordMinLength) {
        this.passwordMinLength = config.passwordMinLength;
    }
    if (config.additionalFields) {
        this.schema = utils.mergeDicts(this.schema, config.additionalFields);
    }
    next(this.schema);
};

module.exports = exports = new LocalAuth;
