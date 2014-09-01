var logger = require('restberry-logger');
var httpStatus = require('http-status');


module.exports = {
    login: function() {
        var self = this;
        self.action = function(req, res, next) {
            logger.info('SESSION', 'login', req.user._id);
            req.user.timestampLastLogIn = new Date();
            req.user.saveAndVerify(req, res, function(user) {
                req.expand.push(user.constructor.singleName());
                user.toJSON(req, res, true, function(json) {
                    next(json);
                });
            });
        };
    },

    logout: function() {
        var self = this;
        self.action = function(req, res, next) {
            if (req.user) {
                logger.info('SESSION', 'logout', req.user._id);
                req.logout();
            }
            res.status(httpStatus.NO_CONTENT);
            next({});
        };
    },
};
