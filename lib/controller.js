var logger = require('restberry-logger');
var httpStatus = require('http-status');


module.exports = {
    login: function() {
        var self = this;
        return function(req, res, next) {
            logger.info('SESSION', 'login', req.user.getId());
            req.user.set('timestampLastLogIn', new Date());
            req.user.save(req, res, function(user) {
                req.expand.push(user.model.singleName());
                user.toJSON(req, res, function(json) {
                    next(json);
                });
            });
        };
    },
};
