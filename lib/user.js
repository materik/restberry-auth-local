UserSchema
    .pre('save', function(next) {
        if (!this.username || !this.username.length) {
            this.username = this.email;
        };
        var p = this.password;
        if (p && p.salt && p.salt.length &&
            p.encrypted && p.encrypted.length) {
            next();
        } else {
            next(new Error('Invalid password, needs to be at lest ' +
                           PASSWORD_MIN_LEN + ' characters long'));
        };
    })
UserSchema
    .virtual('_email')
        .set(function(email) {
            this.email = email;
            this.username = (this.username ? this.username : email);
        })
UserSchema
    .virtual('_encryptPassword')
        .set(function(password) {
            this.password = {};
            if (password && password.length >= PASSWORD_MIN_LEN) {
                this.password.salt = utils.makeSalt();
                this.password.encrypted = this.encryptPassword(password);
            }
        });
