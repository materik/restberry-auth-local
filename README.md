Restberry-Auth-Local
====================

[![](https://img.shields.io/npm/v/restberry-auth-local.svg)](https://www.npmjs.com/package/restberry-auth-local) [![](https://img.shields.io/npm/dm/restberry-auth-local.svg)](https://www.npmjs.com/package/restberry-auth-local)

Passport-local wrapper for Restberry.

## Install

```
npm install restberry-auth-local
```

## Usage

```
var restberryAuth = require('restberry-auth');

var auth = restberryAuth.config(function(auth) {
    ...
})
.use('local', {
    passwordMinLength: 8,
    additionalFields: {
        ...
    },
});

restberry.use(auth);
```

This will add a email and a password field to the User and the possibility to
authenticate with those. One new routes have been created to the User:
POST /login.
