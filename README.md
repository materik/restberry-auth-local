Restberry-Auth-Local
====================

[![](https://img.shields.io/npm/v/restberry-auth-local.svg)](https://www.npmjs.com/package/restberry-auth-local) [![](https://img.shields.io/npm/dm/restberry-auth-local.svg)](https://www.npmjs.com/package/restberry-auth-local)

Passport-local wrapper for Restberry Auth. This package implements the Auth
interface of Restberry-Modules and can be used by Restberry.

## Install

```
npm install restberry-auth-local
```

## Usage

```
var restberryAuth = require('restberry-auth');
var restberryAuthLocal = require('restberry-auth-local');

restberry
    .use(restberryAuth.use(function(auth) {
            ...
        })
        .use(restberryAuthLocal.config({
            passwordMinLength: 8,
            additionalFields: {
                ...
            },
        });
```

This will add a email and a password field to the User and the possibility to
authenticate with those. One new routes have been created to the User:
POST /login.
