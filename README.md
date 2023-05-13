# JWT & WebAuthn demo

Utilizing JWT & WebAuthn together in a backend API.

Made this for [@Sellix](https://github.com/Sellix) in hopes to get an internship with them.

Didn't use Redis for this, since I wanted it to work out-of-the-box for people lacking the PHPRedis extension.

On a live website, Redis or Memcached should be employed to cache data from database, and to blacklist JWT tokens on logout/password reset.

## Showcase

https://github.com/wnelson03/jwt-webauthn-php/assets/83034852/e7b70e04-1391-414a-b6b3-b07613f2e309

## Requirements

PHP >= 8.0.0

MySQL Server with mysqlnd

## Setup

Import `schema.sql` into MySQL or MariaDB and you can run the demo.

For a live website, make sure to change [credentials](#credentials) first.

## Privacy

Emails are hashed with SHA1 so that the operator can't see plain-text emails.

No model name or serial numbers are collected for WebAuthn. The operator can't tell if you're using YubiKey or SoloKey, or any other WebAuthn-compatible device

### Database sample

**Accounts table:**

|id|email|password|securityKey|
|---|---|---|---|
|21|26bead3658ccd9d4598bdca509f9b42cf6b8a3f5|$2y$10$s...|1|

**securitykeys table:**

|id|account|credentialId|credentialPublicKey|
|---|---|---|---|
|3|21|WJTV6t9GmYgGVS8h2OHkZkPGeqUECCe3xOc5sds6WCpMSi8r+9oWZsIdQiEp/nFUkGnv2PqPaZ9ezs6wnGDfkQ==|-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoTQh+4LXNHgMEtAgLrrkJBdFXPoZtciHcs+dJbKA7O/GYdIyfI92Pa8RMoHTCE5EuMp2XkqdxUgTmiq+Ao6AMw==-----END PUBLIC KEY-----|

### JWT sample

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MjEsImF1dGgiOnRydWUsIm1mYSI6bnVsbCwiZW1haWwiOiIyNmJlYWQzNjU4Y2NkOWQ0NTk4YmRjYTUwOWY5YjQyY2Y2YjhhM2Y1In0.065m3mWiufxgUDSj2VUAGS3x4bwW6KLcFBs1shJCrlA
```
**Decoded**
```
{"typ":"JWT","alg":"HS256"}{"id":21,"auth":true,"mfa":null,"email":"26bead3658ccd9d4598bdca509f9b42cf6b8a3f5"}<signatureHere>
```

## Credentials

In a live website, these credentials should be changed and stored in a seperate configuration file such as `credentials.php`, and then you add `credentials.php` to the `.gitignore` and make a `credentials.example.php` for public use.

Another way would be setting the credentials via FastCGI Params in nginx, to create further seperation between the credentials and the source code.

**JWT Secret**

https://github.com/wnelson03/jwt-webauthn-php/blob/ebffedcb77a656fca3e102f4504673cf6d6c8b78/api/main.php#L15

https://github.com/wnelson03/jwt-webauthn-php/blob/ebffedcb77a656fca3e102f4504673cf6d6c8b78/api/main.php#L29

**MySQL Server**

https://github.com/wnelson03/jwt-webauthn-php/blob/ebffedcb77a656fca3e102f4504673cf6d6c8b78/api/main.php#L53

https://github.com/wnelson03/jwt-webauthn-php/blob/ebffedcb77a656fca3e102f4504673cf6d6c8b78/api/main.php#L79

https://github.com/wnelson03/jwt-webauthn-php/blob/ebffedcb77a656fca3e102f4504673cf6d6c8b78/api/routing.php#L81


