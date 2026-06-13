# Domain SSO

Lightweight OIDC SSO for development or internal testing.

It accepts any email under configured domains:

```text
a@smartatomic.singles   OK
b@smartatomic.singles   OK
x@gmail.com             rejected
```

The OIDC implementation is handled by `oidc-provider`; Express is only used for the login UI and app wrapper.

## Configure

Copy `.env.example` to `.env` and edit:

```env
PORT=7080
ISSUER=http://localhost:7080
ALLOWED_EMAIL_DOMAINS=smartatomic.singles,example.com
CLIENT_ID=kiro
CLIENT_SECRET=change-this-client-secret
REDIRECT_URIS=http://localhost:3000/callback
COOKIE_KEYS=change-this-cookie-key-1,change-this-cookie-key-2
DATA_DIR=./data
JWKS_PATH=./data/jwks.json
```

For a real domain, set `ISSUER` to the public HTTPS URL:

```env
ISSUER=https://sso.smartatomic.singles
```

## Run locally

```bash
npm install
npm run dev
```

Open:

```text
http://localhost:7080/.well-known/openid-configuration
```

## Run with Docker

```bash
docker compose up -d --build
```

The service stores long-lived OIDC state in `./data`:

```text
data/jwks.json        token signing key
data/oidc-store.json  authorization/session/grant state
```

Keep this directory when moving or redeploying the service.

## OIDC client settings

Use these values in the app that needs SSO:

```text
Issuer:        http://localhost:7080
Client ID:     kiro
Client Secret: value of CLIENT_SECRET
Scopes:        openid profile email
Flow:          authorization_code
```

Set the app callback URL in `REDIRECT_URIS`.

Multiple redirect URIs are comma-separated:

```env
REDIRECT_URIS=http://localhost:3000/callback,https://app.example.com/oauth/callback
```

Multiple allowed email domains are also comma-separated:

```env
ALLOWED_EMAIL_DOMAINS=smartatomic.singles,example.com,@another.example
```

## Security note

This service only checks that the email string ends with the allowed domain. It does not prove the user owns that mailbox. Use it for development, testing, or trusted internal environments.

The included file adapter is intended for a single container instance. If you need multiple replicas or high traffic, replace it with Redis/PostgreSQL storage.

For production, use Keycloak, Authentik, or another real identity provider with email verification or enterprise IdP login.
