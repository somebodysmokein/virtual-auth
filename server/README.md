# WebAuthn Demo Server

Simple demo server implementing WebAuthn registration and authentication endpoints using `@simplewebauthn/server`.

Usage

1. Install dependencies:

```bash
cd server
npm install
```

2. (Optional) Configure environment variables:

- `RP_NAME` — relying party name (defaults to "Demo YubiKey App")
- `RP_ID` — relying party id (defaults to `localhost`)
- `RP_ORIGIN` — expected origin for WebAuthn (defaults to `http://localhost:19006` — Expo web default)
- `PORT` — server port (defaults to `4000`)

Example run:

```bash
RP_ORIGIN=http://localhost:19006 node index.js
```

Endpoints

- `POST /webauthn/register/options` — body: `{ username, displayName }` → returns registration options under `publicKey`.
- `POST /webauthn/register/verify` — body: `{ username, credential }` → verifies attestation and stores credential.
- `POST /webauthn/authn/options` — body: `{ username }` → returns authentication options under `publicKey`.
- `POST /webauthn/authn/verify` — body: `{ username, credential }` → verifies assertion.

This server is intentionally minimal and stores credentials in memory for demo purposes only. Do not use this in production.
