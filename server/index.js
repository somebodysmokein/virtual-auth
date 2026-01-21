const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require("@simplewebauthn/server");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const express = require("express");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Serve static fallback page
app.use(express.static(path.join(__dirname, "public")));

const RP_NAME = process.env.RP_NAME || "Demo YubiKey App";
const RP_ID = process.env.RP_ID || "localhost";
const ORIGIN = process.env.RP_ORIGIN || "http://localhost:19006";

// In-memory user store for demo purposes. DO NOT USE IN PRODUCTION.
const users = new Map();

function base64urlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlToBuffer(base64url) {
  const base64 =
    base64url.replace(/-/g, "+").replace(/_/g, "/") +
    "==".slice((2 - base64url.length * 3) & 3);
  return Buffer.from(base64, "base64");
}

function bufferToBase64urlIfNeeded(value) {
  if (!value) return value;
  if (Buffer.isBuffer(value)) return base64urlEncode(value);
  if (value instanceof ArrayBuffer) return base64urlEncode(Buffer.from(value));
  if (ArrayBuffer.isView(value))
    return base64urlEncode(Buffer.from(value.buffer));
  return value;
}

function normalizeOptionsForJson(options) {
  const out = JSON.parse(JSON.stringify(options));
  // challenge may be a Buffer/Uint8Array — encode to base64url
  try {
    out.challenge =
      bufferToBase64urlIfNeeded(options.challenge) || out.challenge;
  } catch (_) {}

  if (options.user && options.user.id) {
    out.user = out.user || {};
    out.user.id = bufferToBase64urlIfNeeded(options.user.id) || out.user.id;
  }

  if (options.excludeCredentials && Array.isArray(options.excludeCredentials)) {
    out.excludeCredentials = options.excludeCredentials.map((c, i) => ({
      ...c,
      id: bufferToBase64urlIfNeeded(options.excludeCredentials[i].id) || c.id,
    }));
  }

  if (options.allowCredentials && Array.isArray(options.allowCredentials)) {
    out.allowCredentials = options.allowCredentials.map((c, i) => ({
      ...c,
      id: bufferToBase64urlIfNeeded(options.allowCredentials[i].id) || c.id,
    }));
  }

  return out;
}

app.get("/", (_req, res) => {
  res.send("WebAuthn demo server — use POST /webauthn/* endpoints");
});

app.post("/webauthn/register/options", (req, res) => {
  const { username, displayName } = req.body;
  if (!username) return res.status(400).json({ error: "username required" });

  if (!users.has(username)) {
    users.set(username, {
      id: base64urlEncode(crypto.randomBytes(32)),
      credentials: [],
      currentChallenge: undefined,
    });
  }

  const user = users.get(username);

  const options = generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    user: {
      id: user.id,
      name: username,
      displayName: displayName || username,
    },
    attestationType: "none",
    authenticatorSelection: {
      authenticatorAttachment: "cross-platform",
      userVerification: "preferred",
    },
    // excludeCredentials helps prevent re-registering an existing credential
    // Pass raw bytes for IDs to the generator to avoid double-encoding later
    excludeCredentials: user.credentials.map((c) => ({
      id: base64urlToBuffer(c.credentialID),
      type: "public-key",
    })),
  });

  user.currentChallenge = options.challenge;
  const normalized = normalizeOptionsForJson(options);
  normalized.user = normalized.user || {};
  // Ensure client receives the stored user id and user fields
  normalized.user.id = user.id;
  normalized.user.name = options.user?.name || username;
  normalized.user.displayName =
    options.user?.displayName || displayName || username;
  return res.json({ publicKey: normalized });
});

app.post("/webauthn/register/verify", async (req, res) => {
  const { username, credential } = req.body;
  if (!username || !credential)
    return res.status(400).json({ error: "username and credential required" });
  const user = users.get(username);
  if (!user) return res.status(404).json({ error: "user not found" });

  try {
    // Normalize credential payload from client (accept base64url strings)
    const normalizedCred = JSON.parse(JSON.stringify(credential));
    // Ensure fields are base64url strings (what @simplewebauthn expects)
    if (normalizedCred.rawId && !(typeof normalizedCred.rawId === "string")) {
      // convert ArrayBuffer/Buffer to base64url
      normalizedCred.rawId = base64urlEncode(Buffer.from(normalizedCred.rawId));
    }
    if (!normalizedCred.id && normalizedCred.rawId) {
      normalizedCred.id = normalizedCred.rawId;
    }
    if (normalizedCred.response) {
      if (
        normalizedCred.response.attestationObject &&
        !(typeof normalizedCred.response.attestationObject === "string")
      ) {
        normalizedCred.response.attestationObject = base64urlEncode(
          Buffer.from(normalizedCred.response.attestationObject),
        );
      }
      if (
        normalizedCred.response.clientDataJSON &&
        !(typeof normalizedCred.response.clientDataJSON === "string")
      ) {
        normalizedCred.response.clientDataJSON = base64urlEncode(
          Buffer.from(normalizedCred.response.clientDataJSON),
        );
      }
    }

    const verification = await verifyRegistrationResponse({
      credential: normalizedCred,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    const { verified, registrationInfo } = verification;
    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;
      const credIDb64 = base64urlEncode(credentialID);
      user.credentials.push({
        credentialID: credIDb64,
        credentialPublicKey: base64urlEncode(credentialPublicKey),
        counter,
      });
      return res.json({ verified: true });
    }

    return res.status(400).json({ verified: false });
  } catch (e) {
    console.error(e);
    return res
      .status(500)
      .json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post("/webauthn/authn/options", (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "username required" });
  const user = users.get(username);
  if (!user) return res.status(404).json({ error: "user not found" });

  // Pass raw bytes for allowCredentials to the generator to ensure the authenticator
  // receives the exact byte sequence it expects (avoid sending double-encoded strings)
  const allowCredentials = user.credentials.map((c) => ({
    id: base64urlToBuffer(c.credentialID),
    type: "public-key",
  }));

  const options = generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials,
    userVerification: "preferred",
  });

  user.currentChallenge = options.challenge;
  return res.json({ publicKey: normalizeOptionsForJson(options) });
});

app.post("/webauthn/authn/verify", async (req, res) => {
  const { username, credential } = req.body;
  if (!username || !credential)
    return res.status(400).json({ error: "username and credential required" });
  const user = users.get(username);
  if (!user) return res.status(404).json({ error: "user not found" });

  // Normalize incoming credential: accept standard base64 (with +/=/) or base64url and convert to base64url strings
  const normalizedCred = JSON.parse(JSON.stringify(credential));
  try {
    if (normalizedCred.rawId && typeof normalizedCred.rawId === "string") {
      // If rawId contains + or / or = it's standard base64 — convert to base64url via buffer round-trip
      const buf = Buffer.from(
        normalizedCred.rawId.replace(/-/g, "+").replace(/_/g, "/"),
        "base64",
      );
      normalizedCred.rawId = base64urlEncode(buf);
    }
  } catch (e) {
    // ignore and leave as-is
  }
  if (!normalizedCred.id && normalizedCred.rawId)
    normalizedCred.id = normalizedCred.rawId;

  if (normalizedCred.response) {
    if (
      normalizedCred.response.authenticatorData &&
      !(typeof normalizedCred.response.authenticatorData === "string")
    ) {
      normalizedCred.response.authenticatorData = base64urlEncode(
        Buffer.from(normalizedCred.response.authenticatorData),
      );
    }
    if (
      normalizedCred.response.clientDataJSON &&
      !(typeof normalizedCred.response.clientDataJSON === "string")
    ) {
      normalizedCred.response.clientDataJSON = base64urlEncode(
        Buffer.from(normalizedCred.response.clientDataJSON),
      );
    }
    if (
      normalizedCred.response.signature &&
      !(typeof normalizedCred.response.signature === "string")
    ) {
      normalizedCred.response.signature = base64urlEncode(
        Buffer.from(normalizedCred.response.signature),
      );
    }
    if (
      normalizedCred.response.userHandle &&
      !(typeof normalizedCred.response.userHandle === "string")
    ) {
      try {
        normalizedCred.response.userHandle = base64urlEncode(
          Buffer.from(normalizedCred.response.userHandle),
        );
      } catch (_) {}
    }
  }

  // Find stored authenticator by matching normalized base64url id
  const stored = user.credentials.find(
    (c) =>
      c.credentialID === normalizedCred.id ||
      c.credentialID === normalizedCred.rawId,
  );
  if (!stored)
    return res.status(404).json({ error: "authenticator not found" });

  try {
    const authnResult = await verifyAuthenticationResponse({
      credential: normalizedCred,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: base64urlToBuffer(stored.credentialID),
        credentialPublicKey: base64urlToBuffer(stored.credentialPublicKey),
        counter: stored.counter || 0,
      },
    });

    const { verified, authenticationInfo } = authnResult;
    if (verified && authenticationInfo) {
      // update counter
      stored.counter = authenticationInfo.newCounter;
      return res.json({ verified: true });
    }
    return res.status(400).json({ verified: false });
  } catch (e) {
    console.error(e);
    return res
      .status(500)
      .json({ error: e instanceof Error ? e.message : String(e) });
  }
});

// Debug endpoint: return stored user record for debugging purposes (DEV ONLY)
app.get("/webauthn/debug/:username", (req, res) => {
  const { username } = req.params;
  const user = users.get(username);
  if (!user) return res.status(404).json({ error: "user not found" });
  // return the user object (credentials are base64url strings)
  return res.json({ user });
});

// Store a fallback page result for a username (DEV helper)
app.post("/webauthn/result", (req, res) => {
  const { username, result } = req.body;
  if (!username) return res.status(400).json({ error: "username required" });
  if (!users.has(username))
    return res.status(404).json({ error: "user not found" });
  const user = users.get(username);
  user.lastResult = result;
  return res.json({ ok: true });
});

app.get("/webauthn/result/:username", (req, res) => {
  const { username } = req.params;
  const user = users.get(username);
  if (!user) return res.status(404).json({ error: "user not found" });
  return res.json({ result: user.lastResult || null });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () =>
  console.log(`WebAuthn demo server listening on http://localhost:${PORT}
  RP ID: ${RP_ID}
  ORIGIN: ${ORIGIN}`),
);
