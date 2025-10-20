import { serve } from "bun";
import * as crypto from "crypto";
import { json } from "stream/consumers";

// Configuration
const config = {
  baseUrl: new URL("http://localhost:3000"),
} as { baseUrl: URL };
const salt = crypto.randomBytes(16).toString("hex");

// OIDC Discovery endpoint
const wellKnownConfig = {
  issuer: config.baseUrl,
  authorization_endpoint: new URL("/authorize", config.baseUrl),
  token_endpoint: new URL("/token", config.baseUrl),
  userinfo_endpoint: new URL("userinfo", config.baseUrl),
  jwks_uri: new URL("/.well-known/jwks.json", config.baseUrl),
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email"],
};

// Generate RSA key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Export public key as JWK
const publicKeyObj = crypto.createPublicKey(publicKey);
const jwk = publicKeyObj.export({ format: "jwk" });

// in-memory storage
const clients = new Map([
  ["sample-client", {
    client_id: "sample-client",
    client_secret: "sample-secret",
    redirect_uris: ["http://localhost:3001/callback"],
  }],
]);
const users = new Map([
  ["testuser", {
    id: "user-1",
    username: "testuser",
    email: "test@example.com",
    password: hashPassword("password123"),
  }],
]);
const authCodes = new Map();
const accessTokens = new Map();

// Password hashing
// return the hashed password from using the salt in the configuration
function hashPassword(password: string): string {
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString(
    "hex",
  );
  return hash;
}

serve({
  port: config.baseUrl.port,
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };
    const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (path === "/") {
      return new Response(`Hello from OIDC server\n`, {
        headers: corsHeaders,
      });
    }

    if (path === "/.well-known/openid-configuration") {
      return new Response(JSON.stringify(wellKnownConfig), {
        headers: jsonHeaders,
      });
    }

    if (path === "/.well-known/jwks.json") {
      return new Response(
        JSON.stringify({
          keys: [{ ...jwk, alg: "RS256", use: "sig", kid: "1" }],
        }),
        { headers: jsonHeaders },
      );
    }

    if (path === "/authorize" && method === "GET") {
      const clientId = url.searchParams.get("client_id");
      const redirectUri = url.searchParams.get("redirect_uri");
      const codeChallenge = url.searchParams.get("code_challenge");
      const codeChallengeMethod = url.searchParams.get("code_challenge_method");
      const state = url.searchParams.get("state");

      if (!clientId || !redirectUri || !codeChallenge) {
        return new Response("Missing required parameters", { status: 400 });
      }
      if (
        !clients.get(clientId) ||
        !clients.get(clientId)?.redirect_uris.includes(redirectUri)
      ) {
        return Response("Invalid client or redirect URI", { status: 400 });
      }

      const html = `<!DOCTYPE html>
          <html>
              <head><title>Login</title></head>
              <body>
                <h1>Login</h1>
                <form method="post" action="${wellKnownConfig.authorization_endpoint}">
                  <input type="hidden" name="client_id" value="${clientId}">
                  <input type="hidden" name="redirect_uri" value="${redirectUri}">
                  <input type="hidden" name="code_challenge" value="${codeChallenge}">
                  <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod || "S256"
        }">
                  <input type="hidden" name="state" value="${state || ""}">
                  <input type="text" name="username" placeholder="Username" required autofocus>
                  <input type="password" name="password" placeholder="Password" required>
                  <button type="submit">Login</button>
                </form>
                <p>Demo: testuser / password123</p>
              </body>
          </html>`;
      return new Response(html, {
        "Content-Type": "text/html",
        ...corsHeaders,
      });
    }
    return new Response("Not found", { status: 404, headers: corsHeaders });
  },
});

console.log(`🔐 OIDC Server running on ${config.baseUrl}`);
console.log(
  `📋 Discovery: ${new URL(
    "/.well-known/openid-configuration",
    config.baseUrl,
  )}`,
);
