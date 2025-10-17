import { serve } from "bun";
import { SignJWT, generateKeyPair, exportJWK } from "jose";

// Configuration
const config = {
  port: 3000,
  issuer: "http://localhost:3000",
  baseUrl: "http://localhost:3000",
};

// OIDC Discovery endpoint
const wellKnownConfig = {
  issuer: config.issuer,
  authorization_endpoint: `${config.baseUrl}/authorize`,
  token_endpoint: `${config.baseUrl}/token`,
  userinfo_endpoint: `${config.baseUrl}/userinfo`,
  jwks_uri: `${config.baseUrl}/.well-known/jwks.json`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email"],
};

// Generate RSA key pair for signing JWTs
const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwk = await exportJWK(publicKey);

// In-memory storage
const clients = new Map([
  [
    "sample-client",
    {
      client_id: "sample-client",
      client_secret: "sample-secret",
      redirect_uris: ["http://localhost:3001/callback"],
    },
  ],
]);

const users = new Map([
  [
    "testuser",
    {
      id: "user-1",
      username: "testuser",
      email: "test@example.com",
      password: "password123",
    },
  ],
]);

const authCodes = new Map();
const accessTokens = new Map();

// PKCE helper functions
function base64UrlEncode(buffer: Uint8Array): string {
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function verifySha256(codeChallenge: string, codeVerifier: string): boolean {
  const hash = new Bun.CryptoHasher("sha256").update(codeVerifier).digest();
  const encodedHash = base64UrlEncode(hash);
  return codeChallenge === encodedHash;
}

// Type definitions
interface TokenRequest {
  grant_type: string;
  code?: string;
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  code_verifier?: string;
}

function generateCode() {
  return Math.random().toString(36).substring(2, 15);
}

async function createIdToken(userId: string, clientId: string) {
  const user = users.get(userId);
  if (!user) throw new Error("User not found");

  return await new SignJWT({
    sub: user.id,
    email: user.email,
    name: user.username,
    aud: clientId,
    iss: config.issuer,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  })
    .setProtectedHeader({ alg: "RS256" })
    .sign(privateKey);
}

async function createAccessToken(userId: string, clientId: string) {
  return await new SignJWT({
    sub: userId,
    aud: clientId,
    iss: config.issuer,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    scope: "openid profile email",
  })
    .setProtectedHeader({ alg: "RS256" })
    .sign(privateKey);
}

const server = serve({
  port: config.port,
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Discovery endpoint
      if (path === "/.well-known/openid-configuration") {
        const discoveryConfig = {
          issuer: config.issuer,
          authorization_endpoint: `${config.baseUrl}/authorize`,
          token_endpoint: `${config.baseUrl}/token`,
          userinfo_endpoint: `${config.baseUrl}/userinfo`,
          jwks_uri: `${config.baseUrl}/.well-known/jwks.json`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          scopes_supported: ["openid", "profile", "email"],
        };
        return new Response(JSON.stringify(discoveryConfig), {
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      }

      // JWKS endpoint
      if (path === "/.well-known/jwks.json") {
        return new Response(
          JSON.stringify({
            keys: [
              {
                ...jwk,
                alg: "RS256",
                use: "sig",
                kid: "1",
              },
            ],
          }),
          {
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // Authorization endpoint
      if (path === "/authorize" && method === "GET") {
        const clientId = url.searchParams.get("client_id");
        const redirectUri = url.searchParams.get("redirect_uri");
        const responseType = url.searchParams.get("response_type");
        const state = url.searchParams.get("state");
        const codeChallenge = url.searchParams.get("code_challenge");
        const codeChallengeMethod = url.searchParams.get(
          "code_challenge_method"
        );

        if (!clientId || !redirectUri) {
          return new Response("Missing parameters", { status: 400 });
        }

        const client = clients.get(clientId);
        if (!client || !client.redirect_uris.includes(redirectUri)) {
          return new Response("Invalid client or redirect URI", {
            status: 400,
          });
        }

        // Simple login form
        const html = `<!DOCTYPE html>
<html>
<head>
  <title>OIDC Login</title>
  <style>
    body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f5f5f5; }
    .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }
    h1 { text-align: center; color: #333; }
    input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; border: 1px solid #ddd; border-radius: 4px; }
    button { width: 100%; padding: 10px; margin: 20px 0 0 0; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
    button:hover { background: #0056b3; }
  </style>
</head>
<body>
  <div class="login-box">
    <h1>Login</h1>
    <form method="post" action="/authorize">
      <input type="hidden" name="client_id" value="${clientId}">
      <input type="hidden" name="redirect_uri" value="${redirectUri}">
      <input type="hidden" name="response_type" value="${
        responseType || "code"
      }">
      <input type="hidden" name="state" value="${state || ""}">
      <input type="hidden" name="code_challenge" value="${codeChallenge || ""}">
      <input type="hidden" name="code_challenge_method" value="${
        codeChallengeMethod || ""
      }">
      <input type="text" name="username" placeholder="Username" required autofocus>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Login</button>
    </form>
    <p style="text-align: center; margin-top: 20px; color: #666; font-size: 14px;">Demo: testuser / password123</p>
  </div>
</body>
</html>`;

        return new Response(html, {
          headers: { "Content-Type": "text/html", ...corsHeaders },
        });
      }

      // Handle login
      if (path === "/authorize" && method === "POST") {
        const formData = await req.formData();
        const username = formData.get("username") as string;
        const password = formData.get("password") as string;
        const clientId = formData.get("client_id") as string;
        const redirectUri = formData.get("redirect_uri") as string;
        const state = formData.get("state") as string;
        const codeChallenge = formData.get("code_challenge") as string;
        const codeChallengeMethod = formData.get(
          "code_challenge_method"
        ) as string;

        const user = users.get(username);
        if (!user || user.password !== password) {
          return new Response("Invalid credentials", { status: 401 });
        }

        // Generate auth code
        const code = generateCode();
        authCodes.set(code, {
          userId: user.id,
          clientId,
          redirectUri,
          codeChallenge,
          codeChallengeMethod,
          expiresAt: Date.now() + 600000,
        });

        // Redirect with code
        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set("code", code);
        if (state) redirectUrl.searchParams.set("state", state);

        return Response.redirect(redirectUrl.toString(), 302);
      }

      // Token endpoint
      if (path === "/token" && method === "POST") {
        const body = (await req.json()) as TokenRequest;
        const {
          grant_type,
          code,
          client_id,
          client_secret,
          redirect_uri,
          code_verifier,
        } = body;

        if (grant_type !== "authorization_code") {
          return new Response(
            JSON.stringify({ error: "unsupported_grant_type" }),
            {
              status: 400,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        const client = clients.get(client_id);
        if (!client || client.client_secret !== client_secret) {
          return new Response(JSON.stringify({ error: "invalid_client" }), {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        const authCode = authCodes.get(code);
        if (
          !authCode ||
          authCode.expiresAt < Date.now() ||
          authCode.redirectUri !== redirect_uri
        ) {
          return new Response(JSON.stringify({ error: "invalid_grant" }), {
            status: 400,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        // Verify PKCE if code_challenge was used
        if (authCode.codeChallenge) {
          if (!code_verifier) {
            return new Response(
              JSON.stringify({
                error: "invalid_grant",
                error_description: "code_verifier required",
              }),
              {
                status: 400,
                headers: { "Content-Type": "application/json", ...corsHeaders },
              }
            );
          }

          const method = authCode.codeChallengeMethod || "plain";
          let verified = false;

          if (method === "S256") {
            verified = verifySha256(authCode.codeChallenge, code_verifier);
          } else if (method === "plain") {
            verified = authCode.codeChallenge === code_verifier;
          }

          if (!verified) {
            return new Response(
              JSON.stringify({
                error: "invalid_grant",
                error_description: "invalid code_verifier",
              }),
              {
                status: 400,
                headers: { "Content-Type": "application/json", ...corsHeaders },
              }
            );
          }
        }

        authCodes.delete(code);

        const accessToken = await createAccessToken(authCode.userId, client_id);
        const idToken = await createIdToken(authCode.userId, client_id);

        accessTokens.set(accessToken, { userId: authCode.userId });

        return new Response(
          JSON.stringify({
            access_token: accessToken,
            id_token: idToken,
            token_type: "Bearer",
            expires_in: 3600,
          }),
          {
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // UserInfo endpoint
      if (path === "/userinfo" && method === "GET") {
        const authHeader = req.headers.get("Authorization");
        if (!authHeader?.startsWith("Bearer ")) {
          return new Response(JSON.stringify({ error: "unauthorized" }), {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        const token = authHeader.substring(7);
        if (!accessTokens.has(token)) {
          return new Response(JSON.stringify({ error: "invalid_token" }), {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        const tokenData = accessTokens.get(token);
        let user;
        for (const u of users.values()) {
          if (u.id === tokenData.userId) {
            user = u;
            break;
          }
        }

        if (!user) {
          return new Response(JSON.stringify({ error: "user_not_found" }), {
            status: 404,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        return new Response(
          JSON.stringify({
            sub: user.id,
            email: user.email,
            name: user.username,
          }),
          {
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      return new Response("Not Found", { status: 404 });
    } catch (error) {
      console.error("Error:", error);
      return new Response("Internal Server Error", { status: 500 });
    }
  },
});

console.log("🔐 OIDC Server running on http://localhost:3000");
console.log(
  "📋 Discovery: http://localhost:3000/.well-known/openid-configuration"
);
console.log("👤 Demo user: testuser / password123");
console.log("🔑 Client: sample-client / sample-secret");
