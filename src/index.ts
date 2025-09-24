import { serve } from "bun";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import bcrypt from "bcryptjs";

// Generate RSA key pair for signing JWTs
const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwk = await exportJWK(publicKey);

// In-memory stores (use proper database in production)
const clients = new Map();
const users = new Map();
const authCodes = new Map();
const accessTokens = new Map();

// Sample client registration
clients.set("sample-client", {
  client_id: "sample-client",
  client_secret: "sample-secret",
  redirect_uris: ["http://localhost:3001/callback"],
  response_types: ["code"],
  grant_types: ["authorization_code"],
});

// Sample user
const hashedPassword = await bcrypt.hash("password123", 10);
users.set("testuser", {
  id: "testuser",
  email: "test@example.com",
  password: hashedPassword,
});

// OIDC Discovery endpoint
const wellKnownConfig = {
  issuer: "http://localhost:3000",
  authorization_endpoint: "http://localhost:3000/auth",
  token_endpoint: "http://localhost:3000/token",
  userinfo_endpoint: "http://localhost:3000/userinfo",
  jwks_uri: "http://localhost:3000/.well-known/jwks.json",
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email"],
  token_endpoint_auth_methods_supported: [
    "client_secret_basic",
    "client_secret_post",
  ],
};

function generateAuthCode() {
  return Math.random().toString(36).substring(2, 15);
}

function generateAccessToken() {
  return (
    Math.random().toString(36).substring(2, 15) +
    Math.random().toString(36).substring(2, 15)
  );
}

async function createIdToken(userId: string, clientId: string) {
  const user = users.get(userId);
  if (!user) throw new Error("User not found");

  return await new SignJWT({
    sub: user.id,
    email: user.email,
    aud: clientId,
    iss: "http://localhost:3000",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
  })
    .setProtectedHeader({ alg: "RS256" })
    .sign(privateKey);
}

const server = serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    // CORS headers
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
      if (path === "/.well-known/openid_configuration") {
        return new Response(JSON.stringify(wellKnownConfig, null, 2), {
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      }

      // JWKS endpoint
      if (path === "/.well-known/jwks.json") {
        const jwks = {
          keys: [
            {
              ...jwk,
              alg: "RS256",
              use: "sig",
              kid: "1",
            },
          ],
        };
        return new Response(JSON.stringify(jwks, null, 2), {
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      }

      // Authorization endpoint
      if (path === "/authorize" && method === "GET") {
        const clientId = url.searchParams.get("client_id");
        const redirectUri = url.searchParams.get("redirect_uri");
        const responseType = url.searchParams.get("response_type");
        const scope = url.searchParams.get("scope");
        const state = url.searchParams.get("state");

        if (!clientId || !redirectUri || responseType !== "code") {
          return new Response("Invalid request", {
            status: 400,
            headers: corsHeaders,
          });
        }

        const client = clients.get(clientId);
        if (!client || !client.redirect_uris.includes(redirectUri)) {
          return new Response("Invalid client", {
            status: 400,
            headers: corsHeaders,
          });
        }

        // Simple login form
        const loginForm = `
          <!DOCTYPE html>
          <html>
            <head><title>Login</title></head>
            <body>
              <h2>Login</h2>
              <form method="post" action="/authorize">
                <input type="hidden" name="client_id" value="${clientId}">
                <input type="hidden" name="redirect_uri" value="${redirectUri}">
                <input type="hidden" name="response_type" value="${responseType}">
                <input type="hidden" name="scope" value="${scope || ""}">
                <input type="hidden" name="state" value="${state || ""}">
                <div>
                  <label>Username: <input type="text" name="username" required></label>
                </div>
                <div>
                  <label>Password: <input type="password" name="password" required></label>
                </div>
                <button type="submit">Login</button>
              </form>
            </body>
          </html>
        `;

        return new Response(loginForm, {
          headers: { "Content-Type": "text/html", ...corsHeaders },
        });
      }

      // Handle login form submission
      if (path === "/authorize" && method === "POST") {
        const formData = await req.formData();
        const username = formData.get("username") as string;
        const password = formData.get("password") as string;
        const clientId = formData.get("client_id") as string;
        const redirectUri = formData.get("redirect_uri") as string;
        const state = formData.get("state") as string;

        const user = users.get(username);
        if (!user || !(await bcrypt.compare(password, user.password))) {
          return new Response("Invalid credentials", {
            status: 401,
            headers: corsHeaders,
          });
        }

        // Generate authorization code
        const code = generateAuthCode();
        authCodes.set(code, {
          userId: user.id,
          clientId,
          redirectUri,
          expiresAt: Date.now() + 600000, // 10 minutes
        });

        // Redirect with code
        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set("code", code);
        if (state) redirectUrl.searchParams.set("state", state);

        return Response.redirect(redirectUrl.toString(), 302);
      }

      // Token endpoint
      if (path === "/token" && method === "POST") {
        const formData = await req.formData();
        const grantType = formData.get("grant_type");
        const code = formData.get("code") as string;
        const clientId = formData.get("client_id") as string;
        const clientSecret = formData.get("client_secret") as string;

        if (grantType !== "authorization_code") {
          return new Response(
            JSON.stringify({ error: "unsupported_grant_type" }),
            {
              status: 400,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        const client = clients.get(clientId);
        if (!client || client.client_secret !== clientSecret) {
          return new Response(JSON.stringify({ error: "invalid_client" }), {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        const authCode = authCodes.get(code);
        if (!authCode || authCode.expiresAt < Date.now()) {
          return new Response(JSON.stringify({ error: "invalid_grant" }), {
            status: 400,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        authCodes.delete(code);

        // Generate tokens
        const accessToken = generateAccessToken();
        const idToken = await createIdToken(authCode.userId, clientId);

        accessTokens.set(accessToken, {
          userId: authCode.userId,
          clientId,
          expiresAt: Date.now() + 3600000, // 1 hour
        });

        return new Response(
          JSON.stringify({
            access_token: accessToken,
            token_type: "Bearer",
            expires_in: 3600,
            id_token: idToken,
          }),
          {
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // UserInfo endpoint
      if (path === "/userinfo" && method === "GET") {
        const authHeader = req.headers.get("Authorization");
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return new Response(JSON.stringify({ error: "invalid_token" }), {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        const accessToken = authHeader.substring(7);
        const tokenData = accessTokens.get(accessToken);

        if (!tokenData || tokenData.expiresAt < Date.now()) {
          return new Response(JSON.stringify({ error: "invalid_token" }), {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        const user = users.get(tokenData.userId);
        if (!user) {
          return new Response(JSON.stringify({ error: "invalid_token" }), {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        return new Response(
          JSON.stringify({
            sub: user.id,
            email: user.email,
          }),
          {
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      return new Response("Not Found", { status: 404, headers: corsHeaders });
    } catch (error) {
      console.error("Server error:", error);
      return new Response("Internal Server Error", {
        status: 500,
        headers: corsHeaders,
      });
    }
  },
});

console.log(`OIDC Server running on http://localhost:${server.port}`);
console.log(
  "Discovery endpoint: http://localhost:3000/.well-known/openid_configuration"
);
console.log("Sample client_id: sample-client");
console.log("Sample user: testuser / password123");
