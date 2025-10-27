import { serve } from "bun";
import * as crypto from "node:crypto";

// Configuration
const config = {
  baseUrl: new URL("http://localhost:3000"),
  sessionDuration: 15 * 60, // 15 minutes
} as { baseUrl: URL; sessionDuration: number };
const salt = generateCode();

// OIDC Discovery endpoint
const wellKnownConfig = {
  issuer: config.baseUrl,
  authorization_endpoint: new URL("/authorize", config.baseUrl),
  token_endpoint: new URL("/token", config.baseUrl),
  userinfo_endpoint: new URL("/userinfo", config.baseUrl),
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
    redirect_uris: ["http://localhost:3001/"],
  }],
]);

type User = {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
};

const user: User = {
  id: "user-1",
  username: "testuser",
  email: "test@example.com",
  passwordHash: hashPassword("password123"),
};
const usersByUsername = new Map<string, User>([
  ["testuser", user],
]);
const usersById = new Map<string, User>([
  ["user-1", user],
]);

type AuthSession = {
  userId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  expiresAt: number;
};

const authSessions = new Map<string, AuthSession>();

// Generate a random string
function generateCode(): string {
  return crypto.randomBytes(16).toString("hex");
}

// Password hashing
// return the hashed password from using the salt in the configuration
function hashPassword(password: string): string {
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString(
    "hex",
  );
  return hash;
}

function base64UrlEncode(buffer: Uint8Array | string): string {
  let encoded = Buffer.from(buffer).toString("base64");
  encoded = encoded.replace(/=*$/, "");
  encoded = encoded.replaceAll("+", "-").replaceAll("/", "_");
  return encoded;
}

function base64UrlDecode(encoded: string | undefined): Buffer {
  const str = encoded ?? "";
  const padding = "=".repeat((4 - str.length % 4) % 4);
  const base64 = (encoded + padding).replaceAll("-", "+").replaceAll("_", "/");
  return Buffer.from(base64, "base64");
}

// method to verify the code challenge with SHA256
function verifySHA256(codeChallenge: string, codeVerifier: string): boolean {
  const hash = crypto.createHash("sha256").update(codeVerifier).digest();
  return codeChallenge === base64UrlEncode(hash);
}

// JWT creation
type JWTPayload = {
  sub: string;
  email?: string;
  name?: string;
  aud: string;
  iss: string;
  iat: number;
  exp: number;
  scope?: string;
};
function createJWT(payload: JWTPayload): string {
  const header = { alg: "RS256", typ: "JWT" };
  const headerEncoded = base64UrlEncode(JSON.stringify(header));
  const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
  const message = `${headerEncoded}.${payloadEncoded}`;

  const signature = crypto.sign("sha256", Buffer.from(message), privateKey);
  const signatureEncoded = base64UrlEncode(signature);

  return `${message}.${signatureEncoded}`;
}

// JWT verification
// if the token is valid return its payload, null otherwise
function verifyJWT(token: string): JWTPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [headerEncoded, payloadEncoded, signatureEncoded] = parts;
    const message = `${headerEncoded}.${payloadEncoded}`;

    // Verify signature
    const signature = base64UrlDecode(signatureEncoded);
    const isValid = crypto.verify(
      "sha256",
      Buffer.from(message),
      publicKey,
      signature,
    );

    if (!isValid) return null;

    // decode payload
    const payload = JSON.parse(
      base64UrlDecode(payloadEncoded).toString("utf8"),
    );

    // Check expiration
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    // Check issuer
    if (payload.iss !== wellKnownConfig.issuer.href) {
      return null;
    }

    return payload;
  } catch (error) {
    console.warn(`Token ${token} invalid`, error);
    return null;
  }
}

// Token creation
function createIdToken(userId: string, clientId: string) {
  const user = usersById.get(userId);
  if (!user) throw new Error("User not found");

  return createJWT({
    sub: user.id,
    email: user.email,
    name: user.username,
    aud: clientId,
    iss: wellKnownConfig.issuer.href,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + config.sessionDuration,
  });
}

function createAccessToken(
  userId: string,
  clientId: string,
  scope = "openid profile email",
) {
  return createJWT({
    sub: userId,
    aud: clientId,
    iss: wellKnownConfig.issuer.href,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + config.sessionDuration,
    scope,
  });
}
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function jsonRes(body: any, status: number = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

// HTTP SERVER
serve({
  port: config.baseUrl.port,
  async fetch(req: Request) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (path === "/") {
      return new Response(`Hello from OIDC server\n`, {
        headers: corsHeaders,
      });
    }

    if (path === "/.well-known/openid-configuration") {
      return jsonRes(wellKnownConfig);
    }

    if (path === wellKnownConfig.jwks_uri.pathname) {
      return jsonRes({
        keys: [{ ...jwk, alg: "RS256", use: "sig", kid: "1" }],
      });
    }

    // GET Authorization endpoint
    if (
      path === wellKnownConfig.authorization_endpoint.pathname &&
      method === "GET"
    ) {
      const clientId = url.searchParams.get("client_id");
      const redirectUri = url.searchParams.get("redirect_uri");
      const codeChallenge = url.searchParams.get("code_challenge");
      const codeChallengeMethod = url.searchParams.get("code_challenge_method");
      const state = url.searchParams.get("state");
      const responseType = url.searchParams.get("response_type");

      if (responseType !== "code") {
        return jsonRes({
          error: "unsupported_response_type",
          error_description:
            "Only 'code' response_type is supported (OAuth 2.1)",
        }, 400);
      }

      if (!clientId || !redirectUri || !codeChallenge) {
        return jsonRes({
          error: "missing_parameter",
        }, 400);
      }

      if (codeChallengeMethod !== "S256") {
        return jsonRes({
          error: "unsupported_code_challenge_method",
          error_description:
            "Only S256 code_challenge_method is supported (OAuth 2.1 requirement)",
        }, 400);
      }

      // the code challenge should be of 43 chars exaclty.
      // this is explained in the RFC 7636 section 4.1
      // https://www.rfc-editor.org/rfc/rfc7636.html
      if (codeChallengeMethod === "S256" && codeChallenge.length !== 43) {
        return jsonRes({
          error: "invalid_code_challenge",
          error_description:
            "Invalid code_challenge: S256 method requires exactly 43 characters",
        }, 400);
      }

      const client = clients.get(clientId);

      if (!client) {
        return jsonRes({
          error: "invalid_client",
        }, 400);
      }
      if (
        !client.redirect_uris.includes(redirectUri)
      ) {
        return jsonRes({
          error: "invalid_client",
          error_description: "Invalid client or redirect URI",
        }, 400);
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
                  <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}">
                  <input type="hidden" name="state" value="${state || ""}">
                  <input type="text" name="username" placeholder="Username" required autofocus>
                  <input type="password" name="password" placeholder="Password" required>
                  <button type="submit">Login</button>
                </form>
                <p>Demo: testuser / password123</p>
              </body>
          </html>`;
      return new Response(html, {
        headers: {
          "Content-Type": "text/html",
          ...corsHeaders,
        },
      });
    }

    // POST Authorization token
    if (
      path === wellKnownConfig.authorization_endpoint.pathname &&
      method === "POST"
    ) {
      const formData = await req.formData();
      const username = formData.get("username") as string;
      const password = formData.get("password") as string;
      const clientId = formData.get("client_id") as string;
      const redirectUri = formData.get("redirect_uri") as string;
      const codeChallenge = formData.get("code_challenge") as string;
      const codeChallengeMethod = formData.get(
        "code_challenge_method",
      ) as string;
      const state = formData.get("state") as string;

      const user = usersByUsername.get(username);

      if (!user || user.passwordHash !== hashPassword(password)) {
        return jsonRes({
          error: "invalid_credentials",
        }, 401);
      }

      const code = generateCode();
      const expiresAt = Date.now() + (config.sessionDuration * 1000);
      authSessions.set(code, {
        userId: user.id,
        clientId,
        redirectUri,
        codeChallenge,
        codeChallengeMethod,
        expiresAt,
      });

      const redirectUrl = new URL(redirectUri);
      redirectUrl.searchParams.set("code", code);
      if (state) redirectUrl.searchParams.set("state", state);

      return Response.redirect(redirectUrl.href, 302);
    }

    // POST Token endpoint
    if (path === wellKnownConfig.token_endpoint.pathname && method === "POST") {
      type TokenRequest = {
        grant_type: string;
        code: string;
        client_id: string;
        redirect_uri: string;
        code_verifier: string;
      };
      let tokenRequest: TokenRequest;
      if (
        req.headers.get("Content-Type") === "application/x-www-form-urlencoded"
      ) {
        const form = await req.formData();
        tokenRequest = {
          grant_type: form.get("grant_type") as string,
          code: form.get("code") as string,
          client_id: form.get("client_id") as string,
          redirect_uri: form.get("redirect_uri") as string,
          code_verifier: form.get("code_verifier") as string,
        };
      } else {
        tokenRequest = await req.json() as TokenRequest;
      }

      const {
        grant_type,
        code,
        client_id,
        redirect_uri,
        code_verifier,
      } = tokenRequest;

      if (
        !grant_type || !code || !redirect_uri || !client_id || !code_verifier
      ) {
        return jsonRes({
          error: "missing_parameter",
        }, 400);
      }

      if (grant_type !== "authorization_code") {
        return jsonRes({ error: "unsupported_grant_type" }, 400);
      }
      // client_secret is not required
      const client = clients.get(client_id);
      if (!client) {
        return jsonRes({ error: "invalid_client" }, 401);
      }

      const session = authSessions.get(code);
      if (
        !session || session.expiresAt < Date.now() ||
        session.redirectUri !== redirect_uri
      ) {
        return jsonRes({
          error: "invalid_grant",
        }, 400);
      }

      if (!code_verifier) {
        return jsonRes({
          error: "invalid_grant",
          error_description: "code_verifier required",
        }, 400);
      }

      const method = session.codeChallengeMethod || "S256";
      const verified = method === "S256"
        ? verifySHA256(session.codeChallenge, code_verifier)
        : session.codeChallenge === code_verifier;

      if (!verified) {
        return jsonRes({
          error: "invalid_grant",
          error_description: "invalid code_verifier",
        }, 400);
      }

      authSessions.delete(code);

      try {
        const accessToken = createAccessToken(session.userId, client_id);
        const idToken = createIdToken(session.userId, client_id);
        return jsonRes({
          access_token: accessToken,
          id_token: idToken,
          token_type: "Bearer",
          expires_in: config.sessionDuration,
        });
      } catch (error) {
        return jsonRes({
          error: "server_error",
          error_description: `Error in token creation: ${JSON.stringify(error)
            }`,
        }, 500);
      }
    }

    // User info endpoint
    if (
      path === wellKnownConfig.userinfo_endpoint.pathname && method === "GET"
    ) {
      const authHeader = req.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return jsonRes({ error: "unauthorized" }, 401);
      }
      const payload = verifyJWT(authHeader?.substring(7) ?? "");
      if (!payload?.sub) {
        return jsonRes({ error: "invalid_token" }, 401);
      }
      const user = usersById.get(payload.sub);
      if (!user) {
        return jsonRes({ error: "user_not_found" }, 404);
      }

      return jsonRes({
        sub: user.id,
        email: user.email,
        name: user.username,
      });
    }

    return jsonRes({ error: "not_found" }, 404);
  },
});

console.log(`🔐 OIDC Server running on ${config.baseUrl}`);
console.log(
  `📋 Discovery: ${new URL(
    "/.well-known/openid-configuration",
    config.baseUrl,
  )}`,
);
