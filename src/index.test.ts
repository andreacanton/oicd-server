import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as crypto from "crypto";

// Test configuration
const BASE_URL = "http://localhost:3000";
const TEST_CLIENT_ID = "sample-client";
const TEST_CLIENT_SECRET = "sample-secret";
const TEST_REDIRECT_URI = "http://localhost:3001";
const TEST_USERNAME = "testuser";
const TEST_PASSWORD = "password123";

// Type definitions
type OIDCDiscoveryConfig = {
  issuer: string | URL;
  authorization_endpoint: string | URL;
  token_endpoint: string | URL;
  userinfo_endpoint: string | URL;
  jwks_uri: string | URL;
  response_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  scopes_supported: string[];
};

type JWK = {
  kty: string;
  use: string;
  alg: string;
  kid: string;
  n?: string;
  e?: string;
};

type JWKS = {
  keys: JWK[];
};

type TokenResponse = {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
};

type UserInfo = {
  sub: string;
  email: string;
  name: string;
};

type ErrorResponse = {
  error: string;
  error_description?: string;
};

// Helper functions
function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function generateCodeChallenge(verifier: string): string {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return hash.toString("base64url");
}

function generateState(): string {
  return crypto.randomBytes(16).toString("hex");
}

// Start server before tests
let serverProcess: any;

beforeAll(async () => {
  // Import and start the server
  serverProcess = Bun.spawn(["bun", "run", "src/index.ts"], {
    stdout: "pipe",
    stderr: "pipe",
  });

  // Wait for server to start
  await new Promise((resolve) => setTimeout(resolve, 1000));
});

afterAll(() => {
  if (serverProcess) {
    serverProcess.kill();
  }
});

describe("OIDC Server", () => {
  describe("Basic Endpoints", () => {
    test("GET / returns welcome message", async () => {
      const response = await fetch(`${BASE_URL}/`);
      const text = await response.text();

      expect(response.status).toBe(200);
      expect(text).toBe("Hello from OIDC server\n");
    });

    test("OPTIONS / returns CORS headers", async () => {
      const response = await fetch(`${BASE_URL}/`, {
        method: "OPTIONS",
      });

      expect(response.status).toBe(200);
      expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
      expect(response.headers.get("Access-Control-Allow-Methods")).toBe(
        "GET, POST, OPTIONS",
      );
      expect(response.headers.get("Access-Control-Allow-Headers")).toBe(
        "Content-Type, Authorization",
      );
    });

    test("GET /not-found returns 404", async () => {
      const response = await fetch(`${BASE_URL}/not-found`);
      expect(response.status).toBe(404);
    });
  });

  describe("Discovery Endpoints", () => {
    test("GET /.well-known/openid-configuration returns discovery document", async () => {
      const response = await fetch(
        `${BASE_URL}/.well-known/openid-configuration`,
      );
      const config: OIDCDiscoveryConfig = await response
        .json() as OIDCDiscoveryConfig;

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toContain(
        "application/json",
      );

      expect(config.issuer).toBeDefined();
      expect(config.authorization_endpoint).toBeDefined();
      expect(config.token_endpoint).toBeDefined();
      expect(config.userinfo_endpoint).toBeDefined();
      expect(config.jwks_uri).toBeDefined();
      expect(config.response_types_supported).toContain("code");
      expect(config.subject_types_supported).toContain("public");
      expect(config.id_token_signing_alg_values_supported).toContain("RS256");
      expect(config.scopes_supported).toContain("openid");
      expect(config.scopes_supported).toContain("profile");
      expect(config.scopes_supported).toContain("email");
    });

    test("GET /.well-known/jwks.json returns public keys", async () => {
      const response = await fetch(`${BASE_URL}/.well-known/jwks.json`);
      const jwks: JWKS = await response.json() as JWKS;

      expect(response.status).toBe(200);
      expect(jwks.keys).toBeDefined();
      expect(jwks.keys.length).toBeGreaterThan(0);
      expect(jwks.keys[0]?.alg).toBe("RS256");
      expect(jwks.keys[0]?.use).toBe("sig");
      expect(jwks.keys[0]?.kid).toBeDefined();
      expect(jwks.keys[0]?.kty).toBeDefined();
    });
  });

  describe("Authorization Endpoint", () => {
    test("GET /authorize without parameters returns 400", async () => {
      const response = await fetch(`${BASE_URL}/authorize`);
      expect(response.status).toBe(400);
    });

    test("GET /authorize with invalid client_id returns 400", async () => {
      const codeChallenge = generateCodeChallenge(generateCodeVerifier());
      const url = new URL(`${BASE_URL}/authorize`);
      url.searchParams.set("client_id", "invalid-client");
      url.searchParams.set("redirect_uri", TEST_REDIRECT_URI);
      url.searchParams.set("code_challenge", codeChallenge);
      url.searchParams.set("code_challenge_method", "S256");

      const response = await fetch(url);
      expect(response.status).toBe(400);
    });

    test("GET /authorize with invalid redirect_uri returns 400", async () => {
      const codeChallenge = generateCodeChallenge(generateCodeVerifier());
      const url = new URL(`${BASE_URL}/authorize`);
      url.searchParams.set("client_id", TEST_CLIENT_ID);
      url.searchParams.set("redirect_uri", "http://evil.com/callback");
      url.searchParams.set("code_challenge", codeChallenge);
      url.searchParams.set("code_challenge_method", "S256");

      const response = await fetch(url);
      expect(response.status).toBe(400);
    });

    test("GET /authorize with valid parameters returns login form", async () => {
      const codeChallenge = generateCodeChallenge(generateCodeVerifier());
      const url = new URL(`${BASE_URL}/authorize`);
      url.searchParams.set("client_id", TEST_CLIENT_ID);
      url.searchParams.set("redirect_uri", TEST_REDIRECT_URI);
      url.searchParams.set("code_challenge", codeChallenge);
      url.searchParams.set("code_challenge_method", "S256");
      url.searchParams.set("state", generateState());

      const response = await fetch(url);
      const html = await response.text();

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toContain("text/html");
      expect(html).toContain("<form");
      expect(html).toContain('name="username"');
      expect(html).toContain('name="password"');
      expect(html).toContain("Login");
    });

    test("POST /authorize with invalid credentials returns 401", async () => {
      const codeChallenge = generateCodeChallenge(generateCodeVerifier());
      const formData = new FormData();
      formData.append("username", "invalid");
      formData.append("password", "invalid");
      formData.append("client_id", TEST_CLIENT_ID);
      formData.append("redirect_uri", TEST_REDIRECT_URI);
      formData.append("code_challenge", codeChallenge);
      formData.append("code_challenge_method", "S256");

      const response = await fetch(`${BASE_URL}/authorize`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(401);
    });

    test("POST /authorize with valid credentials redirects with code", async () => {
      const codeChallenge = generateCodeChallenge(generateCodeVerifier());
      const state = generateState();
      const formData = new FormData();
      formData.append("username", TEST_USERNAME);
      formData.append("password", TEST_PASSWORD);
      formData.append("client_id", TEST_CLIENT_ID);
      formData.append("redirect_uri", TEST_REDIRECT_URI);
      formData.append("code_challenge", codeChallenge);
      formData.append("code_challenge_method", "S256");
      formData.append("state", state);

      const response = await fetch(`${BASE_URL}/authorize`, {
        method: "POST",
        redirect: "manual",
        body: formData,
      });

      expect(response.status).toBe(302);

      const location = response.headers.get("Location");
      expect(location).toBeDefined();

      const redirectUrl = new URL(location!);
      expect(redirectUrl.searchParams.has("code")).toBe(true);
      expect(redirectUrl.searchParams.get("state")).toBe(state);
    });
  });

  describe("Token Endpoint", () => {
    let authCode: string;
    let codeVerifier: string;

    beforeAll(async () => {
      // Get an authorization code first
      codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      const formData = new FormData();
      formData.append("username", TEST_USERNAME);
      formData.append("password", TEST_PASSWORD);
      formData.append("client_id", TEST_CLIENT_ID);
      formData.append("redirect_uri", TEST_REDIRECT_URI);
      formData.append("code_challenge", codeChallenge);
      formData.append("code_challenge_method", "S256");

      const response = await fetch(`${BASE_URL}/authorize`, {
        method: "POST",
        body: formData,
        redirect: "manual",
      });

      const location = response.headers.get("Location");
      const redirectUrl = new URL(location!);
      authCode = redirectUrl.searchParams.get("code")!;
    });

    test("POST /token with invalid grant_type returns 400", async () => {
      const response = await fetch(`${BASE_URL}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "invalid",
          code: authCode,
          client_id: TEST_CLIENT_ID,
          client_secret: TEST_CLIENT_SECRET,
          redirect_uri: TEST_REDIRECT_URI,
          code_verifier: codeVerifier,
        }),
      });

      const data: ErrorResponse = await response.json();
      expect(response.status).toBe(400);
      expect(data.error).toBe("unsupported_grant_type");
    });

    test("POST /token with invalid client returns 401", async () => {
      const response = await fetch(`${BASE_URL}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code: authCode,
          client_id: "invalid-client",
          client_secret: "invalid-secret",
          redirect_uri: TEST_REDIRECT_URI,
          code_verifier: codeVerifier,
        }),
      });

      const data: ErrorResponse = await response.json();
      expect(response.status).toBe(401);
      expect(data.error).toBe("invalid_client");
    });

    test("POST /token without code_verifier returns 400", async () => {
      const response = await fetch(`${BASE_URL}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code: authCode,
          client_id: TEST_CLIENT_ID,
          client_secret: TEST_CLIENT_SECRET,
          redirect_uri: TEST_REDIRECT_URI,
        }),
      });

      const data: ErrorResponse = await response.json() as ErrorResponse;
      expect(response.status).toBe(400);
      expect(data.error).toBe("invalid_grant");
      expect(data.error_description).toContain("code_verifier");
    });

    test("POST /token with invalid code_verifier returns 400", async () => {
      const response = await fetch(`${BASE_URL}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code: authCode,
          client_id: TEST_CLIENT_ID,
          client_secret: TEST_CLIENT_SECRET,
          redirect_uri: TEST_REDIRECT_URI,
          code_verifier: "invalid-verifier",
        }),
      });

      const data: ErrorResponse = await response.json() as ErrorResponse;
      expect(response.status).toBe(400);
      expect(data.error).toBe("invalid_grant");
    });

    test("POST /token with valid parameters returns tokens", async () => {
      // Get a fresh auth code
      const newVerifier = generateCodeVerifier();
      const newChallenge = generateCodeChallenge(newVerifier);

      const formData = new FormData();
      formData.append("username", TEST_USERNAME);
      formData.append("password", TEST_PASSWORD);
      formData.append("client_id", TEST_CLIENT_ID);
      formData.append("redirect_uri", TEST_REDIRECT_URI);
      formData.append("code_challenge", newChallenge);
      formData.append("code_challenge_method", "S256");

      const authResponse = await fetch(`${BASE_URL}/authorize`, {
        method: "POST",
        body: formData,
        redirect: "manual",
      });

      const location = authResponse.headers.get("Location");
      const redirectUrl = new URL(location!);
      const code = redirectUrl.searchParams.get("code")!;

      // Exchange code for tokens
      const response = await fetch(`${BASE_URL}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          client_id: TEST_CLIENT_ID,
          client_secret: TEST_CLIENT_SECRET,
          redirect_uri: TEST_REDIRECT_URI,
          code_verifier: newVerifier,
        }),
      });

      const data: TokenResponse = await response.json() as TokenResponse;
      expect(response.status).toBe(200);
      expect(data.access_token).toBeDefined();
      expect(data.id_token).toBeDefined();
      expect(data.token_type).toBe("Bearer");
      expect(data.expires_in).toBe(900);

      // Verify token structure
      const accessTokenParts = data.access_token.split(".");
      expect(accessTokenParts.length).toBe(3);

      const idTokenParts = data.id_token.split(".");
      expect(idTokenParts.length).toBe(3);
    });

    test("POST /token with form-encoded data works", async () => {
      // Get a fresh auth code
      const newVerifier = generateCodeVerifier();
      const newChallenge = generateCodeChallenge(newVerifier);

      const authFormData = new FormData();
      authFormData.append("username", TEST_USERNAME);
      authFormData.append("password", TEST_PASSWORD);
      authFormData.append("client_id", TEST_CLIENT_ID);
      authFormData.append("redirect_uri", TEST_REDIRECT_URI);
      authFormData.append("code_challenge", newChallenge);
      authFormData.append("code_challenge_method", "S256");

      const authResponse = await fetch(`${BASE_URL}/authorize`, {
        method: "POST",
        body: authFormData,
        redirect: "manual",
      });

      const location = authResponse.headers.get("Location");
      const redirectUrl = new URL(location!);
      const code = redirectUrl.searchParams.get("code")!;

      // Exchange code using form-encoded data
      const tokenFormData = new URLSearchParams();
      tokenFormData.append("grant_type", "authorization_code");
      tokenFormData.append("code", code);
      tokenFormData.append("client_id", TEST_CLIENT_ID);
      tokenFormData.append("client_secret", TEST_CLIENT_SECRET);
      tokenFormData.append("redirect_uri", TEST_REDIRECT_URI);
      tokenFormData.append("code_verifier", newVerifier);

      const response = await fetch(`${BASE_URL}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenFormData,
      });

      const data: TokenResponse = await response.json() as TokenResponse;
      expect(response.status).toBe(200);
      expect(data.access_token).toBeDefined();
      expect(data.id_token).toBeDefined();
    });
  });

  describe("UserInfo Endpoint", () => {
    let accessToken: string;

    beforeAll(async () => {
      // Get access token
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier);

      const formData = new FormData();
      formData.append("username", TEST_USERNAME);
      formData.append("password", TEST_PASSWORD);
      formData.append("client_id", TEST_CLIENT_ID);
      formData.append("redirect_uri", TEST_REDIRECT_URI);
      formData.append("code_challenge", challenge);
      formData.append("code_challenge_method", "S256");

      const authResponse = await fetch(`${BASE_URL}/authorize`, {
        method: "POST",
        body: formData,
        redirect: "manual",
      });

      const location = authResponse.headers.get("Location");
      const redirectUrl = new URL(location!);
      const code = redirectUrl.searchParams.get("code")!;

      const tokenResponse = await fetch(`${BASE_URL}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          client_id: TEST_CLIENT_ID,
          client_secret: TEST_CLIENT_SECRET,
          redirect_uri: TEST_REDIRECT_URI,
          code_verifier: verifier,
        }),
      });

      const tokenData = await tokenResponse.json() as TokenResponse;
      accessToken = tokenData.access_token;
    });

    test("GET /userinfo without Authorization header returns 401", async () => {
      const response = await fetch(`${BASE_URL}/userinfo`);
      const data: ErrorResponse = await response.json() as ErrorResponse;

      expect(response.status).toBe(401);
      expect(data.error).toBe("unauthorized");
    });

    test("GET /userinfo with invalid token returns 401", async () => {
      const response = await fetch(`${BASE_URL}/userinfo`, {
        headers: { Authorization: "Bearer invalid-token" },
      });
      const data: ErrorResponse = await response.json() as ErrorResponse;

      expect(response.status).toBe(401);
      expect(data.error).toBe("invalid_token");
    });

    test("GET /userinfo with valid token returns user info", async () => {
      const response = await fetch(`${BASE_URL}/userinfo`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const data: UserInfo = await response.json() as UserInfo;

      expect(response.status).toBe(200);
      expect(data.sub).toBe("user-1");
      expect(data.email).toBe("test@example.com");
      expect(data.name).toBe("testuser");
    });
  });

  describe("PKCE Flow", () => {
    test("Complete PKCE flow end-to-end", async () => {
      // 1. Generate PKCE parameters
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);
      const state = generateState();

      // 2. Start authorization
      const authFormData = new FormData();
      authFormData.append("username", TEST_USERNAME);
      authFormData.append("password", TEST_PASSWORD);
      authFormData.append("client_id", TEST_CLIENT_ID);
      authFormData.append("redirect_uri", TEST_REDIRECT_URI);
      authFormData.append("code_challenge", codeChallenge);
      authFormData.append("code_challenge_method", "S256");
      authFormData.append("state", state);

      const authResponse = await fetch(`${BASE_URL}/authorize`, {
        method: "POST",
        body: authFormData,
        redirect: "manual",
      });

      expect(authResponse.status).toBe(302);

      // 3. Extract authorization code
      const location = authResponse.headers.get("Location")!;
      const redirectUrl = new URL(location);
      const code = redirectUrl.searchParams.get("code")!;
      const returnedState = redirectUrl.searchParams.get("state");

      expect(code).toBeDefined();
      expect(returnedState).toBe(state);

      // 4. Exchange code for tokens
      const tokenResponse = await fetch(`${BASE_URL}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          client_id: TEST_CLIENT_ID,
          client_secret: TEST_CLIENT_SECRET,
          redirect_uri: TEST_REDIRECT_URI,
          code_verifier: codeVerifier,
        }),
      });

      const tokenData: TokenResponse = await tokenResponse
        .json() as TokenResponse;
      expect(tokenResponse.status).toBe(200);
      expect(tokenData.access_token).toBeDefined();
      expect(tokenData.id_token).toBeDefined();

      // 5. Use access token to get user info
      const userinfoResponse = await fetch(`${BASE_URL}/userinfo`, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });

      const userinfo: UserInfo = await userinfoResponse.json() as UserInfo;
      expect(userinfoResponse.status).toBe(200);
      expect(userinfo.sub).toBe("user-1");
      expect(userinfo.email).toBe("test@example.com");
      expect(userinfo.name).toBe("testuser");
    });
  });
});
