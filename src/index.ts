import { serve } from "bun";
import * as crypto from "crypto";
import { json } from "stream/consumers";

// Configuration
const config = {
  baseUrl: new URL("http://localhost:3000"),
} as { baseUrl: URL };

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
    }
    return new Response("Not found", { status: 404, headers: corsHeaders });
  },
});

console.info(`Serving OIDC at ${config.baseUrl}`);
console.info(
  `Well known configuration:`,
  JSON.stringify(wellKnownConfig, null, 2),
);
