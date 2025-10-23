# Simple OIDC Server

A minimal OpenID Connect (OIDC) server implementation built with Bun, supporting Authorization Code Flow with PKCE (Proof Key for Code Exchange). Perfect for learning the fundamentals of OAuth 2.0 and OIDC, or for local testing and development.

## Features

- ✅ **Authorization Code Flow with PKCE** - Secure authorization for public clients
- ✅ **Zero Dependencies** - Built using only Bun's standard library and Node.js crypto
- ✅ **OpenID Connect Discovery** - Standard `.well-known` endpoints
- ✅ **JWT Tokens** - RS256 signed ID tokens and access tokens
- ✅ **JWKS Endpoint** - Public key distribution for token verification
- ✅ **UserInfo Endpoint** - Retrieve user profile information
- ✅ **CORS Enabled** - Ready for cross-origin requests

## Requirements

- [Bun](https://bun.sh) runtime (v1.0 or higher)

## Quick Start

1. **Clone the repository**
   ```bash
   git clone git@github.com:andreacanton/oicd-server.git
   cd oidc-server
   ```

2. **Install dependencies**
   ```bash
   bun install
   ```

3. **Run the development server**
   ```bash
   bun run dev
   ```

   The server will start on `http://localhost:3000` with hot-reload enabled.

## Available Scripts

- `bun run dev` - Start development server with auto-reload
- `bun run build` - Build for production
- `bun run start` - Run production build
- `bun test` - Run tests

## Configuration

The server comes pre-configured with sensible defaults in `src/index.ts`. You can modify these in the `config` object:

```typescript
const config = {
  baseUrl: new URL("http://localhost:3000"),
  sessionDuration: 15 * 60,  // 15 minutes in seconds
};
```

### Pre-configured Client

The server includes a sample OAuth client:

- **Client ID**: `sample-client`
- **Client Secret**: `sample-secret`
- **Redirect URI**: `http://localhost:3001/callback`

### Test User

- **Username**: `testuser`
- **Password**: `password123`
- **Email**: `test@example.com`

## OIDC Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OpenID Connect discovery document |
| `GET /.well-known/jwks.json` | JSON Web Key Set for token verification |
| `GET /authorize` | Authorization endpoint (displays login form) |
| `POST /authorize` | Process login and generate authorization code |
| `POST /token` | Token endpoint (exchange code for tokens) |
| `GET /userinfo` | UserInfo endpoint (requires Bearer token) |

## Authorization Flow Example

### 1. Generate PKCE Challenge

```javascript
// Generate code verifier (random string)
const codeVerifier = crypto.randomBytes(32).toString('base64url');

// Create code challenge (SHA256 hash)
const hash = crypto.createHash('sha256').update(codeVerifier).digest();
const codeChallenge = hash.toString('base64url');
```

### 2. Initiate Authorization

Redirect the user to:

```
http://localhost:3000/authorize?
  client_id=sample-client&
  redirect_uri=http://localhost:3001/callback&
  response_type=code&
  code_challenge=CODE_CHALLENGE&
  code_challenge_method=S256&
  state=RANDOM_STATE&
  scope=openid profile email
```

### 3. User Login

The user will see a login form. After successful authentication, they'll be redirected back to your `redirect_uri` with an authorization code:

```
http://localhost:3001/callback?code=AUTHORIZATION_CODE&state=RANDOM_STATE
```

### 4. Exchange Code for Tokens

Make a POST request to the token endpoint:

```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTHORIZATION_CODE",
    "client_id": "sample-client",
    "client_secret": "sample-secret",
    "redirect_uri": "http://localhost:3001/callback",
    "code_verifier": "CODE_VERIFIER"
  }'
```

Response:

```json
{
  "access_token": "eyJhbGc...",
  "id_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### 5. Access UserInfo

Use the access token to retrieve user information:

```bash
curl http://localhost:3000/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

Response:

```json
{
  "sub": "user-1",
  "email": "test@example.com",
  "name": "testuser"
}
```

## Token Structure

### ID Token (JWT)

```json
{
  "sub": "user-1",
  "email": "test@example.com",
  "name": "testuser",
  "aud": "sample-client",
  "iss": "http://localhost:3000",
  "iat": 1234567890,
  "exp": 1234568790
}
```

### Access Token (JWT)

```json
{
  "sub": "user-1",
  "aud": "sample-client",
  "iss": "http://localhost:3000",
  "iat": 1234567890,
  "exp": 1234568790,
  "scope": "openid profile email"
}
```

## Testing with Bruno

The project includes a Bruno collection in the `bruno-prj/` directory for testing all endpoints.

### Setup

1. Install [Bruno](https://www.usebruno.com/)
2. Open the `bruno-prj` collection
3. Select the `dev` environment
4. Run the requests in sequence

### Available Requests

- **Index** - Test basic connectivity
- **Index - OPTIONS** - Test CORS configuration
- **Discovery - Well Known Configuration** - Get OIDC discovery document
- **Discovery - JWKs URI** - Retrieve public keys
- **Authorize** - Start authorization flow
- **Userinfo** - Get user information (requires OAuth2 authentication)

The collection automatically extracts endpoints from the discovery document and supports the full OAuth2 flow with PKCE.

## Adding Custom Clients

Edit the `clients` Map in `src/index.ts`:

```typescript
const clients = new Map([
  ["sample-client", {
    client_id: "sample-client",
    client_secret: "sample-secret",
    redirect_uris: ["http://localhost:3001/callback"],
  }],
  ["your-client-id", {
    client_id: "your-client-id",
    client_secret: "your-client-secret",
    redirect_uris: ["http://your-app.com/callback"],
  }],
]);
```

## Adding Custom Users

Add new users to both Maps in `src/index.ts`:

```typescript
const newUser: User = {
  id: "user-2",
  username: "newuser",
  email: "newuser@example.com",
  passwordHash: hashPassword("newpassword"),
};

usersByUsername.set("newuser", newUser);
usersById.set("user-2", newUser);
```

## Security Features

- ✅ **PKCE (RFC 7636)** - Protects against authorization code interception
- ✅ **RS256 Signatures** - Asymmetric cryptography for token signing
- ✅ **Password Hashing** - PBKDF2 with SHA-512
- ✅ **Token Expiration** - Automatic expiration validation
- ✅ **State Parameter** - CSRF protection support
- ✅ **Redirect URI Validation** - Prevents open redirect vulnerabilities

## Educational Purpose

This server is designed for learning and local testing. **It is NOT production-ready**. Notable limitations:

- ⚠️ In-memory storage (data lost on restart)
- ⚠️ Single hardcoded salt for password hashing
- ⚠️ No persistent key storage (keys regenerated on restart)
- ⚠️ No rate limiting or brute-force protection
- ⚠️ No refresh tokens
- ⚠️ No session management beyond authorization codes
- ⚠️ No admin interface for client/user management
- ⚠️ No user registration or password reset
- ⚠️ No scope validation
- ⚠️ No consent screen

## Use Cases

- 📚 Learning OAuth 2.0 and OpenID Connect fundamentals
- 🧪 Testing OIDC client implementations locally
- 🔬 Understanding JWT structure and validation
- 🎓 Educational demonstrations and workshops
- 🛠️ Rapid prototyping without external dependencies
- 🧩 Integration testing for applications requiring OIDC

## Quick Testing

Test the discovery endpoint:

```bash
curl http://localhost:3000/.well-known/openid-configuration | jq
```

Test the full flow in your browser:

```
http://localhost:3000/authorize?client_id=sample-client&redirect_uri=http://localhost:3001/callback&code_challenge=CHALLENGE&code_challenge_method=S256&response_type=code&scope=openid%20profile%20email
```

## Why Bun?

This project uses Bun for:
- ⚡ Fast startup times and excellent performance
- 🎯 Built-in TypeScript support (no compilation needed)
- 🌐 Native fetch API and web standards
- 🔐 Standard Node.js crypto module
- 🔄 Hot reload in development
- 📦 Zero configuration needed

## Resources

### Official Specifications
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [JSON Web Token (JWT) RFC 7519](https://tools.ietf.org/html/rfc7519)

### Tools & Documentation
- [Bun Documentation](https://bun.sh/docs)
- [Bruno API Client](https://www.usebruno.com/)
- [OpenID Connect Specs](https://openid.net/developers/specs/)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

This is free software: you are free to change and redistribute it under the terms of the GPL v3.

## Contributing

Contributions that maintain simplicity and zero external dependencies are welcome! Please:

1. Keep the codebase dependency-free
2. Maintain educational clarity in code
3. Add tests for new features
4. Update documentation accordingly

## Acknowledgments

This project was created as an educational tool to understand the inner workings of OpenID Connect and OAuth 2.0 authorization servers.
