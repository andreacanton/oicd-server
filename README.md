# 📚 oicd-server: A Minimalist Educational OIDC Server

`oicd-server` is a minimal, zero-dependency OpenID Connect (OIDC) Authorization Server built from scratch using only the **Bun** runtime and standard Node.js `crypto` modules.

Its primary purpose is to provide a clear, simple, and auditable implementation of the **OAuth 2.1 (draft)**-compliant **Authorization Code Flow with PKCE**. It is designed for students, developers, and security enthusiasts who want to understand how OIDC and modern OAuth 2.0 work under the hood.

## ⚠️ This is an Educational Tool

This server is designed exclusively for educational purposes and local development. It is **NOT** intended for production use.

It intentionally omits many production-grade features to keep the core logic simple and easy to read.

**Key Limitations:**
* **In-Memory Storage:** All users, clients, and codes are stored in memory and are lost on restart.
* **Missing Features:** Does not include refresh tokens, user consent screens, or robust session management.
* **Simplified Security:** Uses basic (though secure) crypto implementations. Does not include rate-limiting, comprehensive error handling, or key rotation.

---

## ✨ Features

* ✅ **OAuth 2.1 Compliant Flow:** Implements **Authorization Code Flow with PKCE (RFC 7636)**.
* ✅ **Zero External Dependencies:** Built entirely with the Bun runtime and Node.js `crypto`.
* ✅ **Standard OIDC Discovery:** Provides `.well-known/openid-configuration` for auto-discovery.
* ✅ **JSON Web Tokens (JWT):** Issues `id_token` and `access_token` signed with **RS256**.
* ✅ **JWKS Endpoint:** Serves public keys at `.well-known/jwks.json` for token verification.
* ✅ **Core Endpoints:** Implements `/authorize`, `/token`, and `/userinfo`.

## 🚀 Quick Start

**Prerequisite:** [Bun (v1.0+)](https://bun.sh) must be installed.

1.  **Clone the Repository**
```bash
git clone [https://github.com/andreacanton/oicd-server.git](https://github.com/andreacanton/oicd-server.git)
cd oicd-server
```

2.  **Install & Run**
```bash
bun install
bun run dev
```

The server will start at `http://localhost:3000` with hot-reload enabled.

### Available Scripts

| Script          | Description                                     |
| :-------------- | :---------------------------------------------- |
| `bun run dev`   | Starts the development server with auto-reload. |
| `bun run build` | Creates a production-ready build.               |
| `bun run start` | Runs the production build.                      |
| `bun test`      | Executes all unit tests.                        |

---

## 🛠️ Configuration & Test Data

All test data is defined in-memory in `src/index.ts`.

### Test Client
| Credential        | Value                            |
| :---------------- | :------------------------------- |
| **Client ID**     | `sample-client`                  |
| **Client Secret** | `sample-secret`                  |
| **Redirect URI**  | `http://localhost:3001/callback` |

### Test User
| Credential   | Value              |
| :----------- | :----------------- |
| **Username** | `testuser`         |
| **Password** | `password123`      |
| **Email**    | `test@example.com` |

---

## 🧭 API Endpoints

| Method | Path                                | Description                                                                                |
| :----- | :---------------------------------- | :----------------------------------------------------------------------------------------- |
| `GET`  | `/.well-known/openid-configuration` | **OIDC Discovery Document**. Provides metadata about all other endpoints.                  |
| `GET`  | `/.well-known/jwks.json`            | **JSON Web Key Set**. Provides the public keys to verify JWT signatures.                   |
| `GET`  | `/authorize`                        | **Authorization Endpoint**. Initiates the login flow and displays a login form.            |
| `POST` | `/token`                            | **Token Endpoint**. Exchanges an authorization code for an `id_token` and `access_token`.  |
| `GET`  | `/userinfo`                         | **UserInfo Endpoint**. Returns user profile information (requires a valid `access_token`). |

## 🧪 Example: Full PKCE Flow

Here is how to perform a complete authorization flow manually.

### Step 1. Generate PKCE Verifier and Challenge

You need a `code_verifier` (a random string) and a `code_challenge` (its SHA256 hash). You can use the included Bruno collection or generate them:

```bash
# 1. Generate a random verifier
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | head -c 43)

# 2. Generate the challenge (URL-safe SHA256)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | shasum -a 256 | cut -d' ' -f1 | xxd -r -p | base64 | tr -d '=+/' | tr '/+' '_-')

# You can check them:
echo $CODE_VERIFIER
echo $CODE_CHALLENGE
````

### Step 2. Get the Authorization Code

Construct the authorization URL and open it in your browser.

```
http://localhost:3000/authorize?
  client_id=sample-client
  &redirect_uri=http://localhost:3001/callback
  &response_type=code
  &scope=openid profile email
  &state=somerandomstate123
  &code_challenge=YOUR_CODE_CHALLENGE
  &code_challenge_method=S256
```

Log in with the test user (`testuser` / `password123`). The server will redirect you to:

`http://localhost:3001/callback?code=AUTHORIZATION_CODE&state=somerandomstate123`

Copy the `AUTHORIZATION_CODE` from the URL.

### Step 3. Exchange the Code for Tokens

Now, make a `POST` request to the `/token` endpoint using the `code` and your original `code_verifier`.

```bash
curl -X POST 'http://localhost:3000/token' \
-H 'Content-Type: application/json' \
-d '{
    "grant_type": "authorization_code",
    "code": "THE_AUTHORIZATION_CODE_FROM_STEP_2",
    "client_id": "sample-client",
    "client_secret": "sample-secret",
    "redirect_uri": "http://localhost:3001/callback",
    "code_verifier": "YOUR_ORIGINAL_CODE_VERIFIER_FROM_STEP_1"
}'
```

The server will respond with your tokens:

```json
{
  "access_token": "eyJhbGc...",
  "id_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

> **Note:** The `client_secret` is included here because the `sample-client` is *confidential*. A public client (like a mobile app) would omit the `client_secret`, and the server would validate the request using *only* PKCE.

### Step 4. Access UserInfo

Use the `access_token` to retrieve user information from the `/userinfo` endpoint.

```bash
# Replace ACCESS_TOKEN with the one from the previous step
curl -H 'Authorization: Bearer ACCESS_TOKEN' \
http://localhost:3000/userinfo
```

The server will respond with the user's data:

```json
{
  "sub": "user-1",
  "email": "test@example.com",
  "name": "testuser"
}
```

## 🤝 Contributing

This is an educational project, and contributions are welcome\! The primary goal is to maintain simplicity and clarity.

1.  **Zero-Dependency Policy:** Please do not add any external `npm` packages.
2.  **Clarity over Features:** Code should be easy to read and well-commented.
3.  **Add Tests:** Please add tests for any new logic.

Feel free to open an issue to discuss a potential change or submit a Pull Request.

## 📄 License

This project is licensed under the **GPL-3.0**. See the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.
