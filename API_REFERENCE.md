# OpenID Connect API Reference

Complete API documentation for the Catalyst::Plugin::OpenIDConnect endpoints.

## Base URL

```
http://localhost:5000
```

Replace with your actual issuer URL.

## Authentication Methods

- **Client Authentication**: Use `client_id` and `client_secret` in request body for token endpoint
- **Bearer Token**: Use `Authorization: Bearer <access_token>` header for protected resources

## Discovery Endpoint

### GET /.well-known/openid-configuration

Returns the OpenID Provider Configuration.

**Response:**

```json
{
  "issuer": "http://localhost:5000",
  "authorization_endpoint": "http://localhost:5000/openidconnect/authorize",
  "token_endpoint": "http://localhost:5000/openidconnect/token",
  "userinfo_endpoint": "http://localhost:5000/openidconnect/userinfo",
  "jwks_uri": "http://localhost:5000/openidconnect/jwks",
  "scopes_supported": ["openid", "profile", "email", "phone", "address"],
  "response_types_supported": ["code", "id_token token"],
  "response_modes_supported": ["query", "fragment", "form_post"],
  "grant_types_supported": ["authorization_code", "refresh_token", "implicit"],
  "subject_types_supported": ["public", "pairwise"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "userinfo_signing_alg_values_supported": ["RS256"],
  "claims_supported": [
    "sub", "name", "given_name", "family_name", "email", "email_verified", 
    "picture", "phone_number", "updated_at"
  ],
  "claim_types_supported": ["normal", "aggregated", "distributed"],
  "request_parameter_supported": true,
  "request_uri_parameter_supported": true
}
```

---

## Authorization Endpoint

### GET /openidconnect/authorize

Initiates an OpenID Connect authorization request.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| response_type | string | Yes | Must be "code" |
| client_id | string | Yes | The client identifier |
| redirect_uri | string | Yes | Where to redirect after authorization |
| scope | string | No | Space-separated scopes (default: "openid") |
| state | string | Recommended | CSRF protection state value |
| nonce | string | No | Session binding nonce (client validates it matches auth request) |
| prompt | string | No | "login" to force re-authentication |
| max_age | integer | No | Maximum age of authentication (seconds) |
| ui_locales | string | No | Preferred UI locales |
| id_token_hint | string | No | Preferred user identity |
| login_hint | string | No | Hint for login (e.g., email) |
| acr_values | string | No | Authentication context class references |

**Example Request:**

```
GET /openidconnect/authorize?
    response_type=code&
    client_id=my-app&
    redirect_uri=https://app.example.com/callback&
    scope=openid%20profile%20email&
    state=xyz789&
    nonce=n-0S6_WzA2Mj
```

**Successful Response (Redirect):**

```
HTTP/1.1 302 Found
Location: https://app.example.com/callback?
    code=SplxlOBeZQQYbIHSmLqwuQ&
    state=xyz789
```

**Error Response:**

```
HTTP/1.1 302 Found
Location: https://app.example.com/callback?
    error=access_denied&
    error_description=User+denied+authorization&
    state=xyz789
```

**Error Codes:**

| Code | Description |
|------|-------------|
| invalid_request | Missing or invalid parameter |
| unauthorized_client | Client not authorized for response type |
| access_denied | User denied authorization |
| unsupported_response_type | Response type not supported |
| invalid_scope | Invalid scope requested |
| server_error | Server error occurred |
| temporarily_unavailable | Server temporarily unavailable |

---

## Token Endpoint

### POST /openidconnect/token

Exchanges an authorization code or refresh token for tokens.

**Content-Type:** `application/x-www-form-urlencoded`

#### Authorization Code Grant

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| grant_type | string | Yes | Must be "authorization_code" |
| code | string | Yes | The authorization code |
| redirect_uri | string | Yes | Must match authorization request |
| client_id | string | Yes | The client identifier |
| client_secret | string | Yes | The client secret |

**Example Request:**

```
POST /openidconnect/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=SplxlOBeZQQYbIHSmLqwuQ&
redirect_uri=https://app.example.com/callback&
client_id=my-app&
client_secret=secret123
```

#### Refresh Token Grant

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| grant_type | string | Yes | Must be "refresh_token" |
| refresh_token | string | Yes | The refresh token |
| client_id | string | Yes | The client identifier |
| client_secret | string | Yes | The client secret |
| scope | string | No | Subset of original scopes |

**Example Request:**

```
POST /openidconnect/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&
client_id=my-app&
client_secret=secret123&
scope=openid
```

**Successful Response:**

```json
{
  "access_token": "SlAV32hkKG",
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA"
}
```

**Success Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| access_token | string | The access token |
| token_type | string | Always "Bearer" |
| id_token | string | Signed JWT with user claims |
| expires_in | integer | Token lifetime in seconds |
| refresh_token | string | Token for refreshing access (if granted) |
| scope | string | Granted scopes |

**Error Response:**

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code not found or expired"
}
```

**Error Codes:**

| Code | Description |
|------|-------------|
| invalid_request | Missing or invalid parameter |
| invalid_client | Client authentication failed |
| invalid_grant | Authorization code or refresh token invalid/expired |
| unauthorized_client | Client not authorized for grant type |
| unsupported_grant_type | Grant type not supported |
| invalid_scope | Requested scope exceeds granted scope |
| server_error | Server error occurred |

---

## UserInfo Endpoint

### GET /openidconnect/userinfo

Returns claims about the authenticated user.

**Headers:**

| Header | Value | Required |
|--------|-------|----------|
| Authorization | Bearer \<access_token\> | Yes |

**Example Request:**

```
GET /openidconnect/userinfo HTTP/1.1
Host: localhost:5000
Authorization: Bearer SlAV32hkKG
```

**Successful Response:**

```json
{
  "sub": "24400320",
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "email": "janedoe@example.com",
  "email_verified": true,
  "picture": "https://example.com/jane.jpg",
  "phone_number": "+1-202-555-0101",
  "phone_number_verified": true,
  "gender": "female",
  "birthdate": "1972-03-31",
  "zoneinfo": "America/New_York",
  "locale": "en-US",
  "updated_at": 1311280970
}
```

**Error Response:**

```json
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "invalid_token",
  "error_description": "The access token is invalid"
}
```

**Error Codes:**

| Code | Description |
|------|-------------|
| invalid_token | Access token is invalid or expired |
| insufficient_scope | Token does not have required scope |
| server_error | Server error occurred |

---

## JSON Web Key Set (JWKS) Endpoint

### GET /openidconnect/jwks

Returns the public keys used to verify signatures.

**Example Request:**

```
GET /openidconnect/jwks HTTP/1.1
Host: localhost:5000
```

**Response:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "example-key-1",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  ]
}
```

---

## Logout Endpoint

### POST /openidconnect/logout

Logs out the user and invalidates their session.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| id_token_hint | string | No | The user's ID token |
| post_logout_redirect_uri | string | No | Where to redirect after logout |
| state | string | No | State for redirect |

**Example Request:**

```
POST /openidconnect/logout HTTP/1.1
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded

id_token_hint=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&
post_logout_redirect_uri=https://app.example.com/&
state=xyz789
```

**Success Response:**

If `post_logout_redirect_uri` is provided:
```
HTTP/1.1 302 Found
Location: https://app.example.com/?state=xyz789
```

Otherwise:
```
HTTP/1.1 200 OK
Content-Type: text/plain

Logged out successfully
```

---

## JWT Token Format

### ID Token Structure

ID tokens are signed JWTs containing user claims. They have three parts separated by dots:

```
header.payload.signature
```

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "example-key-1"
}
```

**Payload (Claims):**
```json
{
  "iss": "http://localhost:5000",
  "sub": "24400320",
  "aud": "my-app",
  "nonce": "n-0S6_WzA2Mj",
  "exp": 1311281970,
  "iat": 1311280970,
  "name": "Jane Doe",
  "email": "janedoe@example.com",
  "email_verified": true
}
```

**Verification:**

1. Verify the signature using the public key from the JWKS endpoint
2. Verify `iss` matches expected issuer
3. Verify `aud` contains your client ID
4. Verify `exp` is in the future
5. Verify `nonce` matches the one sent in authorization request

---

## Standard Claims Reference

The UserInfo endpoint and ID token may include these standard claims:

### Profile Claims
- `sub` - Unique subject identifier
- `name` - Full name
- `given_name` - Given (first) name
- `family_name` - Family (last) name
- `middle_name` - Middle name
- `nickname` - Nickname
- `preferred_username` - Preferred username
- `profile` - Profile URL
- `picture` - Picture/avatar URL
- `website` - Website URL
- `gender` - Gender (male, female, other)
- `birthdate` - Birth date (YYYY-MM-DD)
- `zoneinfo` - Timezone (IANA tz string)
- `locale` - Locale/language (BCP47 tag)
- `updated_at` - Profile update time (Unix timestamp)

### Email Claims
- `email` - Email address
- `email_verified` - Whether mail is verified (boolean)

### Phone Claims
- `phone_number` - Phone number (E.164 format)
- `phone_number_verified` - Whether phone verified (boolean)

### Address Claims
- `address` - Physical address (JSON object)

---

## Scopes

### Supported Scopes

| Scope | Description |
|-------|-------------|
| openid | Basic OpenID Connect (required) |
| profile | Name, picture, birthdate, etc. |
| email | Email and email_verified claims |
| phone | Phone number claims |
| address | Physical address claims |

---

## HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 302 | Redirect (authorization code response) |
| 400 | Bad request (invalid parameters) |
| 401 | Unauthorized (invalid/missing token) |
| 500 | Server error |

---

## Rate Limiting

Currently not implemented. Production deployments should add rate limiting.

---

## CORS Configuration

Add CORS headers as needed for your application architecture:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
```

---

## Examples

### Complete OAuth 2.0 / OIDC Flow

#### 1. Initiate Authorization

```bash
curl -X GET "http://localhost:5000/openidconnect/authorize?
  response_type=code&
  client_id=my-app&
  redirect_uri=http://app.example.com/callback&
  scope=openid%20profile%20email&
  state=random-state"
```

#### 2. After User Logs In, Exchange Code for Tokens

```bash
curl -X POST http://localhost:5000/openidconnect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&
      code=<auth_code>&
      redirect_uri=http://app.example.com/callback&
      client_id=my-app&
      client_secret=secret123"
```

Response:
```json
{
  "access_token": "SlAV32hkKG",
  "token_type": "Bearer",
  "id_token": "eyJ...",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA"
}
```

#### 3. Get User Information

```bash
curl -X GET http://localhost:5000/openidconnect/userinfo \
  -H "Authorization: Bearer SlAV32hkKG"
```

Response:
```json
{
  "sub": "24400320",
  "name": "Jane Doe",
  "email": "janedoe@example.com"
}
```

#### 4. Refresh Access Token

```bash
curl -X POST http://localhost:5000/openidconnect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&
      refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&
      client_id=my-app&
      client_secret=secret123"
```

#### 5. Logout

```bash
curl -X POST http://localhost:5000/openidconnect/logout \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id_token_hint=eyJ...&
      post_logout_redirect_uri=http://app.example.com/"
```

---

## See Also

- OpenID Connect 1.0 Core: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0 RFC 6749: https://tools.ietf.org/html/rfc6749
- JWT RFC 7519: https://tools.ietf.org/html/rfc7519

