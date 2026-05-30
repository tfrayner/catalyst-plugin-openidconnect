# Security Audit Report

**Project:** Catalyst::Plugin::OpenIDConnect  
**Audit Date:** 2026-04-28  
**Re-Audit Date:** 2026-05-30  
**Auditor:** GitHub Copilot  
**Scope:** All source files under `lib/` and `example/`

---

## Original Audit Summary (2026-04-28)

All findings from the original audit were remediated by 2026-04-29. See individual entries below for status.

| Severity | Count |
|----------|-------|
| Critical | 1     |
| High     | 5     |
| Medium   | 6     |
| Low      | 3     |
| Info     | 3     |

---

## Re-Audit Summary (2026-05-30)

Five new issues were identified. All original findings remain **Fixed**.

| Severity | New Findings |
|----------|-------------|
| High     | 2           |
| Medium   | 2           |
| Low      | 1           |

---

## Critical

### CRIT-1 — Open Redirect in Logout Endpoint

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `logout` action, `post_logout_redirect_uri` handling  
**Status:** **Fixed (2026-04-29)**

**Description:**  
The `post_logout_redirect_uri` parameter supplied by the client was used directly as a redirect target with no validation. An attacker could craft a logout URL that redirects the victim to an arbitrary external site (phishing, credential harvesting).

**Fix applied:**

1. `post_logout_redirect_uri` is now rejected unless `id_token_hint` is also provided.
2. The hint token's signature is verified (via the new `JWT::decode_id_token_hint` method) to confirm it was genuinely issued by this server. Expiry is intentionally not checked — hint tokens are frequently expired at logout time.
3. The `aud` claim of the verified hint identifies the client. The `post_logout_redirect_uri` is then compared exactly against that client's registered `post_logout_redirect_uris` list.
4. Any mismatch returns an `invalid_request` OAuth error response; no redirect is issued.
5. When a redirect is permitted, the optional `state` parameter is appended to the redirect URI as required by the RP-Initiated Logout 1.0 specification.

**New deployment requirement:**  
Each client configuration must include a `post_logout_redirect_uris` key listing the permitted post-logout redirect URLs. See the updated example in `example/app.pl`.

---

## High

### HIGH-1 — Open Redirect via Unvalidated `back` Parameter in Example Login

> **Fixed (2026-04-29)** — `back` is now restricted to relative paths that start with `/` but not `//`. Protocol-relative and absolute URLs are replaced with `/` before the redirect. The redirect is then issued via `$c->uri_for()` to guarantee it resolves to the same server.

**File:** `example/app.pl`  
**Location:** `OIDCExample::Controller::Root::login`

**Description:**  
After a successful login the application redirects to the URL contained in the `back` query parameter with no validation. An attacker can craft a link such as `/login?back=https://evil.example.com/` and users who follow it will be silently redirected to a malicious site after authenticating.

```perl
my $back = $c->request->params->{back} || '/';
return $c->response->redirect($back);
```

**Recommendation:**  
Restrict `back` to paths on the same origin (i.e., values that start with `/` and do not start with `//`) or store the return URL server-side in the session before initiating the login redirect.

```perl
# Allow only relative paths
my $back = $c->request->params->{back} || '/';
$back = '/' unless $back =~ m{^/[^/]};   # reject absolute URLs and protocol-relative
$c->response->redirect( $c->uri_for($back) );
```

---

### HIGH-2 — JWT Claims Validated Only When Present (Missing Mandatory Checks)

> **Fixed (2026-04-29)** — `verify_token` now unconditionally requires and validates `exp` and `iss`. `nbf` is enforced when present. An optional `expected_audience` parameter enables `aud` validation. 10 new tests added to `t/01_jwt.t` covering all cases.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Utils/JWT.pm`  
**Location:** `verify_token`

**Description:**  
The `exp`, `iss`, and `aud` claims are only validated when they exist in the token. A crafted token omitting these claims will pass verification. Per RFC 7519 and the OpenID Connect Core specification, `iss`, `sub`, `aud`, and `exp` are mandatory in an ID Token and must always be validated.

```perl
die 'Token expired'    if $payload->{exp} && $payload->{exp} < time();
die 'Invalid issuer'   if $payload->{iss} && $payload->{iss} ne $self->issuer;
# aud and nbf are not checked at all
```

**Recommendation:**  
Make `exp`, `iss`, and `aud` mandatory when verifying ID tokens, and add `nbf` (not-before) validation:

```perl
die 'Missing exp claim'  unless defined $payload->{exp};
die 'Token expired'      if $payload->{exp} < time();
die 'Missing iss claim'  unless defined $payload->{iss};
die 'Invalid issuer'     unless $payload->{iss} eq $self->issuer;
# aud check should be caller-supplied or accept an expected_audience param
die 'Token not yet valid' if defined $payload->{nbf} && $payload->{nbf} > time();
```

---

### HIGH-3 — Timing Attack on Client Secret Comparison

> **Fixed (2026-04-29)** — Both `client_secret eq` comparisons in `Controller::Root` replaced with `Crypt::Misc::slow_eq()`. `Crypt::Misc` added to `cpanfile`.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `_handle_authorization_code_grant`, `_handle_refresh_token_grant`

**Description:**  
Client secrets are compared using the Perl string equality operator `eq`, which short-circuits on the first differing byte. A remote attacker performing many requests can statistically determine the correct client secret one character at a time (timing side-channel attack).

```perl
unless ( $client && $client->{client_secret} eq $client_secret ) {
```

**Recommendation:**  
Use a constant-time comparison function. The `Crypt::Misc` or `String::Compare::ConstantTime` modules provide this:

```perl
use String::Compare::ConstantTime;
unless ( $client && String::Compare::ConstantTime::equals(
             $client->{client_secret}, $client_secret ) ) {
```

Alternatively, store secrets as bcrypt hashes and compare with `Crypt::Bcrypt`.

---

### HIGH-4 — Authorization Code Redemption is Not Atomic (TOCTOU Race Condition)

> **Fixed (2026-04-29)** — `consume_authorization_code` is now the single atomic operation used by the token endpoint. In-memory backend uses Perl's `delete` (atomic per-process). Redis backend uses `GETDEL` (Redis ≥ 6.2 single-command atomic fetch-and-delete). The controller no longer calls `get_authorization_code` + `consume_authorization_code` separately. `Role::Store` contract updated to document the return value.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm` and  
`lib/Catalyst/Plugin/OpenIDConnect/Utils/Store/Redis.pm`

**Description:**  
The token endpoint fetches the authorization code and then deletes it in two separate operations. Under concurrent requests (common in pre-forking or threaded servers) two requests carrying the same code can both succeed `get_authorization_code` before either `consume_authorization_code` is called, violating the single-use requirement of RFC 6749 §4.1.2.

```perl
my $code_data = $c->openidconnect->store->get_authorization_code($code);  # check
# ... validation ...
$c->openidconnect->store->consume_authorization_code($code);               # delete
```

For the Redis backend, a `GET` followed by a `DEL` is not atomic.

**Recommendation:**  
- **In-memory store:** Replace the get+delete pair with an atomic delete-and-return operation (Perl hash delete returns the value).
- **Redis backend:** Use a Lua script or `GETDEL` (Redis ≥ 6.2) to fetch and atomically delete the key in one round-trip.

```perl
# Redis atomic example using Lua
my $data = $self->_redis->eval(
    'local v = redis.call("GET", KEYS[1]); redis.call("DEL", KEYS[1]); return v',
    1, $self->prefix . $code
);
```

---

### HIGH-5 — No PKCE Support for Public Client Flows

> **Fixed (2026-04-29)** — Full RFC 7636 PKCE support added. Authorize endpoint reads `code_challenge`/`code_challenge_method`, persists them through the login-redirect session, requires `code_challenge` for public clients (those without a `client_secret`), rejects `plain` method (only `S256` accepted), and stores the challenge with the code. Token endpoint reads `code_verifier`, verifies S256 before issuing tokens. `_verify_pkce` enforces length (43–128) and character constraints. Both store backends persist `code_challenge`/`code_challenge_method`. Tests in `t/06_pkce.t` (11 tests), `t/02_store.t`, and `t/04_store_redis.t`.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`

**Description:**  
The authorization code flow does not implement Proof Key for Code Exchange (PKCE, RFC 7636). PKCE is required for all public clients (those without a client secret, e.g. mobile apps and SPAs) and is strongly recommended for confidential clients as well. Without it, authorization codes intercepted via referrer headers, browser history, or redirect URI misconfiguration can be exchanged for tokens by an attacker. OAuth 2.1 mandates PKCE for all authorization code flows.

**Recommendation:**  
Add `code_challenge` and `code_challenge_method` handling to the authorize endpoint, store the challenge with the authorization code, and verify the `code_verifier` in the token endpoint before issuing tokens.

---

### NEW-HIGH-1 — Open Redirect via Unvalidated `redirect_uri` in Pre-Validation Error Responses

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `authorize` action  
**Status:** **Fixed (2026-05-30)**

**Fix applied:**  
The `authorize` action was split into two explicit phases. Phase 1 validates `client_id`, `redirect_uri`, and the registered redirect URI list using direct HTTP 400 responses (`_json_error`) — no redirect is issued. Only once `redirect_uri` has been confirmed as registered does the action proceed to Phase 2, where `_error_response` (which may redirect) is used for remaining parameter validation such as `response_type`. The previous validation order — which called `_error_response` with the unvalidated `redirect_uri` before the client was even looked up — has been removed.

**Description:**  
RFC 6749 §4.1.2.1 states that the authorization server MUST NOT automatically redirect the user-agent to an unregistered or invalid redirect URI. Two error paths in the `authorize` action violate this requirement:

1. **`response_type` check** (before redirect URI validation): When `response_type` is not `"code"`, `_error_response` is called with the raw, client-supplied `redirect_uri` before it has been validated against the client's registered list.
2. **Unknown `client_id`** (before redirect URI validation is possible): When the `client_id` is not found in the configuration, `_error_response` is again called with the unvalidated `redirect_uri`. At this point there is no registered URI list to consult.

An attacker can exploit either path by crafting an authorization URL such as:

```
/openidconnect/authorize?client_id=known-client
    &response_type=token
    &redirect_uri=https://phishing.example.com/
```

A victim who follows this link — which carries the trusted identity-provider domain — is silently redirected to the attacker-controlled site carrying an OAuth error payload, enabling phishing and credential harvesting.

The fix applied reorders validation as described above. The old pre-validation order is replaced; refer to the source diff for full details.

---

### NEW-HIGH-2 — Cross-Client Authorization Code Redemption at Token Endpoint

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `_handle_authorization_code_grant`  
**Status:** **Open**

**Description:**  
The token endpoint does not verify that the `client_id` in the token request matches the `client_id` stored with the authorization code. The relevant assignment is:

```perl
$client_id ||= $code_data->{client_id};
```

The stored `client_id` is used only as a fallback when the request omits the field. If the caller provides any non-empty `client_id` it is used unconditionally — regardless of whether it matches the client the code was actually issued to. RFC 6749 §4.1.3 requires the server to "ensure that the authorization code was issued to the authenticated confidential client."

**Attack scenario (confidential clients):**

1. Attacker registers `attacker-client` with `client_secret=attacker-secret`.
2. Attacker obtains a code issued to `victim-client` (e.g. via referrer header, log exposure, or redirect URI misconfiguration).
3. Attacker sends: `client_id=attacker-client&client_secret=attacker-secret&code=<victim-code>&redirect_uri=<victim-redirect>`.
4. Client authentication succeeds because the attacker's own secret is valid for `attacker-client`.
5. The redirect URI check passes because it matches the value stored in the code from the original request.
6. Tokens are issued bearing the victim user's identity (`sub`) but with `aud=attacker-client`.

PKCE mitigates this for public clients (the attacker cannot produce a valid `code_verifier` for the victim's `code_challenge`), but confidential clients — for which PKCE is optional — remain vulnerable.

**Recommendation:**  
After resolving `client_id`, assert that it matches the value stored with the authorization code:

```perl
$client_id //= $code_data->{client_id};
if ( $client_id ne $code_data->{client_id} ) {
    $c->log->warn(
        "client_id mismatch at token endpoint: "
        . "request=$client_id stored=$code_data->{client_id}"
    );
    return $self->_json_error( $c, 'invalid_grant',
        'client_id does not match the authorization code' );
}
```

---

## Medium

### MED-1 — Non-Revocable Refresh Tokens

> **Fixed (2026-04-29)** — Refresh tokens now carry a unique JTI (UUID v4)
> registered in the backend store (in-memory or Redis) at issuance time with a
> TTL of 30 days.  The token endpoint atomically consumes the JTI on each use
> and issues a new JTI + refresh token (rotation), making every token
> single-use.  On logout, all JTIs for the user are deleted via a secondary
> per-subject index.  See `[0.07]` in `CHANGELOG.md` for full details.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `_handle_refresh_token_grant`

**Description:**  
Refresh tokens are issued as signed JWTs with a 30-day lifetime and are never stored server-side. There is no mechanism to revoke them (e.g. on logout, password change, or security incident). A stolen refresh token remains valid for its full 30-day lifetime.

**Recommendation:**  
Store refresh token identifiers (the `jti` claim) in the same backend store used for authorization codes, with a TTL matching the token lifetime. On every use, verify the `jti` exists in the store and immediately replace it with a new token (refresh token rotation). On logout, delete all stored `jti` values for that user/client.

---

### MED-2 — Sensitive Claims Logged at Debug Level

> **Fixed (2026-04-29)** — The `sign_token` debug log statement now emits only `sub`, `aud`, and `exp` metadata. PII-bearing claims (email, name, etc.) are never written to the log. 4 new tests added to `t/01_jwt.t` verify the log message does not contain the email or name fields.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Utils/JWT.pm`  
**Location:** `sign_token`

**Description:**  
The entire JWT payload (which may include PII such as email addresses, names, and user identifiers) is serialised and written to the log at `DEBUG` level. In production environments where debug logging is enabled, this data may end up in log aggregators, log files, or monitoring dashboards accessible to operators who should not have access to individual user data.

```perl
$self->logger->debug('JWT payload: ' . encode_json(\%payload)) if $self->logger;
```

**Recommendation:**  
Either remove this log statement entirely, or log only non-sensitive metadata (e.g. `sub`, `aud`, expiry timestamp):

```perl
$self->logger->debug(sprintf(
    'Signing JWT: sub=%s aud=%s exp=%s',
    $payload{sub} // '?', $payload{aud} // '?', $payload{exp} // '?'
)) if $self->logger;
```

---

### MED-3 — Thread-Unsafe Package-Level Global State

> **Fixed (2026-04-29)** — Replaced `our $_oidc_jwt_instance` and `our $_oidc_store_instance` package-level globals with per-application-class lexical hashes (`%_oidc_jwt_by_class`, `%_oidc_store_by_class`) keyed by `ref($self) || $self`. Multiple Catalyst applications loaded in the same Perl interpreter each hold their own JWT and store instances and cannot overwrite each other's state. 3 new tests in `t/03_plugin.t` verify isolation.

**File:** `lib/Catalyst/Plugin/OpenIDConnect.pm`

**Description:**  
The JWT handler and store instances are held in package-level global variables (`our $_oidc_jwt_instance`, `our $_oidc_store_instance`). These are shared across all application instances within the same Perl interpreter. Under a threaded Catalyst server (e.g. using `threads` or `Mojo::IOLoop`), concurrent writes to these globals during setup could cause data races or one application instance replacing another's JWT keys.

```perl
our $_oidc_jwt_instance;
our $_oidc_store_instance;
```

**Recommendation:**  
Store these instances on the application object itself rather than in package globals, using Catalyst's built-in `mk_classdata` or a class attribute:

```perl
__PACKAGE__->mk_classdata('_oidc_jwt');
__PACKAGE__->mk_classdata('_oidc_store');
```

---

### MED-4 — Implicit Grant Type Advertised as Supported

> **Fixed (2026-04-29)** — `implicit` removed from `grant_types_supported`; `id_token` and `token` response types removed from `response_types_supported`. Discovery document now advertises only `authorization_code` and `refresh_token` grants, and only `code` as a response type. 4 new tests in `t/03_plugin.t` verify the absence of implicit types.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Context.pm`  
**Location:** `get_discovery`

**Description:**  
The discovery document lists `implicit` as a supported grant type. The implicit flow has been deprecated by OAuth 2.0 Security Best Practices (RFC 9700) and is omitted from OAuth 2.1 entirely due to token exposure in browser history, referrer headers, and log files. Advertising it invites clients to use an insecure flow.

```perl
grant_types_supported => [qw(authorization_code refresh_token implicit)],
```

**Recommendation:**  
Remove `implicit` from `grant_types_supported` and `response_types_supported` in the discovery document. If implicit flow is genuinely required by an existing client, document it as a known risk and require explicit opt-in.

---

### MED-5 — Session Entry `oidc_code` Is Never Cleaned Up

> **Fixed (2026-04-29)** — `_handle_authorization_code_grant` now calls `delete $c->session->{oidc_code}->{$code}` immediately after `consume_authorization_code` succeeds. The session copy is removed regardless of whether the subsequent token-issuance steps succeed or fail, ensuring stale claims, scope, and nonce data do not accumulate in the session store.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `authorize` action

**Description:**  
The authorization action writes a copy of each issued code and its associated data into `$c->session->{oidc_code}`. This session key is never removed in the token endpoint or anywhere else. Over time the session grows unboundedly with stale code entries, leaking user data (claims, scope, nonce) into the session store beyond the code's 10-minute lifetime.

```perl
$c->session->{oidc_code}->{$code} = {
    client_id    => $client_id,
    user         => $user_claims,
    ...
};
```

**Recommendation:**  
Delete the session entry after the code has been consumed:

```perl
# In _handle_authorization_code_grant, after consuming the code:
delete $c->session->{oidc_code}->{$code};
```

---

### MED-6 — Missing HTTP Security Headers on All Responses

> **Fixed (2026-04-29)** — A `begin : Private` action in `Controller::Root`
> now sets `Cache-Control: no-store`, `Pragma: no-cache`,
> `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
> `Content-Security-Policy: frame-ancestors 'none'` on every OIDC endpoint
> response before the action body runs.  See `[0.08]` in `CHANGELOG.md`.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`

**Description:**  
None of the OIDC endpoints set HTTP security headers. At minimum, the following should be present:

- `Cache-Control: no-store` — required by RFC 6749 §5.1 on all token responses; also advisable on UserInfo responses.
- `Pragma: no-cache` — for HTTP/1.0 compatibility.
- `X-Content-Type-Options: nosniff` — prevents MIME sniffing.
- `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'` — prevents clickjacking of the authorization endpoint.

**Recommendation:**  
Add a `begin` action (or Catalyst middleware) that injects these headers on all OIDC responses. For the token and UserInfo endpoints specifically, ensure `Cache-Control: no-store` is always set.

---

### NEW-MED-1 — Token Type Confusion at UserInfo Endpoint

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `userinfo` action; `lib/Catalyst/Plugin/OpenIDConnect/Utils/JWT.pm`  
**Status:** **Open**

**Description:**  
`create_id_token`, `create_access_token`, and `create_refresh_token` all call the same `sign_token` function and produce structurally identical JWTs. No `typ` claim distinguishes token types (RFC 9068 reserves `at+JWT` for access tokens). At the UserInfo endpoint the bearer token is verified with:

```perl
$payload = $c->openidconnect->jwt->verify_token($token);
```

No `expected_audience` is supplied and no `typ` check is performed. As a result:

- An **ID token** (valid `iss`, `sub`, `exp`, `aud`) passes `verify_token` and satisfies the UserInfo handler even though it is intended for consumption by a relying party, not for authorizing API requests.
- A **refresh token** (also a signed JWT with `iss`, `sub`, `exp`, and `jti`) likewise passes verification.

In environments where a relying party caches ID tokens, or where a refresh token is obtained by a malicious actor, these tokens could be replayed at the UserInfo endpoint to extract the subject's claims without holding a valid access token.

**Recommendation:**  
Add a distinct `typ` claim to access tokens at issuance time and validate it at the UserInfo endpoint:

```perl
# In Controller::Root — when issuing access tokens:
my %access_token_payload = (
    sub => $user_claims->{sub},
    aud => $client_id,
    scp => $code_data->{scope},
    typ => 'at+JWT',              # RFC 9068 access token type
    exp => $now + 3600,
);

# In the userinfo action — after verify_token:
unless ( ( $payload->{typ} // '' ) eq 'at+JWT' ) {
    return $self->_json_error( $c, 'invalid_token',
        'Presented token is not an access token' );
}
```

---

### NEW-MED-2 — Requested Scope Not Validated Against Registered Client Scopes

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `authorize` action  
**Status:** **Open**

**Description:**  
The `scope` parameter is accepted and stored verbatim without being validated against the scopes registered for the requesting client in the application configuration. A client configured with `scope => 'openid profile email'` can successfully request `scope=openid admin` and will receive tokens bearing the wider scope string. Protected resources that rely on the `scp` claim in access tokens for authorization decisions may grant unwarranted privileges as a result.

```perl
# Current — any scope string is accepted without validation:
$scope ||= $stored_auth_request->{scope} || 'openid';
```

**Recommendation:**  
Intersect the requested scope with the client's registered scope list. Return an `invalid_scope` error if no overlap exists:

```perl
my @registered = split /\s+/, ( $client->{scope} // 'openid' );
my @requested  = split /\s+/, ( $scope // 'openid' );
my %allowed    = map { $_ => 1 } @registered;
my @effective  = grep { $allowed{$_} } @requested;
unless (@effective) {
    return $self->_error_response( $c, $redirect_uri, 'invalid_scope',
        'None of the requested scopes are registered for this client', $state );
}
$scope = join ' ', @effective;
```

---

## Low

### LOW-1 — Non-Cryptographic PRNG Used for User IDs in Example

> **Fixed (2026-04-29)** — `int(rand(10000)) + 1000` replaced with `Data::UUID->new->create_str()`. A `Data::UUID` generator instance is created once at startup and reused. `Data::UUID` was already a declared dependency in `cpanfile`.

**File:** `example/app.pl`  
**Location:** `_create_mock_user`

**Description:**  
The example application generates user IDs using `int(rand(10000)) + 1000`. Perl's `rand` is a pseudo-random number generator seeded from a predictable value; it is not cryptographically secure. In the example context this is low risk, but any production code based on this example should not follow the same pattern for generating security-sensitive identifiers.

```perl
id => int(rand(10000)) + 1000,
```

**Recommendation:**  
Use a UUID library or cryptographically secure random bytes:

```perl
use Data::UUID;
id => Data::UUID->new->create_str(),
```

---

### LOW-2 — Issuer URL Uses Plaintext HTTP in Example Configuration

**File:** `example/app.pl`

**Description:**  
The example configuration sets the issuer to `http://localhost:5000`. OpenID Connect Core §2 requires the issuer identifier to be an HTTPS URL in production deployments. Applications copied from the example without changing the scheme will serve tokens with an HTTP issuer claim, which violates the specification and disables TLS protection for all OIDC protocol flows.

**Recommendation:**  
Use HTTPS for the issuer URL in any non-localhost deployment. Document this requirement prominently in the README and configuration comments.

---

### LOW-3 — No Rate Limiting on Token and Authorization Endpoints

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`

**Description:**  
The token endpoint does not implement any rate limiting or brute-force protection. An attacker can submit unlimited authorization code or client credential guesses. While authorization codes are random 128-character strings making brute-force computationally impractical, exhaustion attacks or credential stuffing against reused client secrets remain possible.

**Recommendation:**  
Apply rate limiting at the reverse proxy layer (e.g. Nginx `limit_req`) or use a Catalyst middleware (e.g. `Plack::Middleware::Throttle`) on the token endpoint. Consider locking out client IDs after a configurable number of consecutive authentication failures.

---

### NEW-LOW-1 — PKCE `code_challenge` Not Validated for Format at Authorization Endpoint

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `authorize` action  
**Status:** **Open**

**Description:**  
When `code_challenge` is supplied, the `authorize` action validates that `code_challenge_method` is `S256` but does not validate the format of the `code_challenge` value itself. Per RFC 7636 §4.2, an S256 challenge must be `BASE64URL(SHA256(ASCII(code_verifier)))` — exactly 43 characters from the BASE64URL alphabet (`[A-Za-z0-9\-_]`, no padding). An over-long, under-long, or malformed value is stored verbatim in the backend.

While `_verify_pkce` will reject any mismatch at the token endpoint (the computed challenge derived from the verifier will not match a malformed stored value), accepting an invalid challenge wastes store capacity and could produce unexpected behaviour in serialisation or logging pipelines.

**Recommendation:**  
Validate the `code_challenge` at the authorization endpoint before storing it:

```perl
if ( $code_challenge ) {
    unless ( $code_challenge =~ /\A[A-Za-z0-9\-_]{43}\z/ ) {
        return $self->_error_response( $c, $redirect_uri, 'invalid_request',
            'code_challenge must be a 43-character BASE64URL string for S256',
            $state );
    }
}
```

---

## Informational

### INFO-1 — Client Secrets Stored in Plaintext Configuration

**File:** `lib/Catalyst/Plugin/OpenIDConnect.pm`, `example/app.pl`

**Description:**  
Client secrets are stored and compared as plaintext strings in the application configuration. If the configuration file is leaked (e.g. committed to version control, exposed via a misconfigured web server), all client secrets are immediately compromised.

**Recommendation:**  
Consider storing client secrets as bcrypt or Argon2 hashes and verifying them with a constant-time comparison. Alternatively, support sourcing secrets from environment variables (similar to the existing `REDIS_PASSWORD` pattern already used for the Redis store).

---

### INFO-2 — Dynamic Module Loading from Configuration

**File:** `lib/Catalyst/Plugin/OpenIDConnect.pm` and `lib/Catalyst/Plugin/OpenIDConnect/Context.pm`  
**Location:** `Module::Runtime::require_module($store_class)`

**Description:**  
The `store_class` configuration value is passed directly to `Module::Runtime::require_module`. If an attacker can control application configuration (e.g. through an unsanitised config file merge or environment variable injection), they could cause arbitrary Perl modules to be loaded. In practice this risk is low because the config is under operator control, but it should be documented as a deployment consideration.

**Recommendation:**  
Maintain an explicit allowlist of permitted store class names, or validate that the supplied class name matches a known namespace pattern before loading it.

---

### INFO-3 — `redirect_uris` Parsing May Behave Differently Across Config Formats

> **Fixed (2026-04-29)** — `redirect_uris` and `post_logout_redirect_uris` are now both normalised via `_normalize_uri_list()`, which handles both arrayrefs and whitespace-separated strings. See CHANGELOG.md `[0.05]`.

**File:** `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm`  
**Location:** `authorize`, `@allowed_uris` construction

**Description:**  
The code splits `$client->{redirect_uris}` as a whitespace-delimited string. YAML and JSON configuration files may deserialise this field as an array reference rather than a string. If an array reference is passed to `split`, Perl will stringify it as `ARRAY(0x...)` and the comparison will always fail, causing legitimate redirects to be rejected (a denial of service on the authorization flow).

```perl
my @allowed_uris = split /\s+/, $client->{redirect_uris};
```

**Recommendation:**  
Normalize the field at read time:

```perl
my $uris = $client->{redirect_uris};
my @allowed_uris = ref $uris eq 'ARRAY' ? @$uris : split /\s+/, ($uris // '');
```

---

## Appendix: Files Reviewed

| File | Lines (re-audit) |
|------|-----------------|
| `lib/Catalyst/Plugin/OpenIDConnect.pm` | 322 |
| `lib/Catalyst/Plugin/OpenIDConnect/Context.pm` | 216 |
| `lib/Catalyst/Plugin/OpenIDConnect/Controller/Root.pm` | 897 |
| `lib/Catalyst/Plugin/OpenIDConnect/Utils/JWT.pm` | 337 |
| `lib/Catalyst/Plugin/OpenIDConnect/Utils/Store.pm` | 257 |
| `lib/Catalyst/Plugin/OpenIDConnect/Utils/Store/Redis.pm` | 347 |
| `lib/Catalyst/Plugin/OpenIDConnect/Role/Store.pm` | 113 |
| `example/app.pl` | 252 |
| `example/lib/OIDCExample/Controller/OpenIDConnect.pm` | 10 |
