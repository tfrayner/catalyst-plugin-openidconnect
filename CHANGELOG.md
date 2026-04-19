# Changelog

All notable changes to this project will be documented in this file.

## [v0.0.2] - 2026-04-16 (Bug Fixes & Integration Improvements)

### Changed

- **Controller Integration**: Plugin now requires applications to create an extending controller in the app's namespace for proper route discovery. This ensures compatibility with Catalyst::Plugin::ACL and other route-processing plugins.
  - The plugin's controller (`Catalyst::Plugin::OpenIDConnect::Controller::Root`) is now a base class
  - Applications must create `lib/MyApp/Controller/OpenIDConnect.pm` that extends the plugin controller
  - This allows Catalyst to properly auto-discover routes and prevents dispatcher conflicts

- **Plugin Namespace Configuration**: Moved namespace configuration from extending controller to the base plugin controller
  - Base controller now sets `namespace => 'openidconnect'` by default
  - Extending controllers automatically inherit this configuration
  - Simplifies application setup

- **Simplified Plugin Lifecycle**: Changed from `setup_component`/`finalize_setup` to `after 'setup'` method modifier
  - Uses proper Moose role syntax for plugin hooks
  - Ensures correct execution order with other plugins like ACL

### Fixed

- Fixed "traversal hit a dead end" error when using plugin with existing apps that have route-processing plugins (ACL, etc.)
- Fixed plugin initialization to gracefully handle missing configuration
- Improved error handling for missing private key configuration

### Documentation

- Updated QUICKSTART.md with controller setup instructions
- Updated README.md with extending controller example
- Updated IMPLEMENTATION_GUIDE.md with detailed integration steps
- Updated DEPLOYMENT.md with production controller setup

---

## [v0.0.1] - 2026-04-10 (Initial Release)

### Added

#### Core Implementation
- **Catalyst::Plugin::OpenIDConnect** - Main plugin module
  - Moose role for seamless Catalyst integration
  - Configuration management via catalyst.conf
  - Automatic JWT handler initialization
  - State store management
  - OIDC context object for controllers

- **Catalyst::Plugin::OpenIDConnect::Utils::JWT** - JWT utilities
  - RS256 (RSA SHA-256) signing algorithm
  - Token verification with signature validation
  - Support for ID tokens, access tokens, refresh tokens
  - URL-safe Base64 encoding (RFC 4648)
  - Standard claims handling (iss, aud, exp, iat, sub)
  - Debug decoding without verification

- **Catalyst::Plugin::OpenIDConnect::Utils::Store** - State management
  - In-memory authorization code storage
  - User session management
  - UUID-based session IDs
  - Automatic expiration handling
  - Code consumption (one-time use)
  - Cleanup utilities for expired entries

- **Catalyst::Plugin::OpenIDConnect::Controller::Root** - Protocol endpoints
  - Authorization endpoint (GET /openidconnect/authorize)
  - Token endpoint (POST /openidconnect/token)
  - UserInfo endpoint (GET /openidconnect/userinfo)
  - Discovery endpoint (GET /.well-known/openid-configuration)
  - JWKS endpoint (GET /openidconnect/jwks)
  - Logout endpoint (POST /openidconnect/logout)

#### OAuth 2.0 & OpenID Connect Features
- Authorization Code Flow (full implementation)
- Token Exchange
  - authorization_code grant type
  - refresh_token grant type
- State parameter (CSRF protection)
- Nonce binding
- PKCE-ready (for future implementation)
- Standard claims support
  - Profile claims (name, email, picture, etc.)
  - Email verification
  - Phone verification
  - Address claims
- Token types
  - ID tokens (with user claims)
  - Access tokens (for API access)
  - Refresh tokens (for token refresh)

#### Configuration
- YAML-based configuration via catalyst.conf
- Issuer configuration
  - URL for iss claim
  - RSA private/public key loading
  - Key ID for JWT headers
- Client configuration
  - client_id and client_secret
  - redirect_uris (multiple allowed)
  - response_types and grant_types
  - Scope declarations
- User claims mapping
  - Flexible attribute mapping to OIDC claims
  - Nested attribute support via dot notation
  - Optional claim definitions

#### Security Features
- HTTPS support (via reverse proxy)
- CSRF protection (state parameter)
- Authorization code expiration (10 minutes)
- One-time code consumption
- Session management with expiration
- Bearer token authentication
- JWT signature verification
- Client secret validation
- Redirect URI validation

#### Documentation
- **README.md** - Feature overview and quick start
- **QUICKSTART.md** - 5-minute getting started guide
- **IMPLEMENTATION_GUIDE.md** - Architecture and design decisions
- **API_REFERENCE.md** - Complete endpoint documentation
- **DEPLOYMENT.md** - Production deployment guide
- Inline POD documentation in all modules

#### Tests
- JWT functionality tests (01_jwt.t)
  - Token signing validation
  - Token verification validation
  - Token decoding
  - Invalid token rejection
  - Payload matching
- Store functionality tests (02_store.t)
  - Authorization code creation
  - Code retrieval and validation
  - Code consumption
  - Session management

#### Example Application
- **example/app.pl** - Working Catalyst application
  - Login page (demo login without password)
  - Protected resource example
  - Logout functionality
  - User session management
  - Three configured example clients
- **example/generate_keys.sh** - RSA key generation script
- **example/root/** - HTML templates
  - index.html (home page)
  - login.html (login form)
  - protected.html (protected resource)

#### Project Files
- **cpanfile** - Comprehensive dependency declarations
  - Catalyst and related modules
  - Cryptography libraries
  - JSON processing
  - Testing dependencies
- **dist.ini** - Distribution configuration for CPAN publishing
- Project structure ready for publication

### Implementation Details

#### Algorithm Support
- RS256 (RSA SHA-256) for all JWT operations
- 2048-bit RSA keys (4096-bit recommended for production)

#### Token Lifetimes
- Authorization codes: 10 minutes
- ID tokens: 1 hour
- Access tokens: 1 hour
- Refresh tokens: 30 days
- Sessions: 24 hours (configurable)

#### Standard Claims
- Supported: sub, name, given_name, family_name, email, picture, phone_number, etc.
- User-configurable mapping from application models
- Optional claims support

#### Endpoints
- All endpoints return JSON except authorization (redirects)
- Proper HTTP status codes (200, 302, 400, 401, 500)
- RFC 6749 & RFC 6750 compliance
- OpenID Connect 1.0 Core compliance

### Known Limitations

- In-memory state store (database integration requires extension)
- Single key at a time (key rotation requires restart)
- No HS256 support (RS256 only)
- No Implicit or Hybrid flows
- No PKCE (for public clients)
- No form_post response mode
- No client registration endpoint
- No introspection endpoint

### Requirements

- Perl 5.20 or higher
- Catalyst 5.90100 or higher
- Moose and related modules
- Crypt::OpenSSL modules
- JSON::MaybeXS
- HTTP::Request and LWP stack

### Testing

All modules have unit test coverage. Run tests with:

```bash
prove -l t/
```

### Future Roadmap

- [ ] PKCE support for public clients
- [ ] Implicit and Hybrid flow support
- [ ] Multiple simultaneous keys
- [ ] Database-backed session store
- [ ] Introspection endpoint
- [ ] Revocation endpoint
- [ ] Client metadata endpoint
- [ ] HS256 algorithm support
- [ ] Multi-signature support
- [ ] Request object support
- [ ] Pushed Authorization Requests (PAR)
- [ ] OpenID Connect Federation support

### Author

Tim F. Rayner

### License

This library is available under The Artistic License 2.0 (GPL Compatible). See LICENSE file for details.
