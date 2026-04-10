# Deployment Guide

Production deployment considerations for Catalyst::Plugin::OpenIDConnect.

## Prerequisites

- Perl 5.20 or higher
- Catalyst 5.90100 or higher
- OpenSSL for key generation
- HTTP/HTTPS web server
- Database (optional, for persistent storage)

## Installation

### 1. Install Dependencies

Using cpanm:

```bash
cpanm Catalyst::Plugin::OpenIDConnect
```

Or using cpanfile:

```bash
cpanm --installdeps .
```

### 2. Generate RSA Keys

```bash
# Generate 2048-bit RSA key pair
openssl genrsa -out /secure/path/private.pem 2048

# Extract public key
openssl rsa -in /secure/path/private.pem -pubout -out /secure/path/public.pem

# Set restrictive permissions
chmod 600 /secure/path/private.pem
chmod 644 /secure/path/public.pem
```

Note: For production, consider using 4096-bit keys or storing keys in a HSM (Hardware Security Module).

### 3. Configure Your Application

Create/update `catalyst.conf`:

```
<Plugin::OpenIDConnect>
    <issuer>
        url = https://auth.example.com
        private_key_file = /secure/path/private.pem
        public_key_file = /secure/path/public.pem
        key_id = prod-key-2024-01
    </issuer>
    
    <clients>
        <my-app>
            client_secret = <randomly-generated-secret>
            redirect_uris = https://app.example.com/callback https://app.example.com/oauth/callback
            response_types = code
            grant_types = authorization_code refresh_token
            scope = openid profile email
        </my-app>
    </clients>
    
    <user_claims>
        sub = id
        name = full_name
        email = email
        picture = avatar_url
    </user_claims>
</Plugin::OpenIDConnect>

<Plugin::Session>
    expires = 2592000
    cookie_secure = 1
    cookie_httponly = 1
    cookie_samesite = Lax
</Plugin::Session>
```

## HTTPS Configuration

HTTPS is mandatory for production deployments.

### Using Nginx as Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate /etc/ssl/certs/your-cert.crt;
    ssl_certificate_key /etc/ssl/private/your-key.key;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://catalyst:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }
}

# Force HTTPS
server {
    listen 80;
    server_name auth.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Using Apache as Reverse Proxy

```apache
<VirtualHost *:443>
    ServerName auth.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/your-cert.crt
    SSLCertificateKeyFile /etc/ssl/private/your-key.key
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    ProxyPreserveHost On
    ProxyPass / http://catalyst:5000/
    ProxyPassReverse / http://catalyst:5000/
</VirtualHost>

# Force HTTPS
<VirtualHost *:80>
    ServerName auth.example.com
    Redirect permanent / https://auth.example.com/
</VirtualHost>
```

## Database Integration

### PostgreSQL Example

```perl
package MyApp::Model::OIDC;
use Moose;
extends 'Catalyst::Plugin::OpenIDConnect::Utils::Store';

has dbic => (
    is  => 'ro',
    isa => 'Catalyst::Model::DBIC::Schema',
);

sub create_authorization_code {
    my ($self, $client_id, $user, $scope, $redirect_uri, $nonce) = @_;
    
    my $code = $self->_generate_secure_code();
    
    $self->dbic->resultset('AuthCode')->create({
        code => $code,
        client_id => $client_id,
        user_id => $user->id,
        scope => $scope,
        redirect_uri => $redirect_uri,
        nonce => $nonce,
        created_at => DateTime->now,
        expires_at => DateTime->now->add(minutes => 10),
    });
    
    return $code;
}

sub get_authorization_code {
    my ($self, $code) = @_;
    
    my $code_row = $self->dbic->resultset('AuthCode')->find({ code => $code });
    return unless $code_row;
    
    # Check expiration
    return if DateTime->now > $code_row->expires_at;
    
    return {
        client_id => $code_row->client_id,
        user => $code_row->user,
        scope => $code_row->scope,
        redirect_uri => $code_row->redirect_uri,
        nonce => $code_row->nonce,
    };
}

__PACKAGE__->meta->make_immutable;
```

## Systemd Service

Create `/etc/systemd/system/oidc-catalyst.service`:

```ini
[Unit]
Description=OpenID Connect Provider
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/oidc
ExecStart=/usr/bin/perl app.pl
Restart=always
RestartSec=10

# Limit resources
LimitNOFILE=65535
LimitNPROC=32768

# Security
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/oidc/logs /opt/oidc/var

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable oidc-catalyst
sudo systemctl start oidc-catalyst
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM perl:5.32

WORKDIR /app

# Install dependencies
COPY cpanfile .
RUN apt-get update && apt-get install -y openssl && \
    cpanm -n --installdeps .

# Copy application
COPY . .

# Generate keys (or mount from volume)
RUN mkdir -p /app/keys && \
    openssl genrsa -out /app/keys/private.pem 2048 && \
    openssl rsa -in /app/keys/private.pem -pubout -out /app/keys/public.pem

# Create non-root user
RUN useradd -m -u 1000 catalyst && \
    chown -R catalyst:catalyst /app

USER catalyst

EXPOSE 5000

CMD ["perl", "app.pl"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  oidc:
    build: .
    ports:
      - "5000:5000"
    environment:
      CATALYST_HOME: /app
      CATALYST_ENV: production
    volumes:
      - ./keys:/app/keys:ro
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/.well-known/openid-configuration"]
      interval: 30s
      timeout: 10s
      retries: 3
  
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - oidc
```

## Monitoring

### Health Check Endpoint

```perl
sub health : Local : ActionClass('RenderView') {
    my ($self, $c) = @_;
    
    # Check database connectivity
    try {
        $c->model('DB')->schema->dbh->ping or die 'DB not responding';
    }
    catch {
        $c->response->status(503);
        $c->stash->{json} = { status => 'error', message => $_ };
        return;
    };
    
    $c->response->status(200);
    $c->stash->{json} = {
        status => 'healthy',
        timestamp => scalar gmtime(),
        version => $VERSION,
    };
}
```

### Logging Configuration

```perl
<Log4perl>
    log4perl.rootLogger = DEBUG, FileApp, FileError
    
    log4perl.appender.FileApp = Log::Log4perl::Appender::File
    log4perl.appender.FileApp.filename = /var/log/oidc/app.log
    log4perl.appender.FileApp.layout = PatternLayout
    log4perl.appender.FileApp.layout.ConversionPattern = %d %p [%c] %m%n
    
    log4perl.appender.FileError = Log::Log4perl::Appender::File
    log4perl.appender.FileError.filename = /var/log/oidc/error.log
    log4perl.appender.FileError.layout = PatternLayout
    log4perl.appender.FileError.layout.ConversionPattern = %d %p [%c] %m%n
    log4perl.appender.FileError.Threshold = ERROR
</Log4perl>
```

### Key Metrics to Monitor

- Authorization request latency
- Token exchange time
- UserInfo endpoint response time
- Authorization code expiration rate
- Session creation/destruction rate
- Error rate by endpoint
- Token verification failures
- Failed authentication attempts

## Security Best Practices

### General

1. **Always use HTTPS** - All OIDC endpoints must be over HTTPS
2. **Validate redirect URIs** - Strict matching required
3. **Use POST for sensitive data** - Never pass secrets in URLs
4. **Implement rate limiting** - Prevent brute force attacks
5. **Log security events** - Track failed attempts, suspicious activity
6. **Regular key rotation** - Rotate keys annually
7. **Monitor for vulnerabilities** - Keep Perl and dependencies updated

### Key Management

1. **Rotate keys periodically** - At least annually
2. **Keep private keys secure** - Restrict file permissions (600)
3. **Don't hardcode secrets** - Use environment variables or secure vaults
4. **Use key IDs** - Allow key rotation without breaking clients
5. **Publish public keys via JWKS** - Don't require manual download

### Session Management

1. **Use secure cookies** - Set `Secure`, `HttpOnly`, `SameSite` flags
2. **Short-lived sessions** - Default to 30 minutes
3. **CSRF protection** - Validate `state` parameter
4. **Nonce binding** - Prevent man-in-the-middle attacks
5. **Session timeout** - Clear old sessions regularly

### Client Authentication

1. **Use client secrets** - Not for public (JavaScript) clients
2. **PKCE for public clients** - RFC 7636 authorization code protection
3. **Validate redirect URIs** - Exact match required
4. **Limit client scope** - Principle of least privilege
5. **Client authentication at token endpoint** - Required

## Performance Optimization

### Caching

```perl
# Cache JWKS response (5 minutes)
sub jwks : Local {
    my ($self, $c) = @_;
    
    $c->response->header('Cache-Control' => 'public, max-age=300');
    # ... return JWKS
}

# Cache discovery (1 hour)
sub discovery : Path('/.well-known/openid-configuration') {
    my ($self, $c) = @_;
    
    $c->response->header('Cache-Control' => 'public, max-age=3600');
    # ... return discovery
}
```

### Database Indexes

```sql
CREATE INDEX idx_auth_code_code ON auth_codes(code);
CREATE INDEX idx_auth_code_expires ON auth_codes(expires_at);
CREATE INDEX idx_session_user ON sessions(user_id);
CREATE INDEX idx_session_created ON sessions(created_at);
```

### Connection Pooling

```perl
<Model::DB>
    <connect_info>
        <0>
            dbi:Pg:dbname=oidc;host=localhost
        </0>
        <1>
            postgres
        </1>
        <2>
            password
        </2>
        <3>
            {
                AutoCommit = 1
                RaiseError = 1
                PrintError = 0
                pg_enable_utf8 = 1
            }
        </3>
    </connect_info>
    <storage>
        <0>pg
        <1></1>
        <2>
            {
                pool_type = Static
                pool_size = 10
            }
        </2>
    </storage>
</Model::DB>
```

## Backup and Recovery

### Database Backups

```bash
# Daily backup
0 2 * * * /usr/bin/pg_dump -U postgres oidc | gzip > /backups/oidc-$(date +\%Y\%m\%d).sql.gz

# Keep 30 days of backups
find /backups -name 'oidc-*.sql.gz' -mtime +30 -delete
```

### Key Backups

```bash
# Store keys in secure backup location
cp /secure/path/private.pem /secure/backup/private-$(date +\%Y\%m\%d).pem.gpg
gpg --encrypt --recipient <key-id> /secure/backup/private-*.pem
```

## Troubleshooting

### Common Issues

**Tokens Invalid After Key Rotation**
- Ensure both old and new keys are published in JWKS during rotation period
- Clients need time to receive updated keys

**Token Verification Fails**
- Check clock skew (sync NTP on all servers)
- Verify issuer URL matches configuration
- Ensure token hasn't expired

**CORS Errors**
- Add appropriate `Access-Control-*` headers
- Check allowed origins in frontend configuration

**Session Loss**
- Verify session storage is persistent (not in-memory)
- Check session cookie settings (Secure, HttpOnly)
- Check session expiration time

## Maintenance

### Regular Tasks

1. **Daily**: Monitor error logs, check application health
2. **Weekly**: Review failed authentication attempts
3. **Monthly**: Check performance metrics, update dependencies
4. **Quarterly**: Security audit, penetration testing
5. **Annually**: Key rotation, compliance review

### Update Procedure

```bash
# Test updates in staging first
cpanm -n --installdeps .

# Back up database
pg_dump oidc > oidc-$(date +%Y%m%d).sql

# Update code
git pull origin main

# Restart application
sudo systemctl restart oidc-catalyst

# Verify health checks pass
curl https://auth.example.com/health
```

## References

- OWASP OAuth 2.0 Security: https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2_0_Security_Cheat_Sheet.html
- OpenID Connect Security: https://openid.net/certification/
- NIST Authentication Guidelines: https://pages.nist.gov/sp-800-63/sp-800-63-3/

