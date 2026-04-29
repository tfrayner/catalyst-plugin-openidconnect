package Catalyst::Plugin::OpenIDConnect::Controller::Root;

use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

use JSON::MaybeXS qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64 decode_base64);
use Crypt::PK::RSA;
use Crypt::Misc qw(slow_eq);
use URI;
use DateTime;
use Try::Tiny;

# Set the namespace for OpenIDConnect routes
__PACKAGE__->config(namespace => 'openidconnect');

=head1 NAME

Catalyst::Plugin::OpenIDConnect::Controller::Root - OIDC Protocol Endpoints

=head1 SYNOPSIS

Handles OpenID Connect protocol endpoints:
  - /openidconnect/authorize     - Authorization endpoint
  - /openidconnect/token         - Token endpoint
  - /openidconnect/userinfo      - UserInfo endpoint  
  - /openidconnect/logout        - Logout endpoint
  - /.well-known/openid-configuration - Discovery endpoint

=cut

=head2 discovery

GET /.well-known/openid-configuration

Returns the OpenID Connect provider configuration.

=cut

sub discovery : Path('/.well-known/openid-configuration') {
    my ( $self, $c ) = @_;

    my $config = $c->openidconnect->config;

    $c->log->debug('OpenID Connect discovery endpoint accessed') if $config->{debug};
    $self->_json_response( $c, $c->openidconnect->get_discovery() );
}

=head2 authorize

GET /openidconnect/authorize

OpenID Connect authorization endpoint.

Query parameters:
  - response_type (REQUIRED): "code"
  - client_id (REQUIRED): The client ID
  - redirect_uri (REQUIRED): Where to redirect after authorization
  - scope (RECOMMENDED): Space-separated scopes (default: "openid")
  - state (RECOMMENDED): CSRF protection state parameter
  - nonce (OPTIONAL): String to bind to the ID token

=cut

sub authorize : Local {
    my ( $self, $c ) = @_;

    my $config = $c->openidconnect->config;

    $c->log->debug('Authorization endpoint accessed') if $config->{debug};

    my $response_type = $c->request->params->{response_type};
    my $client_id     = $c->request->params->{client_id};
    my $redirect_uri  = $c->request->params->{redirect_uri};
    my $scope         = $c->request->params->{scope};
    my $state         = $c->request->params->{state};
    my $nonce         = $c->request->params->{nonce};

    $c->log->debug("Authorization request - client_id: $client_id, response_type: $response_type, redirect_uri: $redirect_uri") if $config->{debug};

    my $stored_auth_request = $c->session->{oidc_auth_request} || {};
    $response_type //= $stored_auth_request->{response_type};
    $client_id     //= $stored_auth_request->{client_id};
    $redirect_uri  //= $stored_auth_request->{redirect_uri};
    $scope         ||= $stored_auth_request->{scope} || 'openid';
    $state         //= $stored_auth_request->{state};
    $nonce         //= $stored_auth_request->{nonce};

    # Validate request parameters
    unless ( $response_type && $response_type eq 'code' ) {
        $c->log->warn("Invalid response_type: $response_type");
        return $self->_error_response(
            $c, $redirect_uri, 'invalid_request',
            'response_type must be "code"', $state
        );
    }

    unless ($client_id) {
        $c->log->warn('Missing client_id parameter');
        return $self->_error_response(
            $c, undef, 'invalid_request',
            'client_id is required'
        );
    }

    unless ($redirect_uri) {
        $c->log->warn('Missing redirect_uri parameter');
        return $self->_error_response(
            $c, undef, 'invalid_request',
            'redirect_uri is required'
        );
    }

    # Get client config
    my $client = $c->openidconnect->get_client($client_id);
    unless ($client) {
        $c->log->error("Unknown client: $client_id");
        return $self->_error_response(
            $c, $redirect_uri, 'invalid_client',
            'Unknown client', $state
        );
    }

    # Validate redirect URI
    my @allowed_uris = _normalize_uri_list( $client->{redirect_uris} );
    unless ( grep { $_ eq $redirect_uri } @allowed_uris ) {
        $c->log->error("Redirect URI mismatch for client $client_id: $redirect_uri");
        return $self->_error_response(
            $c, undef, 'invalid_request',
            'Redirect URI not registered'
        );
    }

    # Check if user is authenticated
    unless ( $c->user ) {
        $c->log->debug('User not authenticated, redirecting to login') if $config->{debug};
        $c->session->{oidc_auth_request} = {
            response_type => $response_type,
            client_id     => $client_id,
            redirect_uri  => $redirect_uri,
            scope         => $scope,
            state         => $state,
            nonce         => $nonce,
        };

        return $c->response->redirect( $c->uri_for('/login', { back => '/openidconnect/authorize' }) );
    }

    $c->log->info("Authorization granted for user: " . $c->user->id . " to client: $client_id");

    # Extract user claims now, while the live user object is available.
    # Storing the plain claims hashref (rather than the user object itself)
    # means the store never needs to serialise application-specific objects
    # such as DBIx::Class rows or LDAP entries — it always receives and
    # returns plain data.
    my $user_claims = $c->openidconnect->get_user_claims( $c->user );

    # Create authorization code
    my $code = $c->openidconnect->store->create_authorization_code(
        $client_id, $user_claims, $scope, $redirect_uri, $nonce
    );

    # Store authorization in session for later token request
    $c->session->{oidc_code}->{$code} = {
        client_id    => $client_id,
        user         => $user_claims,
        scope        => $scope,
        redirect_uri => $redirect_uri,
        nonce        => $nonce,
    };

    # Clear the stored authorization request after resuming the flow.
    delete $c->session->{oidc_auth_request};

    # Build redirect URI with code and state
    my $callback_uri = URI->new($redirect_uri);
    $callback_uri->query_form(
        code  => $code,
        state => $state,
    );

    $c->log->debug("Redirecting to: " . $callback_uri->as_string) if $config->{debug};
    $c->response->redirect( $callback_uri->as_string );
}

=head2 token

POST /openidconnect/token

Token endpoint for exchanging authorization code for tokens.

Parameters (form-encoded):
  - grant_type (REQUIRED): "authorization_code" or "refresh_token"
  - code (REQUIRED for authorization_code): The authorization code
  - redirect_uri (REQUIRED): Must match authorization request
  - client_id (OPTIONAL): The client ID (extracted from code if not provided)
  - client_secret (OPTIONAL): The client secret (required for confidential clients, optional for public clients)

Returns:
  - access_token: The access token
  - token_type: "Bearer"
  - id_token: The ID token
  - expires_in: Token expiration in seconds
  - refresh_token: (optional) Refresh token

=cut

sub token : Local {
    my ( $self, $c ) = @_;

    my $config = $c->openidconnect->config;

    $c->response->content_type('application/json');
    $c->log->debug('Token endpoint accessed') if $config->{debug};

    my $grant_type = $c->request->params->{grant_type};

    unless ($grant_type) {
        $c->log->warn('Missing grant_type parameter');
        return $self->_json_error( $c, 'invalid_request', 'grant_type is required' );
    }

    $c->log->debug("Token request with grant_type: $grant_type") if $config->{debug};

    if ( $grant_type eq 'authorization_code' ) {
        return $self->_handle_authorization_code_grant($c);
    } elsif ( $grant_type eq 'refresh_token' ) {
        return $self->_handle_refresh_token_grant($c);
    } else {
        $c->log->warn("Unsupported grant_type: $grant_type");
        return $self->_json_error( $c, 'unsupported_grant_type', "Unsupported grant_type: $grant_type" );
    }
}

=head2 userinfo

GET /openidconnect/userinfo
Authorization: Bearer <access_token>

UserInfo endpoint returning authenticated user's claims.

=cut

sub userinfo : Local {
    my ( $self, $c ) = @_;

    my $config = $c->openidconnect->config;
    $c->log->debug('UserInfo endpoint accessed') if $config->{debug};

    # Get bearer token
    my $auth_header = $c->request->header('Authorization') || '';
    my ($token) = $auth_header =~ /^Bearer\s+(\S+)$/;

    unless ($token) {
        $c->log->warn('Missing or invalid Authorization header');
        return $self->_json_error( $c, 'invalid_token', 'Missing or invalid Authorization header' );
    }

    # Verify token
    my $payload;
    try {
        $payload = $c->openidconnect->jwt->verify_token($token);
        $c->log->debug('Access token verified successfully') if $config->{debug};
    }
    catch {
        $c->log->warn("Token verification failed: $_");
        return $self->_json_error( $c, 'invalid_token', "Token verification failed: $_" );
    };

    # Get user and claims
    my $user_id = $payload->{sub};
    unless ($user_id) {
        $c->log->error('Token missing sub claim');
        return $self->_json_error( $c, 'invalid_token', 'Token missing sub claim' );
    }

    $c->log->debug("UserInfo requested for user: $user_id") if $config->{debug};

    # This would normally fetch the user from database
    # For now, we'll use the claims already in the token
    my %claims = (
        sub => $payload->{sub},
    );

    # Add other standard claims from token
    for my $claim (qw(name email email_verified picture phone_number phone_number_verified)) {
        $claims{$claim} = $payload->{$claim} if exists $payload->{$claim};
    }

    $c->log->debug('UserInfo response prepared') if $config->{debug};
    $self->_json_response( $c, \%claims );
}

=head2 logout

POST /openidconnect/logout

Logout endpoint to invalidate tokens and clear sessions.

Implements OpenID Connect RP-Initiated Logout 1.0.

Parameters:
  - id_token_hint (REQUIRED when post_logout_redirect_uri is supplied): A
    previously issued ID Token identifying the client requesting logout.
    The token's signature is verified to confirm it was issued by this server.
    Expiry is intentionally not checked — hint tokens are often expired.
  - post_logout_redirect_uri (OPTIONAL): URL to redirect to after logout.
    Must be registered in the client's C<post_logout_redirect_uris> list.
    Providing this parameter without a valid C<id_token_hint> is rejected
    with an C<invalid_request> error to prevent open-redirect attacks.
  - state (OPTIONAL): Opaque value returned verbatim in the redirect query
    string (only when post_logout_redirect_uri is also provided).

=cut

sub logout : Local {
    my ( $self, $c ) = @_;

    my $config = $c->openidconnect->config;

    $c->log->debug('Logout endpoint accessed') if $config->{debug};

    # Clear user session
    if ( $c->user ) {
        $c->log->info('Logging out user: ' . $c->user->id);
        $c->user->logout();
    }

    # Destroy session
    if ( $c->sessionid ) {
        $c->log->debug('Destroying session: ' . $c->sessionid) if $config->{debug};
        $c->delete_session('User session destroyed');
    }

    my $redirect_uri   = $c->request->params->{post_logout_redirect_uri};
    my $id_token_hint  = $c->request->params->{id_token_hint};
    my $state          = $c->request->params->{state};

    if ($redirect_uri) {
        # id_token_hint is required when a redirect is requested so that we
        # can identify the client and verify the URI is registered for it.
        # Without this check an attacker could redirect to any arbitrary URL.
        unless ($id_token_hint) {
            $c->log->warn('post_logout_redirect_uri provided without id_token_hint');
            return $self->_json_error( $c, 'invalid_request',
                'id_token_hint is required when post_logout_redirect_uri is provided' );
        }

        # Decode the hint token (signature verified, expiry ignored).
        my $hint_claims = $c->openidconnect->jwt->decode_id_token_hint($id_token_hint);
        unless ($hint_claims) {
            $c->log->warn('Invalid id_token_hint provided at logout');
            return $self->_json_error( $c, 'invalid_request', 'Invalid id_token_hint' );
        }

        # aud may be a string or an array per RFC 7519 §4.1.3.
        my $aud       = $hint_claims->{aud};
        my $client_id = ref $aud eq 'ARRAY' ? $aud->[0] : $aud;

        unless ($client_id) {
            $c->log->warn('id_token_hint is missing the aud claim');
            return $self->_json_error( $c, 'invalid_request',
                'id_token_hint does not contain an aud claim' );
        }

        # Look up the client and validate the redirect URI against its
        # registered post_logout_redirect_uris list.
        my $client = $c->openidconnect->get_client($client_id);
        unless ($client) {
            $c->log->warn("Unknown client in id_token_hint aud claim: $client_id");
            return $self->_json_error( $c, 'invalid_request',
                'Unknown client in id_token_hint' );
        }

        my @allowed = _normalize_uri_list( $client->{post_logout_redirect_uris} );
        unless ( grep { $_ eq $redirect_uri } @allowed ) {
            $c->log->warn(
                "Unregistered post_logout_redirect_uri for client $client_id: $redirect_uri"
            );
            return $self->_json_error( $c, 'invalid_request',
                'post_logout_redirect_uri is not registered for this client' );
        }

        # Build the final redirect URI, appending state if supplied.
        my $final_uri = URI->new($redirect_uri);
        $final_uri->query_form( $final_uri->query_form, state => $state )
            if defined $state && $state ne '';

        $c->log->debug( 'Redirecting to post-logout URI: ' . $final_uri->as_string )
            if $config->{debug};
        return $c->response->redirect( $final_uri->as_string );
    }

    # Return success JSON response
    $c->log->info('Logout completed successfully');
    $self->_json_response( $c, {
        message => 'Logged out successfully',
    });
}

# Normalise a redirect-URI config field.
# Accepts either an arrayref (YAML / JSON / Perl hash config) or a
# whitespace-delimited string (Config::General / Apache-style config).
# Returns a flat list of URI strings.
# Used for both redirect_uris and post_logout_redirect_uris so that both
# fields behave identically regardless of config format.
sub _normalize_uri_list {
    my ($field) = @_;
    return () unless defined $field;
    return ref $field eq 'ARRAY' ? @$field : split /\s+/, $field;
}

=head2 jwks

GET /openidconnect/jwks

JSON Web Key Set endpoint for key discovery.

Returns the public key(s) for verifying signatures.

=cut

sub jwks : Local {
    my ( $self, $c ) = @_;

    my $config = $c->openidconnect->config;

    $c->log->debug('JWKS endpoint accessed') if $config->{debug};

    # Get JWT handler and public key
    my $jwt = $c->openidconnect->jwt;
    my $public_key = $jwt->public_key;

    $c->log->debug('Extracting public key parameters for JWKS') if $config->{debug};

    # Convert OpenSSL public key to Crypt::PK::RSA for easier parameter extraction
    my $public_key_pem = $public_key->get_public_key_string();
    my $pk = Crypt::PK::RSA->new(\$public_key_pem);

    # Get key parameters for JWK generation
    my $keydata = $pk->key2hash();

    # Convert modulus and exponent to base64url
    # Note: key2hash() returns lowercase keys (e, N, etc.)
    my $n = $self->_bigint_to_base64url($keydata->{N});
    my $e = $self->_bigint_to_base64url($keydata->{e});

    # Create JWK with all required fields
    my %jwk = (
        kty => 'RSA',
        use => 'sig',
        kid => $jwt->key_id,
        alg => 'RS256',
        n   => $n,
        e   => $e,
    );

    $c->log->debug('JWKS response prepared with key ID: ' . $jwt->key_id) if $config->{debug};
    $self->_json_response( $c, { keys => [ \%jwk ] } );
}

# Private helper methods

sub _handle_authorization_code_grant {
    my ( $self, $c ) = @_;

    my $config = $c->openidconnect->config;

    $c->log->debug('Processing authorization_code grant') if $config->{debug};

    my $code          = $c->request->params->{code};
    my $redirect_uri  = $c->request->params->{redirect_uri};
    my $client_id     = $c->request->params->{client_id};
    my $client_secret = $c->request->params->{client_secret};

    unless ( $code && $redirect_uri ) {
        $c->log->warn('Missing code or redirect_uri in token request');
        return $self->_json_error( $c, 'invalid_request', 'code and redirect_uri are required' );
    }

    $c->log->debug("Token request - code: $code, client_id: $client_id") if $config->{debug};

    # Get authorization code to validate and extract client_id if not provided
    my $code_data = $c->openidconnect->store->get_authorization_code($code);
    unless ($code_data) {
        $c->log->warn("Authorization code not found or expired: $code");
        return $self->_json_error( $c, 'invalid_grant', 'Authorization code not found or expired' );
    }

    # Use client_id from authorization code if not provided in request (public client flow)
    $client_id ||= $code_data->{client_id};

    # Verify redirect URI matches
    unless ( $code_data->{redirect_uri} eq $redirect_uri ) {
        $c->log->error("Redirect URI mismatch for code: $code (expected: " . $code_data->{redirect_uri} . ", got: $redirect_uri)");
        return $self->_json_error( $c, 'invalid_grant', 'Redirect URI mismatch' );
    }

    # If client_secret is provided, verify client credentials (confidential client)
    if ($client_secret) {
        $c->log->debug("Verifying client credentials for: $client_id") if $config->{debug};
        my $client = $c->openidconnect->get_client($client_id);
        unless ( $client && slow_eq( $client->{client_secret}, $client_secret ) ) {
            $c->log->warn("Client authentication failed for: $client_id");
            return $self->_json_error( $c, 'invalid_client', 'Client authentication failed' );
        }
    } else {
        # For public clients (no secret provided), at least verify client exists
        my $client = $c->openidconnect->get_client($client_id);
        unless ($client) {
            $c->log->warn("Unknown client: $client_id");
            return $self->_json_error( $c, 'invalid_client', 'Unknown client' );
        }
    }

    # Consume the code (one-time use)
    $c->openidconnect->store->consume_authorization_code($code);
    $c->log->debug("Authorization code consumed: $code") if $config->{debug};

    # User claims were extracted and stored at authorization time, so
    # $code_data->{user} is already the mapped claims hashref.
    my $user_claims = $code_data->{user};

    # Create tokens
    my $now = time();
    my %id_token_payload = (
        %$user_claims,
        aud => $client_id,
        exp => $now + 3600,  # 1 hour
    );

    $id_token_payload{nonce} = $code_data->{nonce} if $code_data->{nonce};

    my $id_token = $c->openidconnect->jwt->create_id_token(%id_token_payload);
    $c->log->debug('ID token created') if $config->{debug};

    my %access_token_payload = (
        sub => $user_claims->{sub},
        aud => $client_id,
        scp => $code_data->{scope},
        exp => $now + 3600,
    );

    my $access_token = $c->openidconnect->jwt->create_access_token(%access_token_payload);
    $c->log->debug('Access token created') if $config->{debug};

    my %refresh_token_payload = (
        sub => $user_claims->{sub},
        aud => $client_id,
        exp => $now + ( 30 * 24 * 3600 ),  # 30 days
    );

    my $refresh_token = $c->openidconnect->jwt->create_refresh_token(%refresh_token_payload);
    $c->log->debug('Refresh token created') if $config->{debug};

    $c->log->info("Tokens issued for client: $client_id, user: " . $user_claims->{sub});

    # Return tokens
    $self->_json_response( $c, {
        access_token  => $access_token,
        token_type    => 'Bearer',
        id_token      => $id_token,
        expires_in    => 3600,
        refresh_token => $refresh_token,
    });
}

sub _handle_refresh_token_grant {
    my ( $self, $c ) = @_;

    my $config = $c->openidconnect->config;

    $c->log->debug('Processing refresh_token grant') if $config->{debug};

    my $refresh_token = $c->request->params->{refresh_token};
    my $client_id     = $c->request->params->{client_id};
    my $client_secret = $c->request->params->{client_secret};

    unless ( $refresh_token && $client_id && $client_secret ) {
        $c->log->warn('Missing required parameters for refresh token grant');
        return $self->_json_error( $c, 'invalid_request', 'Missing required parameters' );
    }

    $c->log->debug("Refresh token request for client: $client_id") if $config->{debug};

    # Verify client
    my $client = $c->openidconnect->get_client($client_id);
    unless ( $client && slow_eq( $client->{client_secret}, $client_secret ) ) {
        $c->log->warn("Client authentication failed for: $client_id");
        return $self->_json_error( $c, 'invalid_client', 'Client authentication failed' );
    }

    # Verify refresh token
    my $payload;
    try {
        $payload = $c->openidconnect->jwt->verify_token($refresh_token);
        $c->log->debug('Refresh token verified') if $config->{debug};
    }
    catch {
        $c->log->warn("Invalid refresh token: $_");
        return $self->_json_error( $c, 'invalid_grant', 'Invalid refresh token' );
    };

    # Create new access token
    my $now = time();
    my %new_payload = (
        sub => $payload->{sub},
        aud => $client_id,
        exp => $now + 3600,
    );

    my $access_token = $c->openidconnect->jwt->create_access_token(%new_payload);
    $c->log->debug('New access token created from refresh token') if $config->{debug};

    $c->log->info("Access token refreshed for client: $client_id, user: " . $payload->{sub});

    $self->_json_response( $c, {
        access_token => $access_token,
        token_type   => 'Bearer',
        expires_in   => 3600,
    });
}

sub _error_response {
    my ( $self, $c, $redirect_uri, $error, $error_description, $state ) = @_;

    my $config = $c->openidconnect->config;

    $c->log->warn("OAuth error: $error - $error_description");

    if ($redirect_uri) {
        my $callback_uri = URI->new($redirect_uri);
        $callback_uri->query_form(
            error             => $error,
            error_description => $error_description,
            state             => $state,
        );
        $c->log->debug("Redirecting error response to: " . $callback_uri->as_string) if $config->{debug};
        return $c->response->redirect( $callback_uri->as_string );
    } else {
        return $self->_json_response( $c, {
            error             => $error,
            error_description => $error_description,
        });
    }
}

sub _json_error {
    my ( $self, $c, $error, $error_description ) = @_;

    $c->log->warn("JSON error response: $error - $error_description");
    $c->response->status(400);
    return $self->_json_response( $c, {
        error             => $error,
        error_description => $error_description,
    });
}

sub _json_response {
    my ( $self, $c, $data ) = @_;

    $c->response->content_type('application/json');
    $c->response->body( encode_json($data) );
}

sub _hex_to_base64url {
    my ( $self, $hex_string ) = @_;

    # Remove any spaces or newlines
    $hex_string =~ s/\s+//g;

    # Convert hex to binary
    my $binary = pack('H*', $hex_string);

    # Encode to base64
    my $base64 = encode_base64($binary, '');

    # Convert to base64url (- instead of +, _ instead of /)
    $base64 =~ tr/+\//\-_/;

    # Remove padding
    $base64 =~ s/=+$//;

    return $base64;
}

sub _bigint_to_base64url {
    my ( $self, $hex_str ) = @_;

    return '' unless $hex_str;  # Handle empty/undef

    # Crypt::PK::RSA returns big integers as hex strings (lowercase)
    # Convert directly using the hex-to-base64url method
    return $self->_hex_to_base64url($hex_str);
}

__PACKAGE__->meta->make_immutable;
1;

=head1 AUTHOR

Tim F. Rayner

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the terms of The Artistic License 2.0.

=cut
