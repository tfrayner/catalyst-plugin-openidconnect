package Catalyst::Plugin::OpenIDConnect::Controller::Root;

use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

use JSON::MaybeXS qw(encode_json decode_json);
use URI;
use DateTime;
use Try::Tiny;

__PACKAGE__->config->{namespace} = 'openidconnect';

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

sub discovery : Path('/.well-known/openid-configuration') : ActionClass('RenderView') {
    my ( $self, $c ) = @_;

    $c->response->content_type('application/json');
    $c->stash->{discovery} = $c->openidconnect->get_discovery();
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

    my $response_type = $c->request->params->{response_type};
    my $client_id     = $c->request->params->{client_id};
    my $redirect_uri  = $c->request->params->{redirect_uri};
    my $scope         = $c->request->params->{scope} || 'openid';
    my $state         = $c->request->params->{state};
    my $nonce         = $c->request->params->{nonce};

    # Validate request parameters
    unless ( $response_type && $response_type eq 'code' ) {
        return $self->_error_response(
            $c, $redirect_uri, 'invalid_request',
            'response_type must be "code"', $state
        );
    }

    unless ($client_id) {
        return $self->_error_response(
            $c, undef, 'invalid_request',
            'client_id is required'
        );
    }

    unless ($redirect_uri) {
        return $self->_error_response(
            $c, undef, 'invalid_request',
            'redirect_uri is required'
        );
    }

    # Get client config
    my $client = $c->openidconnect->get_client($client_id);
    unless ($client) {
        return $self->_error_response(
            $c, $redirect_uri, 'invalid_client',
            'Unknown client', $state
        );
    }

    # Validate redirect URI
    my @allowed_uris = split /\s+/, $client->{redirect_uris};
    unless ( grep { $_ eq $redirect_uri } @allowed_uris ) {
        return $self->_error_response(
            $c, undef, 'invalid_request',
            'Redirect URI not registered'
        );
    }

    # Check if user is authenticated
    unless ( $c->user ) {
        $c->session->{oidc_auth_request} = {
            response_type => $response_type,
            client_id     => $client_id,
            redirect_uri  => $redirect_uri,
            scope         => $scope,
            state         => $state,
            nonce         => $nonce,
        };

        return $c->response->redirect( $c->uri_for('/login?back=/openidconnect/authorize') );
    }

    # Create authorization code
    my $code = $c->openidconnect->store->create_authorization_code(
        $client_id, $c->user, $scope, $redirect_uri, $nonce
    );

    # Store authorization in session for later token request
    $c->session->{oidc_code}->{$code} = {
        client_id    => $client_id,
        user         => $c->user,
        scope        => $scope,
        redirect_uri => $redirect_uri,
        nonce        => $nonce,
    };

    # Build redirect URI with code and state
    my $callback_uri = URI->new($redirect_uri);
    $callback_uri->query_form(
        code  => $code,
        state => $state,
    );

    $c->response->redirect( $callback_uri->as_string );
}

=head2 token

POST /openidconnect/token

Token endpoint for exchanging authorization code for tokens.

Parameters (form-encoded):
  - grant_type (REQUIRED): "authorization_code" or "refresh_token"
  - code (REQUIRED for authorization_code): The authorization code
  - redirect_uri (REQUIRED): Must match authorization request
  - client_id (REQUIRED): The client ID
  - client_secret (REQUIRED): The client secret

Returns:
  - access_token: The access token
  - token_type: "Bearer"
  - id_token: The ID token
  - expires_in: Token expiration in seconds
  - refresh_token: (optional) Refresh token

=cut

sub token : Local {
    my ( $self, $c ) = @_;

    $c->response->content_type('application/json');

    my $grant_type = $c->request->params->{grant_type};

    unless ($grant_type) {
        return $self->_json_error( $c, 'invalid_request', 'grant_type is required' );
    }

    if ( $grant_type eq 'authorization_code' ) {
        return $self->_handle_authorization_code_grant($c);
    } elsif ( $grant_type eq 'refresh_token' ) {
        return $self->_handle_refresh_token_grant($c);
    } else {
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

    $c->response->content_type('application/json');

    # Get bearer token
    my $auth_header = $c->request->header('Authorization') || '';
    my ($token) = $auth_header =~ /^Bearer\s+(\S+)$/;

    unless ($token) {
        return $self->_json_error( $c, 'invalid_token', 'Missing or invalid Authorization header' );
    }

    # Verify token
    my $payload;
    try {
        $payload = $c->openidconnect->jwt->verify_token($token);
    }
    catch {
        return $self->_json_error( $c, 'invalid_token', "Token verification failed: $_" );
    };

    # Get user and claims
    my $user_id = $payload->{sub};
    unless ($user_id) {
        return $self->_json_error( $c, 'invalid_token', 'Token missing sub claim' );
    }

    # This would normally fetch the user from database
    # For now, we'll use the claims already in the token
    my %claims = (
        sub => $payload->{sub},
    );

    # Add other standard claims from token
    for my $claim (qw(name email email_verified picture phone_number phone_number_verified)) {
        $claims{$claim} = $payload->{$claim} if exists $payload->{$claim};
    }

    $c->stash->{json} = \%claims;
    $c->forward('View::JSON');
}

=head2 logout

POST /openidconnect/logout

Logout endpoint to invalidate tokens and clear sessions.

Parameters:
  - id_token_hint: The ID token being logged out
  - post_logout_redirect_uri: Where to redirect after logout
  - state: State parameter for redirect

=cut

sub logout : Local {
    my ( $self, $c ) = @_;

    # Clear user session
    if ( $c->user ) {
        $c->user->logout();
    }

    # Destroy session
    if ( $c->sessionid ) {
        $c->delete_session('User session destroyed');
    }

    my $redirect_uri = $c->request->params->{post_logout_redirect_uri};
    if ($redirect_uri) {
        # Validate redirect URI (in production, check against registered URIs)
        $c->response->redirect($redirect_uri);
    } else {
        $c->response->body('Logged out successfully');
    }
}

=head2 jwks

GET /openidconnect/jwks

JSON Web Key Set endpoint for key discovery.

Returns the public key(s) for verifying signatures.

=cut

sub jwks : Local {
    my ( $self, $c ) = @_;

    $c->response->content_type('application/json');

    # Get JWT handler
    my $jwt = $c->openidconnect->jwt;

    # Create JWK from public key
    my $public_key_pem = $jwt->public_key->get_public_key_string();

    # Extract modulus and exponent from RSA public key
    # For now, return simplified structure - in production, use cryptographic libraries
    my %jwk = (
        kty => 'RSA',
        use => 'sig',
        kid => $jwt->key_id,
        alg => 'RS256',
        # In a production system, extract actual modulus and exponent
    );

    $c->stash->{json} = {
        keys => [ \%jwk ],
    };

    $c->forward('View::JSON');
}

# Private helper methods

sub _handle_authorization_code_grant {
    my ( $self, $c ) = @_;

    my $code          = $c->request->params->{code};
    my $redirect_uri  = $c->request->params->{redirect_uri};
    my $client_id     = $c->request->params->{client_id};
    my $client_secret = $c->request->params->{client_secret};

    unless ( $code && $redirect_uri && $client_id && $client_secret ) {
        return $self->_json_error( $c, 'invalid_request', 'Missing required parameters' );
    }

    # Verify client credentials
    my $client = $c->openidconnect->get_client($client_id);
    unless ( $client && $client->{client_secret} eq $client_secret ) {
        return $self->_json_error( $c, 'invalid_client', 'Client authentication failed' );
    }

    # Get authorization code
    my $code_data = $c->openidconnect->store->get_authorization_code($code);
    unless ($code_data) {
        return $self->_json_error( $c, 'invalid_grant', 'Authorization code not found or expired' );
    }

    # Verify redirect URI matches
    unless ( $code_data->{redirect_uri} eq $redirect_uri ) {
        return $self->_json_error( $c, 'invalid_grant', 'Redirect URI mismatch' );
    }

    # Consume the code (one-time use)
    $c->openidconnect->store->consume_authorization_code($code);

    # Get user claims
    my $user_claims = $c->openidconnect->get_user_claims( $code_data->{user} );

    # Create tokens
    my $now = time();
    my %id_token_payload = (
        %$user_claims,
        aud => $client_id,
        exp => $now + 3600,  # 1 hour
    );

    $id_token_payload{nonce} = $code_data->{nonce} if $code_data->{nonce};

    my $id_token = $c->openidconnect->jwt->create_id_token(%id_token_payload);

    my %access_token_payload = (
        sub => $user_claims->{sub},
        aud => $client_id,
        scp => $code_data->{scope},
        exp => $now + 3600,
    );

    my $access_token = $c->openidconnect->jwt->create_access_token(%access_token_payload);

    my %refresh_token_payload = (
        sub => $user_claims->{sub},
        aud => $client_id,
        exp => $now + ( 30 * 24 * 3600 ),  # 30 days
    );

    my $refresh_token = $c->openidconnect->jwt->create_refresh_token(%refresh_token_payload);

    # Return tokens
    $c->stash->{json} = {
        access_token  => $access_token,
        token_type    => 'Bearer',
        id_token      => $id_token,
        expires_in    => 3600,
        refresh_token => $refresh_token,
    };

    $c->forward('View::JSON');
}

sub _handle_refresh_token_grant {
    my ( $self, $c ) = @_;

    my $refresh_token = $c->request->params->{refresh_token};
    my $client_id     = $c->request->params->{client_id};
    my $client_secret = $c->request->params->{client_secret};

    unless ( $refresh_token && $client_id && $client_secret ) {
        return $self->_json_error( $c, 'invalid_request', 'Missing required parameters' );
    }

    # Verify client
    my $client = $c->openidconnect->get_client($client_id);
    unless ( $client && $client->{client_secret} eq $client_secret ) {
        return $self->_json_error( $c, 'invalid_client', 'Client authentication failed' );
    }

    # Verify refresh token
    my $payload;
    try {
        $payload = $c->openidconnect->jwt->verify_token($refresh_token);
    }
    catch {
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

    $c->stash->{json} = {
        access_token => $access_token,
        token_type   => 'Bearer',
        expires_in   => 3600,
    };

    $c->forward('View::JSON');
}

sub _error_response {
    my ( $self, $c, $redirect_uri, $error, $error_description, $state ) = @_;

    if ($redirect_uri) {
        my $callback_uri = URI->new($redirect_uri);
        $callback_uri->query_form(
            error             => $error,
            error_description => $error_description,
            state             => $state,
        );
        return $c->response->redirect( $callback_uri->as_string );
    } else {
        $c->response->content_type('application/json');
        $c->stash->{json} = {
            error             => $error,
            error_description => $error_description,
        };
        return $c->forward('View::JSON');
    }
}

sub _json_error {
    my ( $self, $c, $error, $error_description ) = @_;

    $c->response->status(400);
    $c->stash->{json} = {
        error             => $error,
        error_description => $error_description,
    };

    return $c->forward('View::JSON');
}

__PACKAGE__->meta->make_immutable;
1;

=head1 AUTHOR

Tim F. Rayner

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the terms of The Artistic License 2.0.

=cut
