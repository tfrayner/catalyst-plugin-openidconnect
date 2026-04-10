package Catalyst::Plugin::OpenIDConnect;

use strict;
use warnings;
use Moose::Role;
use namespace::autoclean;

use Catalyst::Plugin::OpenIDConnect::Utils::JWT;
use Catalyst::Plugin::OpenIDConnect::Utils::Store;
use Crypt::OpenSSL::RSA;
use JSON::MaybeXS qw(encode_json decode_json);
use Try::Tiny;
use DateTime;
use DateTime::Format::ISO8601;
use Data::UUID;
use URI;

=head1 NAME

Catalyst::Plugin::OpenIDConnect - OpenID Connect provider plugin for Catalyst

=head1 SYNOPSIS

    package MyApp;
    use Catalyst qw/
        OpenIDConnect
        Session
        Session::Store::File
        Session::State::Cookie
    /;

    MyApp->config(
        'Plugin::OpenIDConnect' => {
            issuer => {
                url => 'http://localhost:5000',
                private_key_file => '/path/to/private.pem',
                public_key_file => '/path/to/public.pem',
                key_id => 'key-123',
            },
            clients => {
                'my-client' => {
                    client_secret => 'secret123',
                    redirect_uris => ['http://localhost:3000/callback'],
                    response_types => ['code'],
                    grant_types => ['authorization_code'],
                    scope => 'openid profile email',
                },
            },
        },
    );

=head1 DESCRIPTION

A Catalyst plugin implementing the OpenID Connect specification,
providing OAuth 2.0 authentication and authorization.

=cut

requires 'config', 'log', 'uri_for', 'user', 'request', 'response';

=head1 ATTRIBUTES

=head2 _oidc_jwt

JWT handler instance.

=cut

has _oidc_jwt => (
    is       => 'rw',
    isa      => 'Catalyst::Plugin::OpenIDConnect::Utils::JWT',
    lazy     => 1,
    builder  => '_build_jwt',
);

=head2 _oidc_store

State and code storage.

=cut

has _oidc_store => (
    is       => 'rw',
    isa      => 'Catalyst::Plugin::OpenIDConnect::Utils::Store',
    lazy     => 1,
    builder  => '_build_store',
);

=head1 METHODS

=head2 setup_component

Catalyst component setup hook.

=cut

sub setup_component {
    my ($self) = @_;
    return unless ref $self eq 'Catalyst' or $self->isa('Catalyst');
    
    my $c = $self;
    
    # Load and validate configuration
    my $config = $c->config->{'Plugin::OpenIDConnect'} || {};
    
    # Create JWT handler
    my $jwt = $c->_oidc_build_jwt_handler($config);
    $c->_oidc_jwt($jwt);
    
    # Create store
    my $store = Catalyst::Plugin::OpenIDConnect::Utils::Store->new();
    $c->_oidc_store($store);
    
    $c->log->info('OpenID Connect plugin initialized');
}

=head2 finalize_setup

Fully initialize the plugin after all components are loaded.

=cut

sub finalize_setup {
    my ($self) = @_;
    return unless ref $self eq 'Catalyst' or $self->isa('Catalyst');
    
    my $c = $self;
    $c->next::method() if $c->can('next::method');
    
    # Register built-in routes if needed
    # Controllers are auto-discovered by Catalyst
}

=head2 openidconnect()

Returns the OIDC context/handler object for use in controllers.

=cut

sub openidconnect {
    my ($c) = @_;
    return _OpenIDConnectContext->new( catalyst => $c );
}

=head2 _oidc_build_jwt_handler($config)

Builds and configures the JWT handler from config.

=cut

sub _oidc_build_jwt_handler {
    my ( $c, $config ) = @_;

    my $issuer_cfg = $config->{issuer} || {};
    my $issuer_url = $issuer_cfg->{url} || $c->uri_for('/')->as_string;

    # Load private key
    my $private_key_file = $issuer_cfg->{private_key_file}
        or die 'issuer.private_key_file is required';

    open my $key_fh, '<', $private_key_file
        or die "Cannot read private key file: $!";
    my $key_data = do { local $/; <$key_fh> };
    close $key_fh;

    my $private_key = Crypt::OpenSSL::RSA->new_private_key($key_data);
    $private_key->use_pkcs1_padding();

    # Load or derive public key
    my $public_key;
    if ( my $public_key_file = $issuer_cfg->{public_key_file} ) {
        open $key_fh, '<', $public_key_file
            or die "Cannot read public key file: $!";
        my $pub_data = do { local $/; <$key_fh> };
        close $key_fh;
        $public_key = Crypt::OpenSSL::RSA->new_public_key($pub_data);
    } else {
        # Extract public key from private key
        $public_key = Crypt::OpenSSL::RSA->new_public_key(
            $private_key->get_public_key_string()
        );
    }
    $public_key->use_pkcs1_padding();

    my $key_id = $issuer_cfg->{key_id} || 'default';

    return Catalyst::Plugin::OpenIDConnect::Utils::JWT->new(
        private_key => $private_key,
        public_key  => $public_key,
        key_id      => $key_id,
        issuer      => $issuer_url,
    );
}

=head2 _build_jwt

Lazy builder for JWT handler.

=cut

sub _build_jwt {
    my ($c) = @_;
    my $config = $c->config->{'Plugin::OpenIDConnect'} || {};
    return $c->_oidc_build_jwt_handler($config);
}

=head2 _build_store

Lazy builder for store.

=cut

sub _build_store {
    my ($c) = @_;
    return Catalyst::Plugin::OpenIDConnect::Utils::Store->new();
}

# Context object for passing to controllers
package _OpenIDConnectContext;

use Moose;
use namespace::autoclean;

has catalyst => (
    is  => 'ro',
    isa => 'Catalyst',
);

sub jwt {
    my ($self) = @_;
    return $self->catalyst->_oidc_jwt();
}

sub store {
    my ($self) = @_;
    return $self->catalyst->_oidc_store();
}

sub config {
    my ($self) = @_;
    return $self->catalyst->config->{'Plugin::OpenIDConnect'} || {};
}

sub get_client {
    my ( $self, $client_id ) = @_;
    my $clients = $self->config->{clients} || {};
    return $clients->{$client_id};
}

sub get_user_claims {
    my ( $self, $user ) = @_;

    my $claims_config = $self->config->{user_claims} || {
        sub      => 'id',
        name     => 'name',
        email    => 'email',
    };

    my %claims;

    for my $claim_name ( keys %$claims_config ) {
        my $accessor = $claims_config->{$claim_name};
        my @parts = split /\./, $accessor;

        my $value = $user;
        for my $part (@parts) {
            last unless defined $value;
            if ( ref $value eq 'HASH' ) {
                $value = $value->{$part};
            } else {
                $value = $value->$part() if $value->can($part);
            }
        }

        $claims{$claim_name} = $value if defined $value;
    }

    return \%claims;
}

sub get_discovery {
    my ($self) = @_;

    my $c = $self->catalyst;
    my $issuer_url = $self->config->{issuer}{url} || $c->uri_for('/')->as_string;

    return {
        issuer                          => $issuer_url,
        authorization_endpoint          => $c->uri_for('/openidconnect/authorize')->as_string,
        token_endpoint                  => $c->uri_for('/openidconnect/token')->as_string,
        userinfo_endpoint               => $c->uri_for('/openidconnect/userinfo')->as_string,
        jwks_uri                        => $c->uri_for('/openidconnect/jwks')->as_string,
        registration_endpoint           => undef,
        scopes_supported                => [qw(openid profile email phone address)],
        response_types_supported        => [qw(code id_token token id_token token code id_token token)],
        response_modes_supported        => [qw(query fragment form_post)],
        grant_types_supported           => [qw(authorization_code refresh_token implicit)],
        subject_types_supported         => [qw(public pairwise)],
        id_token_signing_alg_values_supported => ['RS256'],
        userinfo_signing_alg_values_supported => ['RS256'],
        request_parameter_supported    => 1,
        request_uri_parameter_supported => 1,
        claims_supported                => [
            qw(
                sub name given_name family_name middle_name nickname
                preferred_username profile picture website email email_verified
                gender birthdate zoneinfo locale phone_number phone_number_verified
                address updated_at
            )
        ],
        claim_types_supported          => [qw(normal aggregated distributed)],
    };
}

__PACKAGE__->meta->make_immutable;
1;

=head1 AUTHOR

Trevor Frayner <tfrayner@example.com>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
