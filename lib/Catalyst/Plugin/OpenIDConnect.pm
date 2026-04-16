package Catalyst::Plugin::OpenIDConnect;

use strict;
use warnings;
use Moose::Role;
use namespace::autoclean;

use Catalyst::Plugin::OpenIDConnect::Context;
use Catalyst::Plugin::OpenIDConnect::Utils::JWT;
use Catalyst::Plugin::OpenIDConnect::Utils::Store;
use Crypt::OpenSSL::RSA;
use JSON::MaybeXS qw(encode_json decode_json);
use Try::Tiny;
use DateTime;
use DateTime::Format::ISO8601;
use Data::UUID;
use URI;

our $VERSION = '0.01';

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

=head1 CREATING THE OPENIDCONNECT CONTROLLER

To enable the OpenIDConnect endpoints, create a controller in your app that extends
the plugin's controller. Create the file C<lib/MyApp/Controller/OpenIDConnect.pm>:

    package MyApp::Controller::OpenIDConnect;

    use Moose;
    use namespace::autoclean;

    BEGIN { extends 'Catalyst::Plugin::OpenIDConnect::Controller::Root' }

    __PACKAGE__->meta->make_immutable;
    1;

Then, in your main app module, explicitly load this controller before setup:

    package MyApp;
    use Catalyst qw/
        OpenIDConnect
        Session
        Session::Store::File
        Session::State::Cookie
    /;
    
    # Load the controller before setup so Catalyst discovers it
    use MyApp::Controller::OpenIDConnect;
    
    MyApp->config(...);
    MyApp->setup(...);

=head1 DESCRIPTION

A Catalyst plugin implementing the OpenID Connect specification,
providing OAuth 2.0 authentication and authorization.

NOTE: This plugin provides the core OpenIDConnect functionality (JWT handling, 
state management, and a reusable controller). To use it in your application, 
you must create a controller in your app's namespace that extends the plugin's 
controller. This allows you to keep full control over your routing and avoid 
namespace conflicts with ACL and other route-processing plugins.

=cut

requires 'config', 'log', 'uri_for', 'user', 'request', 'response';

# Package-level storage for JWT and Store instances
our $_oidc_jwt_instance;
our $_oidc_store_instance;

=head1 ATTRIBUTES

=head2 _oidc_jwt

JWT handler instance.

=cut

# Accessor method for JWT handler
sub _oidc_jwt {
    my ($self, $value) = @_;
    if (defined $value) {
        die 'JWT handler must be an instance of Catalyst::Plugin::OpenIDConnect::Utils::JWT'
            unless ref $value && $value->isa('Catalyst::Plugin::OpenIDConnect::Utils::JWT');
        $_oidc_jwt_instance = $value;
    }
    return $_oidc_jwt_instance;
}

=head2 _oidc_store

State and code storage.

=cut

# Accessor method for Store handler
sub _oidc_store {
    my ($self, $value) = @_;
    if (defined $value) {
        die 'Store handler must be an instance of Catalyst::Plugin::OpenIDConnect::Utils::Store'
            unless ref $value && $value->isa('Catalyst::Plugin::OpenIDConnect::Utils::Store');
        $_oidc_store_instance = $value;
    }
    return $_oidc_store_instance;
}

=head1 METHODS

=head2 setup

Catalyst setup hook - initialize the plugin.

=cut

after 'setup' => sub {
    my ($app) = @_;
    
    my $config = $app->config->{'Plugin::OpenIDConnect'} || {};
    
    # Only initialize if properly configured
    if ( $config->{issuer} && $config->{issuer}{private_key_file} ) {
        try {
            # Create JWT handler
            my $jwt = $app->_oidc_build_jwt_handler($config);
            $app->_oidc_jwt($jwt);
            
            # Create store
            my $store = Catalyst::Plugin::OpenIDConnect::Utils::Store->new();
            $app->_oidc_store($store);
            
            $app->log->info('OpenID Connect plugin initialized');
        }
        catch {
            $app->log->error("Failed to initialize OpenID Connect plugin: $_");
        };
    }
};

=head2 openidconnect()

Returns the OIDC context/handler object for use in controllers.

=cut

sub openidconnect {
    my ($c) = @_;
    return Catalyst::Plugin::OpenIDConnect::Context->new( catalyst => $c );
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

1;

=head1 AUTHOR

Tim F. Rayner

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the terms of The Artistic License 2.0.

=cut
