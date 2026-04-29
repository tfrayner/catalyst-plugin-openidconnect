package Catalyst::Plugin::OpenIDConnect::Utils::Store;

use strict;
use warnings;
use Moose;
use namespace::autoclean;

use Try::Tiny;
use Bytes::Random::Secure qw(random_bytes);
use MIME::Base64 qw(encode_base64url);

with 'Catalyst::Plugin::OpenIDConnect::Role::Store';

=head1 NAME

Catalyst::Plugin::OpenIDConnect::Utils::Store - In-process memory store for OIDC state

=head1 DESCRIPTION

Provides in-process memory storage for authorization codes and OIDC session
state. Suitable for development and single-process deployments.

B<Not suitable for multi-process servers such as FastCGI or pre-forking>
because each worker process has its own independent copy of the data.
For those deployments, use L<Catalyst::Plugin::OpenIDConnect::Utils::Store::Redis>
or another shared-backend store that consumes
L<Catalyst::Plugin::OpenIDConnect::Role::Store>.

=head1 ATTRIBUTES

=head2 codes

Storage for authorization codes (code => {client_id, user, scope, ...})

=cut

has codes => (
    is      => 'ro',
    isa     => 'HashRef',
    default => sub { {} },
);

=head2 sessions

Storage for user sessions (session_id => {user, tokens, ...})

=cut

has sessions => (
    is      => 'ro',
    isa     => 'HashRef',
    default => sub { {} },
);

=head2 logger

Optional logger instance for debug/info logging.

=cut

has logger => (
    is       => 'ro',
    isa      => 'Maybe[Object]',
    required => 0,
);

=head1 METHODS

=head2 create_authorization_code($client_id, $user, $scope, $redirect_uri, $nonce)

Creates an authorization code for the given parameters.

Returns the authorization code string.

=cut

sub create_authorization_code {
    my ( $self, $client_id, $user, $scope, $redirect_uri, $nonce ) = @_;

    $self->logger->debug("Creating authorization code for client: $client_id") if $self->logger;

    my $code = _generate_secure_random();

    $self->codes->{$code} = {
        client_id    => $client_id,
        user         => $user,
        scope        => $scope,
        redirect_uri => $redirect_uri,
        nonce        => $nonce,
        created_at   => time(),
        expires_at   => time() + 600,  # 10 minutes
    };

    $self->logger->debug("Authorization code created: $code (expires in 600 seconds)") if $self->logger;

    return $code;
}

=head2 get_authorization_code($code)

Retrieves an authorization code by value.

Returns the code data hashref or undef if not found.

=cut

sub get_authorization_code {
    my ( $self, $code ) = @_;

    $self->logger->debug("Retrieving authorization code: $code") if $self->logger;

    my $code_data = $self->codes->{$code};

    return unless $code_data;

    # Check if code is expired
    if ( $code_data->{expires_at} < time() ) {
        $self->logger->warn("Authorization code expired: $code") if $self->logger;
        delete $self->codes->{$code};
        return;
    }

    $self->logger->debug("Authorization code found: $code") if $self->logger;
    return $code_data;
}

=head2 consume_authorization_code($code)

Atomically deletes the authorization code and returns its data.  Uses Perl's
C<delete> which fetches and removes the hash entry in a single operation,
making it race-free within a single process.

Returns the code data hashref on success, or C<undef> if the code does not
exist or has expired.

=cut

sub consume_authorization_code {
    my ( $self, $code ) = @_;

    $self->logger->debug("Consuming authorization code: $code") if $self->logger;

    # delete() is atomic within a single process: it removes and returns the
    # value in one step, preventing two concurrent requests from both
    # succeeding a check-then-delete sequence.
    my $code_data = delete $self->codes->{$code};
    return unless $code_data;

    if ( $code_data->{expires_at} < time() ) {
        $self->logger->warn("Authorization code expired at consume time: $code")
            if $self->logger;
        return;
    }

    $self->logger->debug("Authorization code consumed: $code") if $self->logger;
    return $code_data;
}

# Generate a cryptographically secure random string for codes and tokens.
# Uses Bytes::Random::Secure to draw from the OS CSPRNG (e.g. /dev/urandom),
# which is safe even after fork() — important for pre-forking servers.
sub _generate_secure_random {
    # 120 random bytes -> 160 base64url characters; after stripping the
    # non-alphanumeric "-" and "_" characters (roughly 3% of chars) we have
    # well over 128 alphanumeric characters to work with.
    my $bytes   = random_bytes(120);
    my $encoded = encode_base64url($bytes);
    $encoded    =~ s/[^a-zA-Z0-9]//g;
    return substr( $encoded, 0, 128 );
}

__PACKAGE__->meta->make_immutable;
1;

=head1 AUTHOR

Tim F. Rayner

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the terms of The Artistic License 2.0.

=cut
