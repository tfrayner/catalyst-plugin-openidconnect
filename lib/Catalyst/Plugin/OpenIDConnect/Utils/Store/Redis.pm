package Catalyst::Plugin::OpenIDConnect::Utils::Store::Redis;

use strict;
use warnings;
use Moose;
use namespace::autoclean;

use JSON::MaybeXS qw(decode_json);
use Bytes::Random::Secure qw(random_bytes);
use MIME::Base64 qw(encode_base64url);
use Try::Tiny;

# Encoder that serializes blessed objects as plain hashrefs, which is necessary
# because the 'user' field may be a Catalyst user object.  Upon retrieval from
# Redis the user data is returned as a plain hashref; the plugin's
# get_user_claims() already handles both hashrefs and method-bearing objects.
my $_json = JSON::MaybeXS->new( convert_blessed => 1, allow_blessed => 1 );

with 'Catalyst::Plugin::OpenIDConnect::Role::Store';

=head1 NAME

Catalyst::Plugin::OpenIDConnect::Utils::Store::Redis - Redis-backed OIDC store

=head1 SYNOPSIS

    # In your Catalyst application configuration:
    'Plugin::OpenIDConnect' => {
        store_class => 'Catalyst::Plugin::OpenIDConnect::Utils::Store::Redis',
        store_args  => {
            server => '127.0.0.1:6379',  # default
            prefix => 'myapp:oidc:',     # optional namespace prefix
            # password => 'secret',      # if Redis AUTH is required
        },
        issuer => { ... },
        clients => { ... },
    },

=head1 DESCRIPTION

A Redis-backed implementation of L<Catalyst::Plugin::OpenIDConnect::Role::Store>
that stores authorization codes in Redis with automatic TTL expiry.

Because all FastCGI/pre-fork worker processes share the same Redis server, this
backend is safe for multi-process deployments. Code expiry is enforced natively
by Redis via C<SETEX>, so no background cleanup is needed.

Requires the L<Redis::Fast> module (C<Redis::Fast> is preferred for performance;
C<Redis> also works — install whichever suits your environment).

=head1 ATTRIBUTES

=head2 server

The Redis server address in C<< host:port >> form. Defaults to C<127.0.0.1:6379>.

=cut

has server => (
    is      => 'ro',
    isa     => 'Str',
    default => '127.0.0.1:6379',
);

=head2 prefix

Key namespace prefix prepended to every Redis key. Defaults to C<oidc:code:>.
Set this to a unique value per application to avoid collisions on shared Redis
instances.

=cut

has prefix => (
    is      => 'ro',
    isa     => 'Str',
    default => 'oidc:code:',
);

=head2 password

Optional Redis AUTH password. Leave unset if your Redis server does not require
authentication.

=cut

has password => (
    is       => 'ro',
    isa      => 'Maybe[Str]',
    required => 0,
);

=head2 code_ttl

Lifetime of an authorization code in seconds. Defaults to 600 (10 minutes).
The value is passed directly to Redis C<SETEX>.

=cut

has code_ttl => (
    is      => 'ro',
    isa     => 'Int',
    default => 600,
);

=head2 logger

Optional logger instance for debug/info/warn logging.

=cut

has logger => (
    is       => 'ro',
    isa      => 'Maybe[Object]',
    required => 0,
);

=head2 _redis

The underlying Redis connection, lazily created on first use. This defers the
TCP connection until after the parent process has forked, which is necessary for
pre-forking servers: each worker gets its own independent socket.

=cut

has _redis => (
    is      => 'ro',
    lazy    => 1,
    builder => '_build_redis',
);

sub _build_redis {
    my ($self) = @_;

    # Prefer Redis::Fast when available; fall back to Redis.
    my $class;
    for my $candidate (qw( Redis::Fast Redis )) {
        if ( eval "require $candidate; 1" ) {
            $class = $candidate;
            last;
        }
    }
    die 'Neither Redis::Fast nor Redis is installed. '
      . 'Install one to use the Redis store backend.'
      unless $class;

    $self->logger->debug("Connecting to Redis via $class at " . $self->server)
        if $self->logger;

    my %args = (
        server    => $self->server,
        reconnect => 60,
        every     => 500_000,   # microseconds between reconnect attempts
    );
    $args{password} = $self->password if defined $self->password;

    return $class->new(%args);
}

=head1 METHODS

=head2 create_authorization_code($client_id, $user, $scope, $redirect_uri, $nonce)

Creates an authorization code and stores it in Redis with an automatic TTL equal
to L</code_ttl> seconds.

Returns the authorization code string.

=cut

sub create_authorization_code {
    my ( $self, $client_id, $user, $scope, $redirect_uri, $nonce ) = @_;

    $self->logger->debug("Creating authorization code for client: $client_id")
        if $self->logger;

    my $code = _generate_secure_random();
    my $now  = time();

    my $data = $_json->encode({
        client_id    => $client_id,
        user         => $user,
        scope        => $scope,
        redirect_uri => $redirect_uri,
        nonce        => $nonce,
        created_at   => $now,
        expires_at   => $now + $self->code_ttl,
    });

    $self->_redis->setex( $self->prefix . $code, $self->code_ttl, $data );

    $self->logger->debug(
        "Authorization code created: $code (TTL=" . $self->code_ttl . "s)")
        if $self->logger;

    return $code;
}

=head2 get_authorization_code($code)

Retrieves authorization code data from Redis.

Returns a hashref with the code data, or C<undef> if the code does not exist
or has already expired (Redis TTL handles expiry automatically).

=cut

sub get_authorization_code {
    my ( $self, $code ) = @_;

    $self->logger->debug("Retrieving authorization code: $code") if $self->logger;

    my $raw = $self->_redis->get( $self->prefix . $code );
    return unless defined $raw;

    my $data = try {
        decode_json($raw);
    }
    catch {
        $self->logger->warn("Failed to decode authorization code data: $_")
            if $self->logger;
        undef;
    };

    $self->logger->debug("Authorization code found: $code") if $self->logger && $data;
    return $data;
}

=head2 consume_authorization_code($code)

Atomically deletes the authorization code from Redis, enforcing single-use
semantics.

=cut

sub consume_authorization_code {
    my ( $self, $code ) = @_;

    $self->logger->debug("Consuming authorization code: $code") if $self->logger;
    $self->_redis->del( $self->prefix . $code );
}

# Generate a cryptographically secure random string for authorization codes.
# Uses Bytes::Random::Secure which reads from the OS CSPRNG. The lazy _redis
# attribute means the connection is made after fork(), so random state is
# not shared between worker processes.
sub _generate_secure_random {
    my $bytes   = random_bytes(120);
    my $encoded = encode_base64url($bytes);
    $encoded    =~ s/[^a-zA-Z0-9]//g;
    return substr( $encoded, 0, 128 );
}

__PACKAGE__->meta->make_immutable;
1;

=head1 DEPENDENCIES

L<Redis::Fast> (preferred) or L<Redis>, plus L<JSON::MaybeXS> and
L<Bytes::Random::Secure>.

=head1 AUTHOR

Tim F. Rayner

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the terms of The Artistic License 2.0.

=cut
