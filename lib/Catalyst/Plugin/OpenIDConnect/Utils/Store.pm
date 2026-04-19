package Catalyst::Plugin::OpenIDConnect::Utils::Store;

use strict;
use warnings;
use Moose;
use namespace::autoclean;

use DateTime;
use Data::UUID;
use Try::Tiny;

=head1 NAME

Catalyst::Plugin::OpenIDConnect::Store - In-memory and pluggable store for OIDC state

=head1 DESCRIPTION

Provides storage for authorization codes, tokens, and OIDC session state.
Can be extended to use database backends.

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

=head2 uuid_gen

UUID generator for creating unique IDs.

=cut

has uuid_gen => (
    is      => 'ro',
    isa     => 'Data::UUID',
    default => sub { Data::UUID->new() },
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

Consumes (removes) an authorization code after it's been exchanged for tokens.

=cut

sub consume_authorization_code {
    my ( $self, $code ) = @_;
    $self->logger->debug("Consuming authorization code: $code") if $self->logger;
    delete $self->codes->{$code};
}

=head2 create_session($user, $tokens)

Creates a new user session with tokens.

Returns the session ID.

=cut

sub create_session {
    my ( $self, $user, $tokens ) = @_;

    $self->logger->debug('Creating new user session') if $self->logger;

    my $session_id = $self->uuid_gen->to_string( $self->uuid_gen->create() );

    $self->sessions->{$session_id} = {
        user       => $user,
        tokens     => $tokens,
        created_at => time(),
        last_activity => time(),
    };

    $self->logger->debug("Session created: $session_id") if $self->logger;

    return $session_id;
}

=head2 get_session($session_id)

Retrieves a user session by session ID.

Returns the session data hashref or undef if not found.

=cut

sub get_session {
    my ( $self, $session_id ) = @_;
    $self->logger->debug("Retrieving session: $session_id") if $self->logger;
    return $self->sessions->{$session_id};
}

=head2 update_session_tokens($session_id, $tokens)

Updates the tokens in a session.

=cut

sub update_session_tokens {
    my ( $self, $session_id, $tokens ) = @_;

    my $session = $self->sessions->{$session_id};
    return unless $session;

    $session->{tokens} = $tokens;
    $session->{last_activity} = time();
}

=head2 destroy_session($session_id)

Removes a session.

=cut

sub destroy_session {
    my ( $self, $session_id ) = @_;
    delete $self->sessions->{$session_id};
}

=head2 cleanup_expired_codes

Removes expired authorization codes.

=cut

sub cleanup_expired_codes {
    my ($self) = @_;

    $self->logger->debug('Cleaning up expired authorization codes') if $self->logger;

    my $now = time();
    my @expired = grep { $self->codes->{$_}{expires_at} < $now }
                  keys %{ $self->codes };

    delete @{ $self->codes }{@expired};

    $self->logger->debug("Expired codes cleaned up: " . scalar(@expired) . " codes removed") if $self->logger;

    return scalar @expired;
}

=head2 cleanup_expired_sessions($max_age)

Removes sessions older than max_age seconds.

=cut

sub cleanup_expired_sessions {
    my ( $self, $max_age ) = @_;
    $max_age ||= 3600 * 24;  # 24 hours by default

    $self->logger->debug("Cleaning up expired sessions (max_age: $max_age seconds)") if $self->logger;

    my $now = time();
    my @expired = grep { ( $now - $self->sessions->{$_}{last_activity} ) > $max_age }
                  keys %{ $self->sessions };

    delete @{ $self->sessions }{@expired};

    $self->logger->debug("Expired sessions cleaned up: " . scalar(@expired) . " sessions removed") if $self->logger;

    return scalar @expired;
}

# Generate a secure random string for codes and tokens
sub _generate_secure_random {
    my @chars = ( 'a' .. 'z', 'A' .. 'Z', 0 .. 9 );
    my $code = '';
    for ( 1 .. 128 ) {
        $code .= $chars[ rand @chars ];
    }
    return $code;
}

__PACKAGE__->meta->make_immutable;
1;

=head1 AUTHOR

Tim F. Rayner

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the terms of The Artistic License 2.0.

=cut
