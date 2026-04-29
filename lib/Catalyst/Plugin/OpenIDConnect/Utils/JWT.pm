package Catalyst::Plugin::OpenIDConnect::Utils::JWT;

use strict;
use warnings;
use Moose;
use namespace::autoclean;

use JSON::MaybeXS qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha256);
use Crypt::OpenSSL::RSA;
use DateTime;
use Try::Tiny;

=head1 NAME

Catalyst::Plugin::OpenIDConnect::Utils::JWT - JWT handling for OpenID Connect

=head1 DESCRIPTION

Provides JWT signing and verification functionality using RS256 (RSA SHA-256) algorithm
for OpenID Connect token creation and validation.

=head1 ATTRIBUTES

=head2 private_key

The RSA private key for signing tokens.

=cut

has private_key => (
    is       => 'ro',
    isa      => 'Crypt::OpenSSL::RSA',
    required => 1,
);

=head2 public_key

The RSA public key for verifying tokens.

=cut

has public_key => (
    is       => 'ro',
    isa      => 'Crypt::OpenSSL::RSA',
    required => 1,
);

=head2 key_id

The key ID (kid) used in JWT headers.

=cut

has key_id => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

=head2 issuer

The issuer URL/identifier for the iss claim.

=cut

has issuer => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
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

=head2 sign_token(%payload)

Signs a JWT token with the configured private key using RS256 algorithm.

Returns the complete JWT (header.payload.signature).

=cut

sub sign_token {
    my ( $self, %payload ) = @_;

    $self->logger->debug('Signing JWT token') if $self->logger;

    # Set standard claims
    $payload{iss} = $self->issuer unless defined $payload{iss};
    $payload{iat} = time() unless defined $payload{iat};

    $self->logger->debug('JWT payload: ' . encode_json(\%payload)) if $self->logger;

    # Prep header
    my %header = (
        alg => 'RS256',
        typ => 'JWT',
        kid => $self->key_id,
    );

    # Encode header and payload
    my $header_json   = encode_json( \%header );
    my $payload_json  = encode_json( \%payload );

    my $header_b64   = _urlsafe_b64_encode($header_json);
    my $payload_b64  = _urlsafe_b64_encode($payload_json);

    # Create signature (explicitly use SHA256 for RS256)
    my $signing_input = "$header_b64.$payload_b64";
    my $priv_key = $self->private_key;
    $priv_key->use_sha256_hash();
    my $signature = $priv_key->sign($signing_input);
    my $signature_b64 = _urlsafe_b64_encode($signature);

    my $token = "$signing_input.$signature_b64";
    $self->logger->debug('JWT token signed successfully') if $self->logger;
    
    return $token;
}

=head2 verify_token($token)

Verifies a JWT token with the configured public key.

Returns a hashref with decoded claims on success.
Raises an exception on verification failure.

=cut

sub verify_token {
    my ( $self, $token ) = @_;

    $self->logger->debug('Verifying JWT token') if $self->logger;

    return try {
        my @parts = split /\./, $token;
        die 'Invalid JWT format' unless @parts == 3;

        my ( $header_b64, $payload_b64, $signature_b64 ) = @parts;

        $self->logger->debug('JWT format validated (3 parts)') if $self->logger;

        # Verify signature (explicitly use SHA256 for RS256)
        my $signing_input = "$header_b64.$payload_b64";
        my $signature = _urlsafe_b64_decode($signature_b64);
        
        my $pub_key = $self->public_key;
        $pub_key->use_sha256_hash();
        die 'Invalid signature' unless $pub_key->verify(
            $signing_input,
            $signature
        );

        $self->logger->debug('JWT signature verified') if $self->logger;

        # Decode payload
        my $payload_json = _urlsafe_b64_decode($payload_b64);
        my $payload = decode_json($payload_json);

        $self->logger->debug('JWT payload decoded successfully') if $self->logger;

        # Validate claims
        die 'Token expired' if $payload->{exp} && $payload->{exp} < time();
        die 'Invalid issuer' if $payload->{iss} && $payload->{iss} ne $self->issuer;

        $self->logger->debug('JWT claims validated') if $self->logger;

        return $payload;
    }
    catch {
        $self->logger->warn("Token verification failed: $_") if $self->logger;
        die "Token verification failed: $_";
    };
}

=head2 create_id_token(%claims)

Creates a signed ID token with the specified claims.

=cut

sub create_id_token {
    my ( $self, %claims ) = @_;

    my %payload = (
        typ => 'JWT',
        %claims,
    );

    return $self->sign_token(%payload);
}

=head2 create_access_token(%claims)

Creates a signed access token with the specified claims.

=cut

sub create_access_token {
    my ( $self, %claims ) = @_;

    return $self->sign_token(%claims);
}

=head2 create_refresh_token(%claims)

Creates a signed refresh token with the specified claims.

=cut

sub create_refresh_token {
    my ( $self, %claims ) = @_;

    return $self->sign_token(%claims);
}

=head2 decode_id_token_hint($token)

Decodes a JWT passed as an C<id_token_hint> during logout.

Verifies the token signature against the configured public key to confirm
it was genuinely issued by this server, but deliberately skips expiry
validation — hint tokens are frequently expired at logout time by design.

Returns a hashref of the token's claims on success, or C<undef> if the
token is malformed or the signature cannot be verified.

=cut

sub decode_id_token_hint {
    my ( $self, $token ) = @_;

    return try {
        my @parts = split /\./, $token;
        return undef unless @parts == 3;

        my ( $header_b64, $payload_b64, $signature_b64 ) = @parts;

        # Verify signature — ensures the token was genuinely issued by us
        # and was not crafted by an attacker to spoof a client_id.
        my $signing_input = "$header_b64.$payload_b64";
        my $signature     = _urlsafe_b64_decode($signature_b64);
        my $pub_key       = $self->public_key;
        $pub_key->use_sha256_hash();
        return undef unless $pub_key->verify( $signing_input, $signature );

        my $payload_json = _urlsafe_b64_decode($payload_b64);
        return decode_json($payload_json);
    }
    catch {
        $self->logger->warn("id_token_hint decode failed: $_") if $self->logger;
        return undef;
    };
}

# Helper: URL-safe base64 encode (RFC 4648 Section 5)
sub _urlsafe_b64_encode {
    my ($data) = @_;
    my $b64 = encode_base64($data, '');
    $b64 =~ tr|+/|-_|;
    $b64 =~ s/=+$//;
    return $b64;
}

# Helper: URL-safe base64 decode (RFC 4648 Section 5)
sub _urlsafe_b64_decode {
    my ($data) = @_;
    $data =~ tr|-_|+/|;
    my $padding = length($data) % 4;
    $data .= '=' x ( 4 - $padding ) if $padding;
    return decode_base64($data);
}

__PACKAGE__->meta->make_immutable;
1;

=head1 AUTHOR

Tim F. Rayner

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the terms of The Artistic License 2.0.

=cut
