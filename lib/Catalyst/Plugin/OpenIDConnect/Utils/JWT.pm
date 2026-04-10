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

=head1 METHODS

=head2 sign_token(%payload)

Signs a JWT token with the configured private key using RS256 algorithm.

Returns the complete JWT (header.payload.signature).

=cut

sub sign_token {
    my ( $self, %payload ) = @_;

    # Set standard claims
    $payload{iss} = $self->issuer unless defined $payload{iss};
    $payload{iat} = time() unless defined $payload{iat};

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

    # Create signature
    my $signing_input = "$header_b64.$payload_b64";
    my $signature = $self->private_key->sign($signing_input);
    my $signature_b64 = _urlsafe_b64_encode($signature);

    return "$signing_input.$signature_b64";
}

=head2 verify_token($token)

Verifies a JWT token with the configured public key.

Returns a hashref with decoded claims on success.
Raises an exception on verification failure.

=cut

sub verify_token {
    my ( $self, $token ) = @_;

    return try {
        my @parts = split /\./, $token;
        die 'Invalid JWT format' unless @parts == 3;

        my ( $header_b64, $payload_b64, $signature_b64 ) = @parts;

        # Verify signature
        my $signing_input = "$header_b64.$payload_b64";
        my $signature = _urlsafe_b64_decode($signature_b64);

        die 'Invalid signature' unless $self->public_key->verify(
            $signing_input,
            $signature
        );

        # Decode payload
        my $payload_json = _urlsafe_b64_decode($payload_b64);
        my $payload = decode_json($payload_json);

        # Validate claims
        die 'Token expired' if $payload->{exp} && $payload->{exp} < time();
        die 'Invalid issuer' if $payload->{iss} && $payload->{iss} ne $self->issuer;

        return $payload;
    }
    catch {
        die "Token verification failed: $_";
    };
}

=head2 decode_token($token)

Decodes a JWT token WITHOUT verifying the signature.
Useful for extracting header or payload information for debugging.

Warning: Do not use for security-sensitive operations.

=cut

sub decode_token {
    my ( $self, $token ) = @_;

    return try {
        my @parts = split /\./, $token;
        die 'Invalid JWT format' unless @parts == 3;

        my ( $header_b64, $payload_b64, $signature_b64 ) = @parts;

        my $header = decode_json( _urlsafe_b64_decode($header_b64) );
        my $payload = decode_json( _urlsafe_b64_decode($payload_b64) );

        return {
            header    => $header,
            payload   => $payload,
            signature => $signature_b64,
        };
    }
    catch {
        die "Token decoding failed: $_";
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

Trevor Frayner <tfrayner@example.com>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
