#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use Test::Exception;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Catalyst::Plugin::OpenIDConnect::Utils::JWT;
use Crypt::OpenSSL::RSA;
use JSON::MaybeXS qw(encode_json);
use MIME::Base64  qw(encode_base64);

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);

my $private_key = $rsa;
my $public_key = Crypt::OpenSSL::RSA->new_public_key(
    $rsa->get_public_key_string()
);

my $jwt = Catalyst::Plugin::OpenIDConnect::Utils::JWT->new(
    private_key => $private_key,
    public_key  => $public_key,
    key_id      => 'test-key',
    issuer      => 'http://localhost:5000',
);

ok($jwt, 'JWT handler created');

# ---------------------------------------------------------------------------
# Helper: build a validly-signed JWT with exactly the given payload.
# Unlike sign_token(), this does NOT auto-set iss/iat so we can test
# tokens that intentionally omit mandatory claims.
# ---------------------------------------------------------------------------
sub _raw_jwt {
    my (%payload) = @_;
    my $encode = sub {
        my $b64 = encode_base64($_[0], '');
        $b64 =~ tr|+/=|-_|d;
        return $b64;
    };
    my $header      = $encode->(encode_json({ alg => 'RS256', typ => 'JWT', kid => 'test-key' }));
    my $body        = $encode->(encode_json(\%payload));
    my $signing_in  = "$header.$body";
    $private_key->use_sha256_hash();
    my $sig = $encode->($private_key->sign($signing_in));
    return "$signing_in.$sig";
}

# ---------------------------------------------------------------------------
# Basic signing and verification (happy path)
# ---------------------------------------------------------------------------

my %payload = (
    sub   => 'user-123',
    name  => 'Test User',
    email => 'test@example.com',
    aud   => 'test-client',
    exp   => time() + 3600,   # mandatory: expiry one hour from now
);

my $token;
lives_ok {
    $token = $jwt->sign_token(%payload);
} 'Token signed successfully';

ok($token, 'Token is not empty');
like($token, qr/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/,
    'Token has correct format');

my $verified_payload;
lives_ok {
    $verified_payload = $jwt->verify_token($token);
} 'Token verified successfully';

is($verified_payload->{sub},   'user-123',              'sub claim matches');
is($verified_payload->{name},  'Test User',             'name claim matches');
is($verified_payload->{email}, 'test@example.com',      'email claim matches');
is($verified_payload->{iss},   'http://localhost:5000', 'issuer claim set correctly');

# ---------------------------------------------------------------------------
# Structurally invalid token
# ---------------------------------------------------------------------------

throws_ok {
    $jwt->verify_token('invalid.token.here');
} qr/Token verification failed/, 'Invalid token rejected';

# ---------------------------------------------------------------------------
# HIGH-2: exp claim — mandatory, must be present and not expired
# ---------------------------------------------------------------------------

my $no_exp_token = _raw_jwt(
    sub => 'user-x',
    iss => 'http://localhost:5000',
    aud => 'test-client',
    # exp intentionally omitted
);

throws_ok {
    $jwt->verify_token($no_exp_token);
} qr/Token verification failed/, 'Token without exp claim rejected';

my $expired_token = _raw_jwt(
    sub => 'user-x',
    iss => 'http://localhost:5000',
    aud => 'test-client',
    exp => time() - 3600,   # expired 1 hour ago
);

throws_ok {
    $jwt->verify_token($expired_token);
} qr/Token verification failed/, 'Expired token rejected';

# ---------------------------------------------------------------------------
# HIGH-2: iss claim — mandatory, must be present and match configured issuer
# ---------------------------------------------------------------------------

my $no_iss_token = _raw_jwt(
    sub => 'user-x',
    aud => 'test-client',
    exp => time() + 3600,
    # iss intentionally omitted
);

throws_ok {
    $jwt->verify_token($no_iss_token);
} qr/Token verification failed/, 'Token without iss claim rejected';

my $wrong_iss_token = _raw_jwt(
    sub => 'user-x',
    iss => 'https://evil.example.com',
    aud => 'test-client',
    exp => time() + 3600,
);

throws_ok {
    $jwt->verify_token($wrong_iss_token);
} qr/Token verification failed/, 'Token with wrong issuer rejected';

# ---------------------------------------------------------------------------
# HIGH-2: nbf claim — optional but enforced when present
# ---------------------------------------------------------------------------

my $future_nbf_token = _raw_jwt(
    sub => 'user-x',
    iss => 'http://localhost:5000',
    aud => 'test-client',
    exp => time() + 7200,
    nbf => time() + 3600,   # not valid for another hour
);

throws_ok {
    $jwt->verify_token($future_nbf_token);
} qr/Token verification failed/, 'Token with future nbf rejected';

my $past_nbf_token = _raw_jwt(
    sub => 'user-x',
    iss => 'http://localhost:5000',
    aud => 'test-client',
    exp => time() + 3600,
    nbf => time() - 60,     # became valid 1 minute ago
);

lives_ok {
    $jwt->verify_token($past_nbf_token);
} 'Token with past nbf accepted';

# ---------------------------------------------------------------------------
# HIGH-2: expected_audience — validated when caller supplies it
# ---------------------------------------------------------------------------

my $aud_token = _raw_jwt(
    sub => 'user-x',
    iss => 'http://localhost:5000',
    aud => 'my-client',
    exp => time() + 3600,
);

lives_ok {
    $jwt->verify_token($aud_token, expected_audience => 'my-client');
} 'Token with matching expected_audience accepted';

throws_ok {
    $jwt->verify_token($aud_token, expected_audience => 'other-client');
} qr/Token verification failed/, 'Token with wrong expected_audience rejected';

my $no_aud_token = _raw_jwt(
    sub => 'user-x',
    iss => 'http://localhost:5000',
    exp => time() + 3600,
    # aud intentionally omitted
);

throws_ok {
    $jwt->verify_token($no_aud_token, expected_audience => 'my-client');
} qr/Token verification failed/,
    'Token missing aud claim rejected when expected_audience supplied';

# When no expected_audience is given, aud absence does not cause failure
lives_ok {
    $jwt->verify_token($no_aud_token);
} 'Token without aud accepted when no expected_audience is required';

done_testing();
