#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use Test::Exception;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Catalyst::Plugin::OpenIDConnect::Utils::JWT;
use Crypt::OpenSSL::RSA;

# Generate test keys
my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);

my $private_key = $rsa;
my $public_key = Crypt::OpenSSL::RSA->new_public_key(
    $rsa->get_public_key_string()
);

# Create JWT handler
my $jwt = Catalyst::Plugin::OpenIDConnect::Utils::JWT->new(
    private_key => $private_key,
    public_key  => $public_key,
    key_id      => 'test-key',
    issuer      => 'http://localhost:5000',
);

ok($jwt, 'JWT handler created');

# Test token signing
my %payload = (
    sub => 'user-123',
    name => 'Test User',
    email => 'test@example.com',
    aud => 'test-client',
);

my $token;
lives_ok {
    $token = $jwt->sign_token(%payload);
} 'Token signed successfully';

ok($token, 'Token is not empty');
like($token, qr/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/, 'Token has correct format');

# Test token verification
my $verified_payload;
lives_ok {
    $verified_payload = $jwt->verify_token($token);
} 'Token verified successfully';

is($verified_payload->{sub}, 'user-123', 'sub claim matches');
is($verified_payload->{name}, 'Test User', 'name claim matches');
is($verified_payload->{email}, 'test@example.com', 'email claim matches');
is($verified_payload->{iss}, 'http://localhost:5000', 'issuer claim set correctly');

# Test invalid token verification
throws_ok {
    $jwt->verify_token('invalid.token.here');
} qr/Token verification failed/, 'Invalid token rejected';

done_testing();
