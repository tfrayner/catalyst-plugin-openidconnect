#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use Test::Exception;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Catalyst::Plugin::OpenIDConnect::Utils::Store;
use Catalyst::Plugin::OpenIDConnect::Role::Store;

# ---------------------------------------------------------------------------
# Role compliance
# ---------------------------------------------------------------------------

ok(
    Catalyst::Plugin::OpenIDConnect::Utils::Store->DOES(
        'Catalyst::Plugin::OpenIDConnect::Role::Store'
    ),
    'Utils::Store consumes Role::Store',
);

# ---------------------------------------------------------------------------
# Basic lifecycle
# ---------------------------------------------------------------------------

my $store = Catalyst::Plugin::OpenIDConnect::Utils::Store->new();
ok($store, 'Store created');

my $code = $store->create_authorization_code(
    'test-client',
    bless( { id => 'user-123' }, 'TestUser' ),
    'openid profile email',
    'http://localhost:3000/callback',
    'random-nonce-123',
);

ok($code, 'Authorization code created');
like($code, qr/^[a-zA-Z0-9]+$/, 'Code is alphanumeric');
is( length($code), 128, 'Code is 128 characters long' );

# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

my $code_data = $store->get_authorization_code($code);
ok($code_data, 'Authorization code retrieved');
is($code_data->{client_id},    'test-client',                    'Client ID matches');
is($code_data->{scope},        'openid profile email',           'Scope matches');
is($code_data->{redirect_uri}, 'http://localhost:3000/callback', 'Redirect URI matches');
is($code_data->{nonce},        'random-nonce-123',               'Nonce matches');
ok($code_data->{created_at},  'created_at is set');
ok($code_data->{expires_at},  'expires_at is set');
ok( $code_data->{expires_at} > time(), 'Code is not yet expired' );

# ---------------------------------------------------------------------------
# Missing code returns undef
# ---------------------------------------------------------------------------

is( $store->get_authorization_code('nonexistent-code'), undef,
    'get_authorization_code returns undef for unknown code' );

# ---------------------------------------------------------------------------
# Consumption (single-use enforcement)
# ---------------------------------------------------------------------------

$store->consume_authorization_code($code);
is( $store->get_authorization_code($code), undef,
    'Code is consumed and no longer available' );

# Double-consume must not die
lives_ok { $store->consume_authorization_code($code) }
    'Consuming an already-consumed code does not die';

# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

{
    my $expired_store = Catalyst::Plugin::OpenIDConnect::Utils::Store->new();
    my $expired_code  = $expired_store->create_authorization_code(
        'client', bless( {}, 'U' ), 'openid', 'http://example.com/cb', undef,
    );

    # Back-date the expiry timestamp
    $expired_store->codes->{$expired_code}{expires_at} = time() - 1;

    is( $expired_store->get_authorization_code($expired_code), undef,
        'Expired code returns undef' );

    # The store should have cleaned up the key
    ok( !exists $expired_store->codes->{$expired_code},
        'Expired code removed from internal hash' );
}

# ---------------------------------------------------------------------------
# CSPRNG: codes must be unique
# ---------------------------------------------------------------------------

{
    my $s = Catalyst::Plugin::OpenIDConnect::Utils::Store->new();
    my %seen;
    for ( 1 .. 20 ) {
        my $c = $s->create_authorization_code(
            'c', bless( {}, 'U' ), 'openid', 'http://example.com/', undef );
        ok( !$seen{$c}, "Code $_ is unique" );
        $seen{$c}++;
    }
}

done_testing();
