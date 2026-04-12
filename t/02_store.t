#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Catalyst::Plugin::OpenIDConnect::Utils::Store;

# Create store
my $store = Catalyst::Plugin::OpenIDConnect::Utils::Store->new();

ok($store, 'Store created');

# Test authorization code creation
my $code = $store->create_authorization_code(
    'test-client',
    bless({id => 'user-123'}, 'TestUser'),
    'openid profile email',
    'http://localhost:3000/callback',
    'random-nonce-123',
);

ok($code, 'Authorization code created');
like($code, qr/^[a-zA-Z0-9]+$/, 'Code is alphanumeric');

# Test authorization code retrieval
my $code_data = $store->get_authorization_code($code);
ok($code_data, 'Authorization code retrieved');
is($code_data->{client_id}, 'test-client', 'Client ID matches');
is($code_data->{scope}, 'openid profile email', 'Scope matches');
is($code_data->{redirect_uri}, 'http://localhost:3000/callback', 'Redirect URI matches');
is($code_data->{nonce}, 'random-nonce-123', 'Nonce matches');

# Test code consumption
$store->consume_authorization_code($code);
my $consumed = $store->get_authorization_code($code);
is($consumed, undef, 'Code is consumed and no longer available');

# Test session creation
my $session_id = $store->create_session(
    bless({id => 'user-456'}, 'TestUser'),
    { access_token => 'token123', id_token => 'idtoken456' },
);

ok($session_id, 'Session created');

# Test session retrieval
my $session = $store->get_session($session_id);
ok($session, 'Session retrieved');
is($session->{tokens}->{access_token}, 'token123', 'Access token in session');

done_testing();
