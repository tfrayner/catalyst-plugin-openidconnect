#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use Test::Exception;
use FindBin;
use lib "$FindBin::Bin/../lib";

# ---------------------------------------------------------------------------
# Skip the whole file if neither Redis::Fast nor Redis is available.
# This avoids hard failures in environments without a Redis client installed.
# ---------------------------------------------------------------------------

my $redis_class;
for my $candidate (qw( Redis::Fast Redis )) {
    if ( eval "require $candidate; 1" ) {
        $redis_class = $candidate;
        last;
    }
}

plan skip_all => 'Neither Redis::Fast nor Redis is installed'
    unless $redis_class;

use Scalar::Util qw(blessed);
use Catalyst::Plugin::OpenIDConnect::Utils::Store::Redis;
use Catalyst::Plugin::OpenIDConnect::Role::Store;

# ---------------------------------------------------------------------------
# Helpers: build a mock Redis handle that records calls
# ---------------------------------------------------------------------------

{
    package MockRedis;

    sub new {
        my ( $class, %args ) = @_;
        return bless { store => {}, calls => [] }, $class;
    }

    sub setex {
        my ( $self, $key, $ttl, $value ) = @_;
        push @{ $self->{calls} }, [ setex => $key, $ttl, $value ];
        $self->{store}{$key} = { value => $value, ttl => $ttl };
    }

    sub get {
        my ( $self, $key ) = @_;
        my $entry = $self->{store}{$key} or return undef;
        return $entry->{value};
    }

    sub del {
        my ( $self, $key ) = @_;
        push @{ $self->{calls} }, [ del => $key ];
        delete $self->{store}{$key};
    }

    sub recorded_calls { $_[0]->{calls} }
}

# ---------------------------------------------------------------------------
# Subclass that injects the mock Redis handle, bypassing the lazy builder
# ---------------------------------------------------------------------------

{
    package MockRedisStore;
    use Moose;
    extends 'Catalyst::Plugin::OpenIDConnect::Utils::Store::Redis';

    # Override the builder method rather than the attribute declaration;
    # this avoids the Moose restriction on mixing builder and default.
    sub _build_redis { MockRedis->new() }

    __PACKAGE__->meta->make_immutable;
}

# ---------------------------------------------------------------------------
# Role compliance
# ---------------------------------------------------------------------------

ok(
    Catalyst::Plugin::OpenIDConnect::Utils::Store::Redis->DOES(
        'Catalyst::Plugin::OpenIDConnect::Role::Store'
    ),
    'Utils::Store::Redis consumes Role::Store',
);

# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------

my $store = MockRedisStore->new(
    prefix   => 'test:oidc:code:',
    code_ttl => 600,
);
ok( $store, 'Redis store created' );
is( $store->prefix,   'test:oidc:code:', 'prefix attribute set' );
is( $store->code_ttl, 600,               'code_ttl attribute set' );

# ---------------------------------------------------------------------------
# create_authorization_code
# ---------------------------------------------------------------------------

my $code = $store->create_authorization_code(
    'test-client',
    bless( { id => 'user-123' }, 'TestUser' ),
    'openid profile email',
    'http://localhost:3000/callback',
    'nonce-abc',
);

ok( $code, 'create_authorization_code returns a code' );
like( $code, qr/^[a-zA-Z0-9]+$/, 'Code is alphanumeric' );
is( length($code), 128, 'Code is 128 characters long' );

# Verify that setex was called with the right key and TTL
my $calls = $store->_redis->recorded_calls;
is( scalar @$calls, 1, 'One Redis call made for create' );
is( $calls->[0][0], 'setex', 'setex was called' );
like( $calls->[0][1], qr/^test:oidc:code:/, 'Key has correct prefix' );
is( $calls->[0][2], 600, 'TTL is code_ttl' );

# ---------------------------------------------------------------------------
# get_authorization_code
# ---------------------------------------------------------------------------

my $data = $store->get_authorization_code($code);
ok( $data, 'get_authorization_code returns data' );
is( $data->{client_id},    'test-client',                    'client_id matches' );
is( $data->{scope},        'openid profile email',           'scope matches' );
is( $data->{redirect_uri}, 'http://localhost:3000/callback', 'redirect_uri matches' );
is( $data->{nonce},        'nonce-abc',                      'nonce matches' );
ok( $data->{created_at},  'created_at is set' );
ok( $data->{expires_at},  'expires_at is set' );

is( $store->get_authorization_code('nonexistent'), undef,
    'get_authorization_code returns undef for unknown code' );

# ---------------------------------------------------------------------------
# consume_authorization_code
# ---------------------------------------------------------------------------

$store->consume_authorization_code($code);

is( $store->get_authorization_code($code), undef,
    'Code is unavailable after consume' );

# Confirm del was called
my $del_calls = [ grep { $_->[0] eq 'del' } @{ $store->_redis->recorded_calls } ];
is( scalar @$del_calls, 1, 'del was called once' );
like( $del_calls->[0][1], qr/^test:oidc:code:/, 'del used correct key prefix' );

# Double-consume must not die
lives_ok { $store->consume_authorization_code($code) }
    'Consuming an already-consumed code does not die';

# ---------------------------------------------------------------------------
# CSPRNG: codes must be unique
# ---------------------------------------------------------------------------

{
    my $s = MockRedisStore->new( prefix => 'u:' );
    my %seen;
    for ( 1 .. 20 ) {
        my $c = $s->create_authorization_code(
            'c', bless( {}, 'U' ), 'openid', 'http://example.com/', undef );
        ok( !$seen{$c}, "Code $_ is unique" );
        $seen{$c}++;
    }
}

# ---------------------------------------------------------------------------
# Configurable prefix and TTL
# ---------------------------------------------------------------------------

{
    my $s2 = MockRedisStore->new(
        prefix   => 'myapp:auth:',
        code_ttl => 300,
    );
    my $c = $s2->create_authorization_code(
        'client2', bless( {}, 'U' ), 'openid', 'http://example.com/cb', undef );

    my $recent = $s2->_redis->recorded_calls->[-1];
    like( $recent->[1], qr/^myapp:auth:/, 'Custom prefix applied' );
    is( $recent->[2], 300, 'Custom TTL applied' );
}

# ---------------------------------------------------------------------------
# JSON corruption is handled gracefully
# ---------------------------------------------------------------------------

{
    my $s3 = MockRedisStore->new( prefix => 'bad:' );
    $s3->_redis->{store}{'bad:corrupt'} = { value => 'not-valid-json', ttl => 600 };
    my $result = $s3->get_authorization_code('corrupt');
    is( $result, undef, 'Corrupt JSON returns undef without dying' );
}

done_testing();
