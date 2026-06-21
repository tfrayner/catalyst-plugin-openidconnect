#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use Test::Exception;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Catalyst::Plugin::OpenIDConnect::Context;

# ---------------------------------------------------------------------------
# Shared mock objects
# ---------------------------------------------------------------------------

package MockLogger;
use Moose;
sub debug {}
sub info  {}
sub warn  {}
sub error {}

package MockCatalystEP;    # "EP" = Extension Points, avoids polluting other test namespaces
use Moose;

has config => (
    is      => 'ro',
    isa     => 'HashRef',
    default => sub { {} },
);

has _oidc_jwt   => ( is => 'rw' );
has _oidc_store => ( is => 'rw' );

has log => (
    is      => 'ro',
    default => sub { MockLogger->new() },
);

package main;

# ---------------------------------------------------------------------------
# Helper: build a fresh Context bound to a unique anonymous subclass of
# MockCatalystEP so that per-class handler storage does not leak between
# subtests.
# ---------------------------------------------------------------------------
my $_class_counter = 0;
sub fresh_context {
    my (%config) = @_;
    my $class = 'MockCatalystEP_' . ++$_class_counter;
    { no strict 'refs'; push @{"${class}::ISA"}, 'MockCatalystEP'; }
    my $mock = bless MockCatalystEP->new(
        config => { 'Plugin::OpenIDConnect' => { %config } },
    ), $class;
    return Catalyst::Plugin::OpenIDConnect::Context->new( catalyst => $mock );
}

# ===========================================================================
# claims_provider tests
# ===========================================================================

subtest 'claims_provider: returns undef when not set' => sub {
    my $ctx = fresh_context();
    is( $ctx->claims_provider, undef, 'claims_provider is undef by default' );
};

subtest 'claims_provider: setter stores a code ref' => sub {
    my $ctx = fresh_context();
    my $cb  = sub { {} };
    my $ret = $ctx->claims_provider($cb);
    is( $ret, $ctx, 'claims_provider setter returns $self for chaining' );
    is( $ctx->claims_provider, $cb, 'claims_provider getter returns the stored code ref' );
};

subtest 'claims_provider: rejects non-code argument' => sub {
    my $ctx = fresh_context();
    dies_ok { $ctx->claims_provider('not_a_coderef') }
        'claims_provider dies when given a non-code argument';
};

subtest 'claims_provider: can be cleared by passing undef' => sub {
    my $ctx = fresh_context();
    $ctx->claims_provider( sub { {} } );
    $ctx->claims_provider(undef);
    is( $ctx->claims_provider, undef, 'claims_provider can be cleared' );
};

subtest 'claims_provider: get_user_claims delegates to provider' => sub {
    my $ctx = fresh_context();

    my $custom_user = { id => 'u-999', display => 'Alice', role => 'admin' };

    $ctx->claims_provider(sub {
        my ( $c, $user ) = @_;
        return {
            sub          => $user->{id},
            name         => $user->{display},
            custom_role  => $user->{role},
        };
    });

    my $claims = $ctx->get_user_claims($custom_user);
    is( $claims->{sub},         'u-999', 'sub claim from provider' );
    is( $claims->{name},        'Alice',  'name claim from provider' );
    is( $claims->{custom_role}, 'admin',  'custom claim from provider' );
    ok( !exists $claims->{email}, 'no email claim (not returned by provider)' );
};

subtest 'claims_provider: get_user_claims falls back to config mapping when no provider' => sub {
    my $ctx = fresh_context(
        user_claims => {
            sub   => 'id',
            name  => 'full_name',
            email => 'email_address',
        },
    );

    my $user = {
        id            => 'u-42',
        full_name     => 'Bob Builder',
        email_address => 'bob@example.com',
    };

    my $claims = $ctx->get_user_claims($user);
    is( $claims->{sub},   'u-42',            'fallback: sub claim' );
    is( $claims->{name},  'Bob Builder',      'fallback: name claim' );
    is( $claims->{email}, 'bob@example.com',  'fallback: email claim' );
};

subtest 'claims_provider: provider receives catalyst context as first arg' => sub {
    my $ctx = fresh_context();
    my $received_c;

    $ctx->claims_provider(sub {
        my ( $c, $user ) = @_;
        $received_c = $c;
        return { sub => 'x' };
    });

    $ctx->get_user_claims( { id => 'x' } );
    isa_ok( $received_c, 'MockCatalystEP', 'provider receives the Catalyst context' );
};

# ===========================================================================
# scope_handler tests
# ===========================================================================

subtest 'scope_handler: returns undef when not set' => sub {
    my $ctx = fresh_context();
    is( $ctx->scope_handler, undef, 'scope_handler is undef by default' );
};

subtest 'scope_handler: setter stores a code ref' => sub {
    my $ctx = fresh_context();
    my $cb  = sub { split /\s+/, $_[1] };
    my $ret = $ctx->scope_handler($cb);
    is( $ret, $ctx, 'scope_handler setter returns $self for chaining' );
    is( $ctx->scope_handler, $cb, 'scope_handler getter returns the stored code ref' );
};

subtest 'scope_handler: rejects non-code argument' => sub {
    my $ctx = fresh_context();
    dies_ok { $ctx->scope_handler('not_a_coderef') }
        'scope_handler dies when given a non-code argument';
};

subtest 'scope_handler: can be cleared by passing undef' => sub {
    my $ctx = fresh_context();
    $ctx->scope_handler( sub { } );
    $ctx->scope_handler(undef);
    is( $ctx->scope_handler, undef, 'scope_handler can be cleared' );
};

subtest 'scope_handler: receives catalyst context and scope string' => sub {
    my $ctx = fresh_context();
    my ( $got_c, $got_scope );

    $ctx->scope_handler(sub {
        my ( $c, $scope_string ) = @_;
        $got_c     = $c;
        $got_scope = $scope_string;
        return split /\s+/, $scope_string;
    });

    my $handler = $ctx->scope_handler;
    my @result  = $handler->( $ctx->catalyst, 'openid profile' );

    isa_ok( $got_c, 'MockCatalystEP', 'handler receives Catalyst context' );
    is( $got_scope, 'openid profile', 'handler receives scope string' );
    is_deeply( \@result, [qw(openid profile)], 'handler return value passed through' );
};

subtest 'scope_handler: handler can filter scopes' => sub {
    my $ctx = fresh_context();

    $ctx->scope_handler(sub {
        my ( $c, $scope_string ) = @_;
        return grep { $_ ne 'phone' } split /\s+/, $scope_string;
    });

    my $handler = $ctx->scope_handler;
    my @result  = $handler->( $ctx->catalyst, 'openid profile phone email' );
    is_deeply( \@result, [qw(openid profile email)], 'handler filtered phone scope' );
};

subtest 'scope_handler: handler can reject by dying' => sub {
    my $ctx = fresh_context();

    $ctx->scope_handler(sub {
        my ( $c, $scope_string ) = @_;
        die "Forbidden scope requested\n";
    });

    my $handler = $ctx->scope_handler;
    dies_ok { $handler->( $ctx->catalyst, 'openid admin' ) }
        'handler rejection propagates as an exception';
    like( $@, qr/Forbidden scope/, 'exception message preserved' );
};

# ===========================================================================
# Per-class isolation: handlers from one app class do not bleed into another
# ===========================================================================

subtest 'handlers are isolated per application class' => sub {
    # Use two distinct mock classes so the per-class keys differ.
    my $mock_a = bless MockCatalystEP->new(
        config => { 'Plugin::OpenIDConnect' => {} }
    ), 'MockCatalystA';
    my $mock_b = bless MockCatalystEP->new(
        config => { 'Plugin::OpenIDConnect' => {} }
    ), 'MockCatalystB';

    my $ctx_a = Catalyst::Plugin::OpenIDConnect::Context->new( catalyst => $mock_a );
    my $ctx_b = Catalyst::Plugin::OpenIDConnect::Context->new( catalyst => $mock_b );

    my $provider_a = sub { { sub => 'user-a' } };
    my $provider_b = sub { { sub => 'user-b' } };

    $ctx_a->claims_provider($provider_a);
    $ctx_b->claims_provider($provider_b);

    is( $ctx_a->claims_provider, $provider_a, 'ctx_a has its own claims_provider' );
    is( $ctx_b->claims_provider, $provider_b, 'ctx_b has its own claims_provider' );
    isnt( $ctx_a->claims_provider, $ctx_b->claims_provider,
        'claims_provider is isolated per class' );

    my $handler_a = sub { qw(openid email) };
    my $handler_b = sub { qw(openid profile) };

    $ctx_a->scope_handler($handler_a);
    $ctx_b->scope_handler($handler_b);

    is( $ctx_a->scope_handler, $handler_a, 'ctx_a has its own scope_handler' );
    is( $ctx_b->scope_handler, $handler_b, 'ctx_b has its own scope_handler' );
    isnt( $ctx_a->scope_handler, $ctx_b->scope_handler,
        'scope_handler is isolated per class' );
};

done_testing();
