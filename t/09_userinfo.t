#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Catalyst::Plugin::OpenIDConnect::Controller::Root;

{
    package UserInfoTestJWT;

    sub new { return bless {}, shift; }

    sub verify_token {
        return {
            typ => 'at+JWT',
            sub => 12345,
        };
    }
}

{
    package UserInfoTestOpenIDConnect;

    sub config { return {}; }
    sub jwt    { return UserInfoTestJWT->new(); }
}

{
    package UserInfoTestRequest;

    sub header { return 'Bearer test-token'; }
}

{
    package UserInfoTestResponse;

    sub content_type {
        $_[0]->{content_type} = $_[1] if @_ > 1;
        return $_[0]->{content_type};
    }

    sub body {
        $_[0]->{body} = $_[1] if @_ > 1;
        return $_[0]->{body};
    }
}

{
    package UserInfoTestLogger;

    sub debug {}
    sub warn  {}
    sub error {}
}

{
    package UserInfoTestCatalyst;

    sub new {
        return bless {
            request       => bless({}, 'UserInfoTestRequest'),
            response      => bless({}, 'UserInfoTestResponse'),
            openidconnect => bless({}, 'UserInfoTestOpenIDConnect'),
            log           => bless({}, 'UserInfoTestLogger'),
        }, shift;
    }

    sub request       { return $_[0]->{request}; }
    sub response      { return $_[0]->{response}; }
    sub openidconnect { return $_[0]->{openidconnect}; }
    sub log           { return $_[0]->{log}; }
}

my $controller = bless {}, 'Catalyst::Plugin::OpenIDConnect::Controller::Root';
my $c = UserInfoTestCatalyst->new();

$controller->userinfo($c);

is( $c->response->content_type, 'application/json',
    'UserInfo response uses JSON' );
like( $c->response->body, qr/"sub"\s*:\s*"12345"/,
    'numeric sub claim is serialised as a JSON string' );
unlike( $c->response->body, qr/"sub"\s*:\s*12345(?:[,}])/,
    'numeric sub claim is not serialised as a JSON number' );

done_testing();
