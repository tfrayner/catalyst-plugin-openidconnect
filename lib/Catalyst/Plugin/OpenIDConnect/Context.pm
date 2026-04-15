package Catalyst::Plugin::OpenIDConnect::Context;

use Moose;
use namespace::autoclean;

=head1 NAME

Catalyst::Plugin::OpenIDConnect::Context - OIDC provider context object

=head1 DESCRIPTION

Context object passed to controllers for accessing OIDC functionality.

=head1 ATTRIBUTES

=head2 catalyst

The Catalyst application instance.

=cut

has catalyst => (
    is  => 'ro',
    required => 1,
);

=head1 METHODS

=head2 jwt()

Returns the JWT handler instance.

=cut

sub jwt {
    my ($self) = @_;
    return $self->catalyst->_oidc_jwt();
}

=head2 store()

Returns the state store instance.

=cut

sub store {
    my ($self) = @_;
    return $self->catalyst->_oidc_store();
}

=head2 config()

Returns the OIDC configuration.

=cut

sub config {
    my ($self) = @_;
    return $self->catalyst->config->{'Plugin::OpenIDConnect'} || {};
}

=head2 get_client($client_id)

Retrieves a client configuration by client ID.

=cut

sub get_client {
    my ( $self, $client_id ) = @_;
    my $clients = $self->config->{clients} || {};
    return $clients->{$client_id};
}

=head2 get_user_claims($user)

Extracts user claims based on the configured user_claims mapping.

The user parameter can be a hash reference or an object with accessor methods.

=cut

sub get_user_claims {
    my ( $self, $user ) = @_;

    my $claims_config = $self->config->{user_claims} || {
        sub      => 'id',
        name     => 'name',
        email    => 'email',
    };

    my %claims;

    for my $claim_name ( keys %$claims_config ) {
        my $accessor = $claims_config->{$claim_name};
        my @parts = split /\./, $accessor;

        my $value = $user;
        for my $part (@parts) {
            last unless defined $value;
            if ( ref $value eq 'HASH' ) {
                $value = $value->{$part};
            } else {
                $value = $value->$part() if $value->can($part);
            }
        }

        $claims{$claim_name} = $value if defined $value;
    }

    return \%claims;
}

=head2 get_discovery()

Returns the OpenID Connect provider configuration document.

=cut

sub get_discovery {
    my ($self) = @_;

    my $c = $self->catalyst;
    my $issuer_url = $self->config->{issuer}{url} || $c->uri_for('/')->as_string;

    return {
        issuer                          => $issuer_url,
        authorization_endpoint          => $c->uri_for('/openidconnect/authorize')->as_string,
        token_endpoint                  => $c->uri_for('/openidconnect/token')->as_string,
        userinfo_endpoint               => $c->uri_for('/openidconnect/userinfo')->as_string,
        jwks_uri                        => $c->uri_for('/openidconnect/jwks')->as_string,
        registration_endpoint           => undef,
        scopes_supported                => [qw(openid profile email phone address)],
        response_types_supported        => [qw(code id_token token id_token token code id_token token)],
        response_modes_supported        => [qw(query fragment form_post)],
        grant_types_supported           => [qw(authorization_code refresh_token implicit)],
        subject_types_supported         => [qw(public pairwise)],
        id_token_signing_alg_values_supported => ['RS256'],
        userinfo_signing_alg_values_supported => ['RS256'],
        request_parameter_supported    => 1,
        request_uri_parameter_supported => 1,
        claims_supported                => [
            qw(
                sub name given_name family_name middle_name nickname
                preferred_username profile picture website email email_verified
                gender birthdate zoneinfo locale phone_number phone_number_verified
                address updated_at
            )
        ],
        claim_types_supported          => [qw(normal aggregated distributed)],
    };
}

__PACKAGE__->meta->make_immutable;
1;

=head1 AUTHOR

Tim F. Rayner

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the terms of The Artistic License 2.0.

=cut
