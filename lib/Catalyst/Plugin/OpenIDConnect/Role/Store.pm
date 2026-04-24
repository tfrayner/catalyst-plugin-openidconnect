package Catalyst::Plugin::OpenIDConnect::Role::Store;

use Moose::Role;
use namespace::autoclean;

=head1 NAME

Catalyst::Plugin::OpenIDConnect::Role::Store - Role defining the OIDC token store interface

=head1 DESCRIPTION

This Moose role defines the interface that any OIDC store backend must implement.
All store classes (in-memory, Redis, database, etc.) must consume this role.

=head1 REQUIRED METHODS

=head2 create_authorization_code($client_id, $user_data, $scope, $redirect_uri, $nonce)

Creates and persists an authorization code for the given parameters.

C<$user_data> must be a plain (unblessed) hashref of the user's OIDC claims,
as returned by C<get_user_claims()>. Callers are responsible for extracting
claims from the live user object before calling this method; doing so here
(rather than in the store) ensures that any application-specific user object
— DBIx::Class row, LDAP entry, etc. — is resolved while the Catalyst context
is still available, and that the store only ever handles plain serialisable data.

Returns the authorization code string.

=cut

requires 'create_authorization_code';

=head2 get_authorization_code($code)

Retrieves an authorization code by its value. Must return C<undef> if the code
does not exist or has expired.

Returns a hashref containing at minimum: C<client_id>, C<user>, C<scope>,
C<redirect_uri>, C<nonce>, C<created_at>, C<expires_at>.

=cut

requires 'get_authorization_code';

=head2 consume_authorization_code($code)

Permanently removes an authorization code after it has been exchanged for tokens.
This enforces single-use semantics for authorization codes.

=cut

requires 'consume_authorization_code';

1;

=head1 AUTHOR

Tim F. Rayner

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the terms of The Artistic License 2.0.

=cut
