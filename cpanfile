requires 'perl', '5.020';
requires 'Catalyst';
requires 'Catalyst::Runtime', '>= 5.90100';
requires 'Catalyst::View::JSON';
requires 'Moose';
requires 'namespace::autoclean';
requires 'JSON::MaybeXS';
requires 'Crypt::OpenSSL::RSA';
requires 'Digest::SHA';
requires 'MIME::Base64';
requires 'DateTime';
requires 'DateTime::Format::ISO8601';
requires 'Config::General';
requires 'URI';
requires 'Try::Tiny';
requires 'Data::UUID';

on 'test' => sub {
    requires 'Test::More', '>= 0.88';
    requires 'Test::Exception';
    requires 'Test::MockObject';
    requires 'Test::Deep';
};
