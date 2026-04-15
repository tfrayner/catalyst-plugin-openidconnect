use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME           => 'Catalyst::Plugin::OpenIDConnect',
    VERSION_FROM   => 'lib/Catalyst/Plugin/OpenIDConnect.pm',
    ABSTRACT_FROM  => 'lib/Catalyst/Plugin/OpenIDConnect.pm',
    AUTHOR         => 'Tim F. Rayner <tfrayner@cpan.org>',
    LICENSE        => 'artistic_2',
    PREREQ_PM      => {
        'perl'                                => '5.020',
        'Catalyst'                            => 0,
        'Catalyst::Runtime'                   => '5.90100',
        'Catalyst::View::JSON'                => 0,
        'Moose'                               => 0,
        'namespace::autoclean'                => 0,
        'JSON::MaybeXS'                       => 0,
        'Crypt::OpenSSL::RSA'                 => '0.35', # for openssl 3 support; upgrade to 0.37+ when possible FIXME
        'Digest::SHA'                         => 0,
        'MIME::Base64'                        => 0,
        'DateTime'                            => 0,
        'DateTime::Format::ISO8601'           => 0,
        'Config::General'                     => 0,
        'URI'                                 => 0,
        'Try::Tiny'                           => 0,
        'Data::UUID'                          => 0,
    },
    TEST_REQUIRES  => {
        'Test::More'           => '0.88',
        'Test::Exception'      => 0,
        'Test::MockObject'     => 0,
        'Test::Deep'           => 0,
    },
    META_MERGE     => {
        'meta-spec' => { version => 2 },
        resources   => {
            repository => {
                type => 'git',
                url  => 'https://github.com/tfrayner/perl-oidc.git',
                web  => 'https://github.com/tfrayner/perl-oidc',
            },
            bugtracker => {
                web => 'https://github.com/tfrayner/perl-oidc/issues',
            },
        },
    },
    PL_FILES       => {},
);
