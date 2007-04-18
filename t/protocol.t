#!perl

use strict;
use warnings;
use Test::More tests => 15;
use Test::Exception;

BEGIN {
	use_ok( 'Crypt::GpgME' );
}

my $ctx;
lives_ok (sub {
    $ctx = Crypt::GpgME->new;
}, 'create new context');

isa_ok ($ctx, 'Crypt::GpgME');

{
    my $proto;

    lives_ok (sub {
            $proto = $ctx->get_protocol;
    }, 'getting protocol');

    is ($proto, 'openpgp', 'default protocol is openpgp');
}

lives_ok (sub {
        $ctx->set_protocol('cms');
}, 'setting protocol to cms');

{
    my $proto;

    lives_ok (sub {
            $proto = $ctx->get_protocol;
    }, 'getting protocol');

    is ($proto, 'cms', 'setting protocol worked');
}

lives_ok (sub {
        $ctx->set_protocol('openpgp');
}, 'setting protocol to openpgp');

{
    my $proto;

    lives_ok (sub {
            $proto = $ctx->get_protocol;
    }, 'getting protocol');

    is ($proto, 'openpgp', 'setting protocol worked');
}

throws_ok(sub {
        $ctx->set_protocol('opengpg');
}, qr/^unknown protocol/, 'setting invalid protocol');

lives_ok (sub {
        $ctx->set_protocol;
}, 'setting protocol without argument works');

{
    my $proto;

    lives_ok (sub {
            $proto = $ctx->get_protocol;
    }, 'getting protocol');

    is ($proto, 'openpgp', 'calling set_protocol without arguments sets to openpgp');
}
