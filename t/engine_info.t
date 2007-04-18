#!perl

#!perl

use strict;
use warnings;
use Test::More tests => 3;
use Test::Exception;

BEGIN {
	use_ok( 'Crypt::GpgME' );
}

{
    my @info;

    lives_ok (sub {
            @info = Crypt::GpgME->get_engine_info;
    }, 'get_engine info');

    ok ((grep { $_->{protocol} =~ /openpgp/ } @info), 'engine info looks sane');
}
