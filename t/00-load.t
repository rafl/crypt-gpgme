#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'Crypt::GpgME' );
}

diag( "Testing Crypt::GpgME $Crypt::GpgME::VERSION, Perl $], $^X" );
