#!perl

use strict;
use warnings;
use Test::More tests => 2;
use Test::Exception;
use Test::MockModule;

BEGIN { use_ok('Crypt::GpgME') }

my $mock = Test::MockModule->new('Crypt::GpgME');
$mock->mock(DESTROY => sub ($) { });

my $fake_obj = bless [], 'Crypt::GpgME';

throws_ok (sub {
        $fake_obj->sig_notation_clear;
}, qr/invalid object/, 'calling methods on invalid objects');

bless $fake_obj, 'Foo'; #to avoid a warning on destroy
