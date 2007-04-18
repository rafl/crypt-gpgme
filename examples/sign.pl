#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::GpgME;

my $ctx = Crypt::GpgME->new;

$ctx->set_passphrase_cb(sub {
        my ($ctx, $hook, $uid_hint, $passphrase_info, $prev_was_bad, $fd) = @_;

        return "foo";
});

my $plain = Crypt::GpgME::Data->new;
$plain->write('test test test');

my $signed = $ctx->sign($plain, 'clear');

$signed->read(my $buf, 1024);
print $buf;
