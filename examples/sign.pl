#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::GpgME;
use IO::Scalar;

my $ctx = Crypt::GpgME->new;

$ctx->set_passphrase_cb(sub { 'foo' });

my $plain = IO::Scalar->new(\q/test test test/);

my $signed = $ctx->sign($plain, 'clear');

print while <$signed>;
