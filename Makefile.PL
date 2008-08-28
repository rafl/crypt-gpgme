#!perl

use strict;
use warnings;
use lib 'ext';
use inc::Module::Install;

name 'Crypt-GpgME';
all_from 'lib/Crypt/GpgME.pm';

requires 'IO::Scalar';
requires_external_bin 'gpgme-config';
test_requires 'Test::Exception';
test_requires 'Test::More';

gpgme;

no_index directory => 'ext';

auto_install;
WriteAll;
