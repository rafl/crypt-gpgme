#!perl

use strict;
use warnings;
use lib 'ext';
use inc::Module::Install;

name 'Crypt-GpgME';
all_from 'lib/Crypt/GpgME.pm';

requires 'IO::Scalar';

build_requires 'Scalar::Util';
build_requires 'Test::More';
build_requires 'Test::Exception';
build_requires 'Test::MockModule';

gpgme;

no_index directory => 'ext';

auto_include;
auto_install;
WriteAll;
