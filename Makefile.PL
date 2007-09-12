#!perl

use strict;
use warnings;
use lib 'ext';
use inc::Module::Install;

name 'Crypt-GpgME';
all_from 'lib/Crypt/GpgME.pm';

requires 'IO::Scalar';

build_requires 'File::Which';
build_requires 'Test::Exception';
build_requires 'Test::More';

gpgme;

no_index directory => 'ext';

auto_install;
WriteAll;
