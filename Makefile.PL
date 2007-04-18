#!perl

use strict;
use warnings;
use lib 'ext';
use inc::Module::Install;

name 'Crypt-GpgME';
all_from 'lib/Crypt/GpgME.pm';

gpgme;

no_index directory => 'ext';

auto_include;
auto_install;
WriteAll;
