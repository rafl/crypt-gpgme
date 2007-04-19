#!perl

use strict;
use warnings;
use Test::More tests => 11;
use Test::Exception;

BEGIN {
	use_ok( 'Crypt::GpgME' );
}

delete $ENV{GPG_AGENT_INFO};
$ENV{GNUPGHOME} = 't/gpg';

my $ctx = Crypt::GpgME->new;
isa_ok ($ctx, 'Crypt::GpgME');

$ctx->set_passphrase_cb(sub { 'abc' });

my $plain = Crypt::GpgME::Data->new;
isa_ok ($plain, 'Crypt::GpgME::Data');

my $data = 'test test test';
my $written;

lives_ok (sub {
    $written = $plain->write($data);
}, 'write data lives');

is ($written, length $data, 'write data wrote everything');

my $signed;
lives_ok (sub {
        $signed = $ctx->sign($plain, 'clear');
}, 'clearsign');

isa_ok ($signed, 'Crypt::GpgME::Data');

my $signed_text;
while ($signed->read(my $buf, 1024) > 0) {
    $signed_text .= $buf;
}

like ($signed_text, qr/$data/, 'signed text looks sane');

my $result;
my $verify_plain;
lives_ok (sub {
        ($result, $verify_plain) = $ctx->verify($signed);
}, 'verify');

isa_ok ($verify_plain, 'Crypt::GpgME::Data');

is (ref $result, 'HASH', 'result is a hash ref');
