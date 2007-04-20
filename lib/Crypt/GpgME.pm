package Crypt::GpgME;

use strict;
use warnings;

our $VERSION = '0.01';
our @ISA;

eval {
    require XSLoader;
    XSLoader::load( __PACKAGE__, $VERSION );
    1;
} or do {
    require DynaLoader;
    push @ISA, 'DynaLoader';
    __PACKAGE__->bootstrap( $VERSION );
};

sub import {
    my ($base, @args) = @_;

    my $do_init = 1;
    my $init_version = undef;

    while (my $arg = shift @args) {
        if ($arg eq '-no-init') {
            $do_init = 0;
        }
        elsif ($arg eq '-init') {
            $do_init = 1;

            if (!@args) {
                require Carp;
                Carp::croak ('-init requires a version number to pass to Crypt::GpgME->check_version');
            }

            $init_version = shift @args;
        }
        else {
            $base->VERSION($arg);
        }
    }

    if ($do_init) {
        $base->check_version( defined $init_version ? $init_version : () );
    }
}

1;

__END__
=head1 NAME

Crypt::GpgME - Perl interface to libgpgme

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

    use IO::File;
    use Crypt::GpgME;

    my $ctx = Crypt::GpgME->new;

    $ctx->set_passphrase_cb(sub { 'abc' });

    my $signed = $ctx->sign( IO::File->new('some_file', 'r') );

    print while <$signed>;

=head1 FUNCTIONS

=head2 GPGME_VERSION

    my $version = Crypt::GpgME->GPGME_VERSION;
    my $version = $ctx->GPGME_VERSION;

Returns a string containing the libgpgme version number this module has been
compiled against.

=head2 new

    my $ctx = Crypt::GpgME->new;

Returns a new Crypt::GpgME instance. Throws an exception on error.

=head1 AUTHOR

Florian Ragwitz, C<< <rafl at debian.org> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-crypt-gpgme at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Crypt-GpgME>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Crypt::GpgME

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Crypt-GpgME>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Crypt-GpgME>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Crypt-GpgME>

=item * Search CPAN

L<http://search.cpan.org/dist/Crypt-GpgME>

=back

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

Copyright 2007 Florian Ragwitz, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
