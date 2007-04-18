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

1;

__END__
=head1 NAME

Crypt::GpgME - Perl interface to libgpgme

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

    use Crypt::GpgME;

    my $foo = Crypt::GpgME->new();
    ...

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
