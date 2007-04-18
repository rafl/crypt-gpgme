#include "perl_gpgme.h"

MODULE = Crypt::GpgME::Data	PACKAGE = Crypt::GpgME::Data	PREFIX = gpgme_data_

PROTOTYPES: ENABLE

gpgme_data_t
gpgme_data_new (class)
	PREINIT:
		gpgme_error_t err;
	CODE:
		err = gpgme_data_new (&RETVAL);
	POSTCALL:
		perl_gpgme_assert_error (err);
	OUTPUT:
		RETVAL

#TODO: set errno?
ssize_t
gpgme_data_read (data, buffer, size)
		gpgme_data_t data
		SV *buffer
		size_t size
	INIT:
		SvUPGRADE (buffer, SVt_PV);
		SvGROW (buffer, size);
	C_ARGS:
		data, SvPVX (buffer), size

ssize_t
gpgme_data_write (data, buffer, size=SvLEN (buffer))
		gpgme_data_t data
		SV *buffer
		size_t size
	INIT:
		SvUPGRADE (buffer, SVt_PV);
		SvGROW (buffer, size);
	C_ARGS:
		data, SvPVX (buffer), size
