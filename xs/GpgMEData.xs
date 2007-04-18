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
gpgme_data_read (data, sv, size)
		gpgme_data_t data
		SV *sv
		size_t size
	PREINIT:
		char *buffer;
	INIT:
		buffer = (char *)malloc (sizeof (char) * size);
	C_ARGS:
		data, buffer, size
	POSTCALL:
		sv_setpvn_mg (sv, buffer, RETVAL);
	CLEANUP:
		free (buffer);

ssize_t
gpgme_data_write (data, sv, size=0)
		gpgme_data_t data
		SV *sv
		size_t size
	PREINIT:
		char *buffer;
	INIT:
		if (!size) {
			buffer = SvPV (sv, size);
		}
		else {
			STRLEN tmp_size;
			buffer = SvPV (sv, tmp_size);

			if (size > tmp_size) {
				size = tmp_size;
			}
		}
	C_ARGS:
		data, buffer, size
