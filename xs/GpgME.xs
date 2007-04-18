#include "perl_gpgme.h"

gpgme_error_t
perl_gpgme_passphrase_cb (void *user_data, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
	perl_gpgme_callback_t *cb = (perl_gpgme_callback_t *)user_data;

	perl_gpgme_callback_invoke (cb, uid_hint, passphrase_info, prev_was_bad, fd);

	return 0; /* FIXME */
}

MODULE = Crypt::GpgME	PACKAGE = Crypt::GpgME	PREFIX = gpgme_

PROTOTYPES: ENABLE

gpgme_ctx_t
gpgme_new (class)
	PREINIT:
		gpgme_error_t err;
	CODE:
		err = gpgme_new (&RETVAL);
	POSTCALL:
		perl_gpgme_assert_error (err);
	OUTPUT:
		RETVAL

void
DESTROY (ctx)
		gpgme_ctx_t ctx
	CODE:
		gpgme_release (ctx);

NO_OUTPUT gpgme_error_t
gpgme_set_protocol (ctx, proto=GPGME_PROTOCOL_OpenPGP)
		gpgme_ctx_t ctx
		gpgme_protocol_t proto
	POSTCALL:
		perl_gpgme_assert_error (RETVAL);

gpgme_protocol_t
gpgme_get_protocol (ctx)
		gpgme_ctx_t ctx

void
gpgme_set_armor (ctx, armor)
		gpgme_ctx_t ctx
		int armor

int
gpgme_get_armor (ctx)
		gpgme_ctx_t ctx

void
gpgme_set_textmode (ctx, textmode)
		gpgme_ctx_t ctx
		int textmode

int
gpgme_get_textmode (ctx)
		gpgme_ctx_t ctx

void
gpgme_set_include_certs (ctx, nr_of_certs=GPGME_INCLUDE_CERTS_DEFAULT)
		gpgme_ctx_t ctx
		int nr_of_certs

int
gpgme_get_include_certs (ctx)
		gpgme_ctx_t ctx

NO_OUTPUT gpgme_error_t
gpgme_set_keylist_mode (ctx, mode=GPGME_KEYLIST_MODE_LOCAL)
		gpgme_ctx_t ctx
		gpgme_keylist_mode_t mode
	POSTCALL:
		perl_gpgme_assert_error (RETVAL);

gpgme_keylist_mode_t
gpgme_get_keylist_mode (ctx)
		gpgme_ctx_t ctx

void
gpgme_set_passphrase_cb (ctx, func, user_data=NULL)
		SV *ctx
		SV *func
		SV *user_data
	PREINIT:
		perl_gpgme_callback_t *cb;
		perl_gpgme_callback_param_type_t param_types[4];
		gpgme_ctx_t c_ctx;
	INIT:
		param_types[0] = PERL_GPGME_CALLBACK_PARAM_TYPE_STR;
		param_types[1] = PERL_GPGME_CALLBACK_PARAM_TYPE_STR;
		param_types[2] = PERL_GPGME_CALLBACK_PARAM_TYPE_INT;
		param_types[3] = PERL_GPGME_CALLBACK_PARAM_TYPE_INT;
	CODE:
		c_ctx = (gpgme_ctx_t)perl_gpgme_get_ptr_from_sv (ctx, "Crypt::GpgME");

		cb = perl_gpgme_callback_new (func, user_data, ctx, 4, param_types);

		gpgme_set_passphrase_cb (c_ctx, perl_gpgme_passphrase_cb, cb);
