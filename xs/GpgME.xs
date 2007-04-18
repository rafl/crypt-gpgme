#include "perl_gpgme.h"

gpgme_error_t
perl_gpgme_passphrase_cb (void *user_data, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
	char *buf;
	perl_gpgme_callback_retval_t *retvals;
	perl_gpgme_callback_t *cb = (perl_gpgme_callback_t *)user_data;

	retvals = (perl_gpgme_callback_retval_t *)malloc (sizeof (perl_gpgme_callback_retval_t) * 1);
	printf ("c callback\n");

	perl_gpgme_callback_invoke (cb, &retvals, uid_hint, passphrase_info, prev_was_bad, fd);

	buf = (char *)retvals[0];

	write (fd, buf, strlen (buf));
	write (fd, "\n", 1);

	/* FIXME: free retvals? */

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
		perl_gpgme_callback_retval_type_t retval_types[1];
		gpgme_ctx_t c_ctx;
	INIT:
		param_types[0] = PERL_GPGME_CALLBACK_PARAM_TYPE_STR; /* uid_hint */
		param_types[1] = PERL_GPGME_CALLBACK_PARAM_TYPE_STR; /* passphrase_info */
		param_types[2] = PERL_GPGME_CALLBACK_PARAM_TYPE_INT; /* prev_was_bad */
		param_types[3] = PERL_GPGME_CALLBACK_PARAM_TYPE_INT; /* fd */
	CODE:
		printf ("set callback\n");
		c_ctx = (gpgme_ctx_t)perl_gpgme_get_ptr_from_sv (ctx, "Crypt::GpgME");
		printf ("ctx: 0x%x\n", (unsigned int)c_ctx);

		cb = perl_gpgme_callback_new (func, user_data, ctx, 4, param_types, 1, retval_types);
		printf ("cb: 0x%x\n", (unsigned int)cb);

		gpgme_set_passphrase_cb (c_ctx, perl_gpgme_passphrase_cb, cb);

NO_OUTPUT gpgme_error_t
gpgme_set_locale (ctx, category, value)
		perl_gpgme_ctx_or_null_t ctx
		int category
		const char *value

gpgme_data_t
gpgme_sign (ctx, plain, mode=GPGME_SIG_MODE_NORMAL)
		gpgme_ctx_t ctx
		gpgme_data_t plain
		gpgme_sig_mode_t mode
	PREINIT:
		gpgme_error_t err;
	INIT:
		err = gpgme_data_new (&RETVAL);
		perl_gpgme_assert_error (err);
	CODE:
		err = gpgme_op_sign (ctx, plain, RETVAL, mode);
	POSTCALL:
		perl_gpgme_assert_error (err);
	OUTPUT:
		RETVAL

BOOT:
	gpgme_check_version (NULL);
	PERL_GPGME_CALL_BOOT (boot_Crypt__GpgME__Data);
