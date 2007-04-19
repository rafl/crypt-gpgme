#include "perl_gpgme.h"

gpgme_error_t
perl_gpgme_passphrase_cb (void *user_data, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
	char *buf;
	perl_gpgme_callback_retval_t retvals[1];
	perl_gpgme_callback_t *cb = (perl_gpgme_callback_t *)user_data;

	perl_gpgme_callback_invoke (cb, retvals, uid_hint, passphrase_info, prev_was_bad, fd);

	buf = (char *)retvals[0];

	write (fd, buf, strlen (buf));
	write (fd, "\n", 1);

	free (buf);

	return 0; /* FIXME */
}

void
perl_gpgme_progress_cb (void *user_data, const char *what, int type, int current, int total) {
	perl_gpgme_callback_t *cb = (perl_gpgme_callback_t *)user_data;

	perl_gpgme_callback_invoke (cb, NULL, what, type, current, total);
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
	PREINIT:
		perl_gpgme_callback_t *cb = NULL;
		gpgme_passphrase_cb_t pass_cb;
	CODE:
		gpgme_get_passphrase_cb (ctx, &pass_cb, (void **)&cb);
		if (cb) {
			perl_gpgme_callback_destroy (cb);
		}

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
		perl_gpgme_callback_t *cb = NULL;
		perl_gpgme_callback_param_type_t param_types[4];
		perl_gpgme_callback_retval_type_t retval_types[1];
		gpgme_ctx_t c_ctx;
		gpgme_passphrase_cb_t pass_cb;
	INIT:
		param_types[0] = PERL_GPGME_CALLBACK_PARAM_TYPE_STR; /* uid_hint */
		param_types[1] = PERL_GPGME_CALLBACK_PARAM_TYPE_STR; /* passphrase_info */
		param_types[2] = PERL_GPGME_CALLBACK_PARAM_TYPE_INT; /* prev_was_bad */
		param_types[3] = PERL_GPGME_CALLBACK_PARAM_TYPE_INT; /* fd */
	CODE:
		c_ctx = (gpgme_ctx_t)perl_gpgme_get_ptr_from_sv (ctx, "Crypt::GpgME");

		gpgme_get_passphrase_cb (c_ctx, &pass_cb, (void **)&cb);

		if (cb) {
			perl_gpgme_callback_destroy (cb);
		}

		cb = perl_gpgme_callback_new (func, user_data, ctx, 4, param_types, 1, retval_types);

		gpgme_set_passphrase_cb (c_ctx, perl_gpgme_passphrase_cb, cb);

void
gpgme_set_progress_cb (ctx, func, user_data=NULL)
		SV *ctx
		SV *func
		SV *user_data
	PREINIT:
		perl_gpgme_callback_t *cb = NULL;
		perl_gpgme_callback_param_type_t param_types[4];
		gpgme_ctx_t c_ctx;
		gpgme_progress_cb_t prog_cb;
	INIT:
		param_types[0] = PERL_GPGME_CALLBACK_PARAM_TYPE_STR;  /* what */
		param_types[1] = PERL_GPGME_CALLBACK_PARAM_TYPE_CHAR; /* type */
		param_types[2] = PERL_GPGME_CALLBACK_PARAM_TYPE_INT;  /* current */
		param_types[3] = PERL_GPGME_CALLBACK_PARAM_TYPE_INT;  /* total */
	CODE:
		c_ctx = (gpgme_ctx_t)perl_gpgme_get_ptr_from_sv (ctx, "Crypt::GpgME");

		gpgme_get_progress_cb (c_ctx, &prog_cb, (void **)&cb);

		if (cb) {
			perl_gpgme_callback_destroy (cb);
		}

		cb = perl_gpgme_callback_new (func, user_data, ctx, 4, param_types, 0, NULL);

		gpgme_set_progress_cb (c_ctx, perl_gpgme_progress_cb, cb);

NO_OUTPUT gpgme_error_t
gpgme_set_locale (ctx, category, value)
		perl_gpgme_ctx_or_null_t ctx
		int category
		const char *value

void
gpgme_get_engine_info (ctx)
		perl_gpgme_ctx_or_null_t ctx
	PREINIT:
		gpgme_engine_info_t info, i;
	PPCODE:
		if (ctx == NULL) {
			gpgme_error_t err;
			err = gpgme_get_engine_info (&info);
			perl_gpgme_assert_error (err);
		}
		else {
			info = gpgme_ctx_get_engine_info (ctx);
		}

		for (i = info; i != NULL; i = i->next) {
			SV *sv = perl_gpgme_hashref_from_engine_info (i);
			sv_2mortal (sv);
			XPUSHs (sv);
		}

NO_OUTPUT gpgme_error_t
gpgme_set_engine_info (ctx, proto, file_name, home_dir)
		perl_gpgme_ctx_or_null_t ctx
		gpgme_protocol_t proto
		const char *file_name
		const char *home_dir
	CODE:
		if (ctx == NULL) {
			RETVAL = gpgme_set_engine_info (proto, file_name, home_dir);
		}
		else {
			RETVAL = gpgme_ctx_set_engine_info (ctx, proto, file_name, home_dir);
		}
	POSTCALL:
		perl_gpgme_assert_error (RETVAL);

void
gpgme_signers_clear (ctx)
		gpgme_ctx_t ctx

NO_OUTPUT gpgme_error_t
gpgme_signers_add (ctx, key)
		gpgme_ctx_t ctx
		const gpgme_key_t key
	POSTCALL:
		perl_gpgme_assert_error (RETVAL);

gpgme_key_t
gpgme_signers_enum (ctx, seq)
		gpgme_ctx_t ctx
		int seq

void
gpgme_sig_notation_clear (ctx)
		gpgme_ctx_t ctx

NO_OUTPUT gpgme_error_t
gpgme_sig_notation_add (ctx, name, value, flags=0)
		gpgme_ctx_t ctx
		const char *name
		const char *value
		gpgme_sig_notation_flags_t flags

void
gpgme_sig_notation_get (ctx)
		gpgme_ctx_t ctx
	PREINIT:
		gpgme_sig_notation_t notations, i;
	PPCODE:
		notations = gpgme_sig_notation_get (ctx);

		for (i = notations; i != NULL; i = i->next) {
			XPUSHs (sv_2mortal (perl_gpgme_hashref_from_notation (i)));
		}

gpgme_key_t
gpgme_get_key (ctx, fpr, secret=0)
		gpgme_ctx_t ctx
		const char *fpr
		int secret
	PREINIT:
		gpgme_error_t err;
	CODE:
		err = gpgme_get_key (ctx, fpr, &RETVAL, secret);
	POSTCALL:
		perl_gpgme_assert_error (err);
	OUTPUT:
		RETVAL

NO_OUTPUT gpgme_error_t
gpgme_cancel (ctx)
		gpgme_ctx_t ctx
	POSTCALL:
		perl_gpgme_assert_error (RETVAL);

void
gpgme_verify (ctx, sig, signed_text=NULL)
		gpgme_ctx_t ctx
		gpgme_data_t sig
		gpgme_data_t signed_text
	PREINIT:
		gpgme_error_t err;
		gpgme_data_t plain = NULL;
		gpgme_verify_result_t result;
	PPCODE:
		if (!signed_text) {
			err = gpgme_data_new (&plain);
			perl_gpgme_assert_error (err);
		}

		err = gpgme_op_verify (ctx, sig, signed_text, plain);
		perl_gpgme_assert_error (err);

		result = gpgme_op_verify_result (ctx);

		XPUSHs (sv_2mortal (perl_gpgme_hashref_from_verify_result (result)));

		if (!signed_text) {
			XPUSHs (sv_2mortal (perl_gpgme_new_sv_from_ptr (plain, "Crypt::GpgME::Data")));
		}

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
		gpgme_data_seek (RETVAL, 0, SEEK_SET);
	OUTPUT:
		RETVAL

NO_OUTPUT gpgme_error_t
gpgme_engine_check_version (ctx, proto)
		perl_gpgme_ctx_or_null_t ctx
		gpgme_protocol_t proto
	C_ARGS:
		proto
	POSTCALL:
		perl_gpgme_assert_error (RETVAL);

BOOT:
	gpgme_check_version (NULL);
	PERL_GPGME_CALL_BOOT (boot_Crypt__GpgME__Key);
	PERL_GPGME_CALL_BOOT (boot_Crypt__GpgME__Data);
