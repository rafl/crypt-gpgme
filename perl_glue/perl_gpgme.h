#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <proto.h>

#include "ppport.h"

#include <gpgme.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "perl_gpgme_data.h"


#define PERL_GPGME_CALL_BOOT(name) \
	{ \
		EXTERN_C XS(name); \
		_perl_gpgme_call_xs (aTHX_ name, cv, mark); \
	}

#ifdef PERL_IMPLICIT_CONTEXT

#define dPERL_GPGME_CALLBACK_MARSHAL_SP \
	SV **sp;

#define PERL_GPGME_MARSHAL_INIT(cb) \
	PERL_SET_CONTEXT (cb->priv); \
	SPAGAIN;

#else

#define dPERL_GPGME_CALLBACK_MARSHAL_SP \
	dSP;

#define PERL_GPGME_MARSHAL_INIT(cb) \
	/* nothing to do */

#endif

typedef gpgme_ctx_t perl_gpgme_ctx_or_null_t;

typedef struct perl_gpgme_status_code_map_St {
	gpgme_status_code_t status;
	const char *string;
} perl_gpgme_status_code_map_t;

static perl_gpgme_status_code_map_t perl_gpgme_status_code_map[] = {
	{ GPGME_STATUS_EOF, "eof" },

	{ GPGME_STATUS_ENTER, "enter" },
	{ GPGME_STATUS_LEAVE, "leave" },
	{ GPGME_STATUS_ABORT, "abort" },

	{ GPGME_STATUS_GOODSIG, "goodsig" },
	{ GPGME_STATUS_BADSIG, "badsig" },
	{ GPGME_STATUS_ERRSIG, "errsig" },

	{ GPGME_STATUS_BADARMOR, "badarmor" },

	{ GPGME_STATUS_RSA_OR_IDEA, "rsa-or-idea" },
	{ GPGME_STATUS_KEYEXPIRED, "keyexpired" },
	{ GPGME_STATUS_KEYREVOKED, "keyrevoked" },

	{ GPGME_STATUS_TRUST_UNDEFINED, "trust-undefined" },
	{ GPGME_STATUS_TRUST_NEVER, "trust-never" },
	{ GPGME_STATUS_TRUST_MARGINAL, "trust-marginal" },
	{ GPGME_STATUS_TRUST_FULLY, "trust-fully" },
	{ GPGME_STATUS_TRUST_ULTIMATE, "trust-ultimate" },

	{ GPGME_STATUS_SHM_INFO, "shm-info" },
	{ GPGME_STATUS_SHM_GET, "shm-get" },
	{ GPGME_STATUS_SHM_GET_BOOL, "shm-get-bool" },
	{ GPGME_STATUS_SHM_GET_HIDDEN, "shm-get-hidden" },

	{ GPGME_STATUS_NEED_PASSPHRASE, "need-passphrase" },
	{ GPGME_STATUS_VALIDSIG, "validsig" },
	{ GPGME_STATUS_SIG_ID, "sig-id" },
	{ GPGME_STATUS_ENC_TO, "enc-to" },
	{ GPGME_STATUS_NODATA, "nodata" },
	{ GPGME_STATUS_BAD_PASSPHRASE, "bad-passphrase" },
	{ GPGME_STATUS_NO_PUBKEY, "no-pubkey" },
	{ GPGME_STATUS_NO_SECKEY, "no-seckey" },
	{ GPGME_STATUS_NEED_PASSPHRASE_SYM, "need-passphrase-sym" },
	{ GPGME_STATUS_DECRYPTION_FAILED, "decryption-failed" },
	{ GPGME_STATUS_DECRYPTION_OKAY, "decryption-okay" },
	{ GPGME_STATUS_MISSING_PASSPHRASE, "missing-passphrase" },
	{ GPGME_STATUS_GOOD_PASSPHRASE, "good-passphrase" },
	{ GPGME_STATUS_GOODMDC, "goodmdc" },
	{ GPGME_STATUS_BADMDC, "badmdc" },
	{ GPGME_STATUS_ERRMDC, "errmdc" },
	{ GPGME_STATUS_IMPORTED, "imported" },
	{ GPGME_STATUS_IMPORT_OK, "import-ok" },
	{ GPGME_STATUS_IMPORT_PROBLEM, "status-import-problem" },
	{ GPGME_STATUS_IMPORT_RES, "import-res" },
	{ GPGME_STATUS_FILE_START, "file-start" },
	{ GPGME_STATUS_FILE_DONE, "file-done" },
	{ GPGME_STATUS_FILE_ERROR, "file-error" },

	{ GPGME_STATUS_BEGIN_DECRYPTION, "begin-decryption" },
	{ GPGME_STATUS_END_DECRYPTION, "end-decryption" },
	{ GPGME_STATUS_BEGIN_ENCRYPTION, "begin-encryption" },
	{ GPGME_STATUS_END_ENCRYPTION, "end-encryption" },

	{ GPGME_STATUS_DELETE_PROBLEM, "delete-problem" },
	{ GPGME_STATUS_GET_BOOL, "get-bool" },
	{ GPGME_STATUS_GET_LINE, "get-line" },
	{ GPGME_STATUS_GET_HIDDEN, "get-hidden" },
	{ GPGME_STATUS_GOT_IT, "got-it" },
	{ GPGME_STATUS_PROGRESS, "progress" },
	{ GPGME_STATUS_SIG_CREATED, "sig-created" },
	{ GPGME_STATUS_SESSION_KEY, "session-key" },
	{ GPGME_STATUS_NOTATION_NAME, "notation-name" },
	{ GPGME_STATUS_NOTATION_DATA, "notation-data" },
	{ GPGME_STATUS_POLICY_URL, "policy-url" },
	{ GPGME_STATUS_BEGIN_STREAM, "begin-stream" },
	{ GPGME_STATUS_END_STREAM, "end-stream" },
	{ GPGME_STATUS_KEY_CREATED, "key-created" },
	{ GPGME_STATUS_USERID_HINT, "userid-hint" },
	{ GPGME_STATUS_UNEXPECTED, "unexpected" },
	{ GPGME_STATUS_INV_RECP, "inv-recp" },
	{ GPGME_STATUS_NO_RECP, "no-recp" },
	{ GPGME_STATUS_ALREADY_SIGNED, "already-signed" },
	{ GPGME_STATUS_SIGEXPIRED, "sigexpired" },
	{ GPGME_STATUS_EXPSIG, "expsig" },
	{ GPGME_STATUS_EXPKEYSIG, "expkeysig" },
	{ GPGME_STATUS_TRUNCATED, "truncated" },
	{ GPGME_STATUS_ERROR, "error" },
	{ GPGME_STATUS_NEWSIG, "newsig" },
	{ GPGME_STATUS_REVKEYSIG, "revkeysig" },
	{ GPGME_STATUS_SIG_SUBPACKET, "sig-subpacket" },
	{ GPGME_STATUS_NEED_PASSPHRASE_PIN, "need-passphrase-pin" },
	{ GPGME_STATUS_SC_OP_FAILURE, "sc-op-failure" },
	{ GPGME_STATUS_SC_OP_SUCCESS, "sc-op-success" },
	{ GPGME_STATUS_CARDCTRL, "cardctrl" },
	{ GPGME_STATUS_BACKUP_KEY_CREATED, "backup-key-created" },
	{ GPGME_STATUS_PKA_TRUST_BAD, "pka-trust-bad" },
	{ GPGME_STATUS_PKA_TRUST_GOOD, "pka-trust-good" },

	{ GPGME_STATUS_PLAINTEXT, "plaintext" },
	{ 0, NULL }
};

typedef enum {
	PERL_GPGME_CALLBACK_PARAM_TYPE_STR,
	PERL_GPGME_CALLBACK_PARAM_TYPE_INT,
	PERL_GPGME_CALLBACK_PARAM_TYPE_CHAR,
	PERL_GPGME_CALLBACK_PARAM_TYPE_STATUS
} perl_gpgme_callback_param_type_t;

typedef enum {
	PERL_GPGME_CALLBACK_RETVAL_TYPE_STR
} perl_gpgme_callback_retval_type_t;

typedef void * perl_gpgme_callback_retval_t;

typedef struct perl_gpgme_callback_St {
	SV *func;
	SV *data;
	SV *obj;
	int n_params;
	perl_gpgme_callback_param_type_t *param_types;
	int n_retvals;
	perl_gpgme_callback_retval_type_t *retval_types;
	void *priv;
} perl_gpgme_callback_t;

void _perl_gpgme_call_xs (pTHX_ void (*subaddr) (pTHX_ CV *cv), CV *cv, SV **mark);

SV *perl_gpgme_new_sv_from_ptr (void *ptr, const char *class);

void *perl_gpgme_get_ptr_from_sv (SV *sv, const char *class);

MAGIC *perl_gpgme_get_magic_from_sv (SV *sv, const char *class);

void perl_gpgme_assert_error (gpgme_error_t err);

perl_gpgme_callback_t *perl_gpgme_callback_new (SV *func, SV *data, SV *obj, int n_params, perl_gpgme_callback_param_type_t param_types[], int n_retvals, perl_gpgme_callback_retval_type_t retval_types[]);

void perl_gpgme_callback_destroy (perl_gpgme_callback_t *cb);

void perl_gpgme_callback_invoke (perl_gpgme_callback_t *cb, perl_gpgme_callback_retval_t *retvals, ...);

SV *perl_gpgme_protocol_to_string (gpgme_protocol_t protocol);

SV *perl_gpgme_hashref_from_engine_info (gpgme_engine_info_t info);

SV *perl_gpgme_hashref_from_subkey (gpgme_subkey_t subkey);

SV *perl_gpgme_hashref_from_uid (gpgme_user_id_t uid);

SV *perl_gpgme_validity_to_string (gpgme_validity_t validity);

SV *perl_gpgme_array_ref_from_signatures (gpgme_key_sig_t sig);

SV *perl_gpgme_hashref_from_signature (gpgme_key_sig_t sig);

SV *perl_gpgme_array_ref_from_notations (gpgme_sig_notation_t notations);

SV *perl_gpgme_hashref_from_notation (gpgme_sig_notation_t notation);

SV *perl_gpgme_hashref_from_verify_result (gpgme_verify_result_t result);

SV *perl_gpgme_array_ref_from_verify_signatures (gpgme_signature_t sigs);

SV *perl_gpgme_hashref_from_verify_signature (gpgme_signature_t sig);

SV *perl_gpgme_sigsum_to_string (gpgme_sigsum_t summary);

SV *perl_gpgme_hash_algo_to_string (gpgme_hash_algo_t algo);

SV *perl_gpgme_hashref_from_trust_item (gpgme_trust_item_t item);

SV *perl_gpgme_sv_from_status_code (gpgme_status_code_t status);
