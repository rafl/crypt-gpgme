#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <proto.h>

#include "ppport.h"

#include <gpgme.h>
#include <string.h>

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

typedef enum {
	PERL_GPGME_CALLBACK_PARAM_TYPE_STR,
	PERL_GPGME_CALLBACK_PARAM_TYPE_INT
} perl_gpgme_callback_param_type_t;

typedef struct perl_gpgme_callback_St {
	SV *func;
	SV *data;
	SV *obj;
	int n_params;
	perl_gpgme_callback_param_type_t *param_types;
	void *priv;
} perl_gpgme_callback_t;

void _perl_gpgme_call_xs (pTHX_ void (*subaddr) (pTHX_ CV *cv), CV *cv, SV **mark);

SV *perl_gpgme_new_sv_from_ptr (void *ptr, const char *class);

void *perl_gpgme_get_ptr_from_sv (SV *sv, const char *class);

MAGIC *perl_gpgme_get_magic_from_sv (SV *sv, const char *class);

void perl_gpgme_assert_error (gpgme_error_t err);

perl_gpgme_callback_t *perl_gpgme_callback_new (SV *func, SV *data, SV *obj, int n_params, perl_gpgme_callback_param_type_t param_types[]);

void perl_gpgme_callback_invoke (perl_gpgme_callback_t *cb, ...);
