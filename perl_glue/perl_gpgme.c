#include "perl_gpgme.h"

void
_perl_gpgme_call_xs (pTHX_ void (*subaddr) (pTHX_ CV *), CV *cv, SV **mark) {
	dSP;
	PUSHMARK (mark);
	(*subaddr) (aTHX_ cv);
	PUTBACK;
}

SV *
perl_gpgme_new_sv_from_ptr (void *ptr, const char *class) {
	SV *obj, *sv;
	HV *stash;

	obj = (SV *)newHV ();
	sv_magic (obj, 0, PERL_MAGIC_ext, (const char *)ptr, 0);
	sv = newRV_noinc (obj);
	stash = gv_stashpv (class, 0);
	sv_bless (sv, stash);

	return sv;
}

void *
perl_gpgme_get_ptr_from_sv (SV *sv, const char *class) {
	MAGIC *mg;

	if (!(mg = perl_gpgme_get_magic_from_sv (sv, class))) {
		return NULL; /* TODO: croak? */
	}

	return (void *)mg->mg_ptr;
}

MAGIC *
perl_gpgme_get_magic_from_sv (SV *sv, const char *class) {
	MAGIC *mg;

	if (!sv || !SvOK (sv) || !SvROK (sv)
	 || (class && !sv_derived_from (sv, class))
	 || !(mg = mg_find (SvRV (sv), PERL_MAGIC_ext))) {
		return NULL; /* TODO: croak? */
	}

	return mg;
}

void
perl_gpgme_assert_error (gpgme_error_t err) {
	if (err == GPG_ERR_NO_ERROR) {
		return;
	}

	croak ("%s: %s", gpgme_strsource (err), gpgme_strerror (err));
}

perl_gpgme_callback_t *
perl_gpgme_callback_new (SV *func, SV *data, SV *obj, int n_params, perl_gpgme_callback_param_type_t param_types[]) {
	perl_gpgme_callback_t *cb;

	cb = (perl_gpgme_callback_t *)malloc (sizeof (perl_gpgme_callback_t));
	memset (cb, 0, sizeof (perl_gpgme_callback_t));

	cb->func = newSVsv (func);

	if (data) {
		cb->data = newSVsv (data);
	}

	if (obj) {
		SvREFCNT_inc (obj);
		cb->obj = obj;
	}

	cb->n_params = n_params;

	if (cb->n_params) {
		if (!param_types) {
			croak ("n_params is %d, but param_types is NULL", n_params);
		}

		cb->param_types = (perl_gpgme_callback_param_type_t *)malloc (sizeof (perl_gpgme_callback_param_type_t) * n_params);
		memcpy (cb->param_types, param_types, n_params * sizeof (perl_gpgme_callback_param_type_t));
	}

#ifdef PERL_IMPLICIT_CONTEXT
	cb->priv = aTHX;
#endif

	return cb;
}

void
perl_gpgme_callback_invoke (perl_gpgme_callback_t *cb, ...) {
	va_list va_args;

	dPERL_GPGME_CALLBACK_MARSHAL_SP;

	if (!cb) {
		croak ("NULL cb in callback_invoke");
	}

	PERL_GPGME_MARSHAL_INIT (cb);

	ENTER;
	SAVETMPS;

	PUSHMARK (sp);

	if (cb->obj) {
		XPUSHs (cb->obj);
	}

	va_start (va_args, cb);

	/* TODO: EXTEND first */
	if (cb->n_params > 0) {
		int i;

		for (i = 0; i < cb->n_params; i++) {
			SV *sv;

			switch (cb->param_types[i]) {
				case PERL_GPGME_CALLBACK_PARAM_TYPE_STR:
					sv = newSVpv (va_arg (va_args, char *), 0);
					break;
				case PERL_GPGME_CALLBACK_PARAM_TYPE_INT:
					sv = newSViv (va_arg (va_args, int));
					break;
				default:
					PUTBACK;
					croak ("unknown perl_gpgme_callback_param_type_t");
			}

			if (!sv) {
				PUTBACK;
				croak ("failed to convert value to sv");
			}

			XPUSHs (sv);
			/* TODO: free sv? */
		}
	}

	va_end (va_args);

	if (cb->data) {
		XPUSHs (cb->data);
	}

	PUTBACK;

	call_sv (cb->func, G_DISCARD); /* TODO: return values needed */

	FREETMPS;
	LEAVE;
}
