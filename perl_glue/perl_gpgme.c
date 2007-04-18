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
perl_gpgme_callback_new (SV *func, SV *data, SV *obj, int n_params, perl_gpgme_callback_param_type_t param_types[], int n_retvals, perl_gpgme_callback_retval_type_t retval_types[]) {
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

	cb->n_retvals = n_retvals;

	if (cb->n_retvals) {
		if (!retval_types) {
			croak ("n_retvals is %d, but retval_types is NULL", n_retvals);
		}

		cb->retval_types = (perl_gpgme_callback_retval_type_t *)malloc (sizeof (perl_gpgme_callback_retval_type_t) * n_retvals);
		memcpy (cb->retval_types, retval_types, n_retvals * sizeof (perl_gpgme_callback_retval_type_t));
	}

#ifdef PERL_IMPLICIT_CONTEXT
	cb->priv = aTHX;
#endif

	return cb;
}

void
perl_gpgme_callback_destroy (perl_gpgme_callback_t *cb) {
	if (cb) {
		if (cb->func) {
			SvREFCNT_dec (cb->func);
			cb->func = NULL;
		}

		if (cb->data) {
			SvREFCNT_dec (cb->func);
			cb->func = NULL;
		}

		if (cb->obj) {
			SvREFCNT_dec (cb->obj);
			cb->obj = NULL;
		}

		if (cb->param_types) {
			free (cb->param_types);
			cb->n_params = 0;
			cb->param_types = NULL;
		}

		if (cb->retval_types) {
			free (cb->retval_types);
			cb->n_retvals = 0;
			cb->retval_types = NULL;
		}

		free (cb);
	}
}

void
perl_gpgme_callback_invoke (perl_gpgme_callback_t *cb, perl_gpgme_callback_retval_t *retvals, ...) {
	va_list va_args;
	int ret, i;
	I32 call_flags;

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

	va_start (va_args, retvals);

	/* TODO: EXTEND first */
	if (cb->n_params > 0) {
		for (i = 0; i < cb->n_params; i++) {
			SV *sv;

			switch (cb->param_types[i]) {
				case PERL_GPGME_CALLBACK_PARAM_TYPE_STR:
					sv = newSVpv (va_arg (va_args, char *), 0);
					break;
				case PERL_GPGME_CALLBACK_PARAM_TYPE_INT:
					sv = newSViv (va_arg (va_args, int));
					break;
				case PERL_GPGME_CALLBACK_PARAM_TYPE_CHAR: {
					char tmp[2];
					tmp[0] = va_arg (va_args, int);
					tmp[1] = '\0';

					sv = newSVpv (tmp, 2);
					break;
				}
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

	if (cb->n_retvals == 0) {
		call_flags = G_VOID|G_DISCARD;
	}
	else if (cb->n_retvals == 1) {
		call_flags = G_SCALAR;
	}
	else {
		call_flags = G_ARRAY;
	}

	ret = call_sv (cb->func, call_flags);

	SPAGAIN;

	if (ret != cb->n_retvals) {
		PUTBACK;
		croak ("callback didn't return as much values as expected (got: %d, expected: %d)", ret, cb->n_retvals);
	}

	for (i = 0; i < ret; i++) {
		switch (cb->retval_types[i]) {
			case PERL_GPGME_CALLBACK_RETVAL_TYPE_STR:
				retvals[i] = (perl_gpgme_callback_retval_t)strdup (POPp);
				break;
			default:
				PUTBACK;
				croak ("unknown perl_gpgme_callback_retval_type_t");
		}
	}

	PUTBACK;
	FREETMPS;
	LEAVE;
}

SV *
perl_gpgme_protocol_to_string (gpgme_protocol_t protocol) {
	SV *ret;

	switch (protocol) {
		case GPGME_PROTOCOL_OpenPGP:
			ret = newSVpvn ("openpgp", 7);
			break;
		case GPGME_PROTOCOL_CMS:
			ret = newSVpvn ("cms", 3);
			break;
		default:
			croak ("unknown protocol");
	}

	return ret;
}

SV *
perl_gpgme_hashref_from_engine_info (gpgme_engine_info_t info) {
	SV *sv;
	HV *hv;

	hv = newHV ();

	/* TODO: error checking */
	if (info->file_name) {
		hv_store (hv, "file_name", 9, newSVpv (info->file_name, 0), 0);
	}

	if (info->home_dir) {
		hv_store (hv, "home_dir", 8, newSVpv (info->home_dir, 0), 0);
	}

	if (info->version) {
		hv_store (hv, "version", 7, newSVpv (info->version, 0), 0);
	}

	if (info->req_version) {
		hv_store (hv, "req_version", 11, newSVpv (info->req_version, 0), 0);
	}

	hv_store (hv, "protocol", 8, perl_gpgme_protocol_to_string (info->protocol), 0);

	sv = newRV_noinc ((SV *)hv);
	return sv;
}

SV *
perl_gpgme_pubkey_algo_to_string (gpgme_pubkey_algo_t algo) {
	SV *ret;

	switch (algo) {
		case GPGME_PK_RSA:
			ret = newSVpvn ("rsa", 3);
			break;
		case GPGME_PK_RSA_E:
			ret = newSVpvn ("rsa-e", 5);
			break;
		case GPGME_PK_RSA_S:
			ret = newSVpvn ("rsa-s", 5);
			break;
		case GPGME_PK_ELG_E:
			ret = newSVpvn ("elg-e", 5);
			break;
		case GPGME_PK_DSA:
			ret = newSVpvn ("dsa", 3);
			break;
		case GPGME_PK_ELG:
			ret = newSVpvn ("elg", 3);
			break;
		default:
			croak ("unknown pubkey algo");
	}

	return ret;
}

SV *
perl_gpgme_hashref_from_subkey (gpgme_subkey_t subkey) {
	SV *sv;
	HV *hv;

	hv = newHV ();

	/* TODO: error checking */
	hv_store (hv, "revoked", 7, newSVuv (subkey->revoked), 0);
	hv_store (hv, "expored", 7, newSVuv (subkey->expired), 0);
	hv_store (hv, "disabled", 8, newSVuv (subkey->disabled), 0);
	hv_store (hv, "invaid", 6, newSVuv (subkey->invalid), 0);
	hv_store (hv, "can_encrypt", 11, newSVuv (subkey->can_encrypt), 0);
	hv_store (hv, "can_sign", 8, newSVuv (subkey->can_sign), 0);
	hv_store (hv, "can_certify", 11, newSVuv (subkey->can_certify), 0);
	hv_store (hv, "secret", 6, newSVuv (subkey->secret), 0);
	hv_store (hv, "can_authenticate", 16, newSVuv (subkey->can_authenticate), 0);
	hv_store (hv, "is_qualified", 12, newSVuv (subkey->is_qualified), 0);
	hv_store (hv, "pubkey_algo", 8, perl_gpgme_pubkey_algo_to_string (subkey->pubkey_algo), 0);
	hv_store (hv, "length", 6, newSVuv (subkey->length), 0);

	if (subkey->keyid) {
		hv_store (hv, "keyid", 5, newSVpv (subkey->keyid, 0), 0);
	}

	if (subkey->fpr) {
		hv_store (hv, "fpr", 3, newSVpv (subkey->fpr, 0), 0);
	}

	hv_store (hv, "timestamp", 9, newSViv (subkey->timestamp), 0); /* FIXME: long int vs. int? */
	hv_store (hv, "expires", 7, newSViv (subkey->expires), 0); /* ditto */

	sv = newRV_noinc ((SV *)hv);
	return sv;
}

SV *
perl_gpgme_hashref_from_uid (gpgme_user_id_t uid) {
	SV *sv;
	HV *hv;

	hv = newHV ();

	hv_store (hv, "revoked", 7, newSVuv (uid->revoked), 0);
	hv_store (hv, "invalid", 7, newSVuv (uid->invalid), 0);
	hv_store (hv, "validity", 8, perl_gpgme_validity_to_string (uid->validity), 0);

	if (uid->uid) {
		hv_store (hv, "uid", 3, newSVpv (uid->uid, 0), 0);
	}

	if (uid->name) {
		hv_store (hv, "name", 4, newSVpv (uid->name, 0), 0);
	}

	if (uid->email) {
		hv_store (hv, "email", 5, newSVpv (uid->email, 0), 0);
	}

	if (uid->comment) {
		hv_store (hv, "comment", 7, newSVpv (uid->comment, 0), 0);
	}

	if (uid->signatures) {
		hv_store (hv, "signatures", 10, perl_gpgme_array_ref_from_signatures (uid->signatures), 0);
	}

	sv = newRV_noinc ((SV *)hv);
	return sv;
}

SV *
perl_gpgme_array_ref_from_signatures (gpgme_key_sig_t sig) {
	SV *sv;
	AV *av;
	gpgme_key_sig_t i;

	for (i = sig; i != NULL; i = i->next) {
		av_push (av, perl_gpgme_hashref_from_signature (i));
	}

	sv = newRV_noinc ((SV *)av);
	return sv;
}

SV *
perl_gpgme_hashref_from_signature (gpgme_key_sig_t sig) {
	SV *sv;
	HV *hv;

	/* TODO: error checking */
	hv_store (hv, "revoked", 7, newSVuv (sig->revoked), 0);
	hv_store (hv, "expired", 7, newSVuv (sig->expired), 0);
	hv_store (hv, "invalid", 7, newSVuv (sig->invalid), 0);
	hv_store (hv, "exportable", 10, newSVuv (sig->exportable), 0);
	hv_store (hv, "pubkey_algo", 11, perl_gpgme_pubkey_algo_to_string (sig->pubkey_algo), 0);

	if (sig->keyid) {
		hv_store (hv, "keyid", 5, newSVpv (sig->keyid, 0), 0);
	}

	hv_store (hv, "timestamp", 9, newSViv (sig->timestamp), 0); /* FIXME: long int vs. IV? */
	hv_store (hv, "expires", 7, newSViv (sig->expires), 0); /* ditto */

	if (sig->status != GPG_ERR_NO_ERROR) {
		hv_store (hv, "status", 6, newSVpvf ("%s: %s", gpgme_strsource (sig->status), gpgme_strerror (sig->status)), 0);
	}

	if (sig->uid) {
		hv_store (hv, "uid", 3, newSVpv (sig->uid, 0), 0);
	}

	if (sig->name) {
		hv_store (hv, "name", 4, newSVpv (sig->name, 0), 0);
	}

	if (sig->email) {
		hv_store (hv, "email", 5, newSVpv (sig->email, 0), 0);
	}

	if (sig->comment) {
		hv_store (hv, "comment", 7, newSVpv (sig->comment, 0), 0);
	}

	/* FIXME: really export this? */
	hv_store (hv, "sig_class", 9, newSVuv (sig->sig_class), 0);

	if (sig->notations) {
		hv_store (hv, "notations", 9, perl_gpgme_array_ref_from_notations (sig->notations), 0);
	}

	sv = newRV_noinc ((SV *)hv);
	return sv;
}

SV *
perl_gpgme_array_ref_from_notations (gpgme_sig_notation_t notations) {
	SV *sv;
	AV *av;
	gpgme_sig_notation_t i;

	for (i = notations; i != NULL; i = i->next) {
		av_push (av, perl_gpgme_hashref_from_notation (i));
	}

	sv = newRV_noinc ((SV *)av);
	return sv;
}

SV *
perl_gpgme_hashref_from_notation (gpgme_sig_notation_t notation) {
	SV *sv;
	HV *hv;

	if (notation->name) {
		hv_store (hv, "name", 4, newSVpv (notation->name, notation->name_len), 0);
	}

	if (notation->value) {
		hv_store (hv, "value", 5, newSVpv (notation->value, notation->value_len), 0);
	}

	/* Don't store the flags. It's human_readable | critical anyway */

	hv_store (hv, "human_readable", 14, newSVuv (notation->human_readable), 0);
	hv_store (hv, "critical", 8, newSVuv (notation->critical), 0);

	sv = newRV_noinc ((SV *)hv);
	return sv;
}

SV *
perl_gpgme_validity_to_string (gpgme_validity_t validity) {
	SV *ret;

	switch (validity) {
		case GPGME_VALIDITY_UNKNOWN:
			ret = newSVpvn ("unknown", 7);
			break;
		case GPGME_VALIDITY_UNDEFINED:
			ret = newSVpvn ("undefined", 9);
			break;
		case GPGME_VALIDITY_NEVER:
			ret = newSVpvn ("never", 5);
			break;
		case GPGME_VALIDITY_MARGINAL:
			ret = newSVpvn ("marginal", 8);
			break;
		case GPGME_VALIDITY_FULL:
			ret = newSVpvn ("full", 4);
			break;
		case GPGME_VALIDITY_ULTIMATE:
			ret = newSVpvn ("ultimate", 8);
			break;
		default:
			croak ("unknown validity");
	}

	return ret;
}
