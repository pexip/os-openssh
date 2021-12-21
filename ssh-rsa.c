/* $OpenBSD: ssh-rsa.c,v 1.67 2018/07/03 11:39:54 djm Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "compat.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "log.h"

#include "openbsd-compat/openssl-compat.h"

static const char *
rsa_hash_alg_ident(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return "ssh-rsa";
	case SSH_DIGEST_SHA256:
		return "rsa-sha2-256";
	case SSH_DIGEST_SHA512:
		return "rsa-sha2-512";
	}
	return NULL;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
static int
rsa_hash_id_from_ident(const char *ident)
{
	if (strcmp(ident, "ssh-rsa") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(ident, "rsa-sha2-256") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(ident, "rsa-sha2-512") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
static int
rsa_hash_id_from_keyname(const char *alg)
{
	int r;

	if ((r = rsa_hash_id_from_ident(alg)) != -1)
		return r;
	if (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

static int
rsa_hash_alg_nid(int type)
{
	switch (type) {
	case SSH_DIGEST_SHA1:
		return NID_sha1;
	case SSH_DIGEST_SHA256:
		return NID_sha256;
	case SSH_DIGEST_SHA512:
		return NID_sha512;
	default:
		return -1;
	}
}

//XXX(ossl3): rename to something more meaningful
int
ssh_rsa_complete_crt_parameters(const BIGNUM *p, const BIGNUM *q,
    const BIGNUM *d, BIGNUM **dmp1, BIGNUM **dmq1)
{
	BIGNUM *aux = NULL, *d_consttime = NULL;
	BIGNUM *rsa_dmq1 = NULL, *rsa_dmp1 = NULL;
	BN_CTX *ctx = NULL;
	int r;

	if ((ctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((aux = BN_new()) == NULL ||
	    (rsa_dmq1 = BN_new()) == NULL ||
	    (rsa_dmp1 = BN_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((d_consttime = BN_dup(d)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	if ((BN_sub(aux, q, BN_value_one()) == 0) ||
	    (BN_mod(rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, p, BN_value_one()) == 0) ||
	    (BN_mod(rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	*dmp1 = rsa_dmp1;
	*dmq1 = rsa_dmq1;
	rsa_dmp1 = rsa_dmq1 = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	BN_CTX_free(ctx);
	return r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg_ident)
{
	EVP_PKEY_CTX *sctx = NULL;
	const EVP_MD *evp_md = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sig = NULL;
	size_t slen = 0;
	u_int dlen, len;
	int hash_alg, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg_ident == NULL || strlen(alg_ident) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_id_from_keyname(alg_ident);
	if (key == NULL || key->rsa == NULL || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;
	if (EVP_PKEY_bits(key->rsa) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;
	if (EVP_PKEY_size(key->rsa) > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;

	/* hash the data */
	evp_md = EVP_get_digestbynid(rsa_hash_alg_nid(hash_alg));
	if (evp_md == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if ((sctx = EVP_PKEY_CTX_new(key->rsa, NULL)) == NULL) {
		ret =  SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_sign_init(sctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PADDING) <= 0 ||
	    EVP_PKEY_CTX_set_signature_md(sctx, evp_md) <= 0 ||
	    EVP_PKEY_sign(sctx, NULL, &slen, digest, dlen) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((sig = malloc(slen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_sign(sctx, sig, &slen, digest, dlen) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(sctx);
	explicit_bzero(digest, sizeof(digest));
	freezero(sig, slen);
	sshbuf_free(b);
	return ret;
}

int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen, const u_char *data, size_t datalen,
    const char *alg)
{
	EVP_PKEY_CTX *sctx = NULL;
	const EVP_MD *evp_md = NULL;
	char *sigtype = NULL;
	int hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, dlen;
	struct sshbuf *b = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sigblob = NULL;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if (EVP_PKEY_bits(key->rsa) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		if ((want_alg = rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;
	evp_md = EVP_get_digestbynid(rsa_hash_alg_nid(hash_alg));
	if (evp_md == NULL) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((sctx = EVP_PKEY_CTX_new(key->rsa, NULL)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_verify_init(sctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PADDING) <= 0 ||
	    EVP_PKEY_CTX_set_signature_md(sctx, evp_md) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	switch (EVP_PKEY_verify(sctx, sigblob, len, digest, dlen)) {
	case 1:
		ret = 0;
		break;
	case 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		break;
	default:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		break;
	}
 out:
	EVP_PKEY_CTX_free(sctx);
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, sizeof(digest));
	return ret;
}
#endif /* WITH_OPENSSL */
