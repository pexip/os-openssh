/*	$OpenBSD: sshbuf-getput-crypto.c,v 1.8 2019/11/15 06:00:20 djm Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller
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

#define SSHBUF_INTERNAL
#include "includes.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/evp.h>
#ifdef OPENSSL_HAS_ECC
# include <openssl/ec.h>
#endif /* OPENSSL_HAS_ECC */

#include "ssherr.h"
#include "sshbuf.h"

#include "openbsd-compat/openssl-compat.h"

int
sshbuf_get_bignum2(struct sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	const u_char *d;
	size_t len;
	int r;

	if (valp != NULL)
		*valp = NULL;
	if ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		return r;
	if (valp != NULL) {
		if ((v = BN_new()) == NULL ||
		    BN_bin2bn(d, len, v) == NULL) {
			BN_clear_free(v);
			return SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	return 0;
}

#ifdef OPENSSL_HAS_ECC
static int
get_ec(const u_char *d, size_t len, EC_POINT *v, const EC_GROUP *g)
{
	/* Refuse overlong bignums */
	if (len == 0 || len > SSHBUF_MAX_ECPOINT)
		return SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	if (*d != POINT_CONVERSION_UNCOMPRESSED)
		return SSH_ERR_INVALID_FORMAT;
	if (v != NULL && EC_POINT_oct2point(g, v, d, len, NULL) != 1)
		return SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	return 0;
}

int
sshbuf_get_ec(struct sshbuf *buf, EC_POINT *v, const EC_GROUP *g)
{
	const u_char *d;
	size_t len;
	int r;

	if ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		return r;
	if ((r = get_ec(d, len, v, g)) != 0)
		return r;
	/* Skip string */
	if (sshbuf_get_string_direct(buf, NULL, NULL) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		return SSH_ERR_INTERNAL_ERROR;
	}
	return 0;
}
#endif /* OPENSSL_HAS_ECC */

int
sshbuf_put_bignum2(struct sshbuf *buf, const BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	int len = BN_num_bytes(v), prepend = 0, r;

	if (len < 0 || len > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	if (BN_bn2bin(v, d + 1) != len)
		return SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	if (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	if ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, sizeof(d));
		return r;
	}
	explicit_bzero(d, sizeof(d));
	return 0;
}

#ifdef OPENSSL_HAS_ECC
int
sshbuf_put_ec(struct sshbuf *buf, const EC_POINT *v, const EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	int ret;

	if ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    NULL, 0, NULL)) > SSHBUF_MAX_ECPOINT) {
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, NULL) != len) {
		return SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	return ret;
}

int
sshbuf_put_eckey(struct sshbuf *buf, const EVP_PKEY *v)
{
	char *curve = NULL, *pub = NULL;
	size_t curve_len = 0, pub_len = 0;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	int nid = -1, r;

	if (EVP_PKEY_get_utf8_string_param(v,
	    OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &curve_len) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((curve = malloc(curve_len + 1)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_get_utf8_string_param(v,
	    OSSL_PKEY_PARAM_GROUP_NAME, curve, curve_len + 1,
	    NULL) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_get_octet_string_param(v,
	    OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((pub = malloc(pub_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_get_octet_string_param(v,
	    OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len, NULL) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((nid = OBJ_sn2nid(curve)) == NID_undef) {
		r = SSH_ERR_EC_CURVE_INVALID;
		goto out;
	}
	if ((group = EC_GROUP_new_by_curve_name(nid)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((point = EC_POINT_new(group)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EC_POINT_oct2point(group, point, pub, pub_len, NULL) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	r = sshbuf_put_ec(buf, point, group);
out:
	EC_POINT_free(point);
	EC_GROUP_free(group);
	free(pub);
	free(curve);
	return r;
}
#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
