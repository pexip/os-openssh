/* 	$OpenBSD: common.c,v 1.5 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/objects.h>
#ifdef OPENSSL_HAS_NISTP256
# include <openssl/ec.h>
#endif /* OPENSSL_HAS_NISTP256 */
#endif /* WITH_OPENSSL */

#include "openbsd-compat/openssl-compat.h"

#include "../test_helper/test_helper.h"

#include "ssherr.h"
#include "authfile.h"
#include "sshkey.h"
#include "sshbuf.h"

#include "common.h"

struct sshbuf *
load_file(const char *name)
{
	struct sshbuf *ret = NULL;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, NULL);
	return ret;
}

struct sshbuf *
load_text_file(const char *name)
{
	struct sshbuf *ret = load_file(name);
	const u_char *p;

	/* Trim whitespace at EOL */
	for (p = sshbuf_ptr(ret); sshbuf_len(ret) > 0;) {
		if (p[sshbuf_len(ret) - 1] == '\r' ||
		    p[sshbuf_len(ret) - 1] == '\t' ||
		    p[sshbuf_len(ret) - 1] == ' ' ||
		    p[sshbuf_len(ret) - 1] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		else
			break;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	return ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(const char *name)
{
	BIGNUM *ret = NULL;
	struct sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (const char *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	return ret;
}

int
has_rsa_n(struct sshkey *k)
{
	BIGNUM *n = NULL;
	int r = 0;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	if (EVP_PKEY_get_bn_param(k->rsa, OSSL_PKEY_PARAM_RSA_N, &n) == 1) {
		BN_clear_free(n);
		r = 1;
	}
	return r;
}

int
has_rsa_e(struct sshkey *k)
{
	BIGNUM *e = NULL;
	int r = 0;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	if (EVP_PKEY_get_bn_param(k->rsa, OSSL_PKEY_PARAM_RSA_E, &e) == 1) {
		BN_clear_free(e);
		r = 1;
	}
	return r;
}

int
has_rsa_p(struct sshkey *k)
{
	BIGNUM *p = NULL;
	int r = 0;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	if (EVP_PKEY_get_bn_param(k->rsa, OSSL_PKEY_PARAM_RSA_FACTOR1, &p)
	    == 1) {
		BN_clear_free(p);
		r = 1;
	}
	return r;
}

int
has_rsa_q(struct sshkey *k)
{
	BIGNUM *q = NULL;
	int r = 0;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	if (EVP_PKEY_get_bn_param(k->rsa, OSSL_PKEY_PARAM_RSA_FACTOR2, &q)
	    == 1) {
		BN_clear_free(q);
		r = 1;
	}
	return r;
}

int
has_dsa_g(struct sshkey *k)
{
	BIGNUM *g = NULL;
	int r = 0;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	if (EVP_PKEY_get_bn_param(k->dsa, OSSL_PKEY_PARAM_FFC_G, &g) == 1) {
		BN_clear_free(g);
		r = 1;
	}
	return r;
}

int
has_dsa_pub_key(struct sshkey *k)
{
	BIGNUM *pub_key = NULL;
	int r = 0;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	if (EVP_PKEY_get_bn_param(k->dsa, OSSL_PKEY_PARAM_PUB_KEY, &pub_key)
	    == 1) {
		BN_clear_free(pub_key);
		r = 1;
	}
	return r;
}

int
has_dsa_priv_key(struct sshkey *k)
{
	BIGNUM *priv_key = NULL;
	int r = 0;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	if (EVP_PKEY_get_bn_param(k->dsa, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key)
	    == 1) {
		BN_clear_free(priv_key);
		r = 1;
	}
	return r;
}

int
has_ec_pub_key(struct sshkey *k)
{
	char pubbuf[4096];
	size_t publen = 0;
	int r = 0;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->ecdsa, NULL);
	if (EVP_PKEY_get_octet_string_param(k->ecdsa, OSSL_PKEY_PARAM_PUB_KEY,
	    NULL, 0, &publen) == 1) {
		ASSERT_SIZE_T_LT(publen, sizeof(pubbuf));
		if (publen > 0 && EVP_PKEY_get_octet_string_param(k->ecdsa,
		    OSSL_PKEY_PARAM_PUB_KEY, pubbuf, publen, NULL) == 1)
			r = 1;
	}
	return r;
}

int
has_ec_priv_key(struct sshkey *k)
{
	BIGNUM *priv_key = NULL;
	int r = 0;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->ecdsa, NULL);
	if (EVP_PKEY_get_bn_param(k->ecdsa, OSSL_PKEY_PARAM_PRIV_KEY,
	    &priv_key) == 1) {
		BN_clear_free(priv_key);
		r = 1;
	}
	return r;
}

int
with_rsa_n(struct sshkey *k, const BIGNUM *exp)
{
	BIGNUM *n = NULL;
	int r;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->rsa,
	    OSSL_PKEY_PARAM_RSA_N, &n), 1);
	r = BN_cmp(n, exp);
	BN_clear_free(n);
	return r == 0;
}

int
with_rsa_e(struct sshkey *k, const BIGNUM *exp)
{
	BIGNUM *e = NULL;
	int r;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->rsa,
	    OSSL_PKEY_PARAM_RSA_E, &e), 1);
	r = BN_cmp(e, exp);
	BN_clear_free(e);
	return r == 0;
}

int
with_rsa_p(struct sshkey *k, const BIGNUM *exp)
{
	BIGNUM *p = NULL;
	int r;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->rsa,
	    OSSL_PKEY_PARAM_RSA_FACTOR1, &p), 1);
	r = BN_cmp(p, exp);
	BN_clear_free(p);
	return r == 0;
}

int
with_rsa_q(struct sshkey *k, const BIGNUM *exp)
{
	BIGNUM *q = NULL;
	int r;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->rsa,
	    OSSL_PKEY_PARAM_RSA_FACTOR2, &q), 1);
	r = BN_cmp(q, exp);
	BN_clear_free(q);
	return r == 0;
}

int
with_dsa_g(struct sshkey *k, const BIGNUM *exp)
{
	BIGNUM *g = NULL;
	int r;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->dsa,
	    OSSL_PKEY_PARAM_FFC_G, &g), 1);
	r = BN_cmp(g, exp);
	BN_clear_free(g);
	return r == 0;
}

int
with_dsa_pub_key(struct sshkey *k, const BIGNUM *exp)
{
	BIGNUM *pub_key = NULL;
	int r;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->dsa,
	    OSSL_PKEY_PARAM_PUB_KEY, &pub_key), 1);
	r = BN_cmp(pub_key, exp);
	BN_clear_free(pub_key);
	return r == 0;
}

int
with_dsa_priv_key(struct sshkey *k, const BIGNUM *exp)
{
	BIGNUM *priv_key = NULL;
	int r;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->dsa,
	    OSSL_PKEY_PARAM_PRIV_KEY, &priv_key), 1);
	r = BN_cmp(priv_key, exp);
	BN_clear_free(priv_key);
	return r == 0;
}

int
rsa_n_size(struct sshkey *k)
{
	BIGNUM *n = NULL;
	int r;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->rsa,
	    OSSL_PKEY_PARAM_RSA_N, &n), 1);
	r = BN_num_bits(n);
	BN_clear_free(n);
	return r;
}

#endif /* WITH_OPENSSL */

