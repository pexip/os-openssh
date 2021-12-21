/* $OpenBSD: kexdh.c,v 1.34 2020/12/04 02:29:25 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "openbsd-compat/openssl-compat.h"

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "dh.h"
#include "log.h"

int
kex_dh_keygen(struct kex *kex)
{
	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		break;
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		break;
	case KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		break;
	case KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (kex->dh == NULL)
		return SSH_ERR_ALLOC_FAIL;
	return (dh_gen_key(kex->dh, kex->we_need * 8));
}

int
kex_dh_compute_key(struct kex *kex, BIGNUM *dh_pub, struct sshbuf *out)
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *peer_key = NULL;
	BIGNUM *dh_p = NULL, *dh_g = NULL, *shared_secret = NULL;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_pub));
	EVP_PKEY_print_params_fp(stderr, kex->dh, 0, NULL);
	fprintf(stderr, "\n");
#endif

	if (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}

	if (EVP_PKEY_get_bn_param(kex->dh,
	    OSSL_PKEY_PARAM_FFC_P, &dh_p) == 0 ||
	    EVP_PKEY_get_bn_param(kex->dh,
	    OSSL_PKEY_PARAM_FFC_G, &dh_g) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((bld = OSSL_PARAM_BLD_new()) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, dh_p) == 0 ||
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, dh_g) == 0 ||
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, dh_pub) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((params = OSSL_PARAM_BLD_to_param(bld)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_fromdata_init(pctx) <= 0 ||
	    EVP_PKEY_fromdata(pctx, &peer_key,
	    EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	EVP_PKEY_CTX_free(pctx);

	if ((pctx = EVP_PKEY_CTX_new(kex->dh, NULL)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_derive_init(pctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(pctx, peer_key) <= 0 ||
	    EVP_PKEY_derive(pctx, NULL, &klen) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((kbuf = malloc(klen)) == NULL ||
	    (shared_secret = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_derive(pctx, kbuf, &klen) <= 0 ||
	    BN_bin2bn(kbuf, (int) klen, shared_secret) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, klen);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(peer_key);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_clear_free(dh_p);
	BN_clear_free(dh_g);
	return r;
}

int
kex_dh_keypair(struct kex *kex)
{
	BIGNUM *pub_key = NULL;
	struct sshbuf *buf = NULL;
	int r;

	if ((r = kex_dh_keygen(kex)) != 0)
		return r;
	if (EVP_PKEY_get_bn_param(kex->dh,
	    OSSL_PKEY_PARAM_PUB_KEY, &pub_key) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_bignum2(buf, pub_key)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
#ifdef DEBUG_KEXDH
	EVP_PKEY_print_params_fp(stderr, kex->dh, 0, NULL);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_key);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	BN_clear_free(pub_key);
	return r;
}

int
kex_dh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	BIGNUM *pub_key = NULL;
	struct sshbuf *server_blob = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if ((r = kex_dh_keygen(kex)) != 0)
		goto out;
	if (EVP_PKEY_get_bn_param(kex->dh,
	    OSSL_PKEY_PARAM_PUB_KEY, &pub_key) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_bignum2(server_blob, pub_key)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;
	if ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
 out:
	BN_clear_free(pub_key);
	EVP_PKEY_free(kex->dh);
	kex->dh = NULL;
	sshbuf_free(server_blob);
	return r;
}

int
kex_dh_dec(struct kex *kex, const struct sshbuf *dh_blob,
    struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	BIGNUM *dh_pub = NULL;
	int r;

	*shared_secretp = NULL;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		goto out;
	sshbuf_reset(buf);
	if ((r = kex_dh_compute_key(kex, dh_pub, buf)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	BN_free(dh_pub);
	EVP_PKEY_free(kex->dh);
	kex->dh = NULL;
	sshbuf_free(buf);
	return r;
}
#endif /* WITH_OPENSSL */
