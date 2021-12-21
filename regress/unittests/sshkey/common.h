/* 	$OpenBSD: common.h,v 1.2 2018/09/13 09:03:20 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
struct sshbuf *load_file(const char *name);

/* Load a text file into a buffer */
struct sshbuf *load_text_file(const char *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(const char *name);

/* Tests for key components */
int has_rsa_n(struct sshkey *k);
int has_rsa_e(struct sshkey *k);
int has_rsa_p(struct sshkey *k);
int has_rsa_q(struct sshkey *k);
int has_dsa_g(struct sshkey *k);
int has_dsa_pub_key(struct sshkey *k);
int has_dsa_priv_key(struct sshkey *k);
int has_ec_pub_key(struct sshkey *k);
int has_ec_priv_key(struct sshkey *k);

int with_rsa_n(struct sshkey *k, const BIGNUM *exp);
int with_rsa_e(struct sshkey *k, const BIGNUM *exp);
int with_rsa_p(struct sshkey *k, const BIGNUM *exp);
int with_rsa_q(struct sshkey *k, const BIGNUM *exp);
int with_dsa_g(struct sshkey *k, const BIGNUM *exp);
int with_dsa_pub_key(struct sshkey *k, const BIGNUM *exp);
int with_dsa_priv_key(struct sshkey *k, const BIGNUM *exp);

int rsa_n_size(struct sshkey *k);
