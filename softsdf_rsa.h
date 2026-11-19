/*
 *  softsdf_rsa.h - self-contained RSA for the SoftSDF simulator.
 *
 *  GmSSL provides no RSA primitives, so softsdf_rsa.c implements a small
 *  schoolbook bignum (32-bit limbs), Miller-Rabin prime generation and
 *  RFC 8017 PKCS#1 v1.5 encryption padding. Test-simulator only: no
 *  side-channel countermeasures.
 */

#ifndef SOFTSDF_RSA_H
#define SOFTSDF_RSA_H

#include <stddef.h>
#include <stdint.h>
#include "sdf.h"

/* RSAref key files: raw 1412-byte packed RSArefPrivateKey serialization */
int softsdf_rsa_keyfile_save(const char *path, const RSArefPrivateKey *priv);
int softsdf_rsa_keyfile_load(const char *path, RSArefPrivateKey *priv);

/* public key part of a private key (bits/m/e copy) */
void softsdf_rsa_pub_from_priv(const RSArefPrivateKey *priv, RSArefPublicKey *pub);

/* key pair generation; keybits must be 1024 or 2048 */
int softsdf_rsa_keygen(unsigned int keybits, RSArefPublicKey *pub, RSArefPrivateKey *priv);

/* structural check: N == p*q, e*d == 1 (mod p-1 && mod q-1), CRT fields consistent */
int softsdf_rsa_check_keypair(const RSArefPublicKey *pub, const RSArefPrivateKey *priv);

/* raw modular exponentiation: in is big-endian, <= modulus byte length,
 * value must be < modulus; out is modulus-length, left zero padded */
int softsdf_rsa_public_op(const RSArefPublicKey *pub,
	const uint8_t *in, size_t inlen, uint8_t *out);
int softsdf_rsa_private_op(const RSArefPrivateKey *priv,
	const uint8_t *in, size_t inlen, uint8_t *out);

/* RFC 8017 EME-PKCS1-v1_5 type 2 (encrypt/decrypt) */
int softsdf_rsa_pkcs1_encrypt(const RSArefPublicKey *pub,
	const uint8_t *in, size_t inlen, uint8_t *out); /* out = modulus bytes */
int softsdf_rsa_pkcs1_decrypt(const RSArefPrivateKey *priv,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int softsdf_rsa_pkcs1_unpad(const uint8_t *em, size_t emlen,
	uint8_t *out, size_t *outlen);

#endif
