/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/sm2.h>
#include <gmssl/hmac.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include "sdf.h"
#include "softsdf_rsa.h"

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "Error: %s:%d: check failed: %s\n", \
			__FILE__, __LINE__, #cond); \
		return -1; \
	} \
} while (0)

#define CHECK_RV(expr) do { \
	int rv_ = (expr); \
	if (rv_ != SDR_OK) { \
		fprintf(stderr, "Error: %s: 0x%X\n", #expr, rv_); \
		return -1; \
	} \
} while (0)

static const char *test_pass = "P@ssw0rd";

/* device handle needed by test_agreement for an extra session */
static void *deviceHandleGlobal = NULL;

/* ---- hash (baseline) ---- */

static int test_hash(void *hSession)
{
	unsigned char ucData[3] = { 0x61, 0x62, 0x63 };
	unsigned char ucHash[32];
	unsigned int uiHashLength = 0;
	SM3_CTX sm3_ctx;
	unsigned char dgst[32];

	CHECK_RV(SDF_HashInit(hSession, SGD_SM3, NULL, NULL, 0));
	CHECK_RV(SDF_HashUpdate(hSession, ucData, sizeof(ucData)));
	CHECK_RV(SDF_HashFinal(hSession, ucHash, &uiHashLength));

	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, ucData, sizeof(ucData));
	sm3_finish(&sm3_ctx, dgst);

	CHECK(uiHashLength == 32);
	CHECK(memcmp(ucHash, dgst, 32) == 0);

	/* step machine: Update after Final must fail */
	{
		int rv = SDF_HashUpdate(hSession, ucData, sizeof(ucData));
		CHECK(rv == SDR_STEPERR);
	}
	return 0;
}

/* ---- SDF_ImportKey ---- */

static int test_importkey(void *hSession)
{
	unsigned char key16[16];
	unsigned char pt[16], ct_dev[16], ct_ref[16];
	unsigned int ctlen = sizeof(ct_dev);
	void *kh = NULL;
	SM4_KEY sk;
	int rv;

	if (rand_bytes(key16, sizeof(key16)) != 1)
		return -1;
	if (rand_bytes(pt, sizeof(pt)) != 1)
		return -1;

	CHECK_RV(SDF_ImportKey(hSession, key16, sizeof(key16), &kh));
	CHECK_RV(SDF_Encrypt(hSession, kh, SGD_SM4_ECB, NULL, pt, sizeof(pt),
		ct_dev, &ctlen));
	CHECK(ctlen == sizeof(pt));

	sm4_set_encrypt_key(&sk, key16);
	sm4_encrypt_blocks(&sk, pt, 1, ct_ref);
	CHECK(memcmp(ct_dev, ct_ref, 16) == 0);

	/* invalid lengths */
	{
		void *bad = NULL;
		rv = SDF_ImportKey(hSession, key16, 0, &bad);
		CHECK(rv == SDR_INARGERR);
		rv = SDF_ImportKey(hSession, key16, 65, &bad);
		CHECK(rv == SDR_INARGERR);
	}
	return 0;
}

/* ---- HMAC (GB/T 15852.2 via SDF_HMACInit/Update/Final) ---- */

static int test_hmac(void *hSession)
{
	unsigned char key[32];
	unsigned char msg[] = "abc";
	unsigned char mac[64], ref[64];
	unsigned int maclen = 0;
	size_t ref_len = 0;
	void *kh = NULL;
	int rv;

	if (rand_bytes(key, sizeof(key)) != 1)
		return -1;
	CHECK_RV(SDF_ImportKey(hSession, key, sizeof(key), &kh));

	/* SM3 HMAC: multi-step equals GmSSL one-shot */
	CHECK_RV(SDF_HMACInit(hSession, kh, SGD_SM3));
	CHECK_RV(SDF_HMACUpdate(hSession, msg, sizeof(msg) - 1));
	CHECK_RV(SDF_HMACFinal(hSession, mac, &maclen));
	CHECK(maclen == 32);
	CHECK(hmac(DIGEST_sm3(), key, sizeof(key), msg, sizeof(msg) - 1,
		ref, &ref_len) == 1);
	CHECK(ref_len == 32);
	CHECK(memcmp(mac, ref, 32) == 0);

	/* SHA256 HMAC: digest identifier mapping */
	maclen = 0;
	CHECK_RV(SDF_HMACInit(hSession, kh, SGD_SHA256));
	CHECK_RV(SDF_HMACUpdate(hSession, msg, sizeof(msg) - 1));
	CHECK_RV(SDF_HMACFinal(hSession, mac, &maclen));
	CHECK(maclen == 32);
	CHECK(hmac(DIGEST_sha256(), key, sizeof(key), msg, sizeof(msg) - 1,
		ref, &ref_len) == 1);
	CHECK(memcmp(mac, ref, 32) == 0);

	/* step machine and algorithm rejection */
	rv = SDF_HMACUpdate(hSession, msg, sizeof(msg) - 1);
	CHECK(rv == SDR_STEPERR);
	CHECK_RV(SDF_HMACInit(hSession, kh, SGD_SM3));
	rv = SDF_HMACFinal(hSession, mac, &maclen);
	CHECK(rv == SDR_OK);
	rv = SDF_HMACFinal(hSession, mac, &maclen);
	CHECK(rv == SDR_STEPERR);
	rv = SDF_HMACInit(hSession, kh, SGD_SHA1);
	CHECK(rv == SDR_ALGNOTSUPPORT);
	return 0;
}

/* ---- multi-packet symmetric (GM/T 0018-2023 6.5) ---- */

/* Init/Update(splits)/Final with tight capacities like real callers
 * (Update: exactly split bytes, Final: 16) to prove the device-side
 * deferred output handling; result appended to out */
static int multipart_encrypt(void *h, void *key, unsigned int alg,
	unsigned char *iv, const unsigned char *data, unsigned int len,
	const unsigned int *splits, int nsplits,
	unsigned char *out, unsigned int *outlen)
{
	unsigned int total = 0;
	unsigned int off = 0;
	int i;

	CHECK_RV(SDF_EncryptInit(h, key, alg, iv, iv ? 16 : 0));
	for (i = 0; i < nsplits; i++) {
		unsigned int cap = splits[i];
		CHECK(off + splits[i] <= len);
		CHECK_RV(SDF_EncryptUpdate(h, (unsigned char *)data + off,
			splits[i], out + total, &cap));
		off += splits[i];
		total += cap;
	}
	CHECK(off == len);
	{
		unsigned int cap = 16;
		CHECK_RV(SDF_EncryptFinal(h, out + total, &cap));
		total += cap;
	}
	*outlen = total;
	return 0;
}

static int multipart_decrypt(void *h, void *key, unsigned int alg,
	unsigned char *iv, const unsigned char *data, unsigned int len,
	const unsigned int *splits, int nsplits,
	unsigned char *out, unsigned int *outlen)
{
	unsigned int total = 0;
	unsigned int off = 0;
	int i;

	CHECK_RV(SDF_DecryptInit(h, key, alg, iv, iv ? 16 : 0));
	for (i = 0; i < nsplits; i++) {
		unsigned int cap = splits[i];
		CHECK(off + splits[i] <= len);
		CHECK_RV(SDF_DecryptUpdate(h, (unsigned char *)data + off,
			splits[i], out + total, &cap));
		off += splits[i];
		total += cap;
	}
	CHECK(off == len);
	{
		unsigned int cap = 16;
		CHECK_RV(SDF_DecryptFinal(h, out + total, &cap));
		total += cap;
	}
	*outlen = total;
	return 0;
}

static int test_multipart(void *h)
{
	unsigned char key[16], iv[16];
	unsigned char data[32];
	unsigned char enc_one[64], enc_multi[64];
	unsigned char dec_one[64], dec_multi[64];
	unsigned int enc_one_len, enc_multi_len, dec_one_len, dec_multi_len;
	unsigned char mac_one[16], mac_multi[16];
	unsigned int mac_one_len = sizeof(mac_one);
	unsigned int mac_multi_len = sizeof(mac_multi);
	void *kh = NULL;
	int rv;

	if (rand_bytes(key, sizeof(key)) != 1)
		return -1;
	if (rand_bytes(iv, sizeof(iv)) != 1)
		return -1;
	if (rand_bytes(data, sizeof(data)) != 1)
		return -1;
	CHECK_RV(SDF_ImportKey(h, key, sizeof(key), &kh));

	/* CBC: unaligned splits must equal the one-shot result (encrypt) and
	 * both decrypt paths must recover the plaintext */
	{
		static const unsigned int esplits[3] = { 5, 12, 15 };
		static const unsigned int dsplits[3] = { 7, 9, 16 };

		enc_one_len = sizeof(enc_one);
		CHECK_RV(SDF_Encrypt(h, kh, SGD_SM4_CBC, iv, data, sizeof(data),
			enc_one, &enc_one_len));
		CHECK(enc_one_len == sizeof(data));
		CHECK(multipart_encrypt(h, kh, SGD_SM4_CBC, iv, data,
			sizeof(data), esplits, 3, enc_multi, &enc_multi_len) == 0);
		CHECK(enc_multi_len == enc_one_len);
		CHECK(memcmp(enc_multi, enc_one, enc_one_len) == 0);

		dec_one_len = sizeof(dec_one);
		CHECK_RV(SDF_Decrypt(h, kh, SGD_SM4_CBC, iv, enc_multi,
			enc_multi_len, dec_one, &dec_one_len));
		dec_multi_len = sizeof(dec_multi);
		CHECK(multipart_decrypt(h, kh, SGD_SM4_CBC, iv, enc_one,
			enc_one_len, dsplits, 3, dec_multi, &dec_multi_len) == 0);
		CHECK(dec_one_len == sizeof(data));
		CHECK(dec_multi_len == sizeof(data));
		CHECK(memcmp(dec_one, data, sizeof(data)) == 0);
		CHECK(memcmp(dec_multi, data, sizeof(data)) == 0);
	}

	/* ECB: trailing partial block rejected (no padding semantics) */
	{
		CHECK_RV(SDF_EncryptInit(h, kh, SGD_SM4_ECB, NULL, 0));
		{
			unsigned int cap = 16;
			CHECK_RV(SDF_EncryptUpdate(h, data, 16, enc_one, &cap));
			CHECK(cap == 16);
			cap = 8;
			CHECK_RV(SDF_EncryptUpdate(h, data + 16, 5, enc_one, &cap));
			CHECK(cap == 0);	/* pending block buffered */
		}
		{
			unsigned int cap = 16;
			rv = SDF_EncryptFinal(h, enc_one, &cap);
			CHECK(rv == SDR_INARGERR);
		}
	}

	/* CTR: odd splits round trip equals one-shot */
	{
		static const unsigned int splits[3] = { 3, 10, 19 };
		enc_one_len = sizeof(enc_one);
		CHECK_RV(SDF_Encrypt(h, kh, SGD_SM4_CTR, iv, data, sizeof(data),
			enc_one, &enc_one_len));
		CHECK(enc_one_len == sizeof(data));
		CHECK(multipart_encrypt(h, kh, SGD_SM4_CTR, iv, data,
			sizeof(data), splits, 3, enc_multi, &enc_multi_len) == 0);
		CHECK(enc_multi_len == enc_one_len);
		CHECK(memcmp(enc_multi, enc_one, enc_one_len) == 0);

		dec_one_len = sizeof(dec_one);
		CHECK_RV(SDF_Decrypt(h, kh, SGD_SM4_CTR, iv, enc_one, enc_one_len,
			dec_one, &dec_one_len));
		CHECK(dec_one_len == sizeof(data));
		CHECK(memcmp(dec_one, data, sizeof(data)) == 0);
	}

	/* CBC-MAC: Init/Update/Final equals the one-shot CalculateMAC */
	{
		static const unsigned int splits[3] = { 8, 8, 16 };
		unsigned int off = 0;
		int i;

		CHECK_RV(SDF_CalculateMAC(h, kh, SGD_SM4_MAC, iv, data,
			sizeof(data), mac_one, &mac_one_len));
		CHECK(mac_one_len == 16);

		CHECK_RV(SDF_CalculateMACInit(h, kh, SGD_SM4_MAC, iv, 16));
		for (i = 0; i < 3; i++) {
			CHECK_RV(SDF_CalculateMACUpdate(h, data + off, splits[i]));
			off += splits[i];
		}
		CHECK(off == sizeof(data));
		CHECK_RV(SDF_CalculateMACFinal(h, mac_multi, &mac_multi_len));
		CHECK(mac_multi_len == 16);
		CHECK(memcmp(mac_one, mac_multi, 16) == 0);
	}

	/* step machine: Update/Final without Init */
	{
		unsigned int cap = 16;
		rv = SDF_EncryptUpdate(h, data, 16, enc_one, &cap);
		CHECK(rv == SDR_STEPERR);
		rv = SDF_CalculateMACFinal(h, mac_one, &mac_one_len);
		CHECK(rv == SDR_STEPERR);
	}
	return 0;
}

/* ---- authenticated encryption (GM/T 0018-2023 表13) ---- */

static int test_authenc(void *h)
{
	unsigned char key[16];
	unsigned char iv12[12], iv9[9];
	unsigned char aad[13], pt[42];
	unsigned char ct[64], ct2[64], tag[16], tag2[16];
	unsigned char pt2[64];
	unsigned int ctlen, taglen, ptlen;
	void *kh = NULL;
	SM4_KEY sk;
	int rv;

	if (rand_bytes(key, sizeof(key)) != 1)
		return -1;
	if (rand_bytes(iv12, sizeof(iv12)) != 1)
		return -1;
	if (rand_bytes(iv9, sizeof(iv9)) != 1)
		return -1;
	if (rand_bytes(aad, sizeof(aad)) != 1)
		return -1;
	if (rand_bytes(pt, sizeof(pt)) != 1)
		return -1;
	CHECK_RV(SDF_ImportKey(h, key, sizeof(key), &kh));

	/* GCM one-shot equals GmSSL */
	ctlen = sizeof(ct);
	taglen = sizeof(tag);
	CHECK_RV(SDF_AuthEnc(h, kh, SGD_SM4_GCM, iv12, sizeof(iv12),
		aad, sizeof(aad), pt, sizeof(pt), ct, &ctlen, tag, &taglen));
	CHECK(ctlen == sizeof(pt));
	CHECK(taglen == 16);
	sm4_set_encrypt_key(&sk, key);
	CHECK(sm4_gcm_encrypt(&sk, iv12, sizeof(iv12), aad, sizeof(aad),
		pt, sizeof(pt), ct2, 16, tag2) == 1);
	CHECK(memcmp(ct, ct2, sizeof(pt)) == 0);
	CHECK(memcmp(tag, tag2, 16) == 0);

	/* GCM round trip + tampered tag rejected */
	ptlen = sizeof(pt2);
	CHECK_RV(SDF_AuthDec(h, kh, SGD_SM4_GCM, iv12, sizeof(iv12),
		aad, sizeof(aad), tag, 16, ct, ctlen, pt2, &ptlen));
	CHECK(ptlen == sizeof(pt));
	CHECK(memcmp(pt2, pt, sizeof(pt)) == 0);
	tag[0] ^= 0x01;
	rv = SDF_AuthDec(h, kh, SGD_SM4_GCM, iv12, sizeof(iv12),
		aad, sizeof(aad), tag, 16, ct, ctlen, pt2, &ptlen);
	CHECK(rv == SDR_VERIFYERR);
	tag[0] ^= 0x01;

	/* CCM one-shot round trip + tampered AAD rejected */
	ctlen = sizeof(ct);
	taglen = sizeof(tag);
	CHECK_RV(SDF_AuthEnc(h, kh, SGD_SM4_CCM, iv9, sizeof(iv9),
		aad, sizeof(aad), pt, sizeof(pt), ct, &ctlen, tag, &taglen));
	CHECK(ctlen == sizeof(pt));
	CHECK(taglen == 16);
	ptlen = sizeof(pt2);
	CHECK_RV(SDF_AuthDec(h, kh, SGD_SM4_CCM, iv9, sizeof(iv9),
		aad, sizeof(aad), tag, 16, ct, ctlen, pt2, &ptlen));
	CHECK(ptlen == sizeof(pt));
	CHECK(memcmp(pt2, pt, sizeof(pt)) == 0);
	aad[0] ^= 0x01;
	rv = SDF_AuthDec(h, kh, SGD_SM4_CCM, iv9, sizeof(iv9),
		aad, sizeof(aad), tag, 16, ct, ctlen, pt2, &ptlen);
	CHECK(rv == SDR_VERIFYERR);
	aad[0] ^= 0x01;

	/* start variable length validation: GCM 1..64, CCM 7..13 */
	ctlen = sizeof(ct);
	taglen = sizeof(tag);
	rv = SDF_AuthEnc(h, kh, SGD_SM4_GCM, NULL, 12, aad, 0, pt, sizeof(pt),
		ct, &ctlen, tag, &taglen);
	CHECK(rv == SDR_INARGERR);
	rv = SDF_AuthEnc(h, kh, SGD_SM4_GCM, iv12, 0, aad, 0, pt, sizeof(pt),
		ct, &ctlen, tag, &taglen);
	CHECK(rv == SDR_INARGERR);
	rv = SDF_AuthEnc(h, kh, SGD_SM4_CCM, iv12, 5, aad, 0, pt, sizeof(pt),
		ct, &ctlen, tag, &taglen);
	CHECK(rv == SDR_INARGERR);

	/* multi-packet GCM equals one-shot */
	{
		static const unsigned int splits[3] = { 7, 20, 15 };
		unsigned int off = 0;
		int i;
		unsigned int total;

		memset(ct2, 0, sizeof(ct2));
		CHECK_RV(SDF_AuthEncInit(h, kh, SGD_SM4_GCM, iv12, sizeof(iv12),
			aad, sizeof(aad), sizeof(pt)));
		for (i = 0; i < 3; i++) {
			unsigned int encout = 0;
			CHECK_RV(SDF_AuthEncUpdate(h, pt + off, splits[i],
				NULL, &encout));
			CHECK(encout == 0);	/* buffered model */
			off += splits[i];
		}
		total = sizeof(pt);
		{
			unsigned int authlen = 16;
			CHECK_RV(SDF_AuthEncFinal(h, ct2, &total, tag2, &authlen));
			CHECK(authlen == 16);
		}
		CHECK(total == sizeof(pt));

		ctlen = sizeof(ct);
		taglen = sizeof(tag);
		CHECK_RV(SDF_AuthEnc(h, kh, SGD_SM4_GCM, iv12, sizeof(iv12),
			aad, sizeof(aad), pt, sizeof(pt), ct, &ctlen, tag, &taglen));
		CHECK(memcmp(ct, ct2, sizeof(pt)) == 0);
		CHECK(memcmp(tag, tag2, 16) == 0);

		/* multi-packet decrypt round trip */
		memset(pt2, 0, sizeof(pt2));
		CHECK_RV(SDF_AuthDecInit(h, kh, SGD_SM4_GCM, iv12, sizeof(iv12),
			aad, sizeof(aad), tag, 16, sizeof(ct)));
		off = 0;
		for (i = 0; i < 3; i++) {
			unsigned int dataout = 0;
			CHECK_RV(SDF_AuthDecUpdate(h, ct + off, splits[i],
				NULL, &dataout));
			CHECK(dataout == 0);
			off += splits[i];
		}
		{
			unsigned int last = sizeof(pt2);
			CHECK_RV(SDF_AuthDecFinal(h, pt2, &last));
			CHECK(last == sizeof(pt));
			CHECK(memcmp(pt2, pt, sizeof(pt)) == 0);
		}
		/* step machine: double Final */
		{
			unsigned int last = sizeof(pt2);
			rv = SDF_AuthDecFinal(h, pt2, &last);
			CHECK(rv == SDR_STEPERR);
		}
	}

	/* multi-packet CCM equals one-shot */
	{
		unsigned int ct_c1 = sizeof(ct), tag_c1 = 16;
		unsigned int ct_c2 = sizeof(ct2), tag_c2 = 16;
		unsigned int off = 0;
		int i;

		CHECK_RV(SDF_AuthEnc(h, kh, SGD_SM4_CCM, iv9, sizeof(iv9),
			aad, sizeof(aad), pt, sizeof(pt), ct, &ct_c1, tag, &tag_c1));
		CHECK_RV(SDF_AuthEncInit(h, kh, SGD_SM4_CCM, iv9, sizeof(iv9),
			aad, sizeof(aad), sizeof(pt)));
		for (i = 0; i < 3; i++) {
			unsigned int encout = 0;
			CHECK_RV(SDF_AuthEncUpdate(h, pt + off, 14, NULL, &encout));
			off += 14;
		}
		CHECK(off == sizeof(pt));
		CHECK_RV(SDF_AuthEncFinal(h, ct2, &ct_c2, tag2, &tag_c2));
		CHECK(ct_c2 == ct_c1);
		CHECK(memcmp(ct, ct2, ct_c1) == 0);
		CHECK(memcmp(tag, tag2, 16) == 0);
	}
	return 0;
}

/* ---- external SM2 sign / decrypt ---- */

static int test_ecc(void *h)
{
	SM2_KEY ext_key;
	ECCrefPrivateKey ext_priv;
	ECCSignature sig;
	SM2_SIGNATURE ref_sig;
	SM2_CIPHERTEXT ctxt;
	ECCCipher cipher;
	unsigned char dgst[32];
	unsigned char msg[] = "external sm2 test";
	unsigned char pt[] = "secret";
	unsigned char out[256];
	unsigned int outlen = sizeof(out);
	SM3_CTX sm3_ctx;
	int rv;

	if (sm2_key_generate(&ext_key) != 1)
		return -1;

	/* digest = SM3(msg) */
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, msg, sizeof(msg) - 1);
	sm3_finish(&sm3_ctx, dgst);

	/* SDF_ExternalSign_ECC: signed with caller key, verified by GmSSL */
	memset(&ext_priv, 0, sizeof(ext_priv));
	ext_priv.bits = 256;
	sm2_z256_to_bytes(ext_key.private_key, ext_priv.K + ECCref_MAX_LEN - 32);
	CHECK_RV(SDF_ExternalSign_ECC(h, SGD_SM2_1, &ext_priv, dgst,
		sizeof(dgst), &sig));
	memcpy(ref_sig.r, sig.r + ECCref_MAX_LEN - 32, 32);
	memcpy(ref_sig.s, sig.s + ECCref_MAX_LEN - 32, 32);
	CHECK(sm2_do_verify(&ext_key, dgst, &ref_sig) == 1);

	/* SDF_ExternalDecrypt_ECC: GmSSL-encrypted ciphertext, external key */
	CHECK(sm2_do_encrypt(&ext_key, (const uint8_t *)pt, sizeof(pt) - 1,
		&ctxt) == 1);
	memset(&cipher, 0, sizeof(cipher));
	memcpy(cipher.x + ECCref_MAX_LEN - 32, ctxt.point.x, 32);
	memcpy(cipher.y + ECCref_MAX_LEN - 32, ctxt.point.y, 32);
	memcpy(cipher.M, ctxt.hash, 32);
	cipher.L = (unsigned int)ctxt.ciphertext_size;
	memcpy(cipher.C, ctxt.ciphertext, ctxt.ciphertext_size);

	/* length query first */
	outlen = 0;
	CHECK_RV(SDF_ExternalDecrypt_ECC(h, SGD_SM2_3, &ext_priv,
		&cipher, NULL, &outlen));
	CHECK(outlen == sizeof(pt) - 1);

	outlen = sizeof(out);
	CHECK_RV(SDF_ExternalDecrypt_ECC(h, SGD_SM2_3, &ext_priv,
		&cipher, out, &outlen));
	CHECK(outlen == sizeof(pt) - 1);
	CHECK(memcmp(out, pt, outlen) == 0);

	/* wrong digest length rejected */
	rv = SDF_ExternalSign_ECC(h, SGD_SM2_1, &ext_priv, dgst, 16, &sig);
	CHECK(rv == SDR_INARGERR);
	return 0;
}

/* ---- RSA (11 functions + raw asymmetric operations) ---- */

static int test_rsa(void *h)
{
	RSArefPublicKey pub, ext_pub, exp_pub;
	RSArefPrivateKey priv, ext_priv;
	unsigned char wrapped[512];
	unsigned char ipk_blob[256];
	unsigned char de_out[256];
	unsigned char em[256], k16[16];
	unsigned char m16[16], out1[512], out2[512];
	unsigned int wlen, de_out_len, olen;
	void *kh1 = NULL, *kh2 = NULL, *kh = NULL;
	unsigned char pt[16], ct1[16], ct2b[16];
	unsigned int ctlen;
	size_t mlen;
	int rv, i;

	/* GenerateKeyPair_RSA: valid sizes + structural check */
	CHECK_RV(SDF_GenerateKeyPair_RSA(h, 1024, &pub, &priv));
	CHECK(priv.bits == 1024);
	CHECK(pub.bits == 1024);
	CHECK(softsdf_rsa_check_keypair(&pub, &priv) == 0);
	CHECK_RV(SDF_GenerateKeyPair_RSA(h, 2048, &pub, &priv));
	CHECK(priv.bits == 2048);
	CHECK(softsdf_rsa_check_keypair(&pub, &priv) == 0);

	rv = SDF_GenerateKeyPair_RSA(h, 512, &pub, &priv);
	CHECK(rv == SDR_INARGERR);

	/* Export public keys (fixture keys are 2048-bit) */
	CHECK_RV(SDF_ExportSignPublicKey_RSA(h, 1, &exp_pub));
	CHECK(exp_pub.bits == 2048);
	CHECK((exp_pub.m[0] & 0x80) != 0);
	CHECK(exp_pub.e[RSAref_MAX_LEN - 3] == 0x01
		&& exp_pub.e[RSAref_MAX_LEN - 2] == 0x00
		&& exp_pub.e[RSAref_MAX_LEN - 1] == 0x01);	/* e == 65537 */
	CHECK_RV(SDF_ExportEncPublicKey_RSA(h, 1, &exp_pub));
	CHECK(exp_pub.bits == 2048);
	rv = SDF_ExportSignPublicKey_RSA(h, 99, &exp_pub);
	CHECK(rv == SDR_KEYNOTEXIST);

	if (rand_bytes(k16, sizeof(k16)) != 1)
		return -1;
	if (rand_bytes(pt, sizeof(pt)) != 1)
		return -1;
	if (rand_bytes(m16, sizeof(m16)) != 1)
		return -1;

	/* IPK -> ISK round trip: same wrapped key, same SM4 result */
	wlen = sizeof(wrapped);
	CHECK_RV(SDF_GenerateKeyWithIPK_RSA(h, 1, 128, wrapped, &wlen, &kh1));
	CHECK(wlen == 256);
	memcpy(ipk_blob, wrapped, 256);	/* keep for the exchange test */
	CHECK_RV(SDF_ImportKeyWithISK_RSA(h, 1, wrapped, wlen, &kh2));
	ctlen = sizeof(ct1);
	CHECK_RV(SDF_Encrypt(h, kh1, SGD_SM4_ECB, NULL, pt, sizeof(pt), ct1, &ctlen));
	ctlen = sizeof(ct2b);
	CHECK_RV(SDF_Encrypt(h, kh2, SGD_SM4_ECB, NULL, pt, sizeof(pt), ct2b, &ctlen));
	CHECK(memcmp(ct1, ct2b, 16) == 0);

	/* EPK -> ExternalPrivateKeyOperation round trip (same K) */
	if (softsdf_rsa_keygen(1024, &ext_pub, &ext_priv) != 0)
		return -1;
	wlen = sizeof(wrapped);
	CHECK_RV(SDF_GenerateKeyWithEPK_RSA(h, 128, &ext_pub, wrapped, &wlen, &kh));
	CHECK(wlen == 128);
	{
		unsigned char k2[16];
		size_t k2len = 0;
		SM4_KEY sk;
		unsigned char ref[16];

		/* stdlib-equivalent unwrap: PKCS1 decrypt of the wrapped blob */
		CHECK(softsdf_rsa_pkcs1_decrypt(&ext_priv, wrapped, wlen, k2,
			sizeof(k2), &k2len) == 0);
		CHECK(k2len == 16);
		ctlen = sizeof(ct1);
		CHECK_RV(SDF_Encrypt(h, kh, SGD_SM4_ECB, NULL, pt, sizeof(pt), ct1, &ctlen));
		sm4_set_encrypt_key(&sk, k2);
		sm4_encrypt_blocks(&sk, pt, 1, ref);
		CHECK(memcmp(ref, ct1, 16) == 0);
	}

	/* ExchangeDigitEnvelopeBaseOnRSA: device unwraps its IPK blob and
	 * re-wraps with the external public key */
	de_out_len = sizeof(de_out);
	CHECK_RV(SDF_ExchangeDigitEnvelopeBaseOnRSA(h, 1, &ext_pub, ipk_blob,
		256, de_out, &de_out_len));
	CHECK(de_out_len == 128);
	olen = sizeof(em);
	CHECK_RV(SDF_ExternalPrivateKeyOperation_RSA(h, &ext_priv, de_out,
		de_out_len, em, &olen));
	CHECK(olen == 128);
	CHECK(softsdf_rsa_pkcs1_unpad(em, olen, out1, sizeof(out1), &mlen) == 0);
	CHECK(mlen == 16);
	/* exchanged K equals the IPK handle's key */
	{
		SM4_KEY sk;
		unsigned char ref[16];
		sm4_set_encrypt_key(&sk, out1);
		sm4_encrypt_blocks(&sk, pt, 1, ref);
		ctlen = sizeof(ct1);
		CHECK_RV(SDF_Encrypt(h, kh1, SGD_SM4_ECB, NULL, pt, sizeof(pt),
			ct1, &ctlen));
		CHECK(memcmp(ref, ct1, 16) == 0);
	}

	/* oversized PKCS#1 plaintext (245 bytes): unpad yields 245 > 64-byte
	 * session_key; must be rejected with SDR_SKOPERR, never memcpy'd */
	{
		unsigned char big_pt[245];
		unsigned char big_env[256];
		unsigned int big_len;

		CHECK_RV(SDF_ExportEncPublicKey_RSA(h, 1, &exp_pub));
		memset(big_pt, 0x41, sizeof(big_pt));
		CHECK(softsdf_rsa_pkcs1_encrypt(&exp_pub, big_pt, sizeof(big_pt),
			big_env) == 0);
		big_len = sizeof(de_out);
		rv = SDF_ExchangeDigitEnvelopeBaseOnRSA(h, 1, &ext_pub, big_env,
			256, de_out, &big_len);
		CHECK(rv == SDR_SKOPERR);
	}

	/* raw asymmetric operations: m^(ed) mod N == m (both domains) */
	olen = sizeof(out1);
	CHECK_RV(SDF_ExternalPublicKeyOperation_RSA(h, &ext_pub, m16, sizeof(m16),
		out1, &olen));
	CHECK(olen == 128);
	olen = sizeof(out2);
	CHECK_RV(SDF_ExternalPrivateKeyOperation_RSA(h, &ext_priv, out1, 128,
		out2, &olen));
	CHECK(olen == 128);
	CHECK(memcmp(out2 + 128 - 16, m16, 16) == 0);
	for (i = 0; i < 128 - 16; i++)
		CHECK(out2[i] == 0);

	olen = sizeof(out1);
	CHECK_RV(SDF_InternalPublicKeyOperation_RSA(h, 1, m16, sizeof(m16),
		out1, &olen));
	CHECK(olen == 256);
	olen = sizeof(out2);
	CHECK_RV(SDF_InternalPrivateKeyOperation_RSA(h, 1, out1, 256, out2, &olen));
	CHECK(olen == 256);
	CHECK(memcmp(out2 + 256 - 16, m16, 16) == 0);
	for (i = 0; i < 256 - 16; i++)
		CHECK(out2[i] == 0);

	/* ImportKeyWithISK with wrong size rejected */
	rv = SDF_ImportKeyWithISK_RSA(h, 1, wrapped, 17, &kh);
	CHECK(rv == SDR_INARGERR);

	/* C2: without key right the four ISK/Exchange entry points deny with
	 * SDR_PARDENY (gosdf probe SKIP policy keys off this) */
	{
		void *hC = NULL;
		ECCrefPublicKey ecc_pub;
		ECCCipher cin, cout;
		unsigned int len;

		CHECK_RV(SDF_ExportEncPublicKey_ECC(h, 1, &ecc_pub));
		memset(&cin, 0, sizeof(cin));
		memset(&cout, 0, sizeof(cout));
		CHECK_RV(SDF_OpenSession(deviceHandleGlobal, &hC));
		rv = SDF_ImportKeyWithISK_RSA(hC, 1, ipk_blob, 256, &kh);
		CHECK(rv == SDR_PARDENY);
		len = sizeof(de_out);
		rv = SDF_ExchangeDigitEnvelopeBaseOnRSA(hC, 1, &ext_pub, ipk_blob,
			256, de_out, &len);
		CHECK(rv == SDR_PARDENY);
		rv = SDF_ImportKeyWithISK_ECC(hC, 1, &cin, &kh);
		CHECK(rv == SDR_PARDENY);
		rv = SDF_ExchangeDigitEnvelopeBaseOnECC(hC, 1, SGD_SM2_3, &ecc_pub,
			&cin, &cout);
		CHECK(rv == SDR_PARDENY);
		SDF_CloseSession(hC);
	}
	return 0;
}

/* ---- SM2 key agreement (3 functions) ---- */

static int test_agreement(void *hA, void *hB)
{
	static const unsigned char sponsor_id[] = "sponsor-id";
	static const unsigned char response_id[] = "response-id";
	ECCrefPublicKey sponsor_pub, sponsor_tmp_pub;
	ECCrefPublicKey response_pub, response_tmp_pub;
	void *ah = NULL;
	void *keyA = NULL, *keyB = NULL;
	unsigned char block[16], ctA[16], ctB[16];
	unsigned int ctlen;
	int rv;

	/* without key right the sponsor side must deny */
	{
		void *hC = NULL;
		void *ahc = NULL;
		CHECK_RV(SDF_OpenSession(deviceHandleGlobal, &hC));
		rv = SDF_GenerateAgreementDataWithECC(hC, 1, 128,
			(unsigned char *)sponsor_id, sizeof(sponsor_id) - 1,
			&sponsor_pub, &sponsor_tmp_pub, &ahc);
		CHECK(rv == SDR_PARDENY);
		SDF_CloseSession(hC);
	}

	CHECK_RV(SDF_GetPrivateKeyAccessRight(hB, 1, (unsigned char *)test_pass,
		(unsigned int)strlen(test_pass)));

	CHECK_RV(SDF_GenerateAgreementDataWithECC(hA, 1, 128,
		(unsigned char *)sponsor_id, sizeof(sponsor_id) - 1,
		&sponsor_pub, &sponsor_tmp_pub, &ah));
	CHECK(ah != NULL);

	CHECK_RV(SDF_GenerateAgreementDataAndKeyWithECC(hB, 1, 128,
		(unsigned char *)response_id, sizeof(response_id) - 1,
		(unsigned char *)sponsor_id, sizeof(sponsor_id) - 1,
		&sponsor_pub, &sponsor_tmp_pub,
		&response_pub, &response_tmp_pub, &keyB));
	CHECK(keyB != NULL);

	CHECK_RV(SDF_GenerateKeyWithECC(hA,
		(unsigned char *)response_id, sizeof(response_id) - 1,
		&response_pub, &response_tmp_pub, ah, &keyA));
	CHECK(keyA != NULL);

	/* both sides derived the same key: identical SM4 output */
	if (rand_bytes(block, sizeof(block)) != 1)
		return -1;
	ctlen = sizeof(ctA);
	CHECK_RV(SDF_Encrypt(hA, keyA, SGD_SM4_ECB, NULL, block, sizeof(block),
		ctA, &ctlen));
	ctlen = sizeof(ctB);
	CHECK_RV(SDF_Encrypt(hB, keyB, SGD_SM4_ECB, NULL, block, sizeof(block),
		ctB, &ctlen));
	CHECK(memcmp(ctA, ctB, 16) == 0);

	/* consuming an already-used agreement handle must fail */
	{
		void *ah2 = NULL;
		rv = SDF_GenerateKeyWithECC(hA,
			(unsigned char *)response_id, sizeof(response_id) - 1,
			&response_pub, &response_tmp_pub, ah, &ah2);
		CHECK(rv == SDR_INARGERR);
	}
	return 0;
}

int main(void)
{
	void *hDeviceHandle = NULL;
	void *hSession = NULL;
	void *hSession2 = NULL;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}
	deviceHandleGlobal = hDeviceHandle;

	ret = SDF_OpenSession(hDeviceHandle, &hSession);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}
	ret = SDF_OpenSession(hDeviceHandle, &hSession2);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession#2: 0x%X\n", ret);
		return -1;
	}

	/* private key right for the RSA/agreement/sign domains */
	ret = SDF_GetPrivateKeyAccessRight(hSession, 1,
		(unsigned char *)test_pass, (unsigned int)strlen(test_pass));
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight: 0x%X\n", ret);
		return -1;
	}

	if (test_hash(hSession) != 0) return -1;
	if (test_importkey(hSession) != 0) return -1;
	if (test_hmac(hSession) != 0) return -1;
	if (test_multipart(hSession) != 0) return -1;
	if (test_authenc(hSession) != 0) return -1;
	if (test_ecc(hSession) != 0) return -1;
	if (test_rsa(hSession) != 0) return -1;
	if (test_agreement(hSession, hSession2) != 0) return -1;

	SDF_ReleasePrivateKeyAccessRight(hSession, 1);
	SDF_CloseSession(hSession2);
	SDF_CloseSession(hSession);
	SDF_CloseDevice(hDeviceHandle);

	printf("test ok\n");
	return 0;
}
