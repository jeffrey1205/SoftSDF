/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/sm4_cbc_mac.h>
#include <gmssl/hmac.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include "sdf.h"
#include "softsdf_rsa.h"


static const uint8_t zeros[ECCref_MAX_LEN - 32] = {0};


#define SOFTSDF_MAX_KEY_SIZE	64

struct SOFTSDF_KEY {
	uint8_t key[SOFTSDF_MAX_KEY_SIZE];
	size_t key_size;
	struct SOFTSDF_KEY *next;
};

typedef struct SOFTSDF_KEY SOFTSDF_KEY;

typedef struct SOFTSDF_SESSION SOFTSDF_SESSION;

/* pending SM2 key agreement handle (SDF_GenerateAgreementDataWithECC) */
struct SOFTSDF_AGREEMENT {
	SOFTSDF_SESSION *session;
	SM2_KEY static_key;	/* sponsor static key */
	SM2_KEY tmp_key;	/* sponsor temp key */
	uint8_t *sponsor_id;
	size_t sponsor_id_len;
	unsigned int key_bits;	/* derived key length in bits */
	struct SOFTSDF_AGREEMENT *next;
};

typedef struct SOFTSDF_AGREEMENT SOFTSDF_AGREEMENT;

/* multi-packet symmetric state (GM/T 0018-2023 6.5), role: 1 enc, 2 dec, 3 MAC */
struct SOFTSDF_SYM_STATE {
	int active;
	int role;
	unsigned int alg;
	union {
#if ENABLE_SM4_ECB
		SM4_ECB_CTX ecb;
#endif
		SM4_CBC_CTX cbc;
		SM4_CTR_CTX ctr;
#if ENABLE_SM4_OFB
		SM4_OFB_CTX ofb;
#endif
#if ENABLE_SM4_CFB
		SM4_CFB_CTX cfb;
#endif
	} u;
	SM4_CBC_MAC_CTX mac;
	/* produced but not yet delivered output: per-call buffers hold only
	 * uiDataLength bytes, block modes can emit one trailing block early */
	uint8_t *obuf;
	size_t obuf_len;
	size_t obuf_cap;
};

typedef struct SOFTSDF_SYM_STATE SOFTSDF_SYM_STATE;

/* buffered AEAD state (GM/T 0018-2023 6.5.5~6.5.21): Init declares the total,
 * Update accumulates, Final runs the one-shot GmSSL GCM/CCM operation.
 * AuthEncFinal/AuthDecFinal take no key handle, so the key is copied here. */
struct SOFTSDF_AEAD_STATE {
	int active;
	int role;		/* 1 = enc, 2 = dec */
	unsigned int alg;
	uint8_t key[16];	/* copied at Init, cleared at Final */
	uint8_t *buf;		/* accumulated plaintext (enc) / ciphertext (dec) */
	size_t len;
	size_t cap;
	uint8_t start_var[64];
	size_t sv_len;
	uint8_t aad[256];
	size_t aad_len;
	uint8_t tag[16];
	size_t tag_len;
};

typedef struct SOFTSDF_AEAD_STATE SOFTSDF_AEAD_STATE;

struct SOFTSDF_CONTAINER {
	unsigned int key_index;
	SM2_KEY sign_key;
	SM2_KEY enc_key;
	struct SOFTSDF_CONTAINER *next;
};
typedef struct SOFTSDF_CONTAINER SOFTSDF_CONTAINER;

struct SOFTSDF_SESSION {
	SOFTSDF_CONTAINER *container_list;
	SOFTSDF_KEY *key_list;
	SOFTSDF_AGREEMENT *agreement_list;
	SM3_CTX sm3_ctx;
	int hash_active;
	HMAC_CTX hmac_ctx;
	int hmac_active;
	SOFTSDF_SYM_STATE sym;
	SOFTSDF_AEAD_STATE aead;
	struct SOFTSDF_SESSION *next;
};

struct SOFTSDF_DEVICE {
	SOFTSDF_SESSION *session_list;
};
typedef struct SOFTSDF_DEVICE SOFTSDF_DEVICE;

SOFTSDF_DEVICE *deviceHandle = NULL;



#define FILENAME_MAX_LEN 256

int SDF_OpenDevice(
	void **phDeviceHandle)
{
	if (phDeviceHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (deviceHandle != NULL) {
		error_print();
		return SDR_OPENDEVICE;
	}

	deviceHandle = (SOFTSDF_DEVICE *)malloc(sizeof(SOFTSDF_DEVICE));
	if (deviceHandle == NULL) {
		error_print();
		return SDR_OPENDEVICE;
	}
	memset(deviceHandle, 0, sizeof(SOFTSDF_DEVICE));

	*phDeviceHandle = deviceHandle;
	return SDR_OK;
}

int SDF_CloseDevice(
	void *hDeviceHandle)
{
	if (hDeviceHandle != deviceHandle) {
		error_print();
		return SDR_INARGERR;
	}

	if (deviceHandle != NULL) {
		while (deviceHandle->session_list) {
			if (SDF_CloseSession(deviceHandle->session_list) != SDR_OK) {
				error_print();
			}
		}
	}

	memset(deviceHandle, 0, sizeof(SOFTSDF_DEVICE));
	free(deviceHandle);
	deviceHandle = NULL;

	return SDR_OK;
}


int SDF_OpenSession(
	void *hDeviceHandle,
	void **phSessionHandle)
{
	SOFTSDF_SESSION *session;

	if (hDeviceHandle == NULL || hDeviceHandle != deviceHandle) {
		error_print();
		return SDR_INARGERR;
	}

	if (phSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!(session = (SOFTSDF_SESSION *)malloc(sizeof(*session)))) {
		error_print();
		return SDR_OPENSESSION;
	}
	memset(session, 0, sizeof(*session));

	// append session to session_list
	if (deviceHandle->session_list == NULL) {
		deviceHandle->session_list = session;
	} else {
		SOFTSDF_SESSION *current = deviceHandle->session_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = session;
	}

	*phSessionHandle = session;
	return SDR_OK;
}

int SDF_CloseSession(
	void *hSessionHandle)
{
	SOFTSDF_SESSION *current_session;
	SOFTSDF_SESSION *prev_session;
	SOFTSDF_CONTAINER *current_container;
	SOFTSDF_CONTAINER *next_container;
	SOFTSDF_KEY *current_key;
	SOFTSDF_KEY *next_key;
	SOFTSDF_AGREEMENT *current_agr;
	SOFTSDF_AGREEMENT *next_agr;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// find hSessionHandle in session_list
	current_session = deviceHandle->session_list;
	prev_session = NULL;
	while (current_session != NULL && current_session != hSessionHandle) {
		prev_session = current_session;
		current_session = current_session->next;
	}
	if (current_session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// free container_list
	current_container = current_session->container_list;
	while (current_container != NULL) {
		next_container = current_container->next;
		memset(current_container, 0, sizeof(*current_container));
		free(current_container);
		current_container = next_container;
	}

	// free key_list
	current_key = current_session->key_list;
	while (current_key != NULL) {
		next_key = current_key->next;
		memset(current_key, 0, sizeof(*current_key));
		free(current_key);
		current_key = next_key;
	}

	// free unconsumed agreement handles
	current_agr = current_session->agreement_list;
	while (current_agr != NULL) {
		next_agr = current_agr->next;
		if (current_agr->sponsor_id) {
			gmssl_secure_clear(current_agr->sponsor_id, current_agr->sponsor_id_len);
			free(current_agr->sponsor_id);
		}
		gmssl_secure_clear(current_agr, sizeof(*current_agr));
		free(current_agr);
		current_agr = next_agr;
	}

	// free buffered multi-packet state
	if (current_session->sym.obuf) {
		gmssl_secure_clear(current_session->sym.obuf,
			current_session->sym.obuf_cap);
		free(current_session->sym.obuf);
	}
	if (current_session->aead.buf) {
		gmssl_secure_clear(current_session->aead.buf,
			current_session->aead.cap);
		free(current_session->aead.buf);
	}

	// delete current_session from session_list
	if (prev_session == NULL) {
		deviceHandle->session_list = current_session->next;
	} else {
		prev_session->next = current_session->next;
	}
	memset(current_session, 0, sizeof(*current_session));
	free(current_session);

	return SDR_OK;
}

#define SOFTSDF_DEV_DATE	"20240622"
#define SOFTSDF_DEV_BATCH_NUM	"001" // as version.major
#define SOFTSDF_DEV_SERIAL_NUM	"0200" // as version.minor
#define SOFTSDF_DEV_SERIAL	SOFTSDF_DEV_DATE \
				SOFTSDF_DEV_BATCH_NUM \
				SOFTSDF_DEV_SERIAL_NUM

int SDF_GetDeviceInfo(
	void *hSessionHandle,
	DEVICEINFO *pstDeviceInfo)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pstDeviceInfo == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	memset(pstDeviceInfo, 0, sizeof(*pstDeviceInfo));
	strncpy((char *)pstDeviceInfo->IssuerName, "GmSSL Project (http://gmssl.org)",
		sizeof(pstDeviceInfo->IssuerName));
	strncpy((char *)pstDeviceInfo->DeviceName, "Soft SDF",
		sizeof(pstDeviceInfo->DeviceName));
	strncpy((char *)pstDeviceInfo->DeviceSerial, SOFTSDF_DEV_SERIAL,
		sizeof(pstDeviceInfo->DeviceSerial));
	pstDeviceInfo->DeviceVersion = 1;
	pstDeviceInfo->StandardVersion = 1;
	pstDeviceInfo->AsymAlgAbility[0] = SGD_SM2_1|SGD_SM2_3;
	pstDeviceInfo->AsymAlgAbility[1] = 256;
	pstDeviceInfo->SymAlgAbility = SGD_SM4|SGD_CBC|SGD_MAC;
#if ENABLE_SM4_ECB
	pstDeviceInfo->SymAlgAbility |= SGD_ECB;
#endif
#if ENABLE_SM4_CFB
	pstDeviceInfo->SymAlgAbility |= SGD_CFB;
#endif
#if ENABLE_SM4_OFB
	pstDeviceInfo->SymAlgAbility |= SGD_OFB;
#endif
	pstDeviceInfo->HashAlgAbility = SGD_SM3;
	pstDeviceInfo->BufferSize = 256*1024;

	return SDR_OK;
}

int SDF_GenerateRandom(
	void *hSessionHandle,
	unsigned int uiLength,
	unsigned char *pucRandom)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucRandom == NULL || uiLength == 0) {
		error_puts("Invalid output buffer or length");
		return SDR_INARGERR;
	}
	if (uiLength > RAND_BYTES_MAX_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (rand_bytes(pucRandom, uiLength) != 1) {
		error_print();
		return SDR_RANDERR;
	}

	return SDR_OK;
}

int SDF_GetPrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucPassword,
	unsigned int uiPwdLength)
{
	int ret = SDR_OK;
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container = NULL;
	char *pass = NULL;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPassword == NULL || uiPwdLength == 0) {
		error_puts("Invalid password or password length");
		return SDR_INARGERR;
	}
	pass = (char *)malloc(uiPwdLength + 1);
	if (pass == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memcpy(pass, pucPassword, uiPwdLength);
	pass[uiPwdLength] = 0;
	if (strlen(pass) != uiPwdLength) {
		error_print();
		ret = SDR_INARGERR;
		goto end;
	}

	// create container
	container = (SOFTSDF_CONTAINER *)malloc(sizeof(*container));
	if (container == NULL) {
		error_print();
		ret = SDR_NOBUFFER;
		goto end;
	}
	memset(container, 0, sizeof(*container));
	container->key_index = uiKeyIndex;

	// load sign_key
	snprintf(filename, FILENAME_MAX_LEN, "sm2sign-%u.pem", uiKeyIndex);
	file = fopen(filename, "r");
	if (file == NULL) {
		perror("Error opening file");
		fprintf(stderr, "open failure %s\n", filename);
		ret = SDR_KEYNOTEXIST;
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&container->sign_key, pass, file) != 1) {
		error_print();
		ret = SDR_PRKRERR;
		goto end;
	}
	fclose(file);

	// load enc_key
	snprintf(filename, FILENAME_MAX_LEN, "sm2enc-%u.pem", uiKeyIndex);
	file = fopen(filename, "r");
	if (file == NULL) {
		perror("Error opening file");
		ret = SDR_KEYNOTEXIST;
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&container->enc_key, pass, file) != 1) {
		error_print();
		ret = SDR_PRKRERR;
		goto end;
	}

	// append container to container_list
	if (session->container_list == NULL) {
		session->container_list = container;
	} else {
		SOFTSDF_CONTAINER *current = session->container_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = container;
	}

	container = NULL;
	ret = SDR_OK;
end:
	if (container) {
		memset(container, 0, sizeof(*container));
		free(container);
	}
	if (pass) {
		memset(pass, 0, uiPwdLength);
		free(pass);
	}
	if (file) fclose(file);
	return ret;
}

int SDF_ReleasePrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *current_container;
	SOFTSDF_CONTAINER *prev_container;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// delete container in container_list with uiKeyIndex
	current_container = session->container_list;
	prev_container = NULL;

	while (current_container != NULL && current_container->key_index != uiKeyIndex) {
		prev_container = current_container;
		current_container = current_container->next;
	}
	if (current_container == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (prev_container == NULL) {
		session->container_list = current_container->next;
	} else {
		prev_container->next = current_container->next;
	}
	memset(current_container, 0, sizeof(*current_container));
	free(current_container);

	return SDR_OK;
}

/* RSA key files: rsasign-%u.key / rsaenc-%u.key, 1412-byte RSArefPrivateKey */
static int rsa_load_keyfile(
	unsigned int key_index,
	const char *prefix,
	RSArefPrivateKey *priv)
{
	char filename[FILENAME_MAX_LEN];
	int ret;

	snprintf(filename, FILENAME_MAX_LEN, "%s-%u.key", prefix, key_index);
	ret = softsdf_rsa_keyfile_load(filename, priv);
	if (ret != 0) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (priv->bits != 1024 && priv->bits != 2048) {
		error_print();
		memset(priv, 0, sizeof(*priv));
		return SDR_KEYNOTEXIST;
	}
	return SDR_OK;
}

/* find container granting private-key right for key index (NULL if none) */
static SOFTSDF_CONTAINER *find_container(SOFTSDF_SESSION *session,
	unsigned int key_index)
{
	SOFTSDF_CONTAINER *container = session->container_list;

	while (container != NULL && container->key_index != key_index) {
		container = container->next;
	}
	return container;
}

/* create session key (bytes==NULL -> random), append to session->key_list */
static SOFTSDF_KEY *session_key_new(SOFTSDF_SESSION *session,
	const uint8_t *bytes, size_t key_size)
{
	SOFTSDF_KEY *key;

	key = (SOFTSDF_KEY *)malloc(sizeof(*key));
	if (key == NULL)
		return NULL;
	memset(key, 0, sizeof(*key));
	if (bytes == NULL) {
		if (rand_bytes(key->key, key_size) != 1) {
			free(key);
			return NULL;
		}
	} else {
		memcpy(key->key, bytes, key_size);
	}
	key->key_size = key_size;
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}
	return key;
}

int SDF_ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	SOFTSDF_SESSION *session;
	RSArefPrivateKey priv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (rsa_load_keyfile(uiKeyIndex, "rsasign", &priv) != SDR_OK)
		return SDR_KEYNOTEXIST;
	softsdf_rsa_pub_from_priv(&priv, pucPublicKey);
	gmssl_secure_clear(&priv, sizeof(priv));
	return SDR_OK;
}

int SDF_ExportEncPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	SOFTSDF_SESSION *session;
	RSArefPrivateKey priv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (rsa_load_keyfile(uiKeyIndex, "rsaenc", &priv) != SDR_OK)
		return SDR_KEYNOTEXIST;
	softsdf_rsa_pub_from_priv(&priv, pucPublicKey);
	gmssl_secure_clear(&priv, sizeof(priv));
	return SDR_OK;
}

int SDF_GenerateKeyPair_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiKeyBits != 1024 && uiKeyBits != 2048) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey == NULL || pucPrivateKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (softsdf_rsa_keygen(uiKeyBits, pucPublicKey, pucPrivateKey) != 0) {
		error_print();
		return SDR_RANDERR;
	}
	return SDR_OK;
}

int SDF_GenerateKeyWithIPK_RSA(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	RSArefPrivateKey priv;
	RSArefPublicKey pub;
	SOFTSDF_KEY *key;
	unsigned int k;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiKeyBits % 8 != 0 || uiKeyBits / 8 > SOFTSDF_MAX_KEY_SIZE
		|| uiKeyBits == 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucKey == NULL || puiKeyLength == NULL || phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (rsa_load_keyfile(uiIPKIndex, "rsaenc", &priv) != SDR_OK)
		return SDR_KEYNOTEXIST;
	softsdf_rsa_pub_from_priv(&priv, &pub);
	gmssl_secure_clear(&priv, sizeof(priv));

	k = pub.bits / 8;
	if (*puiKeyLength < k) {
		error_print();
		return SDR_NOBUFFER;
	}

	key = session_key_new(session, NULL, uiKeyBits / 8);
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	if (softsdf_rsa_pkcs1_encrypt(&pub, key->key, key->key_size, pucKey) != 0) {
		error_print();
		gmssl_secure_clear(key, sizeof(*key));
		/* unlink the just-appended key */
		{
			SOFTSDF_KEY **pp = &session->key_list;
			while (*pp != NULL && *pp != key)
				pp = &(*pp)->next;
			if (*pp == key)
				*pp = key->next;
		}
		free(key);
		return SDR_SKOPERR;
	}
	*puiKeyLength = k;
	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	unsigned int k;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiKeyBits % 8 != 0 || uiKeyBits / 8 > SOFTSDF_MAX_KEY_SIZE
		|| uiKeyBits == 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey == NULL || pucKey == NULL || puiKeyLength == NULL
		|| phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey->bits != 1024 && pucPublicKey->bits != 2048) {
		error_print();
		return SDR_INARGERR;
	}
	k = pucPublicKey->bits / 8;
	if (*puiKeyLength < k) {
		error_print();
		return SDR_NOBUFFER;
	}

	key = session_key_new(session, NULL, uiKeyBits / 8);
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	if (softsdf_rsa_pkcs1_encrypt(pucPublicKey, key->key, key->key_size,
			pucKey) != 0) {
		error_print();
		gmssl_secure_clear(key, sizeof(*key));
		{
			SOFTSDF_KEY **pp = &session->key_list;
			while (*pp != NULL && *pp != key)
				pp = &(*pp)->next;
			if (*pp == key)
				*pp = key->next;
		}
		free(key);
		return SDR_SKOPERR;
	}
	*puiKeyLength = k;
	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_ImportKeyWithISK_RSA(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	RSArefPrivateKey priv;
	size_t mlen = 0;
	unsigned int k;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucKey == NULL || phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (find_container(session, uiISKIndex) == NULL) {
		error_puts("ISK not loaded, call GetPrivateKeyAccess before use ISK\n");
		return SDR_INARGERR;
	}
	if (rsa_load_keyfile(uiISKIndex, "rsaenc", &priv) != SDR_OK)
		return SDR_KEYNOTEXIST;
	k = priv.bits / 8;
	if (uiKeyLength != k) {
		error_print();
		gmssl_secure_clear(&priv, sizeof(priv));
		return SDR_INARGERR;
	}

	key = (SOFTSDF_KEY *)malloc(sizeof(*key));
	if (key == NULL) {
		error_print();
		gmssl_secure_clear(&priv, sizeof(priv));
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));
	if (softsdf_rsa_pkcs1_decrypt(&priv, pucKey, uiKeyLength,
			key->key, &mlen) != 0) {
		error_print();
		gmssl_secure_clear(&priv, sizeof(priv));
		gmssl_secure_clear(key, sizeof(*key));
		free(key);
		return SDR_SKOPERR;
	}
	gmssl_secure_clear(&priv, sizeof(priv));
	key->key_size = mlen;
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}
	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_ExchangeDigitEnvelopeBaseOnRSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDEInput,
	unsigned int uiDELength,
	unsigned char *pucDEOutput,
	unsigned int *puiDELength)
{
	SOFTSDF_SESSION *session;
	RSArefPrivateKey priv;
	uint8_t session_key[SOFTSDF_MAX_KEY_SIZE];
	size_t mlen = 0;
	unsigned int k, kout;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey == NULL || pucDEInput == NULL || pucDEOutput == NULL
		|| puiDELength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey->bits != 1024 && pucPublicKey->bits != 2048) {
		error_print();
		return SDR_INARGERR;
	}
	if (find_container(session, uiKeyIndex) == NULL) {
		error_puts("key index not loaded, call GetPrivateKeyAccess first\n");
		return SDR_INARGERR;
	}
	if (rsa_load_keyfile(uiKeyIndex, "rsaenc", &priv) != SDR_OK)
		return SDR_KEYNOTEXIST;
	k = priv.bits / 8;
	kout = pucPublicKey->bits / 8;
	if (uiDELength != k) {
		error_print();
		gmssl_secure_clear(&priv, sizeof(priv));
		return SDR_INARGERR;
	}
	if (*puiDELength < kout) {
		error_print();
		gmssl_secure_clear(&priv, sizeof(priv));
		return SDR_NOBUFFER;
	}

	if (softsdf_rsa_pkcs1_decrypt(&priv, pucDEInput, uiDELength,
			session_key, &mlen) != 0) {
		error_print();
		gmssl_secure_clear(&priv, sizeof(priv));
		return SDR_SKOPERR;
	}
	gmssl_secure_clear(&priv, sizeof(priv));
	if (softsdf_rsa_pkcs1_encrypt(pucPublicKey, session_key, mlen,
			pucDEOutput) != 0) {
		error_print();
		gmssl_secure_clear(session_key, sizeof(session_key));
		return SDR_PKOPERR;
	}
	gmssl_secure_clear(session_key, sizeof(session_key));
	*puiDELength = kout;
	return SDR_OK;
}

/* ECCrefPublicKey (x/y left-padded 64-byte big-endian) -> validated SM2_KEY */
static int eccref_pubkey_to_sm2_key(const ECCrefPublicKey *pub, SM2_KEY *key)
{
	SM2_POINT point;
	SM2_Z256_POINT public_key;

	if (pub->bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(pub->x, zeros, ECCref_MAX_LEN - 32) != 0
		|| memcmp(pub->y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	memset(&point, 0, sizeof(point));
	memcpy(point.x, pub->x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, pub->y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}
	if (sm2_key_set_public_key(key, &public_key) != 1) {
		error_print();
		return -1;
	}
	return 0;
}

/* SM2_KEY public part -> ECCrefPublicKey (x/y left-padded) */
static void sm2_key_to_eccref_pubkey(const SM2_KEY *key, ECCrefPublicKey *pub)
{
	SM2_POINT point;

	sm2_z256_point_to_bytes(&key->public_key, (uint8_t *)&point);
	memset(pub, 0, sizeof(*pub));
	pub->bits = 256;
	memcpy(pub->x + ECCref_MAX_LEN - 32, point.x, 32);
	memcpy(pub->y + ECCref_MAX_LEN - 32, point.y, 32);
}

int SDF_ExportSignPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	SM2_KEY sm2_key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	snprintf(filename, FILENAME_MAX_LEN, "sm2signpub-%u.pem", uiKeyIndex);
	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (sm2_public_key_info_from_pem(&sm2_key, file) != 1) {
		error_print();
		fclose(file);
		return SDR_KEYNOTEXIST;
	}
	fclose(file);

	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	sm2_key_to_eccref_pubkey(&sm2_key, pucPublicKey);
	return SDR_OK;
}

int SDF_ExportEncPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	SM2_KEY sm2_key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	snprintf(filename, FILENAME_MAX_LEN, "sm2encpub-%u.pem", uiKeyIndex);
	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (sm2_public_key_info_from_pem(&sm2_key, file) != 1) {
		error_print();
		fclose(file);
		return SDR_KEYNOTEXIST;
	}
	fclose(file);

	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	sm2_key_to_eccref_pubkey(&sm2_key, pucPublicKey);
	return SDR_OK;
}

int SDF_GenerateKeyPair_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey)
{
	SOFTSDF_SESSION *session;
	SM2_KEY sm2_key;
	SM2_POINT public_key;
	uint8_t private_key[32];

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiKeyBits != 256) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey == NULL || pucPrivateKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return SDR_RANDERR;
	}

	sm2_z256_to_bytes(sm2_key.private_key, private_key);
	sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&public_key);

	memset(pucPublicKey, 0, sizeof(*pucPublicKey));
	pucPublicKey->bits = 256;
	memcpy(pucPublicKey->x + ECCref_MAX_LEN - 32, public_key.x, 32);
	memcpy(pucPublicKey->y + ECCref_MAX_LEN - 32, public_key.y, 32);

	memset(pucPrivateKey, 0, sizeof(*pucPrivateKey));
	pucPrivateKey->bits = 256;
	memcpy(pucPrivateKey->K + ECCref_MAX_LEN - 32, private_key, 32);

	memset(&sm2_key, 0, sizeof(sm2_key));
	memset(private_key, 0, sizeof(private_key));
	return SDR_OK;
}

/* ECCCipher (caller's field-wise struct) -> SM2_CIPHERTEXT */
static void ecccipher_to_sm2(const ECCCipher *in, SM2_CIPHERTEXT *out)
{
	memset(out, 0, sizeof(*out));
	memcpy(out->point.x, in->x + ECCref_MAX_LEN - 32, 32);
	memcpy(out->point.y, in->y + ECCref_MAX_LEN - 32, 32);
	memcpy(out->hash, in->M, 32);
	memcpy(out->ciphertext, in->C, in->L);
	out->ciphertext_size = in->L;
}

/* SM2_CIPHERTEXT -> ECCCipher, field-wise (caller's struct has flexible C) */
static void sm2_to_ecccipher(const SM2_CIPHERTEXT *in, ECCCipher *out)
{
	memset(out->x, 0, ECCref_MAX_LEN - 32);
	memcpy(out->x + ECCref_MAX_LEN - 32, in->point.x, 32);
	memset(out->y, 0, ECCref_MAX_LEN - 32);
	memcpy(out->y + ECCref_MAX_LEN - 32, in->point.y, 32);
	memcpy(out->M, in->hash, 32);
	out->L = (unsigned int)in->ciphertext_size;
	memcpy(out->C, in->ciphertext, in->ciphertext_size);
}

/* encrypt a session key with a public key into an ECCCipher output */
static int sm2_encrypt_session_key(const SM2_KEY *pub_key,
	const uint8_t *in, size_t inlen, ECCCipher *out)
{
	SM2_CIPHERTEXT ctxt;

	if (sm2_do_encrypt(pub_key, in, inlen, &ctxt) != 1) {
		error_print();
		return -1;
	}
	sm2_to_ecccipher(&ctxt, out);
	return 0;
}

/* decrypt a session key from an ECCCipher (validates L bounds) */
static int sm2_decrypt_session_key(const SM2_KEY *priv_key,
	const ECCCipher *in, uint8_t *out, size_t *outlen)
{
	SM2_CIPHERTEXT ctxt;

	if (in->L > SM2_MAX_PLAINTEXT_SIZE || in->L > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return -1;
	}
	ecccipher_to_sm2(in, &ctxt);
	if (sm2_do_decrypt(priv_key, &ctxt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 0;
}

int SDF_GenerateKeyWithIPK_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file;
	SM2_KEY sm2_key;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	snprintf(filename, FILENAME_MAX_LEN, "sm2encpub-%u.pem", uiIPKIndex);
	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (sm2_public_key_info_from_pem(&sm2_key, file) != 1) {
		error_print();
		fclose(file);
		return SDR_KEYNOTEXIST;
	}
	fclose(file);

	if (uiKeyBits%8 != 0 || uiKeyBits/8 > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// generate key
	key = (SOFTSDF_KEY *)malloc(sizeof(*key));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));
	if (rand_bytes(key->key, uiKeyBits/8) != 1) {
		error_print();
		free(key);
		return SDR_RANDERR;
	}
	key->key_size = uiKeyBits/8;

	// encrypt key with container
	if (sm2_encrypt_session_key(&sm2_key, key->key, key->key_size, pucKey) != 0) {
		error_print();
		gmssl_secure_clear(key, sizeof(*key));
		free(key);
		return SDR_PKOPERR;
	}

	// append key to key_list
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_GenerateKeyWithEPK_ECC(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	SM2_POINT point;
	SM2_Z256_POINT public_key;
	SM2_KEY sm2_key;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiKeyBits%8 != 0 || uiKeyBits/8 > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey == NULL || pucKey == NULL || phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// load public key
	memset(&point, 0, sizeof(point));
	memcpy(point.x, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return SDR_INARGERR;
	}
	if (sm2_key_set_public_key(&sm2_key, &public_key) != 1) {
		error_print();
		return SDR_INARGERR;
	}

	// generate key
	key = (SOFTSDF_KEY *)malloc(sizeof(*key));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));
	if (rand_bytes(key->key, uiKeyBits/8) != 1) {
		error_print();
		free(key);
		return SDR_RANDERR;
	}
	key->key_size = uiKeyBits/8;

	// encrypt key with external public key
	if (sm2_encrypt_session_key(&sm2_key, key->key, key->key_size, pucKey) != 0) {
		error_print();
		gmssl_secure_clear(key, sizeof(*key));
		free(key);
		return SDR_PKOPERR;
	}

	// append key to key_list
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_ImportKeyWithISK_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	container = session->container_list;
	while (container != NULL && container->key_index != uiISKIndex) {
		container = container->next;
	}
	if (container == NULL) {
		error_puts("ISK not loaded, call GetPrivateKeyAccess before use ISK\n");
		return SDR_INARGERR;
	}

	if (pucKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucKey->L > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucKey->L > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// create key
	key = (SOFTSDF_KEY *)malloc(sizeof(*key));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));

	// decrypt key
	if (sm2_decrypt_session_key(&container->enc_key, pucKey, key->key,
			&key->key_size) != 0) {
		error_print();
		gmssl_secure_clear(key, sizeof(*key));
		free(key);
		return SDR_SKOPERR;
	}

	// append key to key_list
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

/* validate SM2 agreement IDs; shared by the three agreement functions */
static int agreement_id_check(const unsigned char *id, unsigned int idlen)
{
	if (id == NULL || idlen == 0 || idlen > SM2_MAX_ID_LENGTH) {
		error_print();
		return -1;
	}
	return 0;
}

/* validate key bits for agreement and derived session key */
static int agreement_bits_check(unsigned int uiKeyBits)
{
	if (uiKeyBits == 0 || uiKeyBits % 8 != 0
		|| uiKeyBits / 8 > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return -1;
	}
	return 0;
}

/* ECCrefPublicKey -> 65-byte uncompressed point (0x04||x||y) */
static int eccref_pubkey_to_octets65(const ECCrefPublicKey *pub, uint8_t out[65])
{
	if (pub->bits != 256
		|| memcmp(pub->x, zeros, ECCref_MAX_LEN - 32) != 0
		|| memcmp(pub->y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	out[0] = 0x04;
	memcpy(out + 1, pub->x + ECCref_MAX_LEN - 32, 32);
	memcpy(out + 33, pub->y + ECCref_MAX_LEN - 32, 32);
	return 0;
}

int SDF_GenerateAgreementDataWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	void **phAgreementHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container;
	SOFTSDF_AGREEMENT *agr;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (agreement_bits_check(uiKeyBits) != 0)
		return SDR_INARGERR;
	if (agreement_id_check(pucSponsorID, uiSponsorIDLength) != 0)
		return SDR_INARGERR;
	if (pucSponsorPublicKey == NULL || pucSponsorTmpPublicKey == NULL
		|| phAgreementHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	container = find_container(session, uiISKIndex);
	if (container == NULL) {
		error_puts("private key right not acquired for agreement\n");
		return SDR_PARDENY;
	}

	agr = (SOFTSDF_AGREEMENT *)malloc(sizeof(*agr));
	if (agr == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(agr, 0, sizeof(*agr));
	agr->session = session;
	agr->static_key = container->sign_key;
	agr->key_bits = uiKeyBits;
	agr->sponsor_id = (uint8_t *)malloc(uiSponsorIDLength);
	if (agr->sponsor_id == NULL) {
		error_print();
		free(agr);
		return SDR_NOBUFFER;
	}
	memcpy(agr->sponsor_id, pucSponsorID, uiSponsorIDLength);
	agr->sponsor_id_len = uiSponsorIDLength;

	if (sm2_key_generate(&agr->tmp_key) != 1) {
		error_print();
		free(agr->sponsor_id);
		gmssl_secure_clear(agr, sizeof(*agr));
		free(agr);
		return SDR_RANDERR;
	}

	sm2_key_to_eccref_pubkey(&agr->static_key, pucSponsorPublicKey);
	sm2_key_to_eccref_pubkey(&agr->tmp_key, pucSponsorTmpPublicKey);

	if (session->agreement_list == NULL) {
		session->agreement_list = agr;
	} else {
		SOFTSDF_AGREEMENT *current = session->agreement_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = agr;
	}

	*phAgreementHandle = agr;
	return SDR_OK;
}

int SDF_GenerateKeyWithECC(
	void *hSessionHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *hAgreementHandle,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_AGREEMENT *agr;
	SOFTSDF_AGREEMENT *prev;
	SOFTSDF_KEY *key;
	SM2_KEY resp_static;
	uint8_t peer_tmp[65];
	uint8_t shared[SOFTSDF_MAX_KEY_SIZE];

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (agreement_id_check(pucResponseID, uiResponseIDLength) != 0)
		return SDR_INARGERR;
	if (pucResponsePublicKey == NULL || pucResponseTmpPublicKey == NULL
		|| hAgreementHandle == NULL || phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	prev = NULL;
	agr = session->agreement_list;
	while (agr != NULL && agr != (SOFTSDF_AGREEMENT *)hAgreementHandle) {
		prev = agr;
		agr = agr->next;
	}
	if (agr == NULL) {
		error_puts("invalid agreement handle\n");
		return SDR_INARGERR;
	}
	if (agr->session != session) {
		error_print();
		return SDR_INARGERR;
	}

	if (eccref_pubkey_to_sm2_key(pucResponsePublicKey, &resp_static) != 0)
		return SDR_INARGERR;
	if (eccref_pubkey_to_octets65(pucResponseTmpPublicKey, peer_tmp) != 0)
		return SDR_INARGERR;

	if (sm2_key_exchange(1,
			&agr->static_key,
			(const char *)agr->sponsor_id, agr->sponsor_id_len,
			&resp_static,
			(const char *)pucResponseID, uiResponseIDLength,
			&agr->tmp_key,
			peer_tmp,
			NULL,
			agr->key_bits / 8, shared) != 1) {
		error_print();
		return SDR_SKOPERR;
	}

	key = session_key_new(session, shared, agr->key_bits / 8);
	gmssl_secure_clear(shared, sizeof(shared));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}

	/* consume the agreement handle */
	if (prev == NULL) {
		session->agreement_list = agr->next;
	} else {
		prev->next = agr->next;
	}
	if (agr->sponsor_id) {
		gmssl_secure_clear(agr->sponsor_id, agr->sponsor_id_len);
		free(agr->sponsor_id);
	}
	gmssl_secure_clear(agr, sizeof(*agr));
	free(agr);

	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_GenerateAgreementDataAndKeyWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container;
	SOFTSDF_KEY *key;
	SM2_KEY sponsor_static;
	SM2_KEY resp_tmp;
	uint8_t peer_tmp[65];
	uint8_t shared[SOFTSDF_MAX_KEY_SIZE];

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (agreement_bits_check(uiKeyBits) != 0)
		return SDR_INARGERR;
	if (agreement_id_check(pucResponseID, uiResponseIDLength) != 0
		|| agreement_id_check(pucSponsorID, uiSponsorIDLength) != 0)
		return SDR_INARGERR;
	if (pucSponsorPublicKey == NULL || pucSponsorTmpPublicKey == NULL
		|| pucResponsePublicKey == NULL || pucResponseTmpPublicKey == NULL
		|| phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	container = find_container(session, uiISKIndex);
	if (container == NULL) {
		error_puts("private key right not acquired for agreement\n");
		return SDR_PARDENY;
	}

	if (eccref_pubkey_to_sm2_key(pucSponsorPublicKey, &sponsor_static) != 0)
		return SDR_INARGERR;
	if (eccref_pubkey_to_octets65(pucSponsorTmpPublicKey, peer_tmp) != 0)
		return SDR_INARGERR;

	if (sm2_key_generate(&resp_tmp) != 1) {
		error_print();
		return SDR_RANDERR;
	}

	/* responder static (device key) and generated temp key */
	sm2_key_to_eccref_pubkey(&container->sign_key, pucResponsePublicKey);
	sm2_key_to_eccref_pubkey(&resp_tmp, pucResponseTmpPublicKey);

	/* is_initiator = 0: ZA is the sponsor's Z, ZB the responder's Z */
	if (sm2_key_exchange(0,
			&container->sign_key,
			(const char *)pucResponseID, uiResponseIDLength,
			&sponsor_static,
			(const char *)pucSponsorID, uiSponsorIDLength,
			&resp_tmp,
			peer_tmp,
			NULL,
			uiKeyBits / 8, shared) != 1) {
		error_print();
		gmssl_secure_clear(&resp_tmp, sizeof(resp_tmp));
		return SDR_SKOPERR;
	}
	gmssl_secure_clear(&resp_tmp, sizeof(resp_tmp));

	key = session_key_new(session, shared, uiKeyBits / 8);
	gmssl_secure_clear(shared, sizeof(shared));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_ExchangeDigitEnvelopeBaseOnECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucEncDataIn,
	ECCCipher *pucEncDataOut)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container;
	SM2_KEY ext_pub;
	uint8_t session_key[SOFTSDF_MAX_KEY_SIZE];
	size_t key_len = 0;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey == NULL || pucEncDataIn == NULL || pucEncDataOut == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (eccref_pubkey_to_sm2_key(pucPublicKey, &ext_pub) != 0)
		return SDR_INARGERR;

	container = find_container(session, uiKeyIndex);
	if (container == NULL) {
		error_puts("key index not loaded, call GetPrivateKeyAccess first\n");
		return SDR_INARGERR;
	}

	if (sm2_decrypt_session_key(&container->enc_key, pucEncDataIn,
			session_key, &key_len) != 0)
		return SDR_SKOPERR;
	if (sm2_encrypt_session_key(&ext_pub, session_key, key_len,
			pucEncDataOut) != 0) {
		gmssl_secure_clear(session_key, sizeof(session_key));
		return SDR_PKOPERR;
	}
	gmssl_secure_clear(session_key, sizeof(session_key));
	return SDR_OK;
}

// XXX: `SDF_GenerateKeyWithKEK` use CBC-Padding, so the `pucKey` can not be decrypted by `SDF_Decrypt`
int SDF_GenerateKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file;
	uint8_t kek[16];
	SM4_KEY sm4_key;
	uint8_t *iv;
	uint8_t *enced;
	size_t enced_len;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiKeyBits % 8 != 0 || uiKeyBits/8 > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM4_CBC && uiAlgID != SGD_SM4_ECB) {
		error_print();
		return SDR_INARGERR;
	}

	// load KEK file with index
	snprintf(filename, FILENAME_MAX_LEN, "kek-%u.key", uiKEKIndex);
	file = fopen(filename, "rb");
	if (file == NULL) {
		fprintf(stderr, "open file: %s\n", filename);
		error_print();
		return SDR_KEYNOTEXIST;
	}

	size_t rlen;
	if ((rlen = fread(kek, 1, sizeof(kek), file)) != sizeof(kek)) {


		printf("rlen = %zu\n", rlen);
		perror("fread");
		error_print();
		fclose(file);
		return SDR_INARGERR;
	}
	fclose(file);

	if (pucKey == NULL || puiKeyLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// generate key
	key = (SOFTSDF_KEY *)malloc(sizeof(SOFTSDF_KEY));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));

	iv = pucKey;
	enced = pucKey + SM4_BLOCK_SIZE;

	if (rand_bytes(iv, SM4_BLOCK_SIZE) != 1) {
		error_print();
		return SDR_RANDERR;
	}

	key->key_size = uiKeyBits/8;
	if (rand_bytes(key->key, key->key_size) != 1) {
		error_print();
		free(key);
		return SDR_RANDERR;
	}

	sm4_set_encrypt_key(&sm4_key, kek);
	if (sm4_cbc_padding_encrypt(&sm4_key, iv, key->key, key->key_size, enced, &enced_len) != 1) {
		error_print();
		memset(&sm4_key, 0, sizeof(sm4_key));
		free(key);
		return SDR_SYMOPERR;
	}
	memset(&sm4_key, 0, sizeof(sm4_key));
	*puiKeyLength = 16 + enced_len;

	// append key to key_list
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_ImportKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file;
	uint8_t kek[16];
	SM4_KEY sm4_key;
	const uint8_t *iv;
	const uint8_t *enced;
	size_t enced_len;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM4_CBC && uiAlgID != SGD_SM4_ECB) {
		error_print();
		return SDR_INARGERR;
	}

	// load KEK file with index
	snprintf(filename, FILENAME_MAX_LEN, "kek-%u.key", uiKEKIndex);
	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (fread(kek, 1, sizeof(kek), file) != sizeof(kek)) {
		error_print();
		fclose(file);
		return SDR_INARGERR;
	}
	fclose(file);


	// decrypt SM4-CBC encrypted pucKey
	if (pucKey == NULL || uiKeyLength <= SM4_BLOCK_SIZE) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiKeyLength > SM4_BLOCK_SIZE + SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	key = (SOFTSDF_KEY *)malloc(sizeof(SOFTSDF_KEY));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));

	iv = pucKey;
	enced = pucKey + SM4_BLOCK_SIZE;
	enced_len = uiKeyLength - SM4_BLOCK_SIZE;

	sm4_set_decrypt_key(&sm4_key, kek);
	if (sm4_cbc_padding_decrypt(&sm4_key, iv, enced, enced_len, key->key, &key->key_size) != 1) {
		error_print();
		memset(&sm4_key, 0, sizeof(sm4_key));
		free(key);
		return SDR_SYMOPERR;
	}
	memset(&sm4_key, 0, sizeof(sm4_key));

	// append key to key_list
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

/* 2012 6.3.20: import a plaintext session key directly */
int SDF_ImportKey(
	void *hSessionHandle,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucKey == NULL || phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiKeyLength == 0 || uiKeyLength > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	key = (SOFTSDF_KEY *)malloc(sizeof(*key));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));
	memcpy(key->key, pucKey, uiKeyLength);
	key->key_size = uiKeyLength;

	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}
	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_DestroyKey(
	void *hSessionHandle,
	void *hKeyHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *current;
	SOFTSDF_KEY *prev;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	current = session->key_list;
	{
		assert(current != NULL);
	}
	prev = NULL;
	while (current != NULL && current != (SOFTSDF_KEY *)hKeyHandle) {
		prev = current;
		current = current->next;
	}
	if (current == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (prev == NULL) {
		session->key_list = current->next;
	} else {
		prev->next = current->next;
	}
	memset(current, 0, sizeof(SOFTSDF_KEY));
	free(current);

	return SDR_OK;
}

/* raw RSA operation output: capacity check + fixed-length copy */
static int rsa_raw_op_output(unsigned int k,
	unsigned char *pucDataOutput, unsigned int *puiOutputLength,
	const uint8_t *tmp)
{
	if (pucDataOutput == NULL || puiOutputLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (*puiOutputLength < k) {
		error_print();
		return SDR_NOBUFFER;
	}
	memcpy(pucDataOutput, tmp, k);
	*puiOutputLength = k;
	return SDR_OK;
}

int SDF_ExternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	SOFTSDF_SESSION *session;
	uint8_t out[256];
	unsigned int k;
	int ret;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey == NULL || pucDataInput == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey->bits != 1024 && pucPublicKey->bits != 2048) {
		error_print();
		return SDR_INARGERR;
	}
	k = pucPublicKey->bits / 8;
	if (pucDataOutput == NULL || puiOutputLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (*puiOutputLength < k) {
		error_print();
		return SDR_NOBUFFER;
	}
	if (softsdf_rsa_public_op(pucPublicKey, pucDataInput, uiInputLength,
			out) != 0) {
		error_print();
		return SDR_PKOPERR;
	}
	ret = rsa_raw_op_output(k, pucDataOutput, puiOutputLength, out);
	gmssl_secure_clear(out, sizeof(out));
	return ret;
}

int SDF_ExternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPrivateKey *pucPrivateKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	SOFTSDF_SESSION *session;
	uint8_t out[256];
	unsigned int k;
	int ret;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPrivateKey == NULL || pucDataInput == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPrivateKey->bits != 1024 && pucPrivateKey->bits != 2048) {
		error_print();
		return SDR_INARGERR;
	}
	k = pucPrivateKey->bits / 8;
	if (pucDataOutput == NULL || puiOutputLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (*puiOutputLength < k) {
		error_print();
		return SDR_NOBUFFER;
	}
	if (softsdf_rsa_private_op(pucPrivateKey, pucDataInput, uiInputLength,
			out) != 0) {
		error_print();
		return SDR_SKOPERR;
	}
	ret = rsa_raw_op_output(k, pucDataOutput, puiOutputLength, out);
	gmssl_secure_clear(out, sizeof(out));
	return ret;
}

int SDF_InternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	SOFTSDF_SESSION *session;
	RSArefPrivateKey priv;
	uint8_t out[256];
	unsigned int k;
	int ret;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucDataInput == NULL || pucDataOutput == NULL
		|| puiOutputLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (find_container(session, uiKeyIndex) == NULL) {
		error_puts("private key right not acquired for private operation\n");
		return SDR_PARDENY;
	}
	if (rsa_load_keyfile(uiKeyIndex, "rsasign", &priv) != SDR_OK)
		return SDR_KEYNOTEXIST;
	k = priv.bits / 8;
	if (*puiOutputLength < k) {
		error_print();
		gmssl_secure_clear(&priv, sizeof(priv));
		return SDR_NOBUFFER;
	}
	if (softsdf_rsa_private_op(&priv, pucDataInput, uiInputLength, out) != 0) {
		error_print();
		gmssl_secure_clear(&priv, sizeof(priv));
		return SDR_SKOPERR;
	}
	gmssl_secure_clear(&priv, sizeof(priv));
	ret = rsa_raw_op_output(k, pucDataOutput, puiOutputLength, out);
	gmssl_secure_clear(out, sizeof(out));
	return ret;
}

int SDF_ExternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature)
{
	SOFTSDF_SESSION *session;
	SM2_POINT point;
	SM2_Z256_POINT public_key;
	SM2_KEY sm2_key;
	SM2_SIGNATURE sig;
	unsigned int i;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_1) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey->bits != 256) {
		error_print();
		return SDR_INARGERR;
	}

	// load public key
	memset(&point, 0, sizeof(point));
	memcpy(point.x, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}
	if (sm2_key_set_public_key(&sm2_key, &public_key) != 1) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucDataInput == NULL || uiInputLength != 32) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucSignature == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucSignature->r[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucSignature->s[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}

	memcpy(sig.r, pucSignature->r + ECCref_MAX_LEN - 32, 32);
	memcpy(sig.s, pucSignature->s + ECCref_MAX_LEN - 32, 32);

	if (sm2_do_verify(&sm2_key, pucDataInput, &sig) != 1) {
		error_print();
		return SDR_VERIFYERR;
	}

	return SDR_OK;
}

int SDF_InternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container;
	SM2_SIGNATURE sig;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// find container with key index
	container = session->container_list;
	while (container != NULL && container->key_index != uiISKIndex) {
		container = container->next;
	}
	if (container == NULL) {
		error_puts("private key right not acquired for signing\n");
		return SDR_PARDENY;
	}

	if (pucData == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiDataLength != SM3_DIGEST_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucSignature == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (sm2_do_sign(&container->sign_key, pucData, &sig) != 1) {
		error_print();
		return SDR_SIGNERR;
	}

	memset(pucSignature, 0, sizeof(*pucSignature));
	memcpy(pucSignature->r + ECCref_MAX_LEN - 32, sig.r, 32);
	memcpy(pucSignature->s + ECCref_MAX_LEN - 32, sig.s, 32);

	return SDR_OK;
}

int SDF_InternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	SM2_KEY sm2_key;
	SM2_SIGNATURE sig;
	unsigned int i;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// load public key from file
	snprintf(filename, FILENAME_MAX_LEN, "sm2signpub-%u.pem", uiIPKIndex);
	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (sm2_public_key_info_from_pem(&sm2_key, file) != 1) {
		error_print();
		fclose(file);
		return SDR_KEYNOTEXIST;
	}
	fclose(file);

	if (pucData == NULL || uiDataLength != SM3_DIGEST_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucSignature == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucSignature->r[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucSignature->s[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}

	memcpy(sig.r, pucSignature->r + ECCref_MAX_LEN - 32, 32);
	memcpy(sig.s, pucSignature->s + ECCref_MAX_LEN - 32, 32);

	if (sm2_do_verify(&sm2_key, pucData, &sig) != 1) {
		error_print();
		return SDR_VERIFYERR;
	}

	return SDR_OK;
}

int SDF_ExternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPrivateKey *pucPrivateKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	SOFTSDF_SESSION *session;
	SM2_KEY sm2_key;
	sm2_z256_t priv;
	SM2_SIGNATURE sig;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_1) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPrivateKey == NULL || pucData == NULL || pucSignature == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPrivateKey->bits != 256
		|| memcmp(pucPrivateKey->K, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiDataLength != SM3_DIGEST_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	sm2_z256_from_bytes(priv, pucPrivateKey->K + ECCref_MAX_LEN - 32);
	if (sm2_key_set_private_key(&sm2_key, priv) != 1) {
		error_print();
		gmssl_secure_clear(priv, sizeof(priv));
		return SDR_INARGERR;
	}
	gmssl_secure_clear(priv, sizeof(priv));

	if (sm2_do_sign(&sm2_key, pucData, &sig) != 1) {
		error_print();
		gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
		return SDR_SIGNERR;
	}
	gmssl_secure_clear(&sm2_key, sizeof(sm2_key));

	memset(pucSignature, 0, sizeof(*pucSignature));
	memcpy(pucSignature->r + ECCref_MAX_LEN - 32, sig.r, 32);
	memcpy(pucSignature->s + ECCref_MAX_LEN - 32, sig.s, 32);
	return SDR_OK;
}

int SDF_ExternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	SOFTSDF_SESSION *session;
	SM2_POINT point;
	SM2_Z256_POINT public_key;
	SM2_KEY sm2_key;
	SM2_CIPHERTEXT ctxt;
	unsigned int i;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey->bits != 256) {
		error_print();
		return SDR_INARGERR;
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucPublicKey->x[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucPublicKey->y[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}

	// parse public key
	memset(&point, 0, sizeof(point));
	memcpy(point.x, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return SDR_INARGERR;
	}
	if (sm2_key_set_public_key(&sm2_key, &public_key) != 1) {
		error_print();
		return SDR_INARGERR;
	}

	if (!pucData) {
		error_print();
		return SDR_INARGERR;
	}

	if(uiDataLength <=0 || uiDataLength > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (sm2_do_encrypt(&sm2_key, pucData, uiDataLength, &ctxt) != 1) {
		error_print();
		return SDR_PKOPERR;
	}

	/* field-wise output: caller's ECCCipher has flexible C, never memset whole struct */
	memset(pucEncData->x, 0, ECCref_MAX_LEN - 32);
	memcpy(pucEncData->x + ECCref_MAX_LEN - 32, ctxt.point.x, 32);
	memset(pucEncData->y, 0, ECCref_MAX_LEN - 32);
	memcpy(pucEncData->y + ECCref_MAX_LEN - 32, ctxt.point.y, 32);
	memcpy(pucEncData->M, ctxt.hash, 32);
	pucEncData->L = ctxt.ciphertext_size;
	memcpy(pucEncData->C, ctxt.ciphertext, ctxt.ciphertext_size);

	return SDR_OK;
}

int SDF_ExternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPrivateKey *pucPrivateKey,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	SOFTSDF_SESSION *session;
	SM2_KEY sm2_key;
	sm2_z256_t priv;
	SM2_CIPHERTEXT ctxt;
	size_t plaintext_len = 0;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPrivateKey == NULL || pucEncData == NULL
		|| puiDataLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPrivateKey->bits != 256
		|| memcmp(pucPrivateKey->K, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucEncData->L > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return SDR_INARGERR;
	}
	if (memcmp(pucEncData->x, zeros, ECCref_MAX_LEN - 32) != 0
		|| memcmp(pucEncData->y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucData == NULL) {
		*puiDataLength = pucEncData->L;
		return SDR_OK;
	}
	if (*puiDataLength < pucEncData->L) {
		error_print();
		return SDR_NOBUFFER;
	}

	sm2_z256_from_bytes(priv, pucPrivateKey->K + ECCref_MAX_LEN - 32);
	if (sm2_key_set_private_key(&sm2_key, priv) != 1) {
		error_print();
		gmssl_secure_clear(priv, sizeof(priv));
		return SDR_INARGERR;
	}
	gmssl_secure_clear(priv, sizeof(priv));

	ecccipher_to_sm2(pucEncData, &ctxt);
	if (sm2_do_decrypt(&sm2_key, &ctxt, pucData, &plaintext_len) != 1) {
		error_print();
		gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
		return SDR_PKOPERR;
	}
	gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
	*puiDataLength = (unsigned int)plaintext_len;
	return SDR_OK;
}

int SDF_Encrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV, // [in] standard 6.5.2: caller's IV is input, never written back
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	SM4_KEY sm4_key;
	uint8_t iv[SM4_BLOCK_SIZE];

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	key = session->key_list;
	while (key != NULL && key != (SOFTSDF_KEY *)hKeyHandle) {
		key = key->next;
	}
	if (key == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (key->key_size < SM4_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucData == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (puiEncDataLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	switch (uiAlgID) {
	case SGD_SM4_CBC:
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		if (uiDataLength % 16) {
			error_print();
			return SDR_INARGERR;
		}
		break;
#if ENABLE_SM4_ECB
	case SGD_SM4_ECB:
		if (uiDataLength % 16) {
			error_print();
			return SDR_INARGERR;
		}
		break;
#endif
#if ENABLE_SM4_CFB
	case SGD_SM4_CFB:
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		break;
#endif
#if ENABLE_SM4_OFB
	case SGD_SM4_OFB:
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		break;
#endif
	case SGD_SM4_CTR:
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		break;
	default:
		error_print();
		return SDR_INARGERR;
	}

	// XXX: change this when add CBC-Padding mode
	*puiEncDataLength = uiDataLength;

	if (pucEncData == NULL) {
		return SDR_OK;
	}

	// TODO: cache `SM4_KEY` in `SOFTSDF_KEY`, reduce cost of calling `sm4_set_encrypt_key`
	sm4_set_encrypt_key(&sm4_key, key->key);

	// GmSSL stream/chain modes mutate the IV buffer; chain on a local copy only
	if (pucIV) {
		memcpy(iv, pucIV, SM4_BLOCK_SIZE);
	}

	switch (uiAlgID) {
	case SGD_SM4_CBC:
		sm4_cbc_encrypt_blocks(&sm4_key, iv, pucData, uiDataLength/16, pucEncData);
		break;
#if ENABLE_SM4_ECB
	case SGD_SM4_ECB:
		sm4_encrypt_blocks(&sm4_key, pucData, uiDataLength/16, pucEncData);
		break;
#endif
#if ENABLE_SM4_CFB
	case SGD_SM4_CFB:
		sm4_cfb_encrypt(&sm4_key, SM4_CFB_128, iv, pucData, uiDataLength, pucEncData);
		break;
#endif
#if ENABLE_SM4_OFB
	case SGD_SM4_OFB:
		sm4_ofb_encrypt(&sm4_key, iv, pucData, uiDataLength, pucEncData);
		break;
#endif
	case SGD_SM4_CTR:
		sm4_ctr_encrypt(&sm4_key, iv, pucData, uiDataLength, pucEncData);
		break;
	default:
		gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		error_print();
		return SDR_INARGERR;
	}

	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));

	return SDR_OK;
}

int SDF_Decrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV, // [in] standard 6.5.3: caller's IV is input, never written back
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	SM4_KEY sm4_key;
	uint8_t iv[SM4_BLOCK_SIZE];

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	key = session->key_list;
	while (key != NULL && key != (SOFTSDF_KEY *)hKeyHandle) {
		key = key->next;
	}
	if (key == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (key->key_size < SM4_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucEncData == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (puiDataLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	switch (uiAlgID) {
	case SGD_SM4_CBC:
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		if (uiEncDataLength % 16) {
			error_print();
			return SDR_INARGERR;
		}
		break;
#if ENABLE_SM4_ECB
	case SGD_SM4_ECB:
		if (uiEncDataLength % 16) {
			error_print();
			return SDR_INARGERR;
		}
		break;
#endif
#if ENABLE_SM4_CFB
	case SGD_SM4_CFB:
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		break;
#endif
#if ENABLE_SM4_OFB
	case SGD_SM4_OFB:
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		break;
#endif
	case SGD_SM4_CTR:
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		break;
	default:
		error_print();
		return SDR_INARGERR;
	}

	*puiDataLength = uiEncDataLength;

	if (pucData == NULL) {
		return SDR_OK;
	}

	// TODO: cache `SM4_KEY` in `SOFTSDF_KEY`, reduce cost of calling `sm4_set_encrypt_key`

	// GmSSL stream/chain modes mutate the IV buffer; chain on a local copy only
	if (pucIV) {
		memcpy(iv, pucIV, SM4_BLOCK_SIZE);
	}

	switch (uiAlgID) {
	case SGD_SM4_CBC:
		sm4_set_decrypt_key(&sm4_key, key->key);
		sm4_cbc_decrypt_blocks(&sm4_key, iv, pucEncData, uiEncDataLength/16, pucData);
		break;
#if ENABLE_SM4_ECB
	case SGD_SM4_ECB:
		sm4_set_decrypt_key(&sm4_key, key->key);
		sm4_encrypt_blocks(&sm4_key, pucEncData, uiEncDataLength/16, pucData);
		break;
#endif
#if ENABLE_SM4_CFB
	case SGD_SM4_CFB:
		sm4_set_encrypt_key(&sm4_key, key->key);
		sm4_cfb_decrypt(&sm4_key, SM4_CFB_128, iv, pucEncData, uiEncDataLength, pucData);
		break;
#endif
#if ENABLE_SM4_OFB
	case SGD_SM4_OFB:
		sm4_set_encrypt_key(&sm4_key, key->key);
		sm4_ofb_encrypt(&sm4_key, iv, pucEncData, uiEncDataLength, pucData);
		break;
#endif
	case SGD_SM4_CTR:
		sm4_set_encrypt_key(&sm4_key, key->key);
		sm4_ctr_encrypt(&sm4_key, iv, pucEncData, uiEncDataLength, pucData);
		break;
	default:
		gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		error_print();
		return SDR_INARGERR;
	}

	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));

	return SDR_OK;
}

int SDF_CalculateMAC(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucMAC,
	unsigned int *puiMACLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	key = session->key_list;
	while (key != NULL && key != (SOFTSDF_KEY *)hKeyHandle) {
		key = key->next;
	}
	if (key == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucData == NULL || uiDataLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}

	if (puiMACLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID == SGD_SM3) {
		SM3_HMAC_CTX hmac_ctx;

		if (pucIV != NULL) {
			error_print();
			return SDR_INARGERR;
		}
		if (key->key_size < 12) {
			error_print();
			return SDR_INARGERR;
		}

		*puiMACLength = SM3_HMAC_SIZE;

		if (!pucMAC) {
			return SDR_OK;
		}

		sm3_hmac_init(&hmac_ctx, key->key, key->key_size);
		sm3_hmac_update(&hmac_ctx, pucData, uiDataLength);
		sm3_hmac_finish(&hmac_ctx, pucMAC);

		memset(&hmac_ctx, 0, sizeof(hmac_ctx));

	} else if (uiAlgID == SGD_SM4_MAC) {
		SM4_CBC_MAC_CTX cbc_mac_ctx;

		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		if (key->key_size < SM4_KEY_SIZE) {
			error_print();
			return SDR_INARGERR;
		}
		*puiMACLength = SM4_CBC_MAC_SIZE;

		if (!pucMAC) {
			return SDR_OK;
		}

		sm4_cbc_mac_init(&cbc_mac_ctx, key->key);
		memcpy(cbc_mac_ctx.iv, pucIV, SM4_BLOCK_SIZE);
		sm4_cbc_mac_update(&cbc_mac_ctx, pucData, uiDataLength);
		sm4_cbc_mac_finish(&cbc_mac_ctx, pucMAC);

		memset(&cbc_mac_ctx, 0, sizeof(cbc_mac_ctx));

	} else {
		error_print();
		return SDR_INARGERR;
	}

	return SDR_OK;
}

#define SOFTSDF_SYM_ENC	1
#define SOFTSDF_SYM_DEC	2
#define SOFTSDF_SYM_MAC	3

/* GmSSL updates emit at most inlen + one buffered block into obuf */
static int sym_obuf_reserve(SOFTSDF_SYM_STATE *sym, size_t extra)
{
	uint8_t *p;
	size_t need = sym->obuf_len + extra;

	if (need <= sym->obuf_cap)
		return 0;
	p = (uint8_t *)realloc(sym->obuf, need);
	if (p == NULL)
		return -1;
	sym->obuf = p;
	sym->obuf_cap = need;
	return 0;
}

/* deliver min(cap, pending output); shift the remainder to the front */
static unsigned int sym_obuf_deliver(SOFTSDF_SYM_STATE *sym,
	unsigned char *out, unsigned int cap)
{
	size_t d = sym->obuf_len;

	if (out == NULL || d == 0)
		return 0;
	if (d > cap)
		d = cap;
	memcpy(out, sym->obuf, d);
	if (d < sym->obuf_len)
		memmove(sym->obuf, sym->obuf + d, sym->obuf_len - d);
	sym->obuf_len -= d;
	return (unsigned int)d;
}

static int sym_find_key(SOFTSDF_SESSION *session, void *hKeyHandle,
	SOFTSDF_KEY **key_out)
{
	SOFTSDF_KEY *key;

	if (hKeyHandle == NULL)
		return SDR_INARGERR;
	key = session->key_list;
	while (key != NULL && key != (SOFTSDF_KEY *)hKeyHandle) {
		key = key->next;
	}
	if (key == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	*key_out = key;
	return SDR_OK;
}

/* IV requirements per mode; ECB takes no IV */
static int sym_iv_check(unsigned int alg, const unsigned char *pucIV,
	unsigned int uiIVLength)
{
	if (alg == SGD_SM4_ECB)
		return SDR_OK;
	if (pucIV == NULL || uiIVLength != SM4_BLOCK_SIZE) {
		error_print();
		return SDR_INARGERR;
	}
	return SDR_OK;
}

int SDF_EncryptInit(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned int uiIVLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	int rv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if ((rv = sym_find_key(session, hKeyHandle, &key)) != SDR_OK)
		return rv;
	if (key->key_size != SM4_KEY_SIZE) {
		error_print();
		return SDR_ALGNOTSUPPORT;
	}

	switch (uiAlgID) {
	case SGD_SM4_ECB:
#if ENABLE_SM4_ECB
		if (sm4_ecb_encrypt_init(&session->sym.u.ecb, key->key) != 1)
			return SDR_SYMOPERR;
		break;
#else
		return SDR_ALGMODNOTSUPPORT;
#endif
	case SGD_SM4_CBC:
		if ((rv = sym_iv_check(uiAlgID, pucIV, uiIVLength)) != SDR_OK)
			return rv;
		if (sm4_cbc_encrypt_init(&session->sym.u.cbc, key->key, pucIV) != 1)
			return SDR_SYMOPERR;
		break;
	case SGD_SM4_CFB:
#if ENABLE_SM4_CFB
		if ((rv = sym_iv_check(uiAlgID, pucIV, uiIVLength)) != SDR_OK)
			return rv;
		if (sm4_cfb_encrypt_init(&session->sym.u.cfb, SM4_CFB_128,
				key->key, pucIV) != 1)
			return SDR_SYMOPERR;
		break;
#else
		return SDR_ALGMODNOTSUPPORT;
#endif
	case SGD_SM4_OFB:
#if ENABLE_SM4_OFB
		if ((rv = sym_iv_check(uiAlgID, pucIV, uiIVLength)) != SDR_OK)
			return rv;
		if (sm4_ofb_encrypt_init(&session->sym.u.ofb, key->key, pucIV) != 1)
			return SDR_SYMOPERR;
		break;
#else
		return SDR_ALGMODNOTSUPPORT;
#endif
	case SGD_SM4_CTR:
		if ((rv = sym_iv_check(uiAlgID, pucIV, uiIVLength)) != SDR_OK)
			return rv;
		if (sm4_ctr_encrypt_init(&session->sym.u.ctr, key->key, pucIV) != 1)
			return SDR_SYMOPERR;
		break;
	default:
		error_print();
		return SDR_ALGMODNOTSUPPORT;
	}

	/* Init restarts: output stranded by an abandoned operation is dropped */
	session->sym.obuf_len = 0;
	session->sym.active = 1;
	session->sym.role = SOFTSDF_SYM_ENC;
	session->sym.alg = uiAlgID;
	return SDR_OK;
}

int SDF_DecryptInit(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned int uiIVLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	int rv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if ((rv = sym_find_key(session, hKeyHandle, &key)) != SDR_OK)
		return rv;
	if (key->key_size != SM4_KEY_SIZE) {
		error_print();
		return SDR_ALGNOTSUPPORT;
	}

	switch (uiAlgID) {
	case SGD_SM4_ECB:
#if ENABLE_SM4_ECB
		if (sm4_ecb_decrypt_init(&session->sym.u.ecb, key->key) != 1)
			return SDR_SYMOPERR;
		break;
#else
		return SDR_ALGMODNOTSUPPORT;
#endif
	case SGD_SM4_CBC:
		if ((rv = sym_iv_check(uiAlgID, pucIV, uiIVLength)) != SDR_OK)
			return rv;
		if (sm4_cbc_decrypt_init(&session->sym.u.cbc, key->key, pucIV) != 1)
			return SDR_SYMOPERR;
		break;
	case SGD_SM4_CFB:
#if ENABLE_SM4_CFB
		if ((rv = sym_iv_check(uiAlgID, pucIV, uiIVLength)) != SDR_OK)
			return rv;
		if (sm4_cfb_decrypt_init(&session->sym.u.cfb, SM4_CFB_128,
				key->key, pucIV) != 1)
			return SDR_SYMOPERR;
		break;
#else
		return SDR_ALGMODNOTSUPPORT;
#endif
	case SGD_SM4_OFB:
#if ENABLE_SM4_OFB
		if ((rv = sym_iv_check(uiAlgID, pucIV, uiIVLength)) != SDR_OK)
			return rv;
		if (sm4_ofb_encrypt_init(&session->sym.u.ofb, key->key, pucIV) != 1)
			return SDR_SYMOPERR;
		break;
#else
		return SDR_ALGMODNOTSUPPORT;
#endif
	case SGD_SM4_CTR:
		if ((rv = sym_iv_check(uiAlgID, pucIV, uiIVLength)) != SDR_OK)
			return rv;
		if (sm4_ctr_encrypt_init(&session->sym.u.ctr, key->key, pucIV) != 1)
			return SDR_SYMOPERR;
		break;
	default:
		error_print();
		return SDR_ALGMODNOTSUPPORT;
	}

	session->sym.obuf_len = 0;
	session->sym.active = 1;
	session->sym.role = SOFTSDF_SYM_DEC;
	session->sym.alg = uiAlgID;
	return SDR_OK;
}

/* dispatch one multi-packet update to GmSSL; output lands in sym->obuf tail */
static int sym_update(SOFTSDF_SESSION *session,
	const unsigned char *in, unsigned int inlen)
{
	SOFTSDF_SYM_STATE *sym = &session->sym;
	size_t n = 0;
	int ok = 1;

	if (sym_obuf_reserve(sym, (size_t)inlen + SM4_BLOCK_SIZE) != 0) {
		error_print();
		return SDR_NOBUFFER;
	}

	switch (sym->alg) {
	case SGD_SM4_ECB:
#if ENABLE_SM4_ECB
		if (sym->role == SOFTSDF_SYM_ENC)
			ok = sm4_ecb_encrypt_update(&sym->u.ecb, in, inlen,
				sym->obuf + sym->obuf_len, &n);
		else
			ok = sm4_ecb_decrypt_update(&sym->u.ecb, in, inlen,
				sym->obuf + sym->obuf_len, &n);
		break;
#endif
	case SGD_SM4_CBC:
		if (sym->role == SOFTSDF_SYM_ENC)
			ok = sm4_cbc_encrypt_update(&sym->u.cbc, in, inlen,
				sym->obuf + sym->obuf_len, &n);
		else
			ok = sm4_cbc_decrypt_update(&sym->u.cbc, in, inlen,
				sym->obuf + sym->obuf_len, &n);
		break;
	case SGD_SM4_CFB:
#if ENABLE_SM4_CFB
		if (sym->role == SOFTSDF_SYM_ENC)
			ok = sm4_cfb_encrypt_update(&sym->u.cfb, in, inlen,
				sym->obuf + sym->obuf_len, &n);
		else
			ok = sm4_cfb_decrypt_update(&sym->u.cfb, in, inlen,
				sym->obuf + sym->obuf_len, &n);
		break;
#endif
	case SGD_SM4_OFB:
#if ENABLE_SM4_OFB
		ok = sm4_ofb_encrypt_update(&sym->u.ofb, in, inlen,
			sym->obuf + sym->obuf_len, &n);
		break;
#endif
	case SGD_SM4_CTR:
		ok = sm4_ctr_encrypt_update(&sym->u.ctr, in, inlen,
			sym->obuf + sym->obuf_len, &n);
		break;
	default:
		return SDR_ALGMODNOTSUPPORT;
	}

	if (ok != 1) {
		error_print();
		return SDR_SYMOPERR;
	}
	sym->obuf_len += n;
	return SDR_OK;
}

int SDF_EncryptUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength)
{
	SOFTSDF_SESSION *session;
	int rv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!session->sym.active || session->sym.role != SOFTSDF_SYM_ENC) {
		error_puts("SDF_EncryptUpdate without SDF_EncryptInit");
		return SDR_STEPERR;
	}
	if (puiEncDataLength == NULL || (pucData == NULL && uiDataLength > 0)) {
		error_print();
		return SDR_INARGERR;
	}

	if ((rv = sym_update(session, pucData, uiDataLength)) != SDR_OK)
		return rv;
	*puiEncDataLength = sym_obuf_deliver(&session->sym, pucEncData,
		*puiEncDataLength);
	return SDR_OK;
}

int SDF_DecryptUpdate(
	void *hSessionHandle,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	SOFTSDF_SESSION *session;
	int rv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!session->sym.active || session->sym.role != SOFTSDF_SYM_DEC) {
		error_puts("SDF_DecryptUpdate without SDF_DecryptInit");
		return SDR_STEPERR;
	}
	if (puiDataLength == NULL || (pucEncData == NULL && uiEncDataLength > 0)) {
		error_print();
		return SDR_INARGERR;
	}

	if ((rv = sym_update(session, pucEncData, uiEncDataLength)) != SDR_OK)
		return rv;
	*puiDataLength = sym_obuf_deliver(&session->sym, pucData,
		*puiDataLength);
	return SDR_OK;
}

/* shared Final: flush per mode, deliver, end the operation */
static int sym_final(SOFTSDF_SESSION *session, int role,
	unsigned char *out, unsigned int *outlen)
{
	SOFTSDF_SYM_STATE *sym = &session->sym;
	size_t n = 0;
	int ok = 1;
	unsigned int d;

	if (outlen == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (!sym->active || sym->role != role) {
		error_puts("multi-packet Final without Init");
		return SDR_STEPERR;
	}

	switch (sym->alg) {
	case SGD_SM4_ECB:
		/* no padding semantics: a trailing partial block is an error,
		 * complete blocks were already emitted by Update */
		if (sym->u.ecb.block_nbytes != 0) {
			error_print();
			return SDR_INARGERR;
		}
		break;
	case SGD_SM4_CBC:
		if (sym->role == SOFTSDF_SYM_DEC) {
			if (sym->u.cbc.block_nbytes == SM4_BLOCK_SIZE) {
				/* GmSSL finish would strip PKCS#7; decrypt raw */
				if (sym_obuf_reserve(sym, SM4_BLOCK_SIZE) != 0)
					return SDR_NOBUFFER;
				sm4_cbc_decrypt_blocks(&sym->u.cbc.sm4_key,
					sym->u.cbc.iv, sym->u.cbc.block, 1,
					sym->obuf + sym->obuf_len);
				sym->obuf_len += SM4_BLOCK_SIZE;
			} else if (sym->u.cbc.block_nbytes != 0) {
				error_print();
				return SDR_INARGERR;
			}
		} else if (sym->u.cbc.block_nbytes != 0) {
			error_print();
			return SDR_INARGERR;
		}
		break;
	case SGD_SM4_CFB:
#if ENABLE_SM4_CFB
		if (sym_obuf_reserve(sym, SM4_BLOCK_SIZE) != 0)
			return SDR_NOBUFFER;
		if (sym->role == SOFTSDF_SYM_ENC)
			ok = sm4_cfb_encrypt_finish(&sym->u.cfb,
				sym->obuf + sym->obuf_len, &n);
		else
			ok = sm4_cfb_decrypt_finish(&sym->u.cfb,
				sym->obuf + sym->obuf_len, &n);
		break;
#endif
	case SGD_SM4_OFB:
#if ENABLE_SM4_OFB
		if (sym_obuf_reserve(sym, SM4_BLOCK_SIZE) != 0)
			return SDR_NOBUFFER;
		ok = sm4_ofb_encrypt_finish(&sym->u.ofb,
			sym->obuf + sym->obuf_len, &n);
		break;
#endif
	case SGD_SM4_CTR:
		if (sym_obuf_reserve(sym, SM4_BLOCK_SIZE) != 0)
			return SDR_NOBUFFER;
		ok = sm4_ctr_encrypt_finish(&sym->u.ctr,
			sym->obuf + sym->obuf_len, &n);
		break;
	default:
		return SDR_ALGMODNOTSUPPORT;
	}
	if (ok != 1) {
		error_print();
		return SDR_SYMOPERR;
	}
	sym->obuf_len += n;

	d = sym_obuf_deliver(sym, out, *outlen);
	*outlen = d;
	sym->active = 0;
	sym->obuf_len = 0;	/* anything undelivered here is lost */
	return SDR_OK;
}

int SDF_EncryptFinal(
	void *hSessionHandle,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	return sym_final(session, SOFTSDF_SYM_ENC, pucEncData, puiEncDataLength);
}

int SDF_DecryptFinal(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	return sym_final(session, SOFTSDF_SYM_DEC, pucData, puiDataLength);
}

int SDF_CalculateMACInit(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned int uiIVLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	int rv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if ((rv = sym_find_key(session, hKeyHandle, &key)) != SDR_OK)
		return rv;
	if (key->key_size != SM4_KEY_SIZE || uiAlgID != SGD_SM4_MAC) {
		error_print();
		return SDR_ALGNOTSUPPORT;
	}
	if (pucIV == NULL || uiIVLength != SM4_BLOCK_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (sm4_cbc_mac_init(&session->sym.mac, key->key) != 1)
		return SDR_SYMOPERR;
	/* initial chaining value, same as the one-shot path */
	memcpy(session->sym.mac.iv, pucIV, SM4_BLOCK_SIZE);

	session->sym.obuf_len = 0;
	session->sym.active = 1;
	session->sym.role = SOFTSDF_SYM_MAC;
	session->sym.alg = SGD_SM4_MAC;
	return SDR_OK;
}

int SDF_CalculateMACUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!session->sym.active || session->sym.role != SOFTSDF_SYM_MAC) {
		error_puts("SDF_CalculateMACUpdate without SDF_CalculateMACInit");
		return SDR_STEPERR;
	}
	if (pucData == NULL || uiDataLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}

	if (sm4_cbc_mac_update(&session->sym.mac, pucData, uiDataLength) != 1) {
		error_print();
		return SDR_SYMOPERR;
	}
	return SDR_OK;
}

int SDF_CalculateMACFinal(
	void *hSessionHandle,
	unsigned char *pucMAC,
	unsigned int *puiMACLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!session->sym.active || session->sym.role != SOFTSDF_SYM_MAC) {
		error_puts("SDF_CalculateMACFinal without SDF_CalculateMACInit");
		return SDR_STEPERR;
	}
	if (pucMAC == NULL || puiMACLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (*puiMACLength < SM4_CBC_MAC_SIZE) {
		error_print();
		return SDR_NOBUFFER;
	}

	if (sm4_cbc_mac_finish(&session->sym.mac, pucMAC) != 1) {
		error_print();
		session->sym.active = 0;
		return SDR_SYMOPERR;
	}
	session->sym.active = 0;
	*puiMACLength = SM4_CBC_MAC_SIZE;
	return SDR_OK;
}

/* ===== GM/T 0018-2023 表13 可鉴别加解密(GCM/CCM) ===== */

#define SOFTSDF_AEAD_MAX_TOTAL	(1 << 20)	/* buffered model cap: 1MiB */

static int aead_alg_ok(unsigned int alg)
{
	return alg == SGD_SM4_GCM || alg == SGD_SM4_CCM;
}

static int aead_start_var_ok(unsigned int alg, unsigned int len)
{
	if (alg == SGD_SM4_GCM)
		return len >= SM4_GCM_MIN_IV_SIZE && len <= SM4_GCM_MAX_IV_SIZE;
	return len >= SM4_CCM_MIN_IV_SIZE && len <= SM4_CCM_MAX_IV_SIZE;
}

/* shared argument checks for one-shot and multi-packet entry points */
static int aead_common_check(SOFTSDF_SESSION *session, void *hKeyHandle,
	unsigned int uiAlgID, const unsigned char *pucStartVar,
	unsigned int uiStartVarLength, SOFTSDF_KEY **key_out)
{
	SOFTSDF_KEY *key;
	int rv;

	if ((rv = sym_find_key(session, hKeyHandle, &key)) != SDR_OK)
		return rv;
	if (key->key_size != SM4_KEY_SIZE) {
		error_print();
		return SDR_ALGNOTSUPPORT;
	}
	if (!aead_alg_ok(uiAlgID)) {
		error_print();
		return SDR_ALGMODNOTSUPPORT;
	}
	if (pucStartVar == NULL
		|| !aead_start_var_ok(uiAlgID, uiStartVarLength)) {
		error_print();
		return SDR_INARGERR;
	}
	*key_out = key;
	return SDR_OK;
}

/* one-shot AEAD core; tag is fixed at 16 bytes; dummy absorbs a zero-length out */
static int aead_crypt(int encrypt, const uint8_t *key, unsigned int uiAlgID,
	const unsigned char *sv, unsigned int sv_len,
	const unsigned char *aad, unsigned int aad_len,
	const unsigned char *in, unsigned int in_len,
	unsigned char *out, const unsigned char *tag, unsigned char *tag_out)
{
	SM4_KEY sk;
	uint8_t dummy;
	uint8_t *outp = in_len > 0 ? out : &dummy;
	int ok;

	if (in_len > 0 && out == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (aad_len > 0 && aad == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	sm4_set_encrypt_key(&sk, key);
	if (encrypt) {
		if (uiAlgID == SGD_SM4_GCM)
			ok = sm4_gcm_encrypt(&sk, sv, sv_len, aad, aad_len,
				in, in_len, outp, 16, tag_out);
		else
			ok = sm4_ccm_encrypt(&sk, sv, sv_len, aad, aad_len,
				in, in_len, outp, 16, tag_out);
	} else {
		if (uiAlgID == SGD_SM4_GCM)
			ok = sm4_gcm_decrypt(&sk, sv, sv_len, aad, aad_len,
				in, in_len, tag, 16, outp);
		else
			ok = sm4_ccm_decrypt(&sk, sv, sv_len, aad, aad_len,
				in, in_len, tag, 16, outp);
	}
	gmssl_secure_clear(&sk, sizeof(sk));
	if (ok != 1) {
		error_print();
		return encrypt ? SDR_SYMOPERR : SDR_VERIFYERR;
	}
	return SDR_OK;
}

/* release AEAD state: clear key + accumulated buffer, end the operation */
static void aead_release(SOFTSDF_AEAD_STATE *st)
{
	gmssl_secure_clear(st->key, sizeof(st->key));
	if (st->buf) {
		gmssl_secure_clear(st->buf, st->cap);
		free(st->buf);
		st->buf = NULL;
	}
	st->cap = 0;
	st->len = 0;
	st->active = 0;
}

int SDF_AuthEnc(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucStartVar,
	unsigned int uiStartVarLength,
	unsigned char *pucAad,
	unsigned int uiAadLength,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength,
	unsigned char *pucAuthData,
	unsigned int *puiAuthDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	int rv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if ((rv = aead_common_check(session, hKeyHandle, uiAlgID, pucStartVar,
			uiStartVarLength, &key)) != SDR_OK)
		return rv;
	if (pucData == NULL && uiDataLength > 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucEncData == NULL || puiEncDataLength == NULL
		|| pucAuthData == NULL || puiAuthDataLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (*puiEncDataLength < uiDataLength || *puiAuthDataLength < 16) {
		error_print();
		return SDR_NOBUFFER;
	}

	rv = aead_crypt(1, key->key, uiAlgID, pucStartVar, uiStartVarLength,
		pucAad, uiAadLength, pucData, uiDataLength, pucEncData,
		NULL, pucAuthData);
	if (rv != SDR_OK)
		return rv;
	*puiEncDataLength = uiDataLength;
	*puiAuthDataLength = 16;
	return SDR_OK;
}

int SDF_AuthDec(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucStartVar,
	unsigned int uiStartVarLength,
	unsigned char *pucAad,
	unsigned int uiAadLength,
	unsigned char *pucAuthData,
	unsigned int uiAuthDataLength,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	int rv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if ((rv = aead_common_check(session, hKeyHandle, uiAlgID, pucStartVar,
			uiStartVarLength, &key)) != SDR_OK)
		return rv;
	if (pucAuthData == NULL || uiAuthDataLength != 16) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucEncData == NULL && uiEncDataLength > 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucData == NULL || puiDataLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (*puiDataLength < uiEncDataLength) {
		error_print();
		return SDR_NOBUFFER;
	}

	rv = aead_crypt(0, key->key, uiAlgID, pucStartVar, uiStartVarLength,
		pucAad, uiAadLength, pucEncData, uiEncDataLength, pucData,
		pucAuthData, NULL);
	if (rv != SDR_OK)
		return rv;
	*puiDataLength = uiEncDataLength;
	return SDR_OK;
}

/* restart or allocate the AEAD accumulation buffer */
static int aead_init_buf(SOFTSDF_AEAD_STATE *st, unsigned int total)
{
	if (total > SOFTSDF_AEAD_MAX_TOTAL) {
		error_print();
		return SDR_NOBUFFER;
	}
	if (st->buf)
		free(st->buf);
	st->buf = (uint8_t *)malloc(total ? total : 1);
	if (st->buf == NULL) {
		error_print();
		st->cap = 0;
		return SDR_NOBUFFER;
	}
	st->cap = total ? total : 1;
	st->len = 0;
	return SDR_OK;
}

int SDF_AuthEncInit(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucStartVar,
	unsigned int uiStartVarLength,
	unsigned char *pucAad,
	unsigned int uiAadLength,
	unsigned int uiDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_AEAD_STATE *st;
	SOFTSDF_KEY *key;
	int rv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if ((rv = aead_common_check(session, hKeyHandle, uiAlgID, pucStartVar,
			uiStartVarLength, &key)) != SDR_OK)
		return rv;
	if (pucAad == NULL && uiAadLength > 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiAadLength > sizeof(st->aad)) {
		error_print();
		return SDR_NOBUFFER;
	}

	st = &session->aead;
	aead_release(st);	/* abandon any previous operation */
	if ((rv = aead_init_buf(st, uiDataLength)) != SDR_OK)
		return rv;
	memcpy(st->start_var, pucStartVar, uiStartVarLength);
	st->sv_len = uiStartVarLength;
	memcpy(st->aad, pucAad, uiAadLength);
	st->aad_len = uiAadLength;
	memcpy(st->key, key->key, SM4_KEY_SIZE);
	st->alg = uiAlgID;
	st->role = 1;
	st->active = 1;
	return SDR_OK;
}

int SDF_AuthDecInit(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucStartVar,
	unsigned int uiStartVarLength,
	unsigned char *pucAad,
	unsigned int uiAadLength,
	unsigned char *pucAuthData,
	unsigned int uiAuthDataLength,
	unsigned int uiDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_AEAD_STATE *st;
	SOFTSDF_KEY *key;
	int rv;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if ((rv = aead_common_check(session, hKeyHandle, uiAlgID, pucStartVar,
			uiStartVarLength, &key)) != SDR_OK)
		return rv;
	if (pucAad == NULL && uiAadLength > 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiAadLength > sizeof(st->aad)) {
		error_print();
		return SDR_NOBUFFER;
	}
	if (pucAuthData == NULL || uiAuthDataLength != 16) {
		error_print();
		return SDR_INARGERR;
	}

	st = &session->aead;
	aead_release(st);	/* abandon any previous operation */
	if ((rv = aead_init_buf(st, uiDataLength)) != SDR_OK)
		return rv;
	memcpy(st->start_var, pucStartVar, uiStartVarLength);
	st->sv_len = uiStartVarLength;
	memcpy(st->aad, pucAad, uiAadLength);
	st->aad_len = uiAadLength;
	memcpy(st->key, key->key, SM4_KEY_SIZE);
	memcpy(st->tag, pucAuthData, 16);
	st->tag_len = 16;
	st->alg = uiAlgID;
	st->role = 2;
	st->active = 1;
	return SDR_OK;
}

/* accumulate caller data; everything is emitted at Final (buffered model) */
static int aead_update(SOFTSDF_AEAD_STATE *st, int role,
	const unsigned char *in, unsigned int inlen,
	unsigned char *out, unsigned int *outlen)
{
	if (!st->active || st->role != role) {
		error_puts("AEAD Update without Init");
		return SDR_STEPERR;
	}
	if (outlen == NULL || (in == NULL && inlen > 0)) {
		error_print();
		return SDR_INARGERR;
	}
	if ((size_t)inlen > st->cap - st->len) {
		error_puts("AEAD Update exceeds Init-declared total");
		return SDR_NOBUFFER;
	}
	if (inlen > 0)
		memcpy(st->buf + st->len, in, inlen);
	st->len += inlen;
	*outlen = 0;	/* buffered model: no output until Final */
	return SDR_OK;
}

int SDF_AuthEncUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	return aead_update(&session->aead, 1, pucData, uiDataLength,
		pucEncData, puiEncDataLength);
}

int SDF_AuthDecUpdate(
	void *hSessionHandle,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	return aead_update(&session->aead, 2, pucEncData, uiEncDataLength,
		pucData, puiDataLength);
}

/* run the one-shot AEAD over the accumulated buffer, then release it */
static int aead_final(SOFTSDF_SESSION *session, int role,
	unsigned char *out, unsigned int *outlen,
	unsigned char *auth, unsigned int *authlen)
{
	SOFTSDF_AEAD_STATE *st = &session->aead;
	int rv;

	if (outlen == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (!st->active || st->role != role) {
		error_puts("AEAD Final without Init");
		return SDR_STEPERR;
	}
	if (role == 1 && authlen == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (*outlen < st->len || (role == 1 && *authlen < 16)) {
		error_print();
		aead_release(st);
		return SDR_NOBUFFER;
	}

	if (role == 1) {
		rv = aead_crypt(1, st->key, st->alg, st->start_var, st->sv_len,
			st->aad, st->aad_len, st->buf, st->len, out, NULL, auth);
	} else {
		rv = aead_crypt(0, st->key, st->alg, st->start_var, st->sv_len,
			st->aad, st->aad_len, st->buf, st->len, out, st->tag, NULL);
	}
	if (rv != SDR_OK) {
		aead_release(st);
		return rv;
	}
	*outlen = (unsigned int)st->len;
	if (role == 1)
		*authlen = 16;
	aead_release(st);
	return SDR_OK;
}

int SDF_AuthEncFinal(
	void *hSessionHandle,
	unsigned char *pucLastEncData,
	unsigned int *puiLastEncDataLength,
	unsigned char *pucAuthData,
	unsigned int *puiAuthDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	return aead_final(session, 1, pucLastEncData, puiLastEncDataLength,
		pucAuthData, puiAuthDataLength);
}

int SDF_AuthDecFinal(
	void *hSessionHandle,
	unsigned char *pucLastData,
	unsigned int *puiLastDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	return aead_final(session, 2, pucLastData, puiLastDataLength, NULL, NULL);
}

int SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM3) {
		error_print();
		return SDR_INARGERR;
	}

	sm3_init(&session->sm3_ctx);
	session->hash_active = 1;

	if (pucPublicKey != NULL) {

		SM2_POINT point;
		SM2_Z256_POINT public_key;
		uint8_t z[32];

		if (pucID == NULL || uiIDLength <= 0) {
			error_print();
			return SDR_INARGERR;
		}

		memset(&point, 0, sizeof(point));
		memcpy(point.x, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
		memcpy(point.y, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
		if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
			error_print();
			return SDR_INARGERR;
		}

		if (sm2_compute_z(z, &public_key, (const char *)pucID, uiIDLength) != 1) {
			error_print();
			return SDR_INARGERR;
		}
		sm3_update(&session->sm3_ctx, z, sizeof(z));
	}

	return SDR_OK;
}

int SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!session->hash_active) {
		error_puts("SDF_HashUpdate without SDF_HashInit");
		return SDR_STEPERR;
	}

	if (pucData == NULL || uiDataLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}

	sm3_update(&session->sm3_ctx, pucData, uiDataLength);

	return SDR_OK;
}

int SDF_HashFinal(void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!session->hash_active) {
		error_puts("SDF_HashFinal without SDF_HashInit");
		return SDR_STEPERR;
	}

	if (pucHash == NULL || puiHashLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	sm3_finish(&session->sm3_ctx, pucHash);
	session->hash_active = 0;

	*puiHashLength = SM3_DIGEST_SIZE;
	return SDR_OK;
}

int SDF_HMACInit(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	const DIGEST *digest;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	key = session->key_list;
	while (key != NULL && key != (SOFTSDF_KEY *)hKeyHandle) {
		key = key->next;
	}
	if (key == NULL) {
		error_puts("HMAC key handle not in this session\n");
		return SDR_KEYNOTEXIST;
	}

	/* GM/T 0018-2023 6.6.2: uiAlgID is the digest identifier */
	switch (uiAlgID) {
	case SGD_SM3:
		digest = DIGEST_sm3();
		break;
	case SGD_SHA256:
		digest = DIGEST_sha256();
		break;
	default:
		error_print();
		return SDR_ALGNOTSUPPORT;
	}

	if (hmac_init(&session->hmac_ctx, digest, key->key, key->key_size) != 1) {
		error_print();
		return SDR_SYMOPERR;
	}
	session->hmac_active = 1;
	return SDR_OK;
}

int SDF_HMACUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!session->hmac_active) {
		error_puts("SDF_HMACUpdate without SDF_HMACInit");
		return SDR_STEPERR;
	}
	if (pucData == NULL || uiDataLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}

	if (hmac_update(&session->hmac_ctx, pucData, uiDataLength) != 1) {
		error_print();
		return SDR_SYMOPERR;
	}
	return SDR_OK;
}

int SDF_HMACFinal(
	void *hSessionHandle,
	unsigned char *pucMAC,
	unsigned int *puiMACLength)
{
	SOFTSDF_SESSION *session;
	size_t maclen = 0;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!session->hmac_active) {
		error_puts("SDF_HMACFinal without SDF_HMACInit");
		return SDR_STEPERR;
	}
	if (pucMAC == NULL || puiMACLength == NULL) {
		error_print();
		session->hmac_active = 0;
		return SDR_INARGERR;
	}

	/* hmac_finish clears the ctx on both paths */
	if (hmac_finish(&session->hmac_ctx, pucMAC, &maclen) != 1) {
		error_print();
		session->hmac_active = 0;
		return SDR_SYMOPERR;
	}
	session->hmac_active = 0;
	*puiMACLength = (unsigned int)maclen;
	return SDR_OK;
}

int SDF_CreateFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiFileSize)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	uint8_t buf[1024] = {0};
	size_t i;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucFileName == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiNameLen <= 0 || uiNameLen > 128) { /* GM/T 0018: 文件名最长 128 字节 */
		error_print();
		return SDR_INARGERR;
	}
	memcpy(filename, pucFileName, uiNameLen);
	filename[uiNameLen] = 0;
	if (strlen(filename) != uiNameLen) {
		error_print();
		return SDR_INARGERR;
	}
	strcat(filename, ".file");

	if (uiFileSize > 64 * 1024) {
		error_print();
		return SDR_INARGERR;
	}

	// fixed-size store: creating an existing file is an error (standard 6.7.2)
	{
		FILE *exist = fopen(filename, "rb");
		if (exist != NULL) {
			fclose(exist);
			error_print();
			return SDR_FILEEXISTS;
		}
	}

	file = fopen(filename, "wb");
	if (file == NULL) {
		error_puts("Failed to create file");
		return SDR_FILEWERR;
	}
	for (i = 0; i < uiFileSize/sizeof(buf); i++) {
		fwrite(buf, 1, sizeof(buf), file);
	}
	fwrite(buf, 1, uiFileSize % sizeof(buf), file);
	fclose(file);

	return SDR_OK;
}

int SDF_ReadFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int *puiReadLength,
	unsigned char *pucBuffer)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	size_t bytesRead;
	unsigned int fileSize;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucFileName == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiNameLen <= 0 || uiNameLen > 128) { /* GM/T 0018: 文件名最长 128 字节 */
		error_print();
		return SDR_INARGERR;
	}
	memcpy(filename, pucFileName, uiNameLen);
	filename[uiNameLen] = 0;
	if (strlen(filename) != uiNameLen) {
		error_print();
		return SDR_INARGERR;
	}
	strcat(filename, ".file");

	if (puiReadLength == NULL || *puiReadLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucBuffer == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_FILENOEXIST;
	}
	// standard 6.7.3: offset must lie inside the file; output = actual bytes read (EOF-clamped)
	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		error_print();
		return SDR_FILEOFSERR;
	}
	fileSize = (unsigned int)ftell(file);
	if (uiOffset > fileSize) {
		fclose(file);
		error_print();
		return SDR_FILEOFSERR;
	}
	if (fseek(file, uiOffset, SEEK_SET) != 0) {
		fclose(file);
		error_print();
		return SDR_FILEOFSERR;
	}
	bytesRead = fread(pucBuffer, 1, *puiReadLength, file);
	fclose(file);

	*puiReadLength = bytesRead;
	return SDR_OK;
}

int SDF_WriteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int uiWriteLength,
	unsigned char *pucBuffer)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	size_t bytesWritten;
	unsigned int fileSize;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucFileName == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiNameLen <= 0 || uiNameLen > 128) { /* GM/T 0018: 文件名最长 128 字节 */
		error_print();
		return SDR_INARGERR;
	}
	memcpy(filename, pucFileName, uiNameLen);
	filename[uiNameLen] = 0;
	if (strlen(filename) != uiNameLen) {
		error_print();
		return SDR_INARGERR;
	}
	strcat(filename, ".file");

	if (uiWriteLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiWriteLength > 64 * 1024) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucBuffer == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// fixed-size store: write must fit inside the file created by SDF_CreateFile
	file = fopen(filename, "r+b");
	if (file == NULL) {
		error_print();
		return SDR_FILENOEXIST;
	}
	if (fseek(file, 0, SEEK_END) != 0) {
		error_print();
		fclose(file);
		return SDR_FILEOFSERR;
	}
	fileSize = (unsigned int)ftell(file);
	if ((uint64_t)uiOffset + uiWriteLength > (uint64_t)fileSize) {
		error_print();
		fclose(file);
		return SDR_FILEOFSERR;
	}
	if (fseek(file, uiOffset, SEEK_SET) != 0) {
		error_print();
		fclose(file);
		return SDR_FILEOFSERR;
	}
	bytesWritten = fwrite(pucBuffer, 1, uiWriteLength, file);
	if (bytesWritten != uiWriteLength) {
		error_print();
		fclose(file);
		return SDR_FILEWERR;
	}
	fclose(file);

	return SDR_OK;
}

int SDF_DeleteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucFileName == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiNameLen <= 0 || uiNameLen > 128) { /* GM/T 0018: 文件名最长 128 字节 */
		error_print();
		return SDR_INARGERR;
	}
	memcpy(filename, pucFileName, uiNameLen);
	filename[uiNameLen] = 0;
	if (strlen(filename) != uiNameLen) {
		error_print();
		return SDR_INARGERR;
	}
	strcat(filename, ".file");

	if (remove(filename) != 0) {
		error_print();
		return SDR_FILENOEXIST;
	}

	return SDR_OK;
}

int SDF_InternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiAlgID,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	SM2_KEY sm2_key;
	SM2_CIPHERTEXT ciphertext;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// load public key by uiISKIndex
	snprintf(filename, FILENAME_MAX_LEN, "sm2encpub-%u.pem", uiIPKIndex);
	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (sm2_public_key_info_from_pem(&sm2_key, file) != 1) {
		error_print();
		fclose(file);
		return SDR_KEYNOTEXIST;
	}
	fclose(file);

	// check uiAlgID
	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_ALGNOTSUPPORT;
	}

	if (pucData == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiDataLength > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucEncData == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// encrypt
	if (sm2_do_encrypt(&sm2_key, pucData, uiDataLength, &ciphertext) != 1) {
		error_print();
		return SDR_PKOPERR;
	}
	memset(pucEncData->x, 0, ECCref_MAX_LEN - 32);
	memcpy(pucEncData->x + ECCref_MAX_LEN - 32, ciphertext.point.x, 32);
	memset(pucEncData->y, 0, ECCref_MAX_LEN - 32);
	memcpy(pucEncData->y + ECCref_MAX_LEN - 32, ciphertext.point.y, 32);
	memcpy(pucEncData->M, ciphertext.hash, 32);
	memcpy(pucEncData->C, ciphertext.ciphertext, ciphertext.ciphertext_size);
	pucEncData->L = (unsigned int)ciphertext.ciphertext_size;

	return SDR_OK;
}

int SDF_InternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiAlgID,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container;
	SM2_CIPHERTEXT ciphertext;
	size_t plaintext_len;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// load public key by uiISKIndex
	container = session->container_list;
	while (container != NULL && container->key_index != uiISKIndex) {
		container = container->next;
	}
	if (container == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// check uiAlgID
	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_ALGNOTSUPPORT;
	}

	// check ciphertext
	if (pucEncData == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucEncData->L > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	// convert ECCCipher to SM2_CIPHERTEXT
	if (memcmp(pucEncData->x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (memcmp(pucEncData->y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return SDR_INARGERR;
	}
	memcpy(ciphertext.point.x, pucEncData->x + ECCref_MAX_LEN - 32, 32);
	memcpy(ciphertext.point.y, pucEncData->y + ECCref_MAX_LEN - 32, 32);
	memcpy(ciphertext.hash, pucEncData->M, 32);
	memcpy(ciphertext.ciphertext, pucEncData->C, pucEncData->L);
	ciphertext.ciphertext_size = pucEncData->L;

	if (puiDataLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucData == NULL) {
		*puiDataLength = pucEncData->L;
		return SDR_OK;
	}

	if (sm2_do_decrypt(&container->enc_key, &ciphertext, pucData, &plaintext_len) != 1) {
		error_print();
		return SDR_PKOPERR;
	}

	*puiDataLength = (unsigned int)plaintext_len;
	return SDR_OK;
}

int SDF_InternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	SOFTSDF_SESSION *session;
	RSArefPrivateKey priv;
	RSArefPublicKey pub;
	uint8_t out[256];
	unsigned int k;
	int ret;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucDataInput == NULL || pucDataOutput == NULL
		|| puiOutputLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (rsa_load_keyfile(uiKeyIndex, "rsasign", &priv) != SDR_OK)
		return SDR_KEYNOTEXIST;
	softsdf_rsa_pub_from_priv(&priv, &pub);
	gmssl_secure_clear(&priv, sizeof(priv));
	k = pub.bits / 8;
	if (*puiOutputLength < k) {
		error_print();
		return SDR_NOBUFFER;
	}
	if (softsdf_rsa_public_op(&pub, pucDataInput, uiInputLength, out) != 0) {
		error_print();
		return SDR_PKOPERR;
	}
	ret = rsa_raw_op_output(k, pucDataOutput, puiOutputLength, out);
	gmssl_secure_clear(out, sizeof(out));
	return ret;
}
