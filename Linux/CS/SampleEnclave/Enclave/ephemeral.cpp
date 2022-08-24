#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include "LURK_header.h"

#include <cstring>

int get_size_of_share_secret(NamedGroup group_id) 
{
	if (group_id == 0x0017 || group_id == 0x001D) {
		return 32;
	}
	else if (group_id == 0x0018) {
		return 48;
	}
	else if (group_id == 0x0019) {
		return 66;
	}
	else if (group_id == 0x001E) {
		return 56;
	}
	else {
		return 0;
	}
}

int copy_pms_into_lurk_request(SInitCertVerifyRequest *request, unsigned char *shared_secret, size_t shared_secret_len)
{
	request->ephemeral->shared_secret->shared_secret_len = get_size_of_share_secret(request->ephemeral->shared_secret->group);
	//something is wrong if this "if" fires since the sizes should be the same
	if ((request->ephemeral->shared_secret->shared_secret_len == 0) ||
		((int)shared_secret_len != request->ephemeral->shared_secret->shared_secret_len)) {
		return -1;
	}
	memcpy(request->ephemeral->shared_secret->shared_secret, shared_secret, request->ephemeral->shared_secret->shared_secret_len);
	return 1;
}

EVP_PKEY *ssl_generate_pkey(EVP_PKEY *pm)
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *pkey = NULL;

	if (pm == NULL) {
		return NULL;
	}
	pctx = EVP_PKEY_CTX_new(pm, NULL);
	if (pctx == NULL) {
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}
	if (EVP_PKEY_keygen_init(pctx) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}
	if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(pctx);
	return pkey;
}
EVP_PKEY *generate_server_ephemeral(EVP_PKEY *ckey, struct SInitCertVerifyResponse *respons, NamedGroup group) 
{
	EVP_PKEY *skey = NULL;
	unsigned char *encodedPoint;
	size_t encoded_pt_len = 0;
	if (ckey == NULL) {
		return NULL;
	}
	skey = ssl_generate_pkey(ckey);
	if (skey == NULL) {
		return NULL;
	}
	encoded_pt_len = EVP_PKEY_get1_tls_encodedpoint(skey, &encodedPoint);
	if (encoded_pt_len == 0) {
		EVP_PKEY_free(skey);
		return NULL;
	}
	memcpy(respons->ephemeral->server_share->key_exchange, encodedPoint, encoded_pt_len);
	respons->ephemeral->server_share->key_len = encoded_pt_len;
	respons->ephemeral->server_share->group = group;
	free(encodedPoint);
	return skey;

}

int get_key_type(NamedGroup group_id)
{
	//TODO add other keys as well
	if (group_id == x25519) {
		return EVP_PKEY_X25519;
	}
	else if (group_id == x448) {
		return EVP_PKEY_X448;
	}
	else if (group_id == secp256r1) {
		return NID_X9_62_prime256v1;
	}
	else if (group_id == secp384r1) {
		return NID_secp384r1;
	}
	else if (group_id == secp521r1) {
		return NID_secp521r1;
	}

	return 0;
}

EVP_PKEY *ssl_generate_param_group(NamedGroup id)
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *pkey = NULL;
	int nid = get_key_type(id);
	if (nid == 0) {
		return NULL;
	}
	//called for X25519 / X448
	if (id == x25519 || id == x448) {
		pkey = EVP_PKEY_new();
		if (pkey != NULL && EVP_PKEY_set_type(pkey, nid))
			return pkey;
		EVP_PKEY_free(pkey);
		return NULL;
	}

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL) {
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}
	if (EVP_PKEY_paramgen_init(pctx) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}
	if (EVP_PKEY_paramgen(pctx, &pkey) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(pctx);
	return pkey;
}

EVP_PKEY *get_peer_public_key(unsigned char *peer_public_key, size_t *peer_public_key_len,
	struct SInitCertVerifyRequest *request)
{
	EVP_PKEY *ckey = ssl_generate_param_group(request->ephemeral->shared_secret->group);
	//int key_type = get_key_type(request->ephemeral->shared_secret->group);

	if (EVP_PKEY_set1_tls_encodedpoint(ckey, peer_public_key, *peer_public_key_len) != 1) {
		return NULL;
	}
	return ckey;

}
int LURK_ssl_derive(EVP_PKEY *privkey, EVP_PKEY *pubkey, struct SInitCertVerifyRequest *request)
{
	int rv = 0;
	unsigned char *pms = NULL;
	size_t pmslen = 0;
	EVP_PKEY_CTX *pctx;

	if (privkey == NULL || pubkey == NULL) {
		return 0;
	}

	pctx = EVP_PKEY_CTX_new(privkey, NULL);

	if (EVP_PKEY_derive_init(pctx) <= 0
		|| EVP_PKEY_derive_set_peer(pctx, pubkey) <= 0
		|| EVP_PKEY_derive(pctx, NULL, &pmslen) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return 0;
	}

	pms = (unsigned char *)malloc(pmslen);
	if (pms == NULL) {
		OPENSSL_clear_free(pms, pmslen);
		EVP_PKEY_CTX_free(pctx);
		return 0;
	}

	if (EVP_PKEY_derive(pctx, pms, &pmslen) <= 0) {
		OPENSSL_clear_free(pms, pmslen);
		EVP_PKEY_CTX_free(pctx);
		return 0;
	}
	if (copy_pms_into_lurk_request(request, pms, pmslen) != 1) {
		return 0;
	}

	OPENSSL_clear_free(pms, pmslen);
	EVP_PKEY_CTX_free(pctx);
	return 1;
}

void handle_ephemeral_secret_gen(unsigned char *peer_public_key, size_t peer_public_key_len,
	struct SInitCertVerifyResponse *respons, struct SInitCertVerifyRequest *req, int *a)
{
	*a = -1;
	EVP_PKEY *ckey = NULL, *skey = NULL;
	// change the client public key from string to struct => ckey
	ckey = get_peer_public_key(peer_public_key, &peer_public_key_len, req);

	//generate the server key and save the public part in respons->ephemeral->server_share->key_exchange
	skey = generate_server_ephemeral(ckey, respons, req->ephemeral->shared_secret->group);
	if (skey == NULL) {
		return ;
	}

	// useing the client public key and server private key generate the pms and save it in the request->ephemeral->shared_secret->shared_secret
	if (LURK_ssl_derive(skey, ckey, req) != 1) {
		return ;
	}
	EVP_PKEY_free(skey);
	EVP_PKEY_free(ckey);
	*a = 1;
	return ;
}