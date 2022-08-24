/* 
	This header file is for generation of Secrets for LURK crypto service.
	This is the only function that need to be seen from outside.  
*/
#pragma once
#include <stdint.h>
#include "LURK_header.h"
#include <openssl/evp.h> 


/* key_req is the type of the key that whant to be return and secret data
	is the requested secret.
*/
int test_handshake_secrets(uint16_t key_req, Secret *secret_list, unsigned char * ecdhe_secret, confidential_secrets &conf_secrets,
	unsigned char *hashed_handshake_till_now, int size_of_ecdhe_secret, int md_index,
	int operation_mode, int &handshake_hash_size);

const EVP_MD *LURK_handshake_lookup_md2(int md_index);

int tls13_hkdf_expand(const EVP_MD *md, const unsigned char *secret,
	const unsigned char *label, size_t labellen,
	const unsigned char *data, size_t datalen,
	unsigned char *out, size_t outlen);

int tls13_generate_secret(const EVP_MD *md, const unsigned char *prevsecret,
	const unsigned char *insecret, size_t insecretlen, unsigned char *outsecret);
