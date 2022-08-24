#pragma once
#include "LURK_header.h"
int calc_fresh_hash(unsigned char *handshake, unsigned char *provided_hash,
	enum Freshness fresh, unsigned char *server_old_rand,
	int md_number, size_t handshake_size);

size_t add_and_hash_sig_verify(unsigned char * old_handshake_binary, size_t old_handshake_size,
	unsigned char *new_thing_to_add, size_t size_of_new_thing_to_add, enum SignatureScheme sig_algo,
	int md_number, unsigned char *out, size_t *outlen);

size_t add_and_hash_finish(unsigned char * old_handshake_binary, size_t old_handshake_size,
	unsigned char *new_thing_to_add, size_t size_of_new_thing_to_add, int md_number, unsigned char *out, size_t *outlen);

size_t add_and_hash_encrypt_extension_and_certificate(unsigned char * old_handshake_binary, size_t old_handshake_size,
	unsigned char *server_enc_extension, size_t server_enc_extension_size, unsigned char* certificate, size_t certificate_len,
	int md_number, unsigned char *out, size_t *outlen);

//int calc_empty_hash(int md_number,unsigned char *out, size_t *outlen);
