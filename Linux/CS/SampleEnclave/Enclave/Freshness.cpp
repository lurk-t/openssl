//#pragma once
#include "Freshness.h"
#include "Parser.h"
#include <openssl/evp.h>
#include "LURK_header.h"
#include <string.h>


int LURK_handshake_lookup_md(int md_index, const EVP_MD **pmd)
{
	const EVP_MD *md;

	if (md_index == 0x04) {
		md = EVP_sha256();
	}
	else if (md_index == 0x05) {
		md = EVP_sha384();
	}
	else {
		return 0;
	}
	*pmd = md;
	return 1;

}

int LURK_freshness_lookup_md(enum Freshness fresh, const EVP_MD **pmd)
{
	const EVP_MD *md = NULL;

	if (fresh == sha256) {
		md = EVP_sha256();

	}
	else {
		return 0;
	}
	*pmd = md;
	return 1;

}
int freshness_func(unsigned char *old_rand, unsigned char *new_rand, unsigned int *new_rand_size, enum Freshness fresh)
{
	int old_rand_size = 32;
	static const unsigned char server_freshness_lable[] = "tls13 pfs srv";
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = NULL;
	if (!LURK_freshness_lookup_md(fresh, &md)) {
		return 0;
	}
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, old_rand, old_rand_size);
	EVP_DigestUpdate(mdctx, server_freshness_lable, strlen((const char*)server_freshness_lable));
	EVP_DigestFinal_ex(mdctx, new_rand, new_rand_size);
	EVP_MD_CTX_free(mdctx);
	return 1;

}


int update_handshake_with_freshness(unsigned char *handshake, enum Freshness fresh, unsigned char *server_old_rand)
{
	unsigned char freshness_res[EVP_MAX_MD_SIZE];
	unsigned int freshness_res_size;
	if (freshness_func(server_old_rand, freshness_res, &freshness_res_size, fresh) == 0) {
		return 0;
	}
	set_server_rand_val(handshake, freshness_res);
	return 1;
}

int hash_raw_handshake(unsigned char *handshake, unsigned char *out, unsigned int *out_size, int md_number, size_t handshake_size) {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = NULL;
	if (!LURK_handshake_lookup_md(md_number, &md)) {
		return 0;
	}
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, handshake, handshake_size);
	EVP_DigestFinal_ex(mdctx, out, out_size);
	EVP_MD_CTX_free(mdctx);
	return 1;

}

int compare_with_provided_hash(unsigned char *first_input, unsigned char *second_input, size_t size)
{
	int result = memcmp(first_input, second_input, size);
	if (result != 0) {
		return 0;
	}
	return result + 1;
}

int calc_fresh_hash(unsigned char *handshake, unsigned char *provided_hash,
	enum Freshness fresh, unsigned char *server_old_rand,
	int md_number, size_t handshake_size)
{
	unsigned char new_handshake_hash[EVP_MAX_MD_SIZE];
	unsigned int size_of_new_handshake_hash;
	if (update_handshake_with_freshness(handshake, fresh, server_old_rand) ==0 || 
		hash_raw_handshake(handshake, new_handshake_hash, &size_of_new_handshake_hash, md_number, handshake_size) == 0) {
		return 0;
	}
	if (!compare_with_provided_hash(provided_hash, new_handshake_hash, size_of_new_handshake_hash)) {
		return 0;
	}
	else {
		return 1;
	}

}


int calc_fresh_hash2(unsigned char *handshake, unsigned char *out_hash,
	enum Freshness fresh, unsigned char *server_old_rand,
	int md_number, size_t handshake_size)
{
	unsigned char new_handshake_hash[EVP_MAX_MD_SIZE];
	unsigned int size_of_new_handshake_hash;
	if (update_handshake_with_freshness(handshake, fresh, server_old_rand) ==0 || 
		hash_raw_handshake(handshake, new_handshake_hash, &size_of_new_handshake_hash, md_number, handshake_size) == 0) {
		return 0;
	}
	memcpy(out_hash, new_handshake_hash, size_of_new_handshake_hash);
	
	return 1;

}
size_t add_size_t__to_handshake(unsigned char *input_array, size_t index_input_array, size_t number_of_digits, size_t input)
{
	for (size_t ui = 0; ui < number_of_digits; ui++) {
		size_t shifts = (ui * 0x8);
		input_array[index_input_array + number_of_digits - ui - 1] = (unsigned char)((input >> shifts) & 0xff);	
	}
	return (index_input_array + number_of_digits);
}

size_t add_unsignedchar__to_handshake(unsigned char *input_array, size_t index_input_array, size_t size_of_input, unsigned char *input)
{
	for (size_t ui = 0; ui < size_of_input; ui++) {	
		input_array[index_input_array + ui] = input[ui];
	}
	return (index_input_array + size_of_input);
}

//TODO check the old_handshake_binary size before 
size_t temp_add_to_handshake_certificates(unsigned char *old_handshake_binary, size_t old_handshake_size,
	unsigned char *new_thing_to_add, size_t size_of_new_thing_to_add)
{
	enum Internal_tls13_message_type msg_type = certificate;
	old_handshake_binary[old_handshake_size] = (unsigned char)msg_type;
	old_handshake_size++;
	/*3 byte for size which is sig_len + 9 (1 Request Context + 3 Certificates Length + 3 Certificate Length + 2 certificate extensions)*/
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 3, (size_of_new_thing_to_add + 9));
	/*1 byte for  Request Context*/
	size_t req_con = 0; // This record is empty because this certificate was not sent in response to a Certificate Request. 
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 1, req_con);
	/*3 byte for  Certificates Length */
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 3, size_of_new_thing_to_add + 5);
	/*3 byte for  Certificate Length*/
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 3, size_of_new_thing_to_add);
	/*certificate data*/
	old_handshake_size = add_unsignedchar__to_handshake(old_handshake_binary, old_handshake_size, size_of_new_thing_to_add, new_thing_to_add);
	/*Certificate Extensions*/
	size_t cert_extension = 0; //
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 2, cert_extension);

	return old_handshake_size;
}

//TODO check the old_handshake_binary size before 
size_t temp_add_to_handshake_encrypted_extensions(unsigned char *old_handshake_binary, size_t old_handshake_size,
	unsigned char *new_thing_to_add, size_t size_of_new_thing_to_add)
{
	enum Internal_tls13_message_type msg_type = encrypted_extensions;
	old_handshake_binary[old_handshake_size] = (unsigned char)msg_type;
	old_handshake_size++;
	/*3 byte for size which is (extension) data + 2 for extension data 00 00*/
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 3, size_of_new_thing_to_add);

	/*extension data*/
	old_handshake_size = add_unsignedchar__to_handshake(old_handshake_binary, old_handshake_size, size_of_new_thing_to_add, new_thing_to_add);

	return old_handshake_size;
}

//TODO check the old_handshake_binary size before 
size_t temp_add_to_handshake_sig_verify(unsigned char *old_handshake_binary, size_t old_handshake_size,
	unsigned char *new_thing_to_add, size_t size_of_new_thing_to_add, enum SignatureScheme sig_algo)
{
	enum Internal_tls13_message_type msg_type = certificate_verify;
	old_handshake_binary[old_handshake_size] = (unsigned char)msg_type;
	old_handshake_size++;
	/*3 byte for size which is sig_len + 4 (2 sig alg + 2 size sig)*/
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 3, (size_of_new_thing_to_add+0x4));
	/*2 byte for  sig alg*/
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 2, (size_t)sig_algo);
	/*2 byte for  sig size*/
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 2, size_of_new_thing_to_add);
	/*signature data*/
	old_handshake_size = add_unsignedchar__to_handshake(old_handshake_binary, old_handshake_size, size_of_new_thing_to_add, new_thing_to_add);

	return old_handshake_size;
}

//TODO check the old_handshake_binary size before 
size_t update_temp_hash_finish(unsigned char *old_handshake_binary, size_t old_handshake_size,
	unsigned char *new_thing_to_add, size_t size_of_new_thing_to_add) 
{
	enum Internal_tls13_message_type msg_type = finished;
	old_handshake_binary[old_handshake_size] = (unsigned char)msg_type;
	old_handshake_size++;
	/*3 byte for size which is finished data*/
	old_handshake_size = add_size_t__to_handshake(old_handshake_binary, old_handshake_size, 3, size_of_new_thing_to_add);
	/*finished data*/
	old_handshake_size = add_unsignedchar__to_handshake(old_handshake_binary, old_handshake_size, size_of_new_thing_to_add, new_thing_to_add);

	return old_handshake_size;
}

size_t add_and_hash_encrypt_extension_and_certificate(unsigned char *old_handshake_binary, size_t old_handshake_size,
	unsigned char *server_enc_extension, size_t server_enc_extension_size, unsigned char *certificate, size_t certificate_len,
	int md_number, unsigned char *out, size_t *outlen)
{
	unsigned int outsize = 0;

	size_t temp_handshake_size;
	temp_handshake_size = temp_add_to_handshake_encrypted_extensions(old_handshake_binary, old_handshake_size,
		server_enc_extension, server_enc_extension_size);
	temp_handshake_size = temp_add_to_handshake_certificates(old_handshake_binary, temp_handshake_size, certificate, certificate_len);

	if (temp_handshake_size == 0) {
		return 0;
	}
	hash_raw_handshake(old_handshake_binary, out, &outsize, md_number, temp_handshake_size);
	*outlen = outsize;
	return temp_handshake_size;

}

size_t add_and_hash_sig_verify(unsigned char *old_handshake_binary, size_t old_handshake_size,
	unsigned char *new_thing_to_add, size_t size_of_new_thing_to_add, enum SignatureScheme sig_algo,
	int md_number, unsigned char *out, size_t *outlen)
{
	unsigned int outsize = 0;

	size_t temp_handshake_size;
	temp_handshake_size = temp_add_to_handshake_sig_verify(old_handshake_binary, old_handshake_size,
		new_thing_to_add, size_of_new_thing_to_add, sig_algo);

	if (temp_handshake_size == 0) {
		return 0;
	}
	hash_raw_handshake(old_handshake_binary, out, &outsize, md_number, temp_handshake_size);
	*outlen = outsize;
	return temp_handshake_size;

}

size_t add_and_hash_finish(unsigned char *old_handshake_binary, size_t old_handshake_size,
	unsigned char *new_thing_to_add, size_t size_of_new_thing_to_add, int md_number, unsigned char *out, size_t *outlen)
{
	unsigned int outsize = 0;
	size_t temp_handshake_size;
	temp_handshake_size = update_temp_hash_finish(old_handshake_binary, old_handshake_size,
		new_thing_to_add, size_of_new_thing_to_add);

	if (temp_handshake_size == 0) {
		return 0;
	}
	hash_raw_handshake(old_handshake_binary, out, &outsize, md_number, temp_handshake_size);
	*outlen = outsize;
	return temp_handshake_size;

}
