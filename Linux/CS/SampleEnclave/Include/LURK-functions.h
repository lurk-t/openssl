#pragma once
#include "LURK_header.h"
#ifdef __cplusplus
extern "C"
{
#endif

	int finger_print_signature(struct SInitCertVerifyRequest *req, size_t size);
	int LURK_S_init_cert_verify(struct SInitCertVerifyRequest *req, struct SInitCertVerifyResponse *respons);
	/*
	* create LURK request structure and initialize it
	* return NULL if unsuccessful
	*/
	struct SInitCertVerifyRequest *new_LURK_request();

	/*
	* create LURK response structure and initialize it
	* return NULL if unsuccessful
	*/
	struct SInitCertVerifyResponse *new_LURK_response();

	int modify_Handshake_binary_SInitCertVerifyRequest(struct SInitCertVerifyRequest *request, unsigned char *handshake_binary_openssl, int handshake_binary_size);
	int modify_Handshake_Hash_SInitCertVerifyRequest(struct SInitCertVerifyRequest *request, unsigned char *handshake_hash_openssl, int handshake_hash_size);
	int modify_shared_secret_SInitCertVerifyRequest(struct SInitCertVerifyRequest *request, unsigned char *provided_shared_secret, int group_id);
	int LURK_OPENSSL(struct SInitCertVerifyRequest *req, struct SInitCertVerifyResponse *respons, unsigned char *lable);
	unsigned char *get_right_secret_from_SInitCertVerifyResponse(struct SInitCertVerifyResponse *response, unsigned char *lable);
	int get_sec_req_by_label(unsigned char *lable);
	int modify_Handshake_Hash_Signature_SInitCertVerifyRequest(struct SInitCertVerifyRequest *request, unsigned char *to_be_signed, int size_of_to_be_signed, int sig_algorithm);
	int initialize_enclave(void);
	int read_from_config_file(void);
	int set_server_old_rand(void *data, struct SInitCertVerifyRequest *request);
	int set_data_before_hash_update(void *data, size_t size, struct SInitCertVerifyRequest *request);
	int compare_secrets(unsigned char *first_input, unsigned char *second_input, int size);
	void LURK_destroy_enclave();
	void LURK_free_request(struct SInitCertVerifyRequest *request);
	void LURK_free_response(struct SInitCertVerifyResponse *response);
	int LURK_ssl_generate_pkey(unsigned char *peer_public_key, size_t peer_public_key_len, size_t group_id, struct SInitCertVerifyRequest *request, struct SInitCertVerifyResponse *respons);
	int LURK_s_new_tickets(struct SInitCertVerifyResponse *respons,
						   unsigned char *tick_nonce, size_t tick_nonce_len, struct SInitCertVerifyRequest *request,
						   unsigned char *session_id, size_t session_id_len, size_t num_tickets, size_t sent_tickets,
						   unsigned char *out, size_t out_len);
	int LURK_get_stateful_ticket_binder_key(struct SInitCertVerifyRequest *request, struct SInitCertVerifyResponse *respons, unsigned char *cache_key);
#ifdef __cplusplus
}
#endif
