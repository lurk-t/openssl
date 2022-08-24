#pragma once
#include "LURK_header.h"
#ifdef __cplusplus
extern "C" {
#endif

	/*
	* Must call new_SInitCertVerifyRequest(), new_SInitCertVerifyResponse() before calling this fuction
	to pass the right thing and be able to retrive the info from it.

	* SInitCertVerifyRequest *req = new_SInitCertVerifyRequest();
	  init_InitCertificateVerifyRequest(*req);
	  SInitCertVerifyResponse *respons = new_SInitCertVerifyResponse(req);
	*/


	int LURK_S_init_cert_verify(struct SInitCertVerifyRequest* req, struct SInitCertVerifyResponse *respons);
	struct SInitCertVerifyRequest * new_SInitCertVerifyRequest();
	struct SInitCertVerifyResponse *new_SInitCertVerifyResponse();
	int init_InitCertificateVerifyRequest(struct SInitCertVerifyRequest *req);
	void InitCertificateVerifyRequest_to_string(struct SInitCertVerifyRequest req);
	void InitCertificateVerifyResponse_to_string(struct SInitCertVerifyResponse resp);
	int modify_Handshake_binary_SInitCertVerifyRequest(struct SInitCertVerifyRequest *request, unsigned char *handshake_binary_openssl, int handshake_binary_size);
	int modify_Handshake_Hash_SInitCertVerifyRequest(struct SInitCertVerifyRequest *request, unsigned char *handshake_hash_openssl, int handshake_hash_size);
	int modify_shared_secret_SInitCertVerifyRequest(struct SInitCertVerifyRequest *request, unsigned char *provided_shared_secret, int group_id);
	int LURK_OPENSSL(struct SInitCertVerifyRequest* req, struct SInitCertVerifyResponse *respons, unsigned char *lable);
	unsigned char * get_right_secret_from_SInitCertVerifyResponse(struct SInitCertVerifyResponse *response, unsigned char *lable);
	int get_sec_req_by_label(unsigned char *lable);
	int modify_Handshake_Hash_Signature_SInitCertVerifyRequest(struct SInitCertVerifyRequest *request, unsigned char *to_be_signed, int size_of_to_be_signed, int sig_algorithm);
	int initialize_enclave(void);
	int read_from_config_file(void);
	int set_server_old_rand(void * data, struct SInitCertVerifyRequest *request);
	int set_data_before_hash_update(void * data, size_t size, struct SInitCertVerifyRequest *request);
	int compare_secrets(unsigned char *first_input, unsigned char *second_input, int size);
	void LURK_destroy_enclave();
	void LURK_free_request(struct SInitCertVerifyRequest *request);
	void LURK_free_response(struct SInitCertVerifyResponse *response);
	int LURK_ssl_generate_pkey(unsigned char* peer_public_key, size_t peer_public_key_len, size_t group_id, struct SInitCertVerifyRequest *request, struct SInitCertVerifyResponse *respons);
#ifdef __cplusplus
}
#endif

