/*
 *   Copyright(C) 2011-2018 Intel Corporation All Rights Reserved.
 *
 *   The source code, information  and  material ("Material") contained herein is
 *   owned  by Intel Corporation or its suppliers or licensors, and title to such
 *   Material remains  with Intel Corporation  or its suppliers or licensors. The
 *   Material  contains proprietary information  of  Intel or  its  suppliers and
 *   licensors. The  Material is protected by worldwide copyright laws and treaty
 *   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
 *   modified, published, uploaded, posted, transmitted, distributed or disclosed
 *   in any way  without Intel's  prior  express written  permission. No  license
 *   under  any patent, copyright  or  other intellectual property rights  in the
 *   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
 *   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
 *   intellectual  property  rights must  be express  and  approved  by  Intel in
 *   writing.
 *
 *   *Third Party trademarks are the property of their respective owners.
 *
 *   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
 *   this  notice or  any other notice embedded  in Materials by Intel or Intel's
 *   suppliers or licensors in any way.
 *
 */
#include "Secret.h"
#include "Signature.h"
#include "ephemeral.h"
#include "LURK_header.h"
#include "Freshness.h"
#include "Ticket.h"

#include <cstring>
#include <stdio.h>

#include "Enclave_t.h" /* print_string */

void Test_Ocall()
{
	int a = 1;
	ocall_print_string(a);
}

/*
* EphemeralRequest can have 2 method:
* 1- secret_provided: in this case the TLS gave us the ECDHE share secret and it is in the request -> SharedSecret
* 2- secret_generated: we generate the ECDHE put the generated share secret in request ->  ShareSecret
* and the public key for the algorithm in the response key_ex

* EphemeralResponse if request method was:
* 1- secret_provided: just method nothing else
* 2- secret_generated: the public_key is EphemeralResponse -> KeyShareEntry 
* and the ECDHE share_secret was updated on request -> ShareSecret

* In the secret_provided case handle_ephemeral_secret_provided() function would be called
* In the secret_generated case  LURK_ssl_generate_pkey_sgx() function would be called directly
*/

int handle_ephemeral_secret_provided(EphemeralRequest *request, EphemeralResponse *response)
{
	// if CS is not generating the secrets: there is no need for key_ex in response
	if (request->method == no_secret || request->method == secret_provided)
	{
		// ephemeral response has only the method in it in case of secret provided
		response->method = request->method;
		return 1;
	}
	return 0;
}

void LURK_ssl_generate_pkey_sgx(unsigned char *peer_public_key, size_t peer_public_key_len,
								struct SInitCertVerifyResponse *respons, struct SInitCertVerifyRequest *req, int *a)
{
	handle_ephemeral_secret_gen(peer_public_key, peer_public_key_len, respons, req, a);
}

int more_exchange(struct SInitCertVerifyRequest *req)
{
	return req->tag;
}

/*
* We have some secrerts that are protected in the SGX (have been malloced in SGX)
* if we are done with this secrets we need to free them
*/
void free_sgx_malloc(struct SInitCertVerifyResponse *respons)
{
	free(respons->conf_secrets.resumption_master_secret);
	free(respons->conf_secrets.early_secret);
	free(respons->conf_secrets.handshake_secret);
	free(respons->conf_secrets.master_secret);
	respons->conf_secrets.resumption_master_secret = NULL;
	respons->conf_secrets.early_secret = NULL;
	respons->conf_secrets.handshake_secret = NULL;
	respons->conf_secrets.master_secret = NULL;
	respons->conf_secrets.resumption_master_secret_len = 0;
	respons->conf_secrets.early_secret_len = 0;
	respons->conf_secrets.handshake_secret_len = 0;
	respons->conf_secrets.master_secret_len = 0;
}

/*
* Input:secret_request, Handshake, SharedSecret
* Handshake: all of the handshake to this point and without record layer
* SharedSecret: it was filled before calling this function and there is an ECDHE in it
Output: Secret *:
*/
int handle_secret_request2(uint16_t secret_request, Handshake *handshake, SharedSecret *ECDH_shared_secret,
						   Secret *secret_list, confidential_secrets &conf_secrets, unsigned char *handshake_hash,
						   int &size_of_handshake_hash, enum Freshness fresh, unsigned char *old_rand, int md_index,
						   int check_freshness, int operation_mode)
{
	//this handshake is client hello and server hello
	unsigned char hashed_handshake[EVP_MAX_MD_SIZE] = {0};
	int size_of_shared_secret = get_size_of_share_secret(ECDH_shared_secret->group);
	if (size_of_shared_secret == 0)
	{
		return 0;
	}
	if (check_freshness == 1)
	{
		/*
		* if secret_request == 0x09 && secret_request == 0x010 (handshake secret or early secret),
		* the hash would be empty. Thus,checking the freshness is usless.
		*/
		if (secret_request != 0x09 && secret_request != 0x010)
		{
			if (handshake_hash != NULL)
			{
				if (calc_fresh_hash(handshake->handshake_binary, handshake_hash, fresh,
									old_rand, md_index, handshake->openssl_till_now) == 1)
				{
					memcpy(hashed_handshake, handshake_hash, size_of_handshake_hash);
				}
				else
				{
					ocall_print_string(1);
					return 0;
				}
			}
			else
			{
				if (calc_fresh_hash2(handshake->handshake_binary, hashed_handshake, fresh,
									 old_rand, md_index, handshake->openssl_till_now) != 1)
				{
					return 0;
				}
			}
		}
	}
	/*no check for freshness*/
	else
	{
		memcpy(hashed_handshake, handshake_hash, size_of_handshake_hash);
	}

	//TODO THIS IF  is extra
	if (secret_request >= 3 && secret_request <= 12)
	{
		//OPENSSL DIFF
		//TODO must change to hashed_handshake and we should not pass the hashed handshake
		if (test_handshake_secrets(secret_request, secret_list, ECDH_shared_secret->shared_secret, conf_secrets,
								   hashed_handshake, size_of_shared_secret, md_index, operation_mode,
								   size_of_handshake_hash) == 1)
		{
			return 1;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
}

/*
* This function just pars (unwrap) the req and response and send the right
* argument to the handle_secret_request2() function.
*/
int handle_secret_request(SInitCertVerifyRequest *request, SInitCertVerifyResponse *response,
						  int check_freshness, unsigned char *handshake_hash_out)
{
	return handle_secret_request2(request->secret_request, request->handshake, request->ephemeral->shared_secret,
								  response->secret_list, response->conf_secrets, handshake_hash_out,
								  request->handshake_hash_size, request->freshness, request->old_rand, request->md_index,
								  check_freshness, request->operation_mode);
}

/* LURK server on TLS server have the init_certificate_verify function*/
int handle_sign_request2(LURKTLS13Certificate *certificate, SignatureScheme sig_algo, Handshake *handshake,
						 unsigned char *handshake_hash, int size_of_handshake_hash, Signature *Signature_respons,
						 enum Freshness fresh, unsigned char *old_rand, int md_index, int check_freshness)
{
	unsigned char hashed_handshake[EVP_MAX_MD_SIZE];

	if (check_freshness == 1)
	{
		if (calc_fresh_hash(handshake->handshake_binary, handshake_hash, fresh,
							old_rand, md_index, handshake->till_now) == 1)
		{
			memcpy(hashed_handshake, handshake_hash, size_of_handshake_hash);
		}
		else
		{
			ocall_print_string(1);
			return 0;
		}
	}
	/*no check for freshness*/
	else
	{
		memcpy(hashed_handshake, handshake_hash, size_of_handshake_hash);
	}
	if (sgining_LURK(Signature_respons->signature, hashed_handshake, sig_algo,
					 size_of_handshake_hash, &Signature_respons->signature_size, certificate) == 0)
	{
		return 0;
	}
	Signature_respons->algorithm = sig_algo;
	return 1;
}

/*
* This function just pars the req and response and send the right 
* argument to the handle_sign_request2() function.
*/
int handle_sign_request(SInitCertVerifyRequest *request, SInitCertVerifyResponse *response,
						int check_freshness)
{
	return handle_sign_request2(request->certificate, request->sig_algo, request->handshake,
								request->handshake_hash, request->handshake_hash_size,
								response->signature, request->freshness, request->old_rand,
								request->md_index, check_freshness);
}

int add_hash_from_sig_verify_to_application_secrets(struct SInitCertVerifyRequest *req, struct SInitCertVerifyResponse *respons)
{
	unsigned char new_handshake_hash[EVP_MAX_MD_SIZE];
	size_t new_handshake_size = 0, unusend_handshake_size = 0;
	size_t finish_size = 0;
	new_handshake_size = add_and_hash_sig_verify(req->handshake->handshake_binary, req->handshake->till_now,
												 respons->signature->signature, respons->signature->signature_size,
												 req->sig_algo, req->md_index, new_handshake_hash, &finish_size);
	if (new_handshake_size == 0)
	{
		return 0;
	}
	/* to generate verify data with finish key (HMAC)*/
	req->secret_request = 12;
	if (handle_secret_request(req, respons, 0, new_handshake_hash) != 1)
	{
		return 0;
	}

	unusend_handshake_size = add_and_hash_finish(req->handshake->handshake_binary, new_handshake_size,
												 respons->secret_list[6].secret_data, finish_size, req->md_index,
												 new_handshake_hash, &new_handshake_size);
	if (unusend_handshake_size == 0)
	{
		return 0;
	}

	memcpy(req->handshake_hash, new_handshake_hash, new_handshake_size);
	req->handshake_hash_size = new_handshake_size;
	req->handshake->till_now = unusend_handshake_size;

	return 1;
}

int add_hash_from_handshake_secrets_to_sig_verify(struct SInitCertVerifyRequest *req, struct SInitCertVerifyResponse *respons)
{
	unsigned char new_handshake_hash[EVP_MAX_MD_SIZE] = {0};
	size_t new_handshake_size = 0;
	size_t hash_size = 0;
	/*we assume that certificate does not change for the measuremets*/
	static size_t certificate_len = 0;
	static unsigned char *right_certificate = NULL;

	/*
	In our implementation this extension is always fixed to ziro
	If you need to use this extension, it would cost you one more
	context switch between TEE and REE
	*/
	unsigned char server_enc_extension[] = {0, 0};

	if (right_certificate == NULL || certificate_len == 0)
	{
		right_certificate = LURK_get_right_certificate(certificate_len);
	}

	new_handshake_size = add_and_hash_encrypt_extension_and_certificate(req->handshake->handshake_binary, req->handshake->till_now,
																		server_enc_extension, sizeof(server_enc_extension), right_certificate, certificate_len,
																		req->md_index, new_handshake_hash, &hash_size);
	if (new_handshake_size == 0)
	{
		return 0;
	}

	memcpy(req->handshake_hash, new_handshake_hash, hash_size);
	req->handshake_hash_size = hash_size;
	//req->handshake->size =  new_handshake_size;
	req->handshake->till_now = new_handshake_size;

	return 1;
}

int generate_resumption_secret(struct SInitCertVerifyRequest *req, struct SInitCertVerifyResponse *respons)
{

	req->secret_request = 8; // asking for resumption master secret
	if (handle_secret_request(req, respons, CHECKING_FRESHNESS, NULL) != 1)
	{
		return -1;
	}
	return 1;
}

void LURK_construct_new_session_ticket_and_resumption_sec(int *status_tic, struct SInitCertVerifyResponse *respons,
														  unsigned char *tick_nonce, size_t tick_nonce_len, struct SInitCertVerifyRequest *req)
{
	*status_tic = -1;

	if (generate_resumption_secret(req, respons) != 1)
	{
		return;
	}

	if (construct_and_cache_new_session_ticket(respons, tick_nonce, tick_nonce_len, req->md_index) != 1)
	{
		return;
	}

	if (more_exchange(req) == 0)
	{
		free_sgx_malloc(respons);
	}
	*status_tic = 1;
	return;
}

void LURK_get_stateful_ticket_binder_key_SGX(int *status_tic, struct SInitCertVerifyRequest *req,
											 struct SInitCertVerifyResponse *respons)
{

	*status_tic = -1;

	size_t hash_len = (size_t)req->handshake_hash_size;
	unsigned char *binder_key = respons->secret_list[SECRET_LIST_INDEX_BINER_KEY].secret_data;

	//! session-> masterkey should be copy to REQ CS ID
	if (lookup_sess_in_cache_and_do_binder(req->md_index, req->session_id, req->handshake_hash, hash_len,
										   respons->conf_secrets.early_secret, binder_key) != 1)
	{
		return;
	}

	respons->secret_list[SECRET_LIST_INDEX_BINER_KEY].secret_type = L_binder_key;
	*status_tic = 1;
	return;
}
//main
void init_certificate_verify(struct SInitCertVerifyRequest *req, int *a, struct SInitCertVerifyResponse *respons)
{

	*a = -1;
	/*
	* We only init the ephemeral for the first time and 
	* if secret is provided by the OpenSSL. Generating it
	* in CS would call  LURK_ssl_generate_pkey_sgx() 
	* directly and then  init_certificate_verify() function
	* would be called! So no need to go to this function
	*/
	if (respons->ephemeral->method == uninitialized_method && req->ephemeral->method == secret_provided)
	{
		handle_ephemeral_secret_provided(req->ephemeral, respons->ephemeral);
	}
	/*
	* Checking if OpenSSL need secret 
	*/
	if (req->secret_request >= 3 && req->secret_request <= 10 && req->operation_mode != OPRATION_MODE_KEY_LESS)
	{
		if (handle_secret_request(req, respons, CHECKING_FRESHNESS, req->handshake_hash) != 1)
		{
			return;
		}
		if (req->operation_mode != OPRATION_MODE_1_EARLY_HS_2_SIG_AP &&
			req->operation_mode != OPRATION_MODE_1_EARLY_2_HS_3_SIG_AP_4_RESUMPTION &&
			req->operation_mode != OPRATION_MODE_1_EARLY_HS_2_SIG_AP_3_RESUMPTION &&
			req->secret_request == 4)
		{
			if (add_hash_from_handshake_secrets_to_sig_verify(req, respons) == 0)
			{
				return;
			}
			if (handle_sign_request(req, respons, NOT_CHECKING_FRESHNESS) != 1)
			{
				return;
			}
			/*
			* This step add finish_hmac to handshake, hash the new handshake,
			* use the new hash to generate the application secrets (client/server).
			* this step was added to reduce context switching (TEE/REE)
			*/
			if (add_hash_from_sig_verify_to_application_secrets(req, respons) == 0)
			{
				return;
			}

			/* to generate server/client application secret with predicted hash*/
			req->secret_request = 5;
			if (handle_secret_request(req, respons, NOT_CHECKING_FRESHNESS, req->handshake_hash) != 1)
			{
				return;
			}
		}
		else
		{
			*a = 1;
			return;
		}
	}
	/*
	* checking if OpenSSL is asking for signature directly
	*/
	if (req->operation_mode == OPRATION_MODE_1_EARLY_HS_2_SIG_AP ||
		req->operation_mode == OPRATION_MODE_1_EARLY_2_HS_3_SIG_AP_4_RESUMPTION ||
		req->operation_mode == OPRATION_MODE_1_EARLY_HS_2_SIG_AP_3_RESUMPTION ||
		req->operation_mode == OPRATION_MODE_KEY_LESS)
	{

		if (handle_sign_request(req, respons, CHECKING_FRESHNESS) != 1)
		{
			return;
		}
		if (req->operation_mode == OPRATION_MODE_KEY_LESS)
		{
			*a = 1;
			return;
		}
		/* 
		* This step add finish_hmac to handshake, hash the new handshake,
		* use the new hash to generate the application secrets (client/server).
		* this step was added to reduce context switching (TEE/REE)
		*/
		if (add_hash_from_sig_verify_to_application_secrets(req, respons) == 0)
		{
			return;
		}
		/* to generate server/client application secret with predicted hash*/
		req->secret_request = 5;
		if (handle_secret_request(req, respons, NOT_CHECKING_FRESHNESS, req->handshake_hash) != 1)
		{
			return;
		}
	}
	*a = 1;
	return;
}

/*
//this function is just for testing the result of the hash it would make the result of the hash to hex
void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
	constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
						   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	int i = 0;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		outputBuffer[2 * i] = hexmap[(hash[i] & 0xF0) >> 4];
		outputBuffer[2 * i + 1] = hexmap[hash[i] & 0x0F];
	}

	outputBuffer[64] = 0;
}

*/