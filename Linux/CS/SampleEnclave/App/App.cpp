#define MAX_BUF_LEN 100
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <time.h>
#include <sys/time.h>

#include "LURK-functions.h"
#include "LURK_header.h"
#include "LURK_Debug.h"

sgx_enclave_id_t global_eid = 0;

/*
* These configs are defualts if there is no config file or there is
* any error for reading the file they would be used
* same order in the file
*/
//This flag would print measurements info
int print_extra_info = 1;
//This flag would print Handshake info
int print_handshake_CS = 1;
// mode for exchange TEE/REE
int mode_of_opration = 1;
// epthemeral_mode
enum EphemeralMethod ephemeral_mode = secret_provided;

int read_from_config_file()
{
	int temp_ephemeral_mode = 0;
	FILE *fptr;

	fptr = fopen("LURK_config.txt", "r");
	if (fptr == NULL)
	{
		printf("Error! opening file");
		return 0;
	}

	// reads text until newline is encountered
	fscanf(fptr, "%d %d %d %d", &print_extra_info, &print_handshake_CS, &mode_of_opration, &temp_ephemeral_mode);
	ephemeral_mode = (EphemeralMethod)temp_ephemeral_mode;
	printf("Data from the file:\n print_extra_info:%d \n print_handshake_CS %d \n mode_of_opration %d \n temp_ephemeral_mode %d \n ",
		   print_extra_info, print_handshake_CS, mode_of_opration, (int)ephemeral_mode);
	fclose(fptr);

	return 1;
}

typedef struct _sgx_errlist_t
{
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
	{SGX_ERROR_UNEXPECTED,
	 "Unexpected error occurred.",
	 NULL},
	{SGX_ERROR_INVALID_PARAMETER,
	 "Invalid parameter.",
	 NULL},
	{SGX_ERROR_OUT_OF_MEMORY,
	 "Out of memory.",
	 NULL},
	{SGX_ERROR_ENCLAVE_LOST,
	 "Power transition occurred.",
	 "Please refer to the sample \"PowerTransition\" for details."},
	{SGX_ERROR_INVALID_ENCLAVE,
	 "Invalid enclave image.",
	 NULL},
	{SGX_ERROR_INVALID_ENCLAVE_ID,
	 "Invalid enclave identification.",
	 NULL},
	{SGX_ERROR_INVALID_SIGNATURE,
	 "Invalid enclave signature.",
	 NULL},
	{SGX_ERROR_OUT_OF_EPC,
	 "Out of EPC memory.",
	 NULL},
	{SGX_ERROR_NO_DEVICE,
	 "Invalid SGX device.",
	 "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
	{SGX_ERROR_MEMORY_MAP_CONFLICT,
	 "Memory map conflicted.",
	 NULL},
	{SGX_ERROR_INVALID_METADATA,
	 "Invalid enclave metadata.",
	 NULL},
	{SGX_ERROR_DEVICE_BUSY,
	 "SGX device was busy.",
	 NULL},
	{SGX_ERROR_INVALID_VERSION,
	 "Enclave version was invalid.",
	 NULL},
	{SGX_ERROR_INVALID_ATTRIBUTE,
	 "Enclave was not authorized.",
	 NULL},
	{SGX_ERROR_ENCLAVE_FILE_ACCESS,
	 "Can't open enclave file.",
	 NULL},
	{SGX_ERROR_NDEBUG_ENCLAVE,
	 "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
	 NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++)
	{
		if (ret == sgx_errlist[idx].err)
		{
			if (NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
	char token_path[MAX_PATH] = {'\0'};
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	/* Step 1: try to retrieve the launch token saved by last transaction
	 *         if there is no token, then create a new one.
	 */
#ifdef _MSC_VER
	/* try to get the token saved in CSIDL_LOCAL_APPDATA */
	if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path))
	{
		strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}
	else
	{
		strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 2);
	}

	/* open the token file */
	HANDLE token_handler = CreateFileA(token_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
	if (token_handler == INVALID_HANDLE_VALUE)
	{
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}
	else
	{
		/* read the token from saved file */
		DWORD read_num = 0;
		ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t))
		{
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
#else /* __GNUC__ */
	/* try to get the token saved in $HOME */
	const char *home_dir = getpwuid(getuid())->pw_dir;

	if (home_dir != NULL &&
		(strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH)
	{
		/* compose the token path */
		strncpy(token_path, home_dir, strlen(home_dir));
		strncat(token_path, "/", strlen("/"));
		strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
	}
	else
	{
		/* if token path is too long or $HOME is NULL */
		strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}

	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
	{
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}

	if (fp != NULL)
	{
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t))
		{
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
#endif
	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		print_error_message(ret);
#ifdef _MSC_VER
		if (token_handler != INVALID_HANDLE_VALUE)
			CloseHandle(token_handler);
#else
		if (fp != NULL)
			fclose(fp);
#endif
		return -1;
	}

	/* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
	if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE)
	{
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (token_handler != INVALID_HANDLE_VALUE)
			CloseHandle(token_handler);
		return 0;
	}

	/* flush the file cache */
	FlushFileBuffers(token_handler);
	/* set access offset to the begin of the file */
	SetFilePointer(token_handler, 0, NULL, FILE_BEGIN);

	/* write back the token */
	DWORD write_num = 0;
	WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, NULL);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	CloseHandle(token_handler);
#else /* __GNUC__ */
	if (updated == FALSE || fp == NULL)
	{
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL)
			fclose(fp);
		return 0;
	}

	/* reopen the file with write capablity */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL)
		return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);
#endif
	return 0;
}

/* OCall functions*/
void ocall_print_string(int a)
{
	printf("this is an Ocall from enclave");
	printf("HASHes DONT match : %d \n", a);
}

int set_EphemeralRequest(EphemeralRequest &ephemeralrequest, EphemeralMethod method, int memory_allocation)
{
	if (method == secret_provided)
	{
		ephemeralrequest.method = method;
		if (memory_allocation == 1)
		{
			ephemeralrequest.shared_secret = (SharedSecret *)malloc(sizeof(SharedSecret));
			// we only allocate the memory but you need to  initialize the shared_secret
			(*ephemeralrequest.shared_secret).group = uninitialized;
			ephemeralrequest.shared_secret->shared_secret[0] = {0};
			ephemeralrequest.shared_secret->shared_secret_len = 0;
			//memcpy(ephemeralrequest.shared_secret->shared_secret, shared_secret_13, sizeof(shared_secret_13));
		}
	}
	else if (method == no_secret || method == secret_generated)
	{
		ephemeralrequest.method = method;
		if (memory_allocation == 1)
		{
			ephemeralrequest.shared_secret = (SharedSecret *)malloc(sizeof(SharedSecret));
			// we only allocate the memory but you need to  initialize the shared_secret
			(*ephemeralrequest.shared_secret).group = uninitialized;
			ephemeralrequest.shared_secret->shared_secret[0] = {0};
			ephemeralrequest.shared_secret->shared_secret_len = 0;
		}
	}
	else
	{
		return -1;
	}
	return 1;
}

int init_InitCertificateVerifyRequest(SInitCertVerifyRequest *req)
{
	req->tag = 1;
	for (int i = 0; i < SESSIN_ID_LEN; i++)
	{
		req->session_id[i] = 0;
	}
	req->freshness = sha256;
	set_EphemeralRequest((*req->ephemeral), ephemeral_mode, 1);
	req->handshake->openssl_till_now = 0;
	req->handshake->till_now = 0;
	//TODO init the handshake_binary ??
	req->handshake->handshake_binary[0] = {0};
	req->sig_algo = rsa_pss_rsae_sha256;
	req->certificate->certificate_type = finger_print;
	(*req->certificate->finger_print) = 1;
	req->certificate->empty = NULL;
	req->certificate->uncompressed_certificate = NULL;
	req->certificate->compressed_certificate = NULL;
	req->changed = 0;
	req->handshake_hash_size = 0;
	req->secret_request = 9; //TESTING
	req->handshake_hash[0] = {0};
	req->md_index = -1;
	req->operation_mode = mode_of_opration;
	req->tag = TAG_CERT_REQEST;
	return 1;
}

//TODO
// This is test function and only for our measurements
int finger_print_signature(SInitCertVerifyRequest *req, size_t size)
{
	if (req->sig_algo == 0x804)
	{
		if (size == 0x100)
		{
			(*req->certificate->finger_print) = 1;
			return 1;
		}
		if (size == 0x181)
		{
			(*req->certificate->finger_print) = 2;
			return 1;
		}
		if (size == 0x200)
		{
			(*req->certificate->finger_print) = 3;
			return 1;
		}
	}
	else
	{
		return 1;
	}
	return -1;
}

void init_response_struct(SInitCertVerifyResponse *response)
{
	response->signature = NULL;

	for (int i = 0; i < LURK_MAX_SECRET_NUMBER; i++)
	{
		response->secret_list[i].secret_type = uninitialized_SecretType;
		for (int j = 0; j < LURK_MAX_MD_SIZE; j++)
		{
			response->secret_list[i].secret_data[j] = 0;
		}
	}
	response->tag = TAG_CERT_REQEST;
	response->ephemeral->method = uninitialized_method;
	response->conf_secrets.resumption_master_secret = NULL;
	response->conf_secrets.early_secret = NULL;
	response->conf_secrets.handshake_secret = NULL;
	response->conf_secrets.master_secret = NULL;
}

/*
* create LURK response structure and initialize it
* return NULL if unsuccessful
*/
SInitCertVerifyResponse *new_LURK_response()
{
	SInitCertVerifyResponse *respons = (SInitCertVerifyResponse *)malloc(sizeof(SInitCertVerifyResponse));
	if (respons == NULL)
	{
		return NULL;
	}
	EphemeralResponse *e_res = (EphemeralResponse *)malloc(sizeof(EphemeralResponse));
	if (e_res == NULL)
	{
		return NULL;
	}
	//TODO need to malloc for Ephemeralresponsee
	respons->ephemeral = e_res;
	// init the new response struct
	init_response_struct(respons);

	return respons;
}

/*
* create LURK request structure and initialize it
* return NULL if unsuccessful
*/
SInitCertVerifyRequest *new_LURK_request()
{
	SInitCertVerifyRequest *req = (SInitCertVerifyRequest *)malloc(sizeof(SInitCertVerifyRequest));
	if (req == NULL)
	{
		return NULL;
	}
	EphemeralRequest *e_req = (EphemeralRequest *)malloc(sizeof(EphemeralRequest));
	if (e_req == NULL)
	{
		return NULL;
	}
	req->ephemeral = e_req;
	Handshake *handsh = (Handshake *)malloc(sizeof(Handshake));
	if (handsh == NULL)
	{
		return NULL;
	}
	req->handshake = handsh;
	LURKTLS13Certificate *cert = (LURKTLS13Certificate *)malloc(sizeof(LURKTLS13Certificate));
	if (cert == NULL)
	{
		return NULL;
	}
	uint32_t fingerprint;
	req->certificate = cert;
	cert->finger_print = &fingerprint;
	//init the request struct
	init_InitCertificateVerifyRequest(req);
	return req;
}

/*int modify_Handshake_binary_SInitCertVerifyRequest(SInitCertVerifyRequest *request, unsigned char *handshake_binary_openssl, int handshake_binary_size) {
	request->changed = 3;
	//request->handshake->handshake_binary = (opaque *)malloc(handshake_binary_size * sizeof(opaque));
	memcpy(request->handshake->handshake_binary, handshake_binary_openssl, handshake_binary_size);
	request->handshake->size = handshake_binary_size;
	return 1;
}*/

int modify_Handshake_Hash_SInitCertVerifyRequest(SInitCertVerifyRequest *request, unsigned char *handshake_hash_openssl, int handshake_hash_size)
{
	request->changed = 2;
	memcpy(request->handshake_hash, handshake_hash_openssl, handshake_hash_size);
	request->handshake_hash_size = handshake_hash_size;
	return 1;
}

int modify_Handshake_Hash_Signature_SInitCertVerifyRequest(SInitCertVerifyRequest *request, unsigned char *to_be_signed, int size_of_to_be_signed, int sig_algorithm)
{
	request->changed = 4;

	memcpy(request->handshake_hash, to_be_signed, size_of_to_be_signed);
	request->handshake_hash_size = size_of_to_be_signed;
	request->signature_size = size_of_to_be_signed;
	request->sig_algo = (SignatureScheme)sig_algorithm;
	return 1;
}

int new_signature_for_response(SInitCertVerifyRequest *request, SInitCertVerifyResponse *respons)
{
	Signature *sig = (Signature *)malloc(sizeof(Signature));
	if (sig == NULL)
	{
		printf("cannot allocate memory");
		return -1;
	}
	//TODO 0x0200 must change to response signature lenght this is just for testing malloc in the right spot
	//EVP_PKEY_size(pkey);
	//TESTING
	sig->signature = NULL;
	sig->signature = (unsigned char *)malloc(sizeof(unsigned char) * 0x200);
	if (sig->signature == NULL)
	{
		printf("cannot allocate memory");
		return -1;
	}
	sig->signature_size = request->signature_size;
	respons->signature = sig;
	return 1;
}

int get_size_of_share_secret(NamedGroup group_id)
{

	if (group_id == 0x0017 || group_id == 0x001D)
	{
		return 32;
	}
	else if (group_id == 0x0018)
	{
		return 48;
	}
	else if (group_id == 0x0019)
	{
		return 66;
	}
	else if (group_id == 0x001E)
	{
		return 56;
	}
	else
	{
		return 0;
	}
}
int modify_shared_secret_SInitCertVerifyRequest(SInitCertVerifyRequest *request, unsigned char *provided_shared_secret, int group_id)
{
	request->changed = 1;
	// if the CS generating the pms the share secret is already in request->ephemeral->shared_secret->shared_secret
	if (request->ephemeral->method != secret_generated)
	{
		request->ephemeral->method = secret_provided;
		request->ephemeral->shared_secret->group = (NamedGroup)group_id;
		int share_secret_size = get_size_of_share_secret(request->ephemeral->shared_secret->group);
		if (share_secret_size == 0)
		{
			return 0;
		}
		request->ephemeral->shared_secret->shared_secret_len = share_secret_size;
		memcpy(request->ephemeral->shared_secret->shared_secret, provided_shared_secret, request->ephemeral->shared_secret->shared_secret_len);
	}
	return 1;
}

//TODO free inside stucts as well
void LURK_free_request(struct SInitCertVerifyRequest *request)
{
	free(request->handshake);

	// if (request->ephemeral->shared_secret) {
	// 	free(request->ephemeral->shared_secret);
	// }
	free(request->ephemeral);

	/*
	if (request->certificate->empty) {
		free(request->certificate->empty);
	}
	if (request->certificate->finger_print) {
		free(request->certificate->finger_print);
	}
	if (request->certificate->uncompressed_certificate) {
		free(request->certificate->uncompressed_certificate);
	}
	if (request->certificate->compressed_certificate) {
		free(request->certificate->compressed_certificate);
	}*/
	free(request->certificate);

	free(request);
	return;
}
//TODO free inside stucts as well
void LURK_free_response(struct SInitCertVerifyResponse *response)
{
	// if (response->ephemeral->server_share->key_exchange) {
	// 	free(response->ephemeral->server_share->key_exchange);
	// }
	// if (response->ephemeral->server_share) {
	// 	free(response->ephemeral->server_share);
	// }
	if (response->ephemeral)
	{
		free(response->ephemeral);
	}

	//free(response->signature->signature);
	free(response->signature);

	free(response);
	return;
}

/* MUST call initialize_enclave() before calling this fuction*/
int LURK_S_init_cert_verify(SInitCertVerifyRequest *req, SInitCertVerifyResponse *respons)
{
	clock_t t;
	t = clock();
	int b = -1;

	if (print_handshake_CS == 1)
	{
		InitCertificateVerifyRequest_to_string(*req);
	}
	init_certificate_verify(global_eid, req, &b, respons);
	if (print_handshake_CS == 1)
	{
		InitCertificateVerifyResponse_to_string(*respons);
	}

	t = clock() - t;
	double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds
	if (print_extra_info == 1)
	{
		printf("TIME INSIDE (LURK_S_init_cert_verify):  %f seconds to execute \n", time_taken);
		printf("STATUS OF RESPONCE IS:%d \n", b);
	}
	return b;
}

void LURK_destroy_enclave()
{
	sgx_destroy_enclave(global_eid);
}

int prep_before_S_init_cert_verify(SInitCertVerifyRequest *req, SInitCertVerifyResponse *respons)
{
	//signature
	if (respons->signature == NULL)
	{
		if (new_signature_for_response(req, respons) != 1)
		{
			return -1;
		}
	}

	if (req->changed == 4 && req->operation_mode == OPRATION_MODE_1_EARLY_HS_2_SIG_AP)
	{
		req->secret_request = 0;
	}
	return 1;
}

/*
* This function simply check the requested secret in the requset struct
* and check if the secret has already been generated and stored in the 
* response struct
* if the request secret is already generated it would return -1 

* Secrets are more complicated there are different options here:
	* normal TLS handshake (EC)DH(E)
	* PSK (unsing statefull tickets)
* Handshake, appliation and exteral secret will use OpenSSL_LURK function
* Resumption secret is generated with constructing the ticket
* binder secret is generated with retriving the ticket (as well as the early secret)
*/
int secret_not_generated(SInitCertVerifyRequest *req, SInitCertVerifyResponse *respons)
{
	/*
	* The OpenSSL_LURK function is only called in following cases:
	* (client/server) handshake secret and (client/server) application secret
	* exp master is also generated with the application secret
	* since in both cases server and client secrets are generated together we 
	* only call OpenSSL_LURK function for server (handshake and application).
	*/
	/* Clinet HS/AP secret and exporter secret*/
	if (req->secret_request == 3 || req->secret_request == 5 || req->secret_request == 7)
	{
		return -1;
	}
	/* Server handshake secret*/
	if (req->secret_request == 4)
	{
		return 1;
	}
	/* Server application secret*/
	if (req->secret_request == 6)
	{
		/* if it is generated it should not have the secret type uninitialized_SecretType*/
		if (respons->secret_list[SECRET_LIST_INDEX_SERVER_AP_SEC].secret_type == uninitialized_SecretType)
		{
			return 1;
		}
		else
		{
			return -1;
		}
	}
}

/*
* there is int variable in the SInitCertVerifyRequest called "changed" the value 
* of this variable is showing the changed filed
	1 is for ephemeral share secret
	2 is for handshake hash
	3 is for handshake binary (it is not used any more)
	4 is for handshake hash (the one that need to be signed)
*/
int chech_if_ECall_needed(SInitCertVerifyRequest *req, SInitCertVerifyResponse *respons)
{
	/*
	* if the request is regarding ephemeral we always need new ECall 
	* Since we need it before the Server hello is finished and that 
	* needs new handshake by its own (at least for now)
	*/
	if (req->changed == 1)
	{
		return 1;
	}
	/*
	* For signature we need new signature if we are not using the 
	* provisioning function to create the signiture in the same handshake
	* as the handshake secret. For now that check is being done in the OpenSSL
	* code it self but it have to be here. But for now since we check it there,
	* we need new ECall each time that we get here (we wont be here if we are using
	* the mentioned config)
	*/
	if (req->changed == 4)
	{
		return 1;
	}
	/*
	* Secrets are more complicated but in nutshel: 
	* if the secret is not there, we generate it 
	*/
	if (req->changed == 2)
	{
		if (secret_not_generated(req, respons) == 1)
		{
			return 1;
		}
		return -1;
	}
	return -1;
}

/*
* Measure the time 
*/
double measure_time(struct timeval begin, struct timeval end)
{
	long seconds = end.tv_sec - begin.tv_sec;
	long microseconds = end.tv_usec - begin.tv_usec;
	double elapsed = seconds + microseconds * 1e-6;
	return elapsed;
}

void print_time_dif(double time_dif)
{
	printf("Time measured: %f seconds.\n", time_dif);
}

/*
* there is a secret list of 11 secret in the response:
	index 0: client handshake traffic secret
	index 1: server handshake traffic secret
	index 9: early secret
	index 10: handshake secret
*/
int LURK_OPENSSL(SInitCertVerifyRequest *req, SInitCertVerifyResponse *respons, unsigned char *lable)
{
	struct timeval begin, end;

	if (print_extra_info == 1)
	{
		printf("LABLE IS %s \n", lable);
	}

	// Start measuring time
	gettimeofday(&begin, 0);

	int new_E_call = 0;
	/*
	* We check if we need to do a handshake for the information requested or 
	* we have already generated the information in the previous handshakes 
	* retun 1 if we need the handshake with LURK CS.
	*/
	new_E_call = chech_if_ECall_needed(req, respons);

	if (new_E_call == 1)
	{
		/*
		* This function prepare the request and response structre 
		* before doing the S_init_cert_verify handshake with CS
		* e.g. allocate memeroy for signature or change the secret 
		* reqest if needed. 
		*/
		if (prep_before_S_init_cert_verify(req, respons) != 1)
		{
			return -1;
		}

		if (LURK_S_init_cert_verify(req, respons) < 0)
		{
			return 0;
		}
	}

	gettimeofday(&end, 0);
	if (print_extra_info == 1)
	{
		print_time_dif(measure_time(begin, end));
	}

	return 1;
}

/*
* PERFORMANCE can be improve by deleting this funcion and get the appropiate index dicrectly
* in the case of early secret and handshake secret since there are no lable we assume the following lable for them
	"early" for early secret
	"handshake" for handshake secret
*/
unsigned char *get_right_secret_from_SInitCertVerifyResponse(SInitCertVerifyResponse *response, unsigned char *lable)
{
	if (memcmp(lable, "c hs traffic", strlen("c hs traffic")) == 0)
	{
		return response->secret_list[SECRET_LIST_INDEX_CLIENT_HS_SEC].secret_data;
	}
	if (memcmp(lable, "s hs traffic", strlen("s hs traffic")) == 0)
	{
		return response->secret_list[SECRET_LIST_INDEX_SERVER_HS_SEC].secret_data;
	}
	return NULL;
}

int get_sec_req_by_label(unsigned char *lable)
{
	if (memcmp(lable, "c hs traffic", strlen("c hs traffic")) == 0)
	{
		return (int)L_client_handshake_traffic_secret;
	}
	if (memcmp(lable, "s hs traffic", strlen("s hs traffic")) == 0)
	{
		return (int)L_server_handshake_traffic_secret;
	}
	if (memcmp(lable, "c ap traffic", strlen("c ap traffic")) == 0)
	{
		return (int)L_client_application_traffic_secret_0;
	}
	if (memcmp(lable, "s ap traffic", strlen("s ap traffic")) == 0)
	{
		return (int)L_server_application_traffic_secret_0;
	}
	if (memcmp(lable, "exp master", strlen("exp master")) == 0)
	{
		return (int)L_exporter_master_secret;
	}
	if (memcmp(lable, "res master", strlen("res master")) == 0)
	{
		return (int)L_resumption_master_secret;
	}
	if (memcmp(lable, "early", strlen("early")) == 0)
	{
		return (int)LURK_early_secret;
	}
	if (memcmp(lable, "handshake", strlen("handshake")) == 0)
	{
		return (int)LURK_handshake_secret;
	}
	return -1;
}

int compare_secrets(unsigned char *first_input, unsigned char *second_input, int size)
{
	int result = memcmp(first_input, second_input, size);
	if (result != 0)
	{
		printf("secret is not the same");
	}
	return result;
}
/*
* PERFORMANCE:
* CHANGE THE UNSIGNED CHAR TO UNSIGNED INT AND DO IT LIKE UPDATE HASH
*/
int set_data_before_hash_update(void *data, size_t size_of_new_handshake, struct SInitCertVerifyRequest *request)
{
	/*
	* To ensure that if we clculate and add the hash of handshake in the 
	* LURK we do not add the same thing again 
	*/
	if (request->handshake->till_now > (int)request->handshake->openssl_till_now)
	{
		request->handshake->openssl_till_now += size_of_new_handshake;
		return 1;
	}
	if ((request->handshake->till_now + size_of_new_handshake > MAX_HANDSHAKE_DATA_SIZE) ||
		(request->handshake->openssl_till_now + size_of_new_handshake > MAX_HANDSHAKE_DATA_SIZE))
	{
		return 0;
	}
	memcpy(request->handshake->handshake_binary + request->handshake->openssl_till_now, (unsigned char *)data, size_of_new_handshake);
	request->handshake->openssl_till_now += size_of_new_handshake;
	request->handshake->till_now = request->handshake->openssl_till_now;
	return 1;
}

int set_server_old_rand(void *data, struct SInitCertVerifyRequest *request)
{
	memcpy(request->old_rand, (unsigned char *)data, SERVER_RANDOM_LEN);
	return 1;
}

int alloc_ephemeral_secret_generated(struct SInitCertVerifyRequest *request, struct SInitCertVerifyResponse *respons,
									 size_t peer_public_key_len, size_t group_id)
{
	//this function should only get called when CS is expected to generate the ephemeral
	if (request->ephemeral->method != secret_generated)
	{
		return -1;
	}
	request->ephemeral->shared_secret->group = (NamedGroup)group_id;
	//init the response based on requset:
	respons->ephemeral->method = request->ephemeral->method;
	respons->ephemeral->server_share = (KeyShareEntry *)malloc(sizeof(KeyShareEntry));
	if (respons->ephemeral->server_share == NULL)
	{
		return -1;
	}
	respons->ephemeral->server_share->key_exchange = (opaque *)malloc(sizeof(unsigned char) * peer_public_key_len);
	if (respons->ephemeral->server_share->key_exchange == NULL)
	{
		return -1;
	}
	return 1;
}
int LURK_ssl_generate_pkey(unsigned char *peer_public_key, size_t peer_public_key_len, size_t group_id,
						   struct SInitCertVerifyRequest *request, struct SInitCertVerifyResponse *respons)
{
	int result = 0;

	if (alloc_ephemeral_secret_generated(request, respons, peer_public_key_len, group_id) != 1)
	{
		return -1;
	}

	LURK_ssl_generate_pkey_sgx(global_eid, peer_public_key, peer_public_key_len, respons, request, &result);
	return result;
}
/*
* For now we just copy the OpenSSL session ID as the LURK CS session ID
*/
void generate_session_id(struct SInitCertVerifyResponse *respons, unsigned char *session_id,
						 size_t session_id_len)
{
	memcpy(respons->session_id, session_id, session_id_len);
}

int last_ticket(size_t num_tickets, size_t sent_tickets)
{
	if (num_tickets <= sent_tickets + 1)
	{
		return 1;
	}
	return 0;
}

void generate_tag(struct SInitCertVerifyRequest *request, struct SInitCertVerifyResponse *respons,
				  size_t num_tickets, size_t sent_tickets)
{
	if (last_ticket(num_tickets, sent_tickets) == 1)
	{
		request->tag = TAG_LAST_EXCHANGE;
		respons->tag = TAG_LAST_EXCHANGE;
	}
}

/*
* We are constucting PSK for new statefull ticket here and if it is sucssesfull,
* we return the LURK session ID (which is for now the same as SSL session ID).
* This session ID can latter be use to retrive the binder key associated with 
* PSK. The CS ID will be saved in the out and the lentgh would be in the out_len.
*/
int LURK_s_new_tickets(struct SInitCertVerifyResponse *respons,
					   unsigned char *tick_nonce, size_t tick_nonce_len, struct SInitCertVerifyRequest *request,
					   unsigned char *session_id, size_t session_id_len, size_t num_tickets, size_t sent_tickets,
					   unsigned char *out, size_t out_len)
{
	generate_session_id(respons, session_id, session_id_len);
	int state = -1;
	generate_tag(request, respons, num_tickets, sent_tickets);
	LURK_construct_new_session_ticket_and_resumption_sec(global_eid, &state, respons, tick_nonce, tick_nonce_len, request);
	memcpy(out, respons->session_id, session_id_len);
	return state;
}

void copy_session_id(unsigned char *des, unsigned char *source)
{
	// lenght of the session is coming from lurk header
	memcpy(des, source, SESSIN_ID_LEN);
}

/*
* We first search the local SGX cache for the PSK. If it is sucessful, 
* 1- we delete the PSK from cache
* 2- generate and  return the binder key in binder key index
* (in request->secret_list) == 5
* retun 1 if suscessful 
* cache_key is the session->master_key as we stored the LURK' CS cache key 
* previously, now that they look it up in the OpenSSL cache they give us the
* CS' cache ID
*/
int LURK_get_stateful_ticket_binder_key(struct SInitCertVerifyRequest *request,
										struct SInitCertVerifyResponse *respons, unsigned char *cache_key)
{
	copy_session_id(request->session_id, cache_key);
	copy_session_id(respons->session_id, cache_key);
	int state = -1;

	LURK_get_stateful_ticket_binder_key_SGX(global_eid, &state, request, respons);
	return state;
}
