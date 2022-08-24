#define MAX_BUF_LEN 100
#define ENCLAVE_FILENAME "Enclave.signed.dll"
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
#include <string.h>
#include <assert.h>
#include <iostream>


//#include <time.h> 


#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif

#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "App.h"
#include "Enclave_u.h"
#include "LURK-functions.h"



#include "LURK_header.h"
#include <time.h>



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
	errno_t err;
	err = fopen_s(&fptr, "LURK_config.txt", "r");
	if (err != 0) {
		printf("Error! opening file");
		return 0;
	}

	// reads text until newline is encountered
	fscanf_s(fptr, "%d %d %d %d", &print_extra_info,&print_handshake_CS,&mode_of_opration,&temp_ephemeral_mode);
	ephemeral_mode = (EphemeralMethod)temp_ephemeral_mode;
	printf("Data from the file:\n print_extra_info:%d \n print_handshake_CS %d \n mode_of_opration %d \n temp_ephemeral_mode %d \n ",
		print_extra_info, print_handshake_CS, mode_of_opration,(int)ephemeral_mode);
	fclose(fptr);

	return 1;
}


/*
there is a secret list of 11 secret in the response :
index 0 : client handshake traffic secret
index 1 : server handshake traffic secret
index 9 : early secret
index 10 : handshake secret
*/
int secret_list_index_c_hs_sec = 0;
int secret_list_index_s_hs_sec = 1;
int secret_list_index_c_ap_sec = 2;
int secret_list_index_s_ap_sec = 3;
int secret_list_index_exporter = 4;
int secret_list_index_resumtion = 5;
int secret_list_index_early_sec = 9;
int secret_list_index_handshake_sec = 10;

//this is for req->handshake-hanshake_binary[??]
const int Max_size_data = 3000;

//this is for req->oldrand[??]
const int size_of_random = 32;



typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
	{
		SGX_ERROR_UNEXPECTED,
		"Unexpected error occurred.",
		NULL
	},
	{
		SGX_ERROR_INVALID_PARAMETER,
		"Invalid parameter.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_MEMORY,
		"Out of memory.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_LOST,
		"Power transition occurred.",
		"Please refer to the sample \"PowerTransition\" for details."
	},
	{
		SGX_ERROR_INVALID_ENCLAVE,
		"Invalid enclave image.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ENCLAVE_ID,
		"Invalid enclave identification.",
		NULL
	},
	{
		SGX_ERROR_INVALID_SIGNATURE,
		"Invalid enclave signature.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_EPC,
		"Out of EPC memory.",
		NULL
	},
	{
		SGX_ERROR_NO_DEVICE,
		"Invalid SGX device.",
		"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
	},
	{
		SGX_ERROR_MEMORY_MAP_CONFLICT,
		"Memory map conflicted.",
		NULL
	},
	{
		SGX_ERROR_INVALID_METADATA,
		"Invalid enclave metadata.",
		NULL
	},
	{
		SGX_ERROR_DEVICE_BUSY,
		"SGX device was busy.",
		NULL
	},
	{
		SGX_ERROR_INVALID_VERSION,
		"Enclave version was invalid.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ATTRIBUTE,
		"Enclave was not authorized.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_FILE_ACCESS,
		"Can't open enclave file.",
		NULL
	},
	{
		SGX_ERROR_NDEBUG_ENCLAVE,
		"The enclave is signed as product enclave, and can not be created as debuggable enclave.",
		NULL
	},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if (ret == sgx_errlist[idx].err) {
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
	char token_path[MAX_PATH] = { '\0' };
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	/* Step 1: try to retrieve the launch token saved by last transaction
	 *         if there is no token, then create a new one.
	 */
#ifdef _MSC_VER
	 /* try to get the token saved in CSIDL_LOCAL_APPDATA */
	if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path)) {
		strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}
	else {
		strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 2);
	}

	/* open the token file */
	HANDLE token_handler = CreateFileA(token_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
	if (token_handler == INVALID_HANDLE_VALUE) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}
	else {
		/* read the token from saved file */
		DWORD read_num = 0;
		ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
#else /* __GNUC__ */
	 /* try to get the token saved in $HOME */
	const char *home_dir = getpwuid(getuid())->pw_dir;

	if (home_dir != NULL &&
		(strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
		/* compose the token path */
		strncpy(token_path, home_dir, strlen(home_dir));
		strncat(token_path, "/", strlen("/"));
		strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
	}
	else {
		/* if token path is too long or $HOME is NULL */
		strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}

	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}

	if (fp != NULL) {
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
#endif
	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
#ifdef _MSC_VER
		if (token_handler != INVALID_HANDLE_VALUE)
			CloseHandle(token_handler);
#else
		if (fp != NULL) fclose(fp);
#endif
		return -1;
	}

	/* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
	if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
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
	if (updated == FALSE || fp == NULL) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL) fclose(fp);
		return 0;
	}

	/* reopen the file with write capablity */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL) return 0;
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
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.*/

	printf("this is an Ocall from enclave");
	printf("HASHes DONT match : %d \n", a);
}

void print_hex_format(unsigned char* input, int input_length) {

	for (int i = 0; i < input_length; i++) {
		printf("%02x", input[i]);
	}

}


/* This  function is for printing a InitCertificateVerifyRequest structure*/
void InitCertificateVerifyRequest_to_string(SInitCertVerifyRequest req) {
	printf("\n \n REQUEST \n");
	printf("Here is the information about Request that is going through the Crypto Server in Intel SGX: \n");
	printf("Request -> Seceret request: ");
	switch (req.secret_request)
	{
	case 3:
		printf("client_handshake_traffic_secret \n");
		break;
	case 4:
		printf("server_handshake_traffic_secret \n");
		break;
	case 5:
		printf("client_application_traffic_secret_0 \n");
		break;
	case 6:
		printf("server_application_traffic_secret_0 \n");
		break;
	case 9:
		printf("early secret \n ");
		break;
	case 10:
		printf("handshake \n");
		break;
	default:
		printf("OUT OF BOUND WE COVER RANGE OF 3 TO 10\n");
	}
	printf("Request -> Ephemeral Request -> type:");
	switch (req.ephemeral->method)
	{
	case 0:
		printf("no_secret \n");
		break;
	case 1:
		printf("secret_provided \n");
		break;
	case 2:
		printf("secret_generated \n");
		break;

	default:
		printf("OUT OF BOUND WE COVER RANGE OF 0 TO 2");
	}
	printf("Request -> LURKTLS13Certificate -> type:");
	switch (req.certificate->certificate_type)
	{
	case 0:
		printf("empty \n");
		break;
	case 1:
		printf("finger_print \n");
		break;
	case 2:
		printf("uncompressed \n");
		break;
	case 3:
		printf("compressed \n");
		break;

	default:
		printf("OUT OF BOUND WE COVER RANGE OF 0 TO 3\n");
	}

	printf("Request -> Signing Algorithm: ");
	switch (req.sig_algo)
	{
	case rsa_pss_rsae_sha256:
		printf("rsa_pss_rsae_sha256");
		break;
	case rsa_pss_rsae_sha384:
		printf("rsa_pss_rsae_sha384");
		break;
	case rsa_pss_rsae_sha512:
		printf("rsa_pss_rsae_sha512");
		break;

	case rsa_pkcs1_sha256:
		printf("rsa_pkcs1_sha256");
		break;
	case rsa_pkcs1_sha384:
		printf("rsa_pkcs1_sha384");
		break;
	case rsa_pkcs1_sha512:
		printf("rsa_pkcs1_sha512");
		break;

	case ecdsa_secp256r1_sha256:
		printf("ecdsa_secp256r1_sha256");
		break;
	case ecdsa_secp384r1_sha384:
		printf("ecdsa_secp384r1_sha384");
		break;
	case ecdsa_secp521r1_sha512:
		printf("ecdsa_secp521r1_sha512");
		break;

	case ed25519:
		printf("ed25519");
		break;
	case ed448:
		printf("ed448");
		break;

	case rsa_pss_pss_sha256:
		printf("rsa_pss_pss_sha256");
		break;
	case rsa_pss_pss_sha384:
		printf("rsa_pss_pss_sha384");
		break;
	case rsa_pss_pss_sha512:
		printf("rsa_pss_pss_sha512");
		break;

	case rsa_pkcs1_sha1:
		printf("rsa_pkcs1_sha1");
		break;
	case ecdsa_sha1:
		printf("ecdsa_sha1");
		break;

	default:
		printf("UNKOWN SIGNARURE");
	}

	printf("\nRequest -> Freshness: ");
	switch (req.freshness)
	{
	case sha256:
		printf("sha256");
		break;
	default:
		printf("UNKOWN FRESHNESS FUNCTION");
	}
	printf("Request -> hashed handshake: \n");
	print_hex_format(req.handshake_hash, req.handshake_hash_size);

	//req.cert_request.signing_request.sig_algo
}


/* This  function is for printing a InitCertificateVerifyResponse structure*/
void InitCertificateVerifyResponse_to_string(SInitCertVerifyResponse resp) {

	printf("\n \n RESPONSE \n");
	printf("Here is the information about Response that is Coming out of the Crypto Server from Intel SGX: \n");
	printf("Response-> ephemeral -> method: %d\n", (int)resp.ephemeral->method);
	if (resp.signature != NULL)
	{
		printf("Response-> Signature\n");
		printf("\t Response-> Signature -> Signature data \n");
		print_hex_format(resp.signature->signature, 0x100);
		printf("\n");
		printf("\t Response-> Signature -> algorithm \n");
		switch (resp.signature->algorithm)
		{
		case rsa_pss_rsae_sha256:
			printf("rsa_pss_rsae_sha256");
			break;
		case rsa_pss_rsae_sha384:
			printf("rsa_pss_rsae_sha384");
			break;
		case rsa_pss_rsae_sha512:
			printf("rsa_pss_rsae_sha512");
			break;

		case rsa_pkcs1_sha256:
			printf("rsa_pkcs1_sha256");
			break;
		case rsa_pkcs1_sha384:
			printf("rsa_pkcs1_sha384");
			break;
		case rsa_pkcs1_sha512:
			printf("rsa_pkcs1_sha512");
			break;

		case ecdsa_secp256r1_sha256:
			printf("ecdsa_secp256r1_sha256");
			break;
		case ecdsa_secp384r1_sha384:
			printf("ecdsa_secp384r1_sha384");
			break;
		case ecdsa_secp521r1_sha512:
			printf("ecdsa_secp521r1_sha512");
			break;

		case ed25519:
			printf("ed25519");
			break;
		case ed448:
			printf("ed448");
			break;

		case rsa_pss_pss_sha256:
			printf("rsa_pss_pss_sha256");
			break;
		case rsa_pss_pss_sha384:
			printf("rsa_pss_pss_sha384");
			break;
		case rsa_pss_pss_sha512:
			printf("rsa_pss_pss_sha512");
			break;

		case rsa_pkcs1_sha1:
			printf("rsa_pkcs1_sha1");
			break;
		case ecdsa_sha1:
			printf("ecdsa_sha1");
			break;

		default:
			printf("UNKOWN SIGNARURE");
		}
	}
	else {
		printf("No signature Yet! ");
	}
	printf("\n  Response ->  Secerets ");
	for (int i = 0; i < 11; i++) {
		printf("\n\t Response ->  Seceret type: ");
		switch (resp.secret_list[i].secret_type)
		{
		case (L_binder_key):
			printf("No data yet");
			break;
		case (L_client_early_traffic_secret):
			printf("client_early_traffic_secret");
			break;
		case (L_early_exporter_master_secret):
			printf("early_exporter_master_secret");
			break;
		case (L_client_handshake_traffic_secret):
			printf("client_handshake_traffic_secret");
			break;
		case (L_server_handshake_traffic_secret):
			printf("server_handshake_traffic_secret");
			break;
		case (L_client_application_traffic_secret_0):
			printf("client_application_traffic_secret_0");
			break;
		case (L_server_application_traffic_secret_0):
			printf("server_application_traffic_secret_0");
			break;
		case (L_exporter_master_secret):
			printf("exporter_master_secret");
			break;
		case (L_resumption_master_secret):
			printf("resumption_master_secret");
			break;
		case (LURK_early_secret):
			printf("LURK_early_secret");
			break;
		case (LURK_handshake_secret):
			printf("LURK_handshake_secret");
			break;
		case (LURK_master_secret):
			printf("LURK_master_secret");
			break;
		case (uninitialized_SecretType):
			printf("uninitialized_SecretType");
			break;
		default:
			printf("UNKOWN SECRET ");
		}
		if (resp.secret_list[i].secret_type != L_binder_key)
		{
			printf("\n\t Response ->  Seceret data: ");
			print_hex_format((unsigned char *)resp.secret_list[i].secret_data, 0x40);
		}
	}
	printf(" \n------------------------------------------------------------------ \n\n\n\n");
	//resp.cert_response.signing_response.signature
}

int set_EphemeralRequest(EphemeralRequest &ephemeralrequest, EphemeralMethod method, int memory_allocation) {
	if (method == secret_provided)
	{
		ephemeralrequest.method = method;
		if (memory_allocation == 1)
		{
			ephemeralrequest.shared_secret = (SharedSecret *)malloc(sizeof(SharedSecret));
			// we only allocate the memory but you need to  initialize the shared_secret
			(*ephemeralrequest.shared_secret).group = uninitialized;
			ephemeralrequest.shared_secret->shared_secret[0] = { 0 };
			ephemeralrequest.shared_secret->shared_secret_len = 0;
			//memcpy(ephemeralrequest.shared_secret->shared_secret, shared_secret_13, sizeof(shared_secret_13));
		}
	}
	else if (method == no_secret || method == secret_generated) {
		ephemeralrequest.method = method;
		if (memory_allocation == 1)
		{
			ephemeralrequest.shared_secret = (SharedSecret *)malloc(sizeof(SharedSecret));
			// we only allocate the memory but you need to  initialize the shared_secret
			(*ephemeralrequest.shared_secret).group = uninitialized;
			ephemeralrequest.shared_secret->shared_secret[0] = { 0 };
			ephemeralrequest.shared_secret->shared_secret_len = 0;
		}
	}
	else {
		return -1;
	}
	return 1;
}
//updated
int init_InitCertificateVerifyRequest(SInitCertVerifyRequest *req)
{
	req->tag = 1;
	req->session_id = 111111;
	req->freshness = sha256;
	set_EphemeralRequest((*req->ephemeral), ephemeral_mode, 1);
	req->handshake->openssl_till_now = 0;
	req->handshake->till_now = 0;
	//TODO init the handshake_binary ?? 
	req->handshake->handshake_binary[0] = { 0 };
	//for (int i = 0; i < 10; i++)
	//{
	//	req->things_that_we_have[i] = 0;
	//}
	req->sig_algo = rsa_pss_rsae_sha256;
	req->certificate->certificate_type = finger_print;
	(*req->certificate->finger_print) = 1111;
	req->certificate->empty = NULL;
	req->certificate->uncompressed_certificate = NULL;
	req->certificate->compressed_certificate = NULL;
	req->changed = 0;
	req->handshake_hash_size = 0;
	req->secret_request = 9;//TESTING
	req->handshake_hash[0] = { 0 };
	req->md_index = -1;
	req->operation_mode = mode_of_opration;
	return 1;
}


//### TO DO must allocate for secret data as well;
/*
Secret *new_secret_list(uint16_t secret_request) {
	Secret *secret_list = NULL;
	if (secret_request == 3 || secret_request == 4) //client_handshake_traffic_secret (h_c) or server_handshake_traffic_secret (h_s) 
	{
		int number_of_secrets = 2;
		secret_list = (Secret *)malloc(number_of_secrets * sizeof(Secret));
	}
	else if (secret_request == 5 || secret_request == 6) //client_handshake_traffic_secret (h_c) or server_handshake_traffic_secret (h_s) 
	{
		int number_of_secrets = 4;
		secret_list = (Secret *)malloc(number_of_secrets * sizeof(Secret));
	}
	else {
		secret_list = NULL;
	}
	return secret_list;
}*/

SInitCertVerifyResponse *new_SInitCertVerifyResponse() {
	SInitCertVerifyResponse *respons = (SInitCertVerifyResponse *)malloc(sizeof(SInitCertVerifyResponse));
	EphemeralResponse *e_res = (EphemeralResponse *)malloc(sizeof(EphemeralResponse));
	respons->signature = NULL;

	//#### TO DO need to malloc for EphemeralResponse
	respons->ephemeral = e_res;
	//respons->secret_list = sec;
	for (int i = 0; i < 11; i++) {
		respons->secret_list[i] = {};
	}
	respons->ephemeral->method = uninitialized_method;
	return respons;
}
SInitCertVerifyRequest * new_SInitCertVerifyRequest() {
	SInitCertVerifyRequest *req = (SInitCertVerifyRequest *)malloc(sizeof(SInitCertVerifyRequest));
	EphemeralRequest *e_req = (EphemeralRequest *)malloc(sizeof(EphemeralRequest));
	req->ephemeral = e_req;
	Handshake *handsh = (Handshake *)malloc(sizeof(Handshake));
	req->handshake = handsh;
	LURKTLS13Certificate *cert = (LURKTLS13Certificate *)malloc(sizeof(LURKTLS13Certificate));
	uint32_t fingerprint;
	req->certificate = cert;
	cert->finger_print = &fingerprint;
	return req;
}

/*int modify_Handshake_binary_SInitCertVerifyRequest(SInitCertVerifyRequest *request, unsigned char *handshake_binary_openssl, int handshake_binary_size) {
	request->changed = 3;
	//request->handshake->handshake_binary = (opaque *)malloc(handshake_binary_size * sizeof(opaque));
	memcpy(request->handshake->handshake_binary, handshake_binary_openssl, handshake_binary_size);
	request->handshake->size = handshake_binary_size;
	return 1;
}*/

int modify_Handshake_Hash_SInitCertVerifyRequest(SInitCertVerifyRequest *request, unsigned char *handshake_hash_openssl, int handshake_hash_size) {
	request->changed = 2;
	memcpy(request->handshake_hash, handshake_hash_openssl, handshake_hash_size);
	request->handshake_hash_size = handshake_hash_size;
	return 1;
}

int modify_Handshake_Hash_Signature_SInitCertVerifyRequest(SInitCertVerifyRequest *request, unsigned char *to_be_signed, int size_of_to_be_signed, int sig_algorithm) {
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
	//TODO 0x0100 must change to response signature lenght this is just for testing
	//EVP_PKEY_size(pkey);    
	//TESTING

	sig->signature = (unsigned char *)malloc(sizeof(unsigned char) * 0x100);
	sig->signature_size = request->signature_size;
	respons->signature = sig;
	return 1;
}

int get_size_of_share_secret(NamedGroup group_id) {

	if (group_id == 0x0017 || group_id == 0x001D) {
		 return 32;
	}
	else if (group_id == 0x0018) {
		return  48;
	}
	else if (group_id == 0x0019) {
		return  66;
	}
	else if (group_id == 0x001E) {
		return 56;
	}
	else {
		return 0;
	}
}
int modify_shared_secret_SInitCertVerifyRequest(SInitCertVerifyRequest *request, unsigned char *provided_shared_secret, int group_id) {
	request->changed = 1;
	// if the CS generating the pms the share secret is already in request->ephemeral->shared_secret->shared_secret
	if (request->ephemeral->method != secret_generated)
	{
		request->ephemeral->method = secret_provided;
		request->ephemeral->shared_secret->group = (NamedGroup)group_id;
		int share_secret_size = get_size_of_share_secret(request->ephemeral->shared_secret->group);
		if (share_secret_size == 0) {
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

	// if(request->ephemeral->shared_secret){
	// 	free(request->ephemeral->shared_secret);
	// }
	free(request->ephemeral);

	/*
	if (request->certificate->empty){
		free(request->certificate->empty);
	}
	if (request->certificate->finger_print){
		free(request->certificate->finger_print);
	}
	if (request->certificate->uncompressed_certificate){
		free(request->certificate->uncompressed_certificate);
	}
	if (request->certificate->compressed_certificate){
		free(request->certificate->compressed_certificate);
	}*/
	free(request->certificate);

	free(request);
	return;
}
//TODO free inside stucts as well
void LURK_free_response(struct SInitCertVerifyResponse *response) {
	// if (response->ephemeral->server_share->key_exchange){
	// 	free(response->ephemeral->server_share->key_exchange);
	// }
	// if(response->ephemeral->server_share ){
	// 	free(response->ephemeral->server_share);
	// }
	if (response->ephemeral) {
		free(response->ephemeral);
	}

	//free(response->signature->signature);
	free(response->signature);

	free(response);
	return;
}

/* MUST call initialize_enclave() before calling this fuction*/
int LURK_S_init_cert_verify(SInitCertVerifyRequest* req, SInitCertVerifyResponse *respons)
{
	clock_t t;
	t = clock();
	int b = -1;

	if (print_handshake_CS == 1) {
		InitCertificateVerifyRequest_to_string(*req);
	}
	init_certificate_verify(global_eid, req, &b, respons);
	if (print_handshake_CS == 1) {
		InitCertificateVerifyResponse_to_string(*respons);
	}

	t = clock() - t;
	double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds 
	if (print_extra_info == 1) {
		printf("TIME INSIDE (LURK_S_init_cert_verify):  %f seconds to execute \n", time_taken);
		printf("STATUS OF RESPONCE IS:%d \n", b);
	}
	return b;
}

void LURK_destroy_enclave()
{
	sgx_destroy_enclave(global_eid);
}

/*
int  get_right_index_for_things_that_we_have(unsigned char *lable) {
	if (memcmp(lable, "c hs traffic", strlen("c hs traffic")) == 0) {
		return 1;
	}
	else if (memcmp(lable, "s hs traffic", strlen("s hs traffic")) == 0) {
		return 1;
	}
	else if (memcmp(lable, "c ap traffic", strlen("c ap traffic")) == 0) {
		return 2;
	}
	else if (memcmp(lable, "s ap traffic", strlen("s ap traffic")) == 0) {
		return 2;
	}
	else if (memcmp(lable, "exp master", strlen("exp master")) == 0) {
		return 2;
	}
	else if (memcmp(lable, "early", strlen("early")) == 0) {
		return 0;
	}
	else if (memcmp(lable, "handshake", strlen("handshake")) == 0) {
		return 0;
	}
	else if (memcmp(lable, "res master", strlen("res master")) == 0) {
		return 4;
	}
	return -1;
}

int set_right_index_for_things_that_we_have(SInitCertVerifyRequest* req) {
	//since after this step we are going to have early secret and handshake secret
	if (req->changed == 1)
	{
		req->things_that_we_have[0] = 1;
		req->changed = 0;

	}
	if (req->changed == 2) {
		if (req->secret_request == 4 || req->secret_request == 3) {
			req->things_that_we_have[1] = 1;
			req->changed = 0;
		}
		else if (req->secret_request == 5 || req->secret_request == 6 || req->secret_request == 7) {
			//TODO with mode not with these indexes
			req->things_that_we_have[2] = 1;
			req->things_that_we_have[4] = 1;
			req->things_that_we_have[1] = 1;
			req->things_that_we_have[0] = 1;
			req->changed = 0;
		}
		else if (req->secret_request == 8) {
			req->things_that_we_have[4] = 1;
			req->changed = 0;
		}

	}
	return 0;

}*/

/*
* there is an array for the things "that we already have" ONLY for secrets
	index 0: is for early secret and handshake secret. (since both of them are drived at the sametime)
	index 1: is for "client/server handshake traffic secret"
	index 2: is for "client/server application traffic secret" and "exporter secret"
	index 3: is for "signature"
	index 4: is for "resumption secret"
* there is int variable in the SInitCertVerifyRequest called "changed" the value of this variable is showing the changed filed
	1 is for ephemeral share secret
	2 is for handshake hash
	3 is for handshake binary
	4 is for handshake hash (the one that need to be signed)
* there is a secret list of 11 secret in the response:
	index 0: client handshake traffic secret
	index 1: server handshake traffic secret
	index 9: early secret
	index 10: handshake secret
*/
int LURK_OPENSSL(SInitCertVerifyRequest* req, SInitCertVerifyResponse *respons, unsigned char *lable)
{

	if (print_extra_info == 1) {
		printf("LABLE IS %s \n", lable);
	}
	// Start measuring time
	clock_t start = clock();

	//int new_E_call = 0;
	//int things_that_we_have_index = 0;
	//"things_that_we_have" is ONLY for secrets
	/*if (lable != NULL) {
		things_that_we_have_index = get_right_index_for_things_that_we_have(lable);
		if (req->things_that_we_have[things_that_we_have_index] == 0) {
			new_E_call = 1;
		}
	}
	else {
		new_E_call = 1;
	}*/

	if ((req->changed == 1 || req->changed == 2 || req->changed == 3 || req->changed == 4) )//&& new_E_call == 1
	{
		//signature
		if (respons->signature == NULL) 
		{
			new_signature_for_response(req, respons);
		}

		if (req->changed == 4 && req->operation_mode == OPRATION_MODE_1_EARLY_HS_2_SIG_AP) {
			req->secret_request = 0;
		}

		if (LURK_S_init_cert_verify(req, respons) < 0) {
			return 0;
		}
		//things_that_we is only for secrets
		//if (req->changed != 4) {
		//	set_right_index_for_things_that_we_have(req);
			//req->handshake_hash[0] = { 0 };
		//}

	}

	clock_t end = clock();
	double elapsed = double(end - start) / CLOCKS_PER_SEC;

	if (print_extra_info == 1) {
		printf("Time measured: %f seconds.\n", elapsed);
	}

	return 1;
}

/*
* PERFORMANCE can be improve by deleting this funcion and get the appropiate index dicrectly
* in the case of early secret and handshake secret since there are no lable we assume the following lable for them
	"early" for early secret
	"handshake" for handshake secret
*/
unsigned char * get_right_secret_from_SInitCertVerifyResponse(SInitCertVerifyResponse *response, unsigned char *lable) {
	if (memcmp(lable, "c hs traffic", strlen("c hs traffic")) == 0) {
		return response->secret_list[secret_list_index_c_hs_sec].secret_data;
	}
	if (memcmp(lable, "s hs traffic", strlen("s hs traffic")) == 0) {
		return response->secret_list[secret_list_index_s_hs_sec].secret_data;
	}
	if (memcmp(lable, "early", strlen("early")) == 0) {
		return response->secret_list[secret_list_index_early_sec].secret_data;
	}
	if (memcmp(lable, "handshake", strlen("handshake")) == 0) {
		return response->secret_list[secret_list_index_handshake_sec].secret_data;
	}
	if (memcmp(lable, "handshake", strlen("handshake")) == 0) {
		return response->secret_list[secret_list_index_handshake_sec].secret_data;
	}
	if (memcmp(lable, "handshake", strlen("handshake")) == 0) {
		return response->secret_list[secret_list_index_handshake_sec].secret_data;
	}
	return NULL;

}

int get_sec_req_by_label(unsigned char *lable) {
	if (memcmp(lable, "c hs traffic", strlen("c hs traffic")) == 0) {
		return 3;
	}
	if (memcmp(lable, "s hs traffic", strlen("s hs traffic")) == 0) {
		return 4;
	}
	if (memcmp(lable, "c ap traffic", strlen("c ap traffic")) == 0) {
		return 5;
	}
	if (memcmp(lable, "s ap traffic", strlen("s ap traffic")) == 0) {
		return 6;
	}
	if (memcmp(lable, "exp master", strlen("exp master")) == 0) {
		return 7;
	}
	if (memcmp(lable, "res master", strlen("res master")) == 0) {
		return 8;
	}
	if (memcmp(lable, "early", strlen("early")) == 0) {
		return 9;
	}
	if (memcmp(lable, "handshake", strlen("handshake")) == 0) {
		return 10;
	}
	return -1;
}

int compare_secrets(unsigned char *first_input, unsigned char *second_input, int size) {
	int result = memcmp(first_input, second_input, size);
	if (result != 0) {
		printf("secret is not the same");
	}
	return result;
}

/*
* PERFORMANCE:
* CHANGE THE UNSIGNED CHAR TO UNSIGNED INT AND DO IT LIKE UPDATE HASH
*/
int set_data_before_hash_update(void * data, size_t size_of_new_handshake, struct SInitCertVerifyRequest *request)
{
	/*
	* To ensure that if we clculate and add the hash of handshake in the 
	* LURK we do not add the same thing again 
	*/
	if (request->handshake->till_now > (int)request->handshake->openssl_till_now) {
		request->handshake->openssl_till_now += size_of_new_handshake;
		return 1;
	}
	if ((request->handshake->till_now + size_of_new_handshake > Max_size_data) ||
		(request->handshake->openssl_till_now + size_of_new_handshake > Max_size_data)) 
	{
		return 0;
	}
	
	memcpy(request->handshake->handshake_binary + request->handshake->openssl_till_now, (unsigned char *)data, size_of_new_handshake);
	request->handshake->openssl_till_now += size_of_new_handshake;
	request->handshake->till_now = request->handshake->openssl_till_now;
	return 1;
}

int set_server_old_rand(void * data, struct SInitCertVerifyRequest *request)
{
	memcpy(request->old_rand, (unsigned char *)data, size_of_random);
	return 1;
}


int LURK_ssl_generate_pkey(unsigned char* peer_public_key, size_t peer_public_key_len, size_t group_id,
	struct SInitCertVerifyRequest *request, struct SInitCertVerifyResponse *respons)
{
	int result = 0;
	//this function should only get called when CS is expected to generate the ephemeral
	if (request->ephemeral->method != secret_generated)
	{
		return result;
	}
	request->ephemeral->shared_secret->group = (NamedGroup)group_id;
	//init the response based on requset:
	respons->ephemeral->method = request->ephemeral->method;
	respons->ephemeral->server_share = (KeyShareEntry *)malloc(sizeof(KeyShareEntry));
	respons->ephemeral->server_share->key_exchange = (opaque *)malloc(sizeof(unsigned char) * peer_public_key_len);
	LURK_ssl_generate_pkey_sgx(global_eid,peer_public_key, peer_public_key_len, respons,request,&result);
	return result;
}


/*

void main2() {

	printf("hello world!");
	struct SInitCertVerifyRequest *req = new_SInitCertVerifyRequest();
	init_InitCertificateVerifyRequest(req);
	
	//TESTING OPTIONS
	//modify_Handshake_binary_SInitCertVerifyRequest(req, client_hello_raw, sizeof(client_hello_raw));
	//modify_Handshake_Hash_SInitCertVerifyRequest(req, client_hello_hash, sizeof(client_hello_hash));

	//testing secrets (handshake)
	



	
	//clock_t t;
	//t = clock();

	//SW is to know if the enclave has been initilize or not
	if (initialize_enclave() < 0) {
		printf("Enter a character before exit ...\n");
		getchar();
	}
	//t = clock() - t;
	//double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds 

	//printf("fun() took %f seconds to execute \n", time_taken);

	



	modify_shared_secret_SInitCertVerifyRequest(req, shared_secret_13, 0x40a);
	req->secret_request = get_sec_req_by_label((unsigned char *)"early");
	struct SInitCertVerifyResponse *respons;
	LURK_OPENSSL(req, respons, (unsigned char *)"early");
	req->secret_request = get_sec_req_by_label((unsigned char *)"handshake");
	LURK_OPENSSL(req, respons, (unsigned char *)"handshake");

	
	
	set_data_before_hash_update(handshake_raw_test, sizeof(handshake_raw_test),req);
	set_server_old_rand((void *)old_server_random_test,req);
	req->secret_request = 4;
	modify_Handshake_Hash_SInitCertVerifyRequest(req, client_hello_hash, sizeof(client_hello_hash));
	LURK_OPENSSL(req, respons, (unsigned char *)"s hs traffic");
	req->secret_request = 3;
	modify_Handshake_Hash_SInitCertVerifyRequest(req, client_hello_hash, sizeof(client_hello_hash));
	LURK_OPENSSL(req, respons, (unsigned char *)"c hs traffic");

	
	

	

	//testing signature
	set_data_before_hash_update(handshake_raw_test, sizeof(handshake_raw_test),req);
	set_server_old_rand((void *)old_server_random_test,req);
	modify_Handshake_Hash_Signature_SInitCertVerifyRequest(req, handshake_hash_test, sizeof(handshake_hash_test), 0x804);
	LURK_OPENSSL(req, respons, NULL);

	

	//testing the app secrets
	req->secret_request = 5;
	modify_Handshake_Hash_SInitCertVerifyRequest(req, full_hash, sizeof(full_hash));
	LURK_OPENSSL(req, respons, (unsigned char *)"s ap traffic");
	req->secret_request = 6;
	modify_Handshake_Hash_SInitCertVerifyRequest(req, full_hash, sizeof(full_hash));
	LURK_OPENSSL(req, respons ,(unsigned char *)"c ap traffic");

	req->secret_request = 7;
	modify_Handshake_Hash_SInitCertVerifyRequest(req, full_hash, sizeof(full_hash));
	 LURK_OPENSSL(req, respons, (unsigned char *)"exp master");
	req->secret_request = 8;
	modify_Handshake_Hash_SInitCertVerifyRequest(req, full_hash, sizeof(full_hash));
	LURK_OPENSSL(req, respons, (unsigned char *)"res master");


	int a;
	scanf_s("%d", &a);



	LURK_destroy_enclave();
	printf("No way it works!");

}



//TESTING INPUTS
unsigned char client_hello_raw[] = {
	0x01,0x00,0x00,0xc6,0x03,0x03,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
	0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
	0x20,0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,0xf0,0xf1,
	0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,0x00,0x06,0x13,0x01,0x13,
	0x02,0x13,0x03,0x01,0x00,0x00,0x77,0x00,0x00,0x00,0x18,0x00,0x16,0x00,0x00,0x13,0x65,0x78,0x61,
	0x6d,0x70,0x6c,0x65,0x2e,0x75,0x6c,0x66,0x68,0x65,0x69,0x6d,0x2e,0x6e,0x65,0x74,0x00,0x0a,0x00,
	0x08,0x00,0x06,0x00,0x1d,0x00,0x17,0x00,0x18,0x00,0x0d,0x00,0x14,0x00,0x12,0x04,0x03,0x08,0x04,
	0x04,0x01,0x05,0x03,0x08,0x05,0x05,0x01,0x08,0x06,0x06,0x01,0x02,0x01,0x00,0x33,0x00,0x26,0x00,
	0x24,0x00,0x1d,0x00,0x20,0x35,0x80,0x72,0xd6,0x36,0x58,0x80,0xd1,0xae,0xea,0x32,0x9a,0xdf,0x91,
	0x21,0x38,0x38,0x51,0xed,0x21,0xa2,0x8e,0x3b,0x75,0xe9,0x65,0xd0,0xd2,0xcd,0x16,0x62,0x54,0x00,
	0x2d,0x00,0x02,0x01,0x01,0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x02,0x00,0x00,0x76,0x03,0x03,0x70,
	0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,0x80,0x81,0x82,0x83,
	0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,0x20,0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,
	0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,
	0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,0x13,0x01,0x00,0x00,0x2e,0x00,0x33,0x00,0x24,0x00,0x1d,0x00,
	0x20,0x9f,0xd7,0xad,0x6d,0xcf,0xf4,0x29,0x8d,0xd3,0xf9,0x6d,0x5b,0x1b,0x2a,0xf9,0x10,0xa0,0x53,
	0x5b,0x14,0x88,0xd7,0xf8,0xfa,0xbb,0x34,0x9a,0x98,0x28,0x80,0xb6,0x15,0x00,0x2b,0x00,0x02,0x03,
	0x04
};
// 0x00,0xc6 ->0x01,0xfc
unsigned char handshake_raw_test[] = {
	0x01,0x00,0x00,0xc6,0x03,0x03,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
	0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
	0x20,0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,0xf0,0xf1,
	0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,0x00,0x06,0x13,0x01,0x13,
	0x02,0x13,0x03,0x01,0x00,0x00,0x77,0x00,0x00,0x00,0x18,0x00,0x16,0x00,0x00,0x13,0x65,0x78,0x61,
	0x6d,0x70,0x6c,0x65,0x2e,0x75,0x6c,0x66,0x68,0x65,0x69,0x6d,0x2e,0x6e,0x65,0x74,0x00,0x0a,0x00,
	0x08,0x00,0x06,0x00,0x1d,0x00,0x17,0x00,0x18,0x00,0x0d,0x00,0x14,0x00,0x12,0x04,0x03,0x08,0x04,
	0x04,0x01,0x05,0x03,0x08,0x05,0x05,0x01,0x08,0x06,0x06,0x01,0x02,0x01,0x00,0x33,0x00,0x26,0x00,
	0x24,0x00,0x1d,0x00,0x20,0x35,0x80,0x72,0xd6,0x36,0x58,0x80,0xd1,0xae,0xea,0x32,0x9a,0xdf,0x91,
	0x21,0x38,0x38,0x51,0xed,0x21,0xa2,0x8e,0x3b,0x75,0xe9,0x65,0xd0,0xd2,0xcd,0x16,0x62,0x54,0x00,
	0x2d,0x00,0x02,0x01,0x01,0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x02,0x00,0x00,0x76,0x03,0x03,0xf8,
	0x75,0xae,0xe8,0xa0,0xc9,0xd2,0x61,0xdc,0x24,0x4c,0xbb,0x5c,0x84,0xf8,0x25,0x97,0xd8,0xcc,0x56,
	0x99,0x4f,0x30,0xef,0xe9,0x4f,0xc9,0xcb,0x93,0x16,0x9b,0x0d,0x20,0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,
	0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,
	0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,0x13,0x01,0x00,0x00,0x2e,0x00,0x33,0x00,0x24,0x00,0x1d,0x00,
	0x20,0x9f,0xd7,0xad,0x6d,0xcf,0xf4,0x29,0x8d,0xd3,0xf9,0x6d,0x5b,0x1b,0x2a,0xf9,0x10,0xa0,0x53,
	0x5b,0x14,0x88,0xd7,0xf8,0xfa,0xbb,0x34,0x9a,0x98,0x28,0x80,0xb6,0x15,0x00,0x2b,0x00,0x02,0x03,
	0x04 };
unsigned char shared_secret_13[]{
  0xdf,0x4a,0x29,0x1b,0xaa,0x1e,0xb7,0xcf,0xa6,0x93,0x4b,0x29,0xb4,0x74,0xba,0xad,0x26,0x97,0xe2,0x9f,0x1f,0x92,0x0d,0xcc,0x77,0xc8,0xa0,0xa0,0x88,0x44,0x76,0x24
};
unsigned char old_server_random_test[] = { 0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f };
unsigned char client_hello_hash[] = { 0xda,0x75,0xce,0x11,0x39,0xac,0x80,0xda,0xe4,0x04,0x4d,0xa9,0x32,0x35,0x0c,0xf6,0x5c,0x97,0xcc,0xc9,0xe3,0x3f,0x1e,0x6f,0x7d,0x2d,0x4b,0x18,0xb7,0x36,0xff,0xd5 };
unsigned char full_hash[] = { 0x22,0x84,0x4b,0x93,0x0e,0x5e,0x0a,0x59,0xa0,0x9d,0x5a,0xc3,0x5f,0xc0,0x32,0xfc,0x91,0x16,0x3b,0x19,0x38,0x74,0xa2,0x65,0x23,0x6e,0x56,0x80,0x77,0x37,0x8d,0x8b };
unsigned char handshake_hash_test[] = { 0x5b,0xf3,0x94,0x0a,0xaa,0xb7,0x79,0xa7,0xa4,0x21,0x58,0x16,0xbe,0x65,0xd0,0xa6,0x58,0x15,0xbb,0xcd,0x6f,0x6a,0xc4,0x68,0x50,0x3f,0x95,0xed,0x7a,0x0d,0xe7,0xc1 };
*/

/*
void set_old_rand(SInitCertVerifyRequest *req) {
	req->old_rand = (unsigned char *)old_server_rand;
}

void set_raw_hanshake(SInitCertVerifyRequest *req) {
	req->handshake->handshake_binary = (unsigned char *)handshake_raw_data;
	req->handshake->size = till_now;
}*/