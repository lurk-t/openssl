//#ifndef  MY_HEADER_H
//#define MY_HEADER_H
/*
* The things that need to be change have been marked with "//TODO "
* The things that I am not sure about have been marked with "//DDDDD"
* The things that are different with LURK specification due to the OpenSSL implementation have been marked with "OpenSSL DIFF"
*/
#pragma once 
#include <stdio.h>
#include <stdint.h> //for uint*_t

/*
* These options are for the opration mode that 
* CS can have and the mode changes the number of
* context switch between REE and TEE (openssl and CS)
*/
#define OPRATION_MODE_1_EARLY_HS_SIG_AP 1
#define OPRATION_MODE_1_EARLY_2_HS_SIG_AP 2
#define OPRATION_MODE_1_EARLY_2_HS_SIG_AP_3_RESUMPTION 3
#define OPRATION_MODE_1_EARLY_2_HS_3_SIG_AP_4_RESUMPTION 4
#define OPRATION_MODE_1_EARLY_HS_2_SIG_AP 5


/*
* Checking the freshness: 
* CS always perform the freshness however depending on the mode
* we sometimes predict the hash and there is no need for freshness
* since the data hash been checked with freshness in the begining
* and has not left the CS since then.
*/
#define NOT_CHECKING_FRESHNESS 0
#define CHECKING_FRESHNESS 1




typedef unsigned char opaque;

enum SecretType // we only need 3,4,5,6 
{
	L_binder_key = 0,
	L_client_early_traffic_secret = 1,
	L_early_exporter_master_secret = 2,
	L_client_handshake_traffic_secret = 3,
	L_server_handshake_traffic_secret = 4,
	L_client_application_traffic_secret_0 = 5,
	L_server_application_traffic_secret_0 = 6,
	L_exporter_master_secret = 7,
	L_resumption_master_secret = 8,
	LURK_early_secret = 9,
	LURK_handshake_secret = 10,
	LURK_master_secret = 11,
	LURK_finish_key = 12,
	LURK_finish_verify_data = 13,
	uninitialized_SecretType = 15
};

//OPENSSL DIFF
// 0x40 is for campatibility with OpenSSL
 struct Secret {
	enum SecretType secret_type;
	opaque secret_data[0x40];
};

//RFC8446 section 4.2.3
 enum SignatureScheme {
	/* RSASSA-PKCS1-v1_5 algorithms */ 
	/* NOT implemented (all 3) */ 
	rsa_pkcs1_sha256 = 0x0401, 
	rsa_pkcs1_sha384 = 0x0501,
	rsa_pkcs1_sha512 = 0x0601,

	/* ECDSA algorithms */ 
	/* implemented (all 3) */ 
	ecdsa_secp256r1_sha256 = 0x0403, 
	ecdsa_secp384r1_sha384 = 0x0503,
	ecdsa_secp521r1_sha512 = 0x0603,

	/* RSASSA-PSS algorithms with public key OID rsaEncryption */
	/* implemented (all 3) */ 
	rsa_pss_rsae_sha256 = 0x0804,
	rsa_pss_rsae_sha384 = 0x0805,
	rsa_pss_rsae_sha512 = 0x0806,

	/* EdDSA algorithms */
	/* implemented (both) */ 
	ed25519 = 0x0807, 
	ed448 = 0x0808,

	/* RSASSA-PSS algorithms with public key OID RSASSA-PSS */ 
	/* NOT implemented (all 3) */
	rsa_pss_pss_sha256 = 0x0809,
	rsa_pss_pss_sha384 = 0x080a,
	rsa_pss_pss_sha512 = 0x080b,

	/* Legacy algorithms */
	/* NOT implemented (both) */
	rsa_pkcs1_sha1 = 0x0201,
	ecdsa_sha1 = 0x0203,// what is the curve name ?

	/* I defined it*/
	uninitialized_SignatureScheme = 0xaaaa
	/* Reserved Code Points */
	//private_use(0xFE00..0xFFFF), 
};
//end of RFC8446 section 4.2.3


struct Handshake {
	opaque handshake_binary[3000];
	uint32_t openssl_till_now;
	int till_now;
};


//TODO 
enum LURKTLS13CertificateType {
	empty = 0,
	finger_print = 1,
	uncompressed = 2,
	compressed = 3
}; 

//TODO
//they have to be change to the appropiriate structs in the future 
typedef unsigned char Certificate;
typedef unsigned char CompressedCertificate;


 struct LURKTLS13Certificate {
	enum LURKTLS13CertificateType certificate_type;
	//select (certificate_type) {
	char *empty;// = NULL; // case: no payload
	uint32_t *finger_print;// = NULL; //case: finger_print= hash_cert
	Certificate *uncompressed_certificate;// = NULL; //case : uncompressedRFC8446 section 4.4.2
	CompressedCertificate *compressed_certificate;// = NULL; //case compressed: draft-ietf-tls-certificate-compression section 4.
};

 enum Internal_tls13_message_type { encrypted_extensions= 0x8, finished = 0x14, certificate=0xb, certificate_verify = 0x0f };
 enum EphemeralMethod { no_secret = 0, secret_provided = 1, secret_generated = 2, uninitialized_method = 3 };
//OPENSSL DIFF x409 = x25519
 enum NamedGroup { secp256r1 = 0x0017, secp384r1 = 0x0018, secp521r1 = 0x0019, x25519 = 0x001D, x448 = 0x001E, uninitialized = 0 };

 enum Freshness { sha256 = 0 };

 struct KeyShareEntry {
	enum NamedGroup group;// = uninitialized;
	opaque *key_exchange;// = NULL; //<1..2^16-1>
	size_t key_len;
};

 struct SharedSecret {
	enum NamedGroup group;// = uninitialized;

	/*Where coordinate_length depends on the chosen group.  For secp256r1,
	secp384r1, secp521r1, x25519, x448, the coordinate_length is
	respectively 32 bytes, 48 bytes, 66 bytes, 32 bytes and 56 bytes.*/
	opaque shared_secret[66];
	//OPENSSL DIFF
	int shared_secret_len;
};
 struct EphemeralRequest {
	enum EphemeralMethod method;// = uninitialized_mthod;;
	//select(method) 
	//case secret_provided:
	struct SharedSecret *shared_secret;// = NULL; 
};

 struct EphemeralResponse {
	enum EphemeralMethod method;// d = uninitialized_mthod;
	//select(method) {
	//case secret_generated: 
	// note that CS need to change the handshake binary as well to generate the signature based on right handshake with updated public key
	struct KeyShareEntry *server_share;// = NULL; // this is the public key that we generated and now we would return it for TLS server.
};

//RFC8446 section 4.4.3.
 struct Signature {
	enum SignatureScheme algorithm;// = uninitialized_SignatureScheme;
	opaque *signature;// = NULL;// <0..2 ^ 16 - 1>;
	size_t signature_size;
};
//end of RFC8446 section 4.4.3.
 struct SInitCertVerifyRequest {
	uint8_t tag; // what is this message, // if tag is 0 it means that its last exchange
	uint32_t session_id; // this is used for messages for one context, so we know they are related to each other
	   /*select tag.last_exchange){
		 case False:
		   uint32 session_id;
	   }*/
	enum Freshness freshness;
	struct EphemeralRequest *ephemeral; //ECDH info with 2 cases secret provided or if they want us to generate it
	struct Handshake *handshake; //RFC8446 section 4 
	struct LURKTLS13Certificate *certificate;
	uint16_t secret_request;
	enum SignatureScheme sig_algo; //RFC8446 section 4.2.3.
	// OPENSSL DIFF
	uint8_t changed;
	opaque old_rand[0x20];
	opaque handshake_hash[0x40];
	int handshake_hash_size;
	int signature_size;
	//int things_that_we_have[10];
	int operation_mode;
	int md_index;
};

//OPENSSL DIFF 4 is for Figure 2: secret_request structure
 struct SInitCertVerifyResponse {
	uint8_t tag;
	uint32_t session_id;
	/* DDDDD
	select tag.last_exchange){
	  case False:
		uint32 session_id;
	}*/
	struct EphemeralResponse *ephemeral;
	struct Signature *signature;
	struct Secret secret_list[11];
};

//#endif // ! MY_HEADER_h
