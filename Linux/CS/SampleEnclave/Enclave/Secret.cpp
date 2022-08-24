#include "Secret.h"

#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>

#include <string>
#include "LURK_header.h"
#include "Freshness.h"

#define IVLEN 12
#define KEYLEN 16

#define TLS13_MAX_LABEL_LEN 249
static const unsigned char default_zeros[EVP_MAX_MD_SIZE] = {0x0};

#ifdef CHARSET_EBCDIC
static const unsigned char client_early_traffic[] = {0x63, 0x20, 0x65, 0x20, /*traffic*/ 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
static const unsigned char client_handshake_traffic[] = {0x63, 0x20, 0x68, 0x73, 0x20, /*traffic*/ 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
static const unsigned char client_application_traffic[] = {0x63, 0x20, 0x61, 0x70, 0x20, /*traffic*/ 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
static const unsigned char server_handshake_traffic[] = {0x73, 0x20, 0x68, 0x73, 0x20, /*traffic*/ 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
static const unsigned char server_application_traffic[] = {0x73, 0x20, 0x61, 0x70, 0x20, /*traffic*/ 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
static const unsigned char exporter_master_secret[] = {0x65, 0x78, 0x70, 0x20, /* master*/ 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00};
static const unsigned char resumption_master_secret[] = {0x72, 0x65, 0x73, 0x20, /* master*/ 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00};
static const unsigned char early_exporter_master_secret[] = {0x65, 0x20, 0x65, 0x78, 0x70, 0x20, /* master*/ 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00};
#else
static const unsigned char client_early_traffic[] = "c e traffic";
static const unsigned char client_handshake_traffic[] = "c hs traffic";
static const unsigned char client_application_traffic[] = "c ap traffic";
static const unsigned char server_handshake_traffic[] = "s hs traffic";
static const unsigned char server_application_traffic[] = "s ap traffic";
static const unsigned char exporter_master_secret[] = "exp master";
static const unsigned char resumption_master_secret[] = "res master";
static const unsigned char early_exporter_master_secret[] = "e exp master";
#endif

/*
* This is not from OpenSSL as I cannot find any thing for WPACKET
* Therefore, I am Mimicking function that are needed for WPACKET
* Performace:
* probably has bad performance!
*/
void generate_hkdflabel(unsigned char *kdflabel, size_t &hkdflabellen,
						const unsigned char *label_prefix, const unsigned char *label, size_t datalen,
						const unsigned char *hash, size_t outlen)
{
	/*
	* 2 bytes for length of derived secret
	* Mimicking WPACKET_put_bytes_u16(&pkt, outlen)
	*/
	int till_now = 0;

	kdflabel[0] = 0;
	kdflabel[1] = (unsigned char)outlen;
	/*
	* 1 byte for length of combined prefix and label
	* Mimicking WPACKET_close(&pkt)
	*/
	size_t label_prefix_len = strlen((const char *)label_prefix);
	size_t label_len = strlen((const char *)label);
	kdflabel[2] = (unsigned char)(label_prefix_len + label_len);
	/* 
	* bytes for the label itself 
	* Mimicking WPACKET_memcpy(&pkt, label_prefix, sizeof(label_prefix) - 1)
	*/
	till_now = 3;
	for (size_t i = 0; i < label_prefix_len; i++)
	{
		kdflabel[till_now + i] = label_prefix[i];
	}
	/* 
	* bytes for the label itself 
	* Mimicking WPACKET_memcpy(&pkt, label, labellen)
	*/
	till_now = 3 + (int)label_prefix_len;
	for (size_t i = 0; i < label_len; i++)
	{
		kdflabel[till_now + i] = label[i];
	}
	till_now = till_now + (int)label_len;
	/*
	* 1 byte length of hash
	* WPACKET_sub_memcpy_u8(&pkt, data, (data == NULL) ? 0 : datalen)
	*/
	kdflabel[till_now] = (unsigned char)datalen;
	till_now++;

	for (int i = 0; i < (int)datalen; i++)
	{
		kdflabel[till_now + i] = hash[i];
	}

	/*
	* WPACKET_get_total_written(&pkt, &hkdflabellen)
	*/
	hkdflabellen = till_now + datalen;
}

/*
 * Given a |secret|; a |label| of length |labellen|; and |data| of length
 * |datalen| (e.g. typically a hash of the handshake messages), derive a new
 * secret |outlen| bytes long and store it in the location pointed to be |out|.
 * The |data| value may be zero length. Any errors will be treated as fatal if
 * |fatal| is set. Returns 1 on success  0 on failure.
 */
int tls13_hkdf_expand(const EVP_MD *md, const unsigned char *secret,
					  const unsigned char *label, size_t labellen,
					  const unsigned char *data, size_t datalen,
					  unsigned char *out, size_t outlen)
{
#ifdef CHARSET_EBCDIC
	static const unsigned char label_prefix[] = {0x74, 0x6C, 0x73, 0x31, 0x33, 0x20, 0x00};
#else
	static const unsigned char label_prefix[] = "tls13 ";
#endif
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	int ret;
	size_t hkdflabellen;
	int hashlen;
	/*
	 * 2 bytes for length of derived secret + 1 byte for length of combined
	 * prefix and label + bytes for the label itself + 1 byte length of hash
	 * + bytes for the hash itself
	 */
	unsigned char hkdflabel[sizeof(uint16_t) + sizeof(uint8_t) + (sizeof(label_prefix) - 1) + TLS13_MAX_LABEL_LEN + 1 + EVP_MAX_MD_SIZE];
	hashlen = EVP_MD_size(md);

	if (pctx == NULL)
		return 0;

	if (labellen > TLS13_MAX_LABEL_LEN)
	{
		EVP_PKEY_CTX_free(pctx);
		return 0;
	}
	// Mimicking function that are needed for WPACKET
	generate_hkdflabel(hkdflabel, hkdflabellen, label_prefix, label, datalen, data, outlen);

	ret = EVP_PKEY_derive_init(pctx) <= 0 || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0 || EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, hashlen) <= 0 || EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdflabel, hkdflabellen) <= 0 || EVP_PKEY_derive(pctx, out, &outlen) <= 0;

	EVP_PKEY_CTX_free(pctx);

	if (ret != 0)
	{
		return 0;
	}

	return ret == 0;
}

/*
 * Given a |secret| generate a |key| of length |keylen| bytes. Returns 1 on
 * success  0 on failure.
 */
int tls13_derive_key(const EVP_MD *md, const unsigned char *secret,
					 unsigned char *key, size_t keylen)
{
#ifdef CHARSET_EBCDIC
	static const unsigned char keylabel[] = {0x6B, 0x65, 0x79, 0x00};
#else
	static const unsigned char keylabel[] = "key";
#endif

	return tls13_hkdf_expand(md, secret, keylabel, sizeof(keylabel) - 1,
							 NULL, 0, key, keylen);
	return 0;
}

/*
 * Given a |secret| generate an |iv| of length |ivlen| bytes. Returns 1 on
 * success  0 on failure.
 */
int tls13_derive_iv(const EVP_MD *md, const unsigned char *secret,
					unsigned char *iv, size_t ivlen)
{
#ifdef CHARSET_EBCDIC
	static const unsigned char ivlabel[] = {0x69, 0x76, 0x00};
#else
	static const unsigned char ivlabel[] = "iv";
#endif

	return tls13_hkdf_expand(md, secret, ivlabel, sizeof(ivlabel) - 1,
							 NULL, 0, iv, ivlen);
	return 0;
}

int tls13_derive_finishedkey(const EVP_MD *md,
							 const unsigned char *secret,
							 unsigned char *fin, size_t finlen)
{
#ifdef CHARSET_EBCDIC
	static const unsigned char finishedlabel[] = {0x66, 0x69, 0x6E, 0x69, 0x73, 0x68, 0x65, 0x64, 0x00};
#else
	static const unsigned char finishedlabel[] = "finished";
#endif

	return tls13_hkdf_expand(md, secret, finishedlabel,
							 sizeof(finishedlabel) - 1, NULL, 0, fin, finlen);
	return 0;
}

/*
 * Given the previous secret |prevsecret| and a new input secret |insecret| of
 * length |insecretlen|, generate a new secret and store it in the location
 * pointed to by |outsecret|. Returns 1 on success  0 on failure.
 */
int tls13_generate_secret(const EVP_MD *md,
						  const unsigned char *prevsecret,
						  const unsigned char *insecret,
						  size_t insecretlen,
						  unsigned char *outsecret)
{
	size_t mdlen, prevsecretlen;
	int mdleni;
	int ret;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
#ifdef CHARSET_EBCDIC
	static const char derived_secret_label[] = {0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64, 0x00};
#else
	static const char derived_secret_label[] = "derived";
#endif
	unsigned char preextractsec[EVP_MAX_MD_SIZE];
	// it was originally SSLfatal //changed
	if (pctx == NULL)
	{
		return 0;
	}
	if (md == NULL)
	{
		return 0;
	}
	mdleni = EVP_MD_size(md);
	/* Ensure cast to size_t is safe */ //not sure //changed
	if (!(mdleni >= 0))
	{
		return 0;
	}
	mdlen = (size_t)mdleni;

	if (insecret == NULL)
	{
		insecret = default_zeros;
		insecretlen = mdlen;
	}
	if (prevsecret == NULL)
	{
		prevsecret = default_zeros;
		prevsecretlen = 0;
	}
	else
	{
		EVP_MD_CTX *mctx = EVP_MD_CTX_new();
		unsigned char hash[EVP_MAX_MD_SIZE];

		/* The pre-extract derive step uses a hash of no messages */
		if (mctx == NULL || EVP_DigestInit_ex(mctx, md, NULL) <= 0 || EVP_DigestFinal_ex(mctx, hash, NULL) <= 0)
		{
			//changed
			EVP_MD_CTX_free(mctx);
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}
		EVP_MD_CTX_free(mctx);

		/* Generate the pre-extract secret */
		if (!tls13_hkdf_expand(md, prevsecret,
							   (const unsigned char *)derived_secret_label,
							   sizeof(derived_secret_label) - 1, hash, mdlen,
							   preextractsec, mdlen))
		{
			/* SSLfatal() already called */
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}

		prevsecret = preextractsec;
		prevsecretlen = mdlen;
	}

	ret = EVP_PKEY_derive_init(pctx) <= 0 || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0 || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0 || EVP_PKEY_CTX_set1_hkdf_key(pctx, insecret, (int)insecretlen) <= 0 || EVP_PKEY_CTX_set1_hkdf_salt(pctx, prevsecret, prevsecretlen) <= 0 || EVP_PKEY_derive(pctx, outsecret, &mdlen) <= 0;

	if (ret != 0)
	{
		return 0;
	}
	EVP_PKEY_CTX_free(pctx);
	if (prevsecret == preextractsec)
		OPENSSL_cleanse(preextractsec, mdlen);

	return ret == 0;
}

/*
 * Given an input secret |insecret| of length |insecretlen| generate the
 * handshake secret. This requires the early secret to already have been
 * generated. Returns 1 on success  0 on failure.
 */
int tls13_generate_handshake_secret(const EVP_MD *md,
									const unsigned char *prevsecret, const unsigned char *insecret,
									size_t insecretlen, unsigned char *outsecret)
{
	/* Calls SSLfatal() if required */
	return tls13_generate_secret(md, prevsecret,
								 insecret, insecretlen,
								 outsecret);
}

/*
 * Given the handshake secret |prev| of length |prevlen| generate the master
 * secret and store its length in |*secret_size|. Returns 1 on success  0 on 
 * failure.
 */
int tls13_generate_master_secret(const EVP_MD *md, unsigned char *out,
								 unsigned char *prev, size_t *secret_size)
{

	*secret_size = EVP_MD_size(md);
	/* Calls SSLfatal() if required */
	return tls13_generate_secret(md, prev, NULL, 0, out);
}

const EVP_MD *LURK_handshake_lookup_md2(int md_index)
{

	if (md_index == 0x04)
	{
		return EVP_sha256();
	}
	else if (md_index == 0x05)
	{
		return EVP_sha384();
	}
	else
	{
		return NULL;
	}
	return NULL;
}

//size of gensecret,derived_key,derived_iv is EVP_MAX_MD_SIZE,KEYLEN,IVLEN
static int test_secret(unsigned char *prk,
					   const unsigned char *label, size_t labellen,
					   unsigned char *gensecret, const EVP_MD *md,
					   unsigned char *hash, size_t hashsize)
{
	//unsigned char *derived_key, unsigned char *derived_iv, they were originally input but we dont need them
	//unsigned char key[KEYLEN];
	//unsigned char iv[IVLEN];
	if (md == NULL)
	{
		return 0;
	}

	if (!tls13_hkdf_expand(md, prk, label, labellen, hash, hashsize,
						   gensecret, hashsize))
	{

		return 0;
	}
	/*
	if (!tls13_derive_key(md, gensecret, derived_key, KEYLEN)) {
		return 0;
	}
	if (!tls13_derive_iv(md, gensecret, derived_iv, IVLEN)) {
		return 0;
	}*/
	return 1;
}

/*
 * Generates the mac for the Finished message. Returns the length of the MAC or
 * 0 on error.
 */
size_t tls13_final_finish_mac(const EVP_MD *md, unsigned char *hash, size_t hashlen,
							  unsigned char *server_finished_secret, unsigned char *out)
{
	//const EVP_MD *md = ssl_handshake_md(s);
	//unsigned char hash[EVP_MAX_MD_SIZE];
	size_t ret = 0;
	EVP_PKEY *key = NULL;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (hash == NULL)
	{
		return 0;
	}

	//if (!ssl_handshake_hash(s, hash, sizeof(hash), &hashlen)) {
	/* SSLfatal() already called */
	//goto err;
	//}

	key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, server_finished_secret, hashlen);

	if (key == NULL || ctx == NULL || EVP_DigestSignInit(ctx, NULL, md, NULL, key) <= 0 || EVP_DigestSignUpdate(ctx, hash, hashlen) <= 0 || EVP_DigestSignFinal(ctx, out, &hashlen) <= 0)
	{
		goto err;
	}

	ret = hashlen;
err:
	EVP_PKEY_free(key);
	EVP_MD_CTX_free(ctx);
	return ret;
}

/*
this function can be improve in performance
1- not all the sequences need to preform for all the key_req.
2- if we do not need drive key and and dirve iv remove them from test_secret.
*/
// TODO free the heap allocted memories!
int test_handshake_secrets(uint16_t key_req, Secret *secret_list, unsigned char *ecdhe_secret, confidential_secrets &conf_secrets,
						   unsigned char *hashed_handshake_till_now, int size_of_ecdhe_secret, int md_index,
						   int operation_mode, int &handshake_hash_size)
{
	int ret = 0;
	const EVP_MD *md = LURK_handshake_lookup_md2(md_index);
	int secret_len = EVP_MD_size(md);
	size_t hashsize = (size_t)secret_len;
	handshake_hash_size = secret_len;

	//unsigned char * early_secret = (unsigned char *)malloc(secret_len * sizeof(char));
	//unsigned char * Handshake_secret = (unsigned char *)malloc(secret_len * sizeof(char));
	//unsigned char * fin = (unsigned char *)malloc(secret_len * sizeof(char));
	unsigned char early_secret[EVP_MAX_MD_SIZE] = {0};
	unsigned char Handshake_secret[EVP_MAX_MD_SIZE] = {0};
	unsigned char fin[EVP_MAX_MD_SIZE] = {0};
	unsigned char C_hts_gensecret[EVP_MAX_MD_SIZE] = {0};
	unsigned char S_hts_gensecret[EVP_MAX_MD_SIZE] = {0};
	unsigned char C_ats_gensecret[EVP_MAX_MD_SIZE] = {0};
	unsigned char S_ats_gensecret[EVP_MAX_MD_SIZE] = {0};
	unsigned char exporter_gensecret[EVP_MAX_MD_SIZE] = {0};
	unsigned char resumtion_gensecret[EVP_MAX_MD_SIZE] = {0};
	unsigned char out_master_secret[EVP_MAX_MD_SIZE] = {0};
	unsigned char verify_data[EVP_MAX_MD_SIZE] = {0};
	size_t master_secret_length;

	//int secret_list_index_c_hs_sec = 0;
	//int secret_list_index_s_hs_sec = 1;
	//int secret_list_index_c_ap_sec = 2;
	//int secret_list_index_s_ap_sec = 3;
	//binder key 5
	int secret_list_index_master_sec = 8;
	// handshake 10
	//early 9

	// If the early and handshake secrets were generated before
	if (key_req == 4 && (operation_mode == OPRATION_MODE_1_EARLY_2_HS_SIG_AP ||
						 operation_mode == OPRATION_MODE_1_EARLY_2_HS_SIG_AP_3_RESUMPTION ||
						 operation_mode == OPRATION_MODE_1_EARLY_2_HS_3_SIG_AP_4_RESUMPTION))
	{
		memcpy(early_secret, conf_secrets.early_secret, secret_len);
		memcpy(Handshake_secret, (secret_list + SECRET_LIST_INDEX_HANDSHAKE_SEC)->secret_data, secret_len);
	}
	if (key_req == 5 || key_req == 6 || key_req == 7)
	{
		//early_secret = (secret_list + SECRET_LIST_INDEX_EARLY_SEC)->secret_data;
		//Handshake_secret = (secret_list + SECRET_LIST_INDEX_HANDSHAKE_SEC)->secret_data;
		memcpy(early_secret, conf_secrets.early_secret, secret_len);
		memcpy(Handshake_secret, (secret_list + SECRET_LIST_INDEX_HANDSHAKE_SEC)->secret_data, secret_len);
	}
	else if (key_req == 8)
	{
		//early_secret = (secret_list + SECRET_LIST_INDEX_EARLY_SEC)->secret_data;
		//Handshake_secret = (secret_list + SECRET_LIST_INDEX_HANDSHAKE_SEC)->secret_data;
		memcpy(early_secret, conf_secrets.early_secret, secret_len);
		memcpy(Handshake_secret, (secret_list + SECRET_LIST_INDEX_HANDSHAKE_SEC)->secret_data, secret_len);
		memcpy(out_master_secret, (secret_list + secret_list_index_master_sec)->secret_data, secret_len);
	}
	else if (key_req > 16)
	{
		return -1;
	}

	if ((key_req == 9 || key_req == 10) && (operation_mode == OPRATION_MODE_1_EARLY_2_HS_SIG_AP ||
											operation_mode == OPRATION_MODE_1_EARLY_2_HS_SIG_AP_3_RESUMPTION ||
											operation_mode == OPRATION_MODE_1_EARLY_2_HS_3_SIG_AP_4_RESUMPTION))
	{
		//<<1>> Early secret
		if (conf_secrets.early_secret == NULL)
		{
			if (!(tls13_generate_secret(md, NULL, NULL, 0, early_secret)))
			{
				goto err;
			}
		}
		else
		{
			memcpy(early_secret, conf_secrets.early_secret, secret_len);
		}

		//<<2>> first secret is = early_secret and new secret is Handshake_secret
		if (!(tls13_generate_handshake_secret(md, early_secret, ecdhe_secret, size_of_ecdhe_secret, Handshake_secret)))
		{
			goto err;
		}
		if (conf_secrets.early_secret == NULL)
		{
			conf_secrets.early_secret = (unsigned char *)malloc(secret_len * sizeof(char));
			if (conf_secrets.early_secret == NULL)
			{
				goto err;
			}
		}
		conf_secrets.early_secret_len = secret_len;
		memcpy(conf_secrets.early_secret, early_secret, secret_len);
		(secret_list + SECRET_LIST_INDEX_HANDSHAKE_SEC)->secret_type = LURK_handshake_secret;
		memcpy((secret_list + SECRET_LIST_INDEX_HANDSHAKE_SEC)->secret_data, Handshake_secret, secret_len);
		return 1;
	}
	if (key_req == 4)
	{
		if (operation_mode != OPRATION_MODE_1_EARLY_2_HS_SIG_AP &&
			operation_mode != OPRATION_MODE_1_EARLY_2_HS_SIG_AP_3_RESUMPTION &&
			operation_mode != OPRATION_MODE_1_EARLY_2_HS_3_SIG_AP_4_RESUMPTION)
		{
			//<<1>> Early secret
			if (conf_secrets.early_secret == NULL)
			{
				if (!(tls13_generate_secret(md, NULL, NULL, 0, early_secret)))
				{
					goto err;
				}
			}
			else
			{
				memcpy(early_secret, conf_secrets.early_secret, secret_len);
			}

			//<<2>> first secret is = early_secret and new secret is Handshake_secret
			if (!(tls13_generate_handshake_secret(md, early_secret, ecdhe_secret, size_of_ecdhe_secret, Handshake_secret)))
			{
				goto err;
			}
			if (conf_secrets.early_secret == NULL)
			{
				conf_secrets.early_secret = (unsigned char *)malloc(secret_len * sizeof(char));
				if (conf_secrets.early_secret == NULL)
				{
					goto err;
				}
			}
			conf_secrets.early_secret_len = secret_len;
			memcpy(conf_secrets.early_secret, early_secret, secret_len);
			(secret_list + SECRET_LIST_INDEX_HANDSHAKE_SEC)->secret_type = LURK_handshake_secret;
			memcpy((secret_list + SECRET_LIST_INDEX_HANDSHAKE_SEC)->secret_data, Handshake_secret, secret_len);
		}
		//<<3>> client_handshake_traffic_secret
		if (!(test_secret(Handshake_secret, client_handshake_traffic,
						  strlen((const char *)client_handshake_traffic), C_hts_gensecret, md, hashed_handshake_till_now, hashsize)))
		{
			goto err;
		}
		secret_list->secret_type = L_client_handshake_traffic_secret;
		memcpy(secret_list->secret_data, C_hts_gensecret, secret_len);

		//<<4>> server_handshake_traffic_secret
		if (!(test_secret(Handshake_secret, server_handshake_traffic,
						  strlen((const char *)server_handshake_traffic), S_hts_gensecret, md, hashed_handshake_till_now, hashsize)))
		{
			goto err;
		}
		(secret_list + SECRET_LIST_INDEX_SERVER_HS_SEC)->secret_type = L_server_handshake_traffic_secret;
		memcpy((secret_list + SECRET_LIST_INDEX_SERVER_HS_SEC)->secret_data, S_hts_gensecret, secret_len);
		//TODO maybe it is better to copy this from openssl
		if (tls13_derive_finishedkey(md, (secret_list + SECRET_LIST_INDEX_SERVER_HS_SEC)->secret_data, fin, hashsize) == 0)
		{
			goto err;
		}
		(secret_list + 7)->secret_type = LURK_finish_key;
		memcpy((secret_list + 7)->secret_data, fin, secret_len);
		return 1;
	}

	if (key_req == 6 || key_req == 5 || key_req == 7)
	{

		//<<5 >>
		//Master secret
		if (!(tls13_generate_master_secret(md, out_master_secret,
										   Handshake_secret, &master_secret_length)))
		{
			goto err;
		}

		(secret_list + 8)->secret_type = LURK_master_secret;
		memcpy((secret_list + 8)->secret_data, out_master_secret, master_secret_length);
		//<<6>>client_application_traffic_secret_0
		if (!(test_secret(out_master_secret, client_application_traffic,
						  strlen((const char *)client_application_traffic), C_ats_gensecret, md, hashed_handshake_till_now, hashsize)))
		{
			goto err;
		}
		(secret_list + SECRET_LIST_INDEX_CLIENT_AP_SEC)->secret_type = L_client_application_traffic_secret_0;
		memcpy((secret_list + SECRET_LIST_INDEX_CLIENT_AP_SEC)->secret_data, C_ats_gensecret, secret_len);

		//<<7>> server_application_traffic_secret_0
		if (!(test_secret(out_master_secret, server_application_traffic,
						  strlen((const char *)server_application_traffic), S_ats_gensecret, md, hashed_handshake_till_now, hashsize)))
		{
			goto err;
		}
		(secret_list + SECRET_LIST_INDEX_SERVER_AP_SEC)->secret_type = L_server_application_traffic_secret_0;
		memcpy((secret_list + SECRET_LIST_INDEX_SERVER_AP_SEC)->secret_data, S_ats_gensecret, secret_len);

		//<<8>> exporter_master_secret
		if (!(test_secret(out_master_secret, exporter_master_secret,
						  strlen((const char *)exporter_master_secret), exporter_gensecret, md, hashed_handshake_till_now, hashsize)))
		{
			goto err;
		}
		(secret_list + 4)->secret_type = L_exporter_master_secret;
		memcpy((secret_list + 4)->secret_data, exporter_gensecret, secret_len);

		return 1;
	}
	if (key_req == 8 && (operation_mode == OPRATION_MODE_1_EARLY_2_HS_SIG_AP_3_RESUMPTION ||
						 operation_mode == OPRATION_MODE_1_EARLY_2_HS_3_SIG_AP_4_RESUMPTION ||
						 operation_mode == OPRATION_MODE_1_EARLY_HS_SIG_AP_2_RESUMPTION ||
						 operation_mode == OPRATION_MODE_1_EARLY_HS_2_SIG_AP_3_RESUMPTION))
	{
		//<<9>> resumtion secret
		if (!(test_secret(out_master_secret, resumption_master_secret,
						  strlen((const char *)resumption_master_secret), resumtion_gensecret, md, hashed_handshake_till_now, hashsize)))
		{
			goto err;
		}
		conf_secrets.resumption_master_secret = (unsigned char *)malloc(secret_len * sizeof(char));
		if (conf_secrets.resumption_master_secret == NULL)
		{
			goto err;
		}
		//(secret_list + 5)->secret_type = L_resumption_master_secret;
		memcpy(conf_secrets.resumption_master_secret, resumtion_gensecret, secret_len);
		conf_secrets.resumption_master_secret_len = secret_len;
	}

	if (key_req == 12)
	{

		size_t verify_data_size;
		verify_data_size = tls13_final_finish_mac(md, hashed_handshake_till_now, hashsize, (secret_list + 7)->secret_data, verify_data);
		if (verify_data_size == 0)
		{
			goto err;
		}
		(secret_list + 6)->secret_type = LURK_finish_verify_data;
		memcpy((secret_list + 6)->secret_data, verify_data, secret_len);

		return 1;
	}

	ret = 1;
err:
	return ret;
}

/*
void sha256_hash_string2(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
	constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
						   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	int i = 0;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		outputBuffer[2 * i] = hexmap[(hash[i] & 0xF0) >> 4];
		outputBuffer[2 * i + 1] = hexmap[hash[i] & 0x0F];
	}

	outputBuffer[64] = 0;
}

*/