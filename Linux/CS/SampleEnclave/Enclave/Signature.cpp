#include "Signature.h"

#include <stdio.h>      /* vsnprintf */
#include "Enclave_t.h"  /* print_string */
#include <string>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h> 


//std::string
const char *privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAxIA2BrrnR2sIlATsp7aRBD/3krwZ7vt9dNeoDQAee0s6SuYP\n"\
"6MBx/HPnAkwNvPS90R05a7pwRkoT6Ur4PfPhCVlUe8lV+0Eto3ZSEeHz3HdsqlM3\n"\
"bso67L7Dqrc7MdVstlKcgJi8yeAoGOIL9/igOv0XBFCeznm9nznx6mnsR5cugw+1\n"\
"ypXelaHmBCLV7r5SeVSh57+KhvZGbQ2fFpUaTPegRpJZXBNS8lSeWvtOv9d6N5UB\n"\
"ROTAJodMZT5AfX0jB0QB9IT/0I96H6BSENH08NXOeXApMuLKvnAf361rS7cRAfRL\n"\
"rWZqERMP4u6Cnk0Cnckc3WcW27kGGIbtwbqUIQIDAQABAoIBAGF7OVIdZp8Hejn0\n"\
"N3L8HvT8xtUEe9kS6ioM0lGgvX5s035Uo4/T6LhUx0VcdXRH9eLHnLTUyN4V4cra\n"\
"ZkxVsE3zAvZl60G6E+oDyLMWZOP6Wu4kWlub9597A5atT7BpMIVCdmFVZFLB4SJ3\n"\
"AXkC3nplFAYP+Lh1rJxRIrIn2g+pEeBboWbYA++oDNuMQffDZaokTkJ8Bn1JZYh0\n"\
"xEXKY8Bi2Egd5NMeZa1UFO6y8tUbZfwgVs6Enq5uOgtfayq79vZwyjj1kd29MBUD\n"\
"8g8byV053ZKxbUOiOuUts97eb+fN3DIDRTcT2c+lXt/4C54M1FclJAbtYRK/qwsl\n"\
"pYWKQAECgYEA4ZUbqQnTo1ICvj81ifGrz+H4LKQqe92Hbf/W51D/Umk2kP702W22\n"\
"HP4CvrJRtALThJIG9m2TwUjl/WAuZIBrhSAbIvc3Fcoa2HjdRp+sO5U1ueDq7d/S\n"\
"Z+PxRI8cbLbRpEdIaoR46qr/2uWZ943PHMv9h4VHPYn1w8b94hwD6vkCgYEA3v87\n"\
"mFLzyM9ercnEv9zHMRlMZFQhlcUGQZvfb8BuJYl/WogyT6vRrUuM0QXULNEPlrin\n"\
"mBQTqc1nCYbgkFFsD2VVt1qIyiAJsB9MD1LNV6YuvE7T2KOSadmsA4fa9PUqbr71\n"\
"hf3lTTq+LeR09LebO7WgSGYY+5YKVOEGpYMR1GkCgYEAxPVQmk3HKHEhjgRYdaG5\n"\
"lp9A9ZE8uruYVJWtiHgzBTxx9TV2iST+fd/We7PsHFTfY3+wbpcMDBXfIVRKDVwH\n"\
"BMwchXH9+Ztlxx34bYJaegd0SmA0Hw9ugWEHNgoSEmWpM1s9wir5/ELjc7dGsFtz\n"\
"uzvsl9fpdLSxDYgAAdzeGtkCgYBAzKIgrVox7DBzB8KojhtD5ToRnXD0+H/M6OKQ\n"\
"srZPKhlb0V/tTtxrIx0UUEFLlKSXA6mPw6XDHfDnD86JoV9pSeUSlrhRI+Ysy6tq\n"\
"eIE7CwthpPZiaYXORHZ7wCqcK/HcpJjsCs9rFbrV0yE5S3FMdIbTAvgXg44VBB7O\n"\
"UbwIoQKBgDuY8gSrA5/A747wjjmsdRWK4DMTMEV4eCW1BEP7Tg7Cxd5n3xPJiYhr\n"\
"nhLGN+mMnVIcv2zEMS0/eNZr1j/0BtEdx+3IC6Eq+ONY0anZ4Irt57/5QeKgKn/L\n"\
"JPhfPySIPG4UmwE4gW8t79vfOKxnUu2fDD1ZXUYopan6EckACNH/\n"\
"-----END RSA PRIVATE KEY-----\n\0";

const char RUST_TLS_RSA_PSS[] = "-----BEGIN PRIVATE KEY----- \n"\
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDdwbEc6ZKih4mQ\n"\
"A916JwctBZgnRmzOKERrzlHjfzy8ZfsUJLENQBN8s3RVRwPThReHdp8bpiVRrNmM\n"\
"RxyXoa5oqxWDjXOu5W4hoISIMbOAq4Kj8G+eS0UKwypKHwJ1aUzEjWQGKxNpIYvc\n"\
"GqwYpN1Yi1+qTgLg2qw1ENtBhrWHhmQruGqDtQTQLe2tbcOuGhIL0cyWIRtEWHWL\n"\
"/wb1Akzhm31WQF+mURtYvYonA/Ta7ErONXCxsEXndTR4iT/XognnOhTJ+uIinNwn\n"\
"52y9Te7MYix6SDBEVeKZx9v3iOYU81zXf+WaxNqZvTfbPjkLsXiymOgVfGQcO4hi\n"\
"QeLoJIHXAgMBAAECggEATFl3xWCV3+eScUcjZf8x9UpLzJnutDwg8o0inJUeMC9c\n"\
"dt77Jni9PN38W7ALnTPhmf45YaeeibRdYnLJYVuFVPwyeAynm7vaYzGE7+9MwixK\n"\
"2m7Zv0JjDwWK9eIfUpVinPmhSo5iLHwkTy/PuNxqaSXzVgtt6kTfrZWUJ8ddkL8M\n"\
"bMQTvSLByspyZq/9n6Xq4cy1kummrYgluGKrh6+b+3/ff4wTfF9txlecM+te0uoI\n"\
"nu5jTRGGSouKKiOWLLkQNPCqrSmy/VfQLkacs3l8Y89Fo4TlBU6MEb02u+fCQ/58\n"\
"q1E8Y7J1/Yjv2VTwav9q1EX9/ncA8b2C0K1Ylgh9QQKBgQD2bZwI03z4Zpo1TnxU\n"\
"d4r0qWVExY7fP9BfJPEn3KE4zlPXbiiNazMprdFoIUEtKNcl77ZYVcvNLCUDOWzj\n"\
"maYtVJm7wuUPcJQU2becuw6N7yZJd9mfXPOiBWmv8Df5AJJymdUcXqMySi9eFr1m\n"\
"SwFhrsFRTs8Fo0bGrw8UTMM72QKBgQDmXsHt80+F7YuVUrVMuhTTr/DqwHgqyCQ1\n"\
"zQXuOeGDaFPSYzgk6XEPPJU+Kil+bFIY7DaMokVHWvJJ9e9iF8fjflSnp2pp1BWa\n"\
"t3D+I3zfX+SCioD8KXcFiMfoH9bqIfBzaQfeMNgqMbR0fpsf/l0n/cwJRQ4KGU7s\n"\
"puXqY0aNLwKBgEa2kU3fEj9dgebGDNtYKmGmsk6XujXJ5AtJWIItx327h0eMbsqV\n"\
"9mqBXFPbJw7EZ2iVbufORtsrTbutINf24T6kxjCg7oYNshCBoTSyYKzN8VinsaUP\n"\
"UUIu93LrJcSoK14DUqn/ZikqLIl9UQAnic/0C7k/OhzOC6M73MHgfS2RAoGBAM0O\n"\
"y9DjI4YzTGw+kuMZQDCuC+TqLgzm2lSJix3ip7oww2wipXc11E2bv7z2Crld8jX9\n"\
"DRFh4AkEC2eKYusN//+gE/qoKzDId/KgFxQgwqaS1PTeFLJgtnFWr5sPvF3sl/wj\n"\
"Ib3F/KSSWe7YQ3zXDlTqtRQLQ9P5cydz6HQaqlJBAoGBAL3xNfmStaUFV4moms64\n"\
"fZ755LqQwN5rwjZLxmRTsOgVI/KPEg44xvbcG885eNW+JhYSPUyvkrP6Qb+I8PEN\n"\
"qdMPUgTetOrnA4T9yf7+U/xHghDSb3BEQKyGlrbRO2GB/iGa3xHD963WozDzeAfQ\n"\
"uxrLrUaQjPsf2AEhrHk8slgM\n"\
"-----END PRIVATE KEY-----\n\0";

const char Certificate_RUST_TLS_RSA_PSS[]= "-----BEGIN CERTIFICATE-----\n"\
"MIIEADCCAmigAwIBAgICAcgwDQYJKoZIhvcNAQELBQAwLDEqMCgGA1UEAwwhcG9u\n"\
"eXRvd24gUlNBIGxldmVsIDIgaW50ZXJtZWRpYXRlMB4XDTE5MDYwOTE3MTUxMloX\n"\
"DTI0MTEyOTE3MTUxMlowGTEXMBUGA1UEAwwOdGVzdHNlcnZlci5jb20wggEiMA0G\n"\
"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdwbEc6ZKih4mQA916JwctBZgnRmzO\n"\
"KERrzlHjfzy8ZfsUJLENQBN8s3RVRwPThReHdp8bpiVRrNmMRxyXoa5oqxWDjXOu\n"\
"5W4hoISIMbOAq4Kj8G+eS0UKwypKHwJ1aUzEjWQGKxNpIYvcGqwYpN1Yi1+qTgLg\n"\
"2qw1ENtBhrWHhmQruGqDtQTQLe2tbcOuGhIL0cyWIRtEWHWL/wb1Akzhm31WQF+m\n"\
"URtYvYonA/Ta7ErONXCxsEXndTR4iT/XognnOhTJ+uIinNwn52y9Te7MYix6SDBE\n"\
"VeKZx9v3iOYU81zXf+WaxNqZvTfbPjkLsXiymOgVfGQcO4hiQeLoJIHXAgMBAAGj\n"\
"gb4wgbswDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwHQYDVR0OBBYEFEweXJqS\n"\
"BzVcf/00QeOC29OwBQszMEIGA1UdIwQ7MDmAFEKPy8hHZVazpvIsxFcGo4YrkEkw\n"\
"oR6kHDAaMRgwFgYDVQQDDA9wb255dG93biBSU0EgQ0GCAXswOwYDVR0RBDQwMoIO\n"\
"dGVzdHNlcnZlci5jb22CFXNlY29uZC50ZXN0c2VydmVyLmNvbYIJbG9jYWxob3N0\n"\
"MA0GCSqGSIb3DQEBCwUAA4IBgQCViHp2pLcIMzl/wN+sULznLYZvrlynU4AHnL8/\n"\
"ba6iSAM6EMlrcu11+UBQglHIN2BEn+Jjas+HT1sQOIOixMgjrMBgirLez8n5DN66\n"\
"o5aK5bu23GjQvzq5JEh0skQDHtSFX0YRwqXIhi1spGtObsnoupxJNBQbdAcDv50/\n"\
"m6/8WXcPbXBnR+wRywFmjb6+OSVNgCRtBFTbR5XRVHMPEwvSk4hVj4jimlnPHZYL\n"\
"3VatCPtZr6iaLZl9E64BbS+J4vPQ0Z/2JMUjtXCuj19k8LO2TTTBz54QVoMF5jrZ\n"\
"xotneq+wmPH3lmozEOmyj4+4CmoyNz+RDhrlok84x3g4YEKUQyK1V4ROi9DtL1CV\n"\
"VoLfHSwS9SiDdD/Qn2n7RICn6DP2lHozICyHX0Op4W+vETHho7Flsw21bMisAGrl\n"\
"wwQ7UYU4XfPOC9hQoCvU60uVe7z+uZvlBY8RwmcW4iFIbfCcPT6Hrom5F1X4Z/dm\n"\
"zDW8ZhLDsjUY/D4lUeWjbO1RCHI=\n"\
"-----END CERTIFICATE-----\n\0";

const char RSA_4096[] = "-----BEGIN PRIVATE KEY-----\n"\
"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\n"\
"IgatrfBaK6/Zi0sGIljcWck+X6M3PAAX\n"\
"-----END PRIVATE KEY-----\n\0";

const char RSA_3078[] = "-----BEGIN PRIVATE KEY-----\n"\
"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\n"\
"2gniYQzqDk1vr1AQHFHQ6AWaMpE=\n"\
"-----END PRIVATE KEY-----\n\0";


const char Certificate_RSA_4096[]="-----BEGIN CERTIFICATE-----\n"\
"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\n"\
"-----END CERTIFICATE-----\n\0";



const char *ED25519_privateKey = "-----BEGIN PRIVATE KEY-----\n"\
"MC4CAQAwBQYDK2VwBCIEIO3khWR2Nc+gG4VtqO74qb7tZV81e1P8ad3zKTnu8ZEf\n"\
"-----END PRIVATE KEY-----\n\0";

const char *ED448_privateKey = "-----BEGIN PRIVATE KEY-----\n"\
"MEcCAQAwBQYDK2VxBDsEOW+W696pD6ttCUUMquXG+8ZnynpuoF007rlq3XnXYYZE\n"\
"UBOWkbJ/96IDvk67KCPeXeu292hP+z84HQ==\n"\
"-----END PRIVATE KEY-----\n\0";

const char *secp384r1_privateKey = "-----BEGIN EC PRIVATE KEY-----\n"\
"MIGkAgEBBDC58isLwEQPfc7bNbheOGr5Ln2ol3WxXevSn0c8kCT/eueFl/tDK73I\n"\
"tAY/RPhfyPmgBwYFK4EEACKhZANiAASvkO/kNMRRUxlLOemMt7hPtcDf1fKfxuD2\n"\
"0FYvUzhQgqCY6IC/MbtqRovlN8sJeio+LkkXM0zPsKh/CuZOPi+kXthcnJHS/krz\n"\
"L/Zj5giP3FuX6hwrD8tTYApgjWOnGOc=\n"\
"-----END EC PRIVATE KEY-----\n\0";


const char *secp256r1_privateKey = "-----BEGIN EC PRIVATE KEY-----\n"\
"MHcCAQEEIMz+14McIfmtVmisO0f3jSvnYemYMCKBfZUOivWP0XDZoAoGCCqGSM49\n"\
"AwEHoUQDQgAEIwC+HHl5cXkHNMyCpbQSU2+XY0RBa9hJ0N+f0ZbU3QJfsphQ4hy8\n"\
"LKiuOGMLTC0sKLEJIjSDnALk3CW10rjGVg==\n"\
"-----END EC PRIVATE KEY-----\n\0";

const char *secp521r1_privateKey = "-----BEGIN EC PRIVATE KEY-----\n"\
"MIHcAgEBBEIAq5W9/n3mgCxjX3eXSchq0EhYO/JoNuQ3c/RkCIH5L5PyGD414Pd/\n"\
"bUq7a/7GPPNlfIRyokII3fvJF0Qh0TAufRygBwYFK4EEACOhgYkDgYYABAH2m7zF\n"\
"2hAqFsIbuz59tSyBAQjY+HQc4jis/IfwbYnbcfKT1ykZ7J/WkmMhldTSjzINSiFd\n"\
"kSgj8TrXbmVsZ91wGgCg+BPCyTvr5/paxj8l0+izTsyQb7BC21YGI9KFUum0Tqvl\n"\
"F23kI0mL6cLvjv6lT4+NAd1wfTLiJEXxbGMGe3h+Mg==\n"\
"-----END EC PRIVATE KEY-----\n\0";



int LURK_tls1_lookup_md(int sig_alg, const EVP_MD **pmd)
{
	const EVP_MD *md;
	if (sig_alg == 0x0401 || sig_alg == 0x0403 || sig_alg == 0x0809 || sig_alg == 0x0804) {
		md = EVP_sha256();
	}
	else if (sig_alg == 0x0501 || sig_alg == 0x0503 || sig_alg == 0x080a || sig_alg == 0x0805) {
		md = EVP_sha384();
	}
	else if (sig_alg == 0x0601 || sig_alg == 0x0603 || sig_alg == 0x0806 || sig_alg == 0x080b) {
		md = EVP_sha512();
	}
	else if (sig_alg == 0x0201 || sig_alg == 0x0203) {
		md = EVP_sha1();
	}
	else if (sig_alg == 0x0807 || sig_alg == 0x0808) {
		md = NULL;
	}
	else {
		return 0;
	}
	*pmd = md;
	return 1;
}

/*
This function give back the corresponding private key
TODO!
MUST incude key ID in this function now it would search in all
private keys wich is WRONG, But its ok since we are testing and
we have only one private key anyway!
TODO!
other signature algorithms need to be added appropriatley. There
are some examples in the "Init_EC_KEY" but they are randomly
generated at the runtime and cannot act as the private key!

*/

const void *select_private_key(int sig_alg, LURKTLS13Certificate *certificate) {
	if (sig_alg == 0x0804 || sig_alg == 0x0805 || sig_alg == 0x0806) {
		//return (const void*)privateKey;
		if (sig_alg == 0x0804)
		{
			if (*certificate->finger_print == 1){
				return (const void*)RUST_TLS_RSA_PSS;
			}
			else if (*certificate->finger_print == 2){
				return (const void*)RSA_3078;
			}
			else if (*certificate->finger_print == 3){
				return (const void*)RSA_4096;
			}
		}
	}
	else if (sig_alg == 0x0807) {
		return (const void*)ED25519_privateKey;
	}
	else if (sig_alg == 0x0808) {
		return (const void*)ED448_privateKey;
	}
	else if (sig_alg == 0x0503) {
		return (const void*)secp384r1_privateKey;
	}
	else if (sig_alg == 0x0403) {
		return (const void*)secp256r1_privateKey;
	}
	else if (sig_alg == 0x0603) {
		return (const void*)secp521r1_privateKey;
	}
	return NULL;
}

int LURK_get_private_key(int sig_alg, EVP_PKEY **priKey,LURKTLS13Certificate *certificate)
{
	EVP_PKEY *pkey = EVP_PKEY_new();
	if (sig_alg == 0x0804 || sig_alg == 0x0805 || sig_alg == 0x0806 || sig_alg == 0x0807 ||
		 sig_alg == 0x0808 || sig_alg == 0x0503 ||  sig_alg == 0x0403 ||sig_alg == 0x0603) {
		BIO *keybio;
		keybio = BIO_new_mem_buf(select_private_key(sig_alg,certificate), -1);
		if (keybio == NULL) {
			return 0;
		}
		if (!PEM_read_bio_PrivateKey(keybio, &pkey, NULL, NULL)) {
			return 0;
		}
		*priKey = pkey;
	}

	else {
		return 0;
	}
	return 1;
}
/*
This fundtions trys to mimic  "if (lu->sig == EVP_PKEY_RSA_PSS)"
since we don't have access to lu->sig, I'm handling it manualy
TODO
other sinature algorithms need to be implemented and decieded!
*/
int LURK_need_padding(int sig_alg)
{
	if (sig_alg == 0x0804 || sig_alg == 0x0805 || sig_alg == 0x0806) {
		return 1;
	}
	else {
		return 0;
	}
}

unsigned char *select_public_key(size_t &certificate_len)
{
	certificate_len = sizeof(Certificate_RUST_TLS_RSA_PSS);
	return (unsigned char *)Certificate_RUST_TLS_RSA_PSS;
}

unsigned char *LURK_get_right_certificate(size_t &certificate_len)
{
	int len;
	unsigned char *outbytes = NULL;
	unsigned char *buf = NULL;
	size_t certLen = 0;
	unsigned char *pemCertString = select_public_key(certLen);

	/*generate x509 object from the embeded certificate*/
	BIO *certBio = BIO_new(BIO_s_mem());
	BIO_write(certBio, pemCertString, certLen);
	X509* certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
	if (!certX509) {
		return NULL;
	}

	/*convert X509 object to DER form*/
	len = i2d_X509(certX509, NULL);
	if (len < 0) {
		return NULL;
	}
	buf = (unsigned char *)OPENSSL_malloc(len);
	if (buf == NULL) {
		return NULL;
	}
	outbytes = buf;
	if (i2d_X509(certX509, &buf) != len) {
		return NULL;
	}
	certificate_len = (size_t)len;
	return outbytes;
}


int Sign(int signature_number, unsigned char *Msg, size_t MsgLen, unsigned char *EncMsg, size_t *MsgLenEnc,LURKTLS13Certificate *certificate)
{
	//TODO we assume that this step is only happening once (in other words signatue algorithm does not change!)
	static const EVP_MD *md = NULL;
	static EVP_PKEY *priKey = NULL;
	static int need_padding = -1;
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
	EVP_PKEY_CTX *pkey_ctx = NULL; // should be newed after the key is assigend 
	
	if (need_padding == -1) {
		need_padding = LURK_need_padding(signature_number);
	}
	if (md == NULL) {
		if (!LURK_tls1_lookup_md(signature_number, &md)) {
			return -1;
		}
	}
	if (priKey == NULL) {
		if (!LURK_get_private_key(signature_number, &priKey,certificate)) {
			return -1;
		}
	}

	size_t siglen = 0;
	siglen = EVP_PKEY_size(priKey);
	//test for load
	//unsigned char *EncMsg_test = (unsigned char *)OPENSSL_malloc(siglen);
	if (EVP_DigestSignInit(md_ctx, &pkey_ctx, md, NULL, priKey) <= 0) {
		return -1;
	}
	if (need_padding == 1) {
		if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0
			|| EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
			return -1;
		}
	}
	if (EVP_DigestSign(md_ctx, EncMsg, &siglen, Msg, MsgLen) <= 0) {
		ocall_print_string(6);
		return -1;
	}
	*MsgLenEnc = siglen;
	EVP_MD_CTX_free(md_ctx);
	return 1;

}


size_t signMessage(unsigned char * plainText, size_t plaintest_len, unsigned char *encMessage, int mode,LURKTLS13Certificate *certificate)
{
	//privateKey has been hardcoded so no need for it!
	size_t encMessageLength;
	//this is not for RSA only is for every thing 
	if (Sign(mode, plainText, plaintest_len, encMessage, &encMessageLength, certificate) <= 0) {

		return 0;
	}

	return encMessageLength;
}



/*
 * Size of the to-be-signed TLS13 data, without the hash size itself:
 * 64 bytes of value 32, 33 context bytes, 1 byte separator
 */
#define TLS13_TBS_START_SIZE            64
#define TLS13_TBS_PREAMBLE_SIZE         (TLS13_TBS_START_SIZE + 33 + 1)

static int get_cert_verify_tbs_data(unsigned char *cert_verify_hash, size_t cert_verify_hash_len, unsigned char *tls13tbs, void **hdata, size_t *hdatalen)
{
#ifdef CHARSET_EBCDIC
	static const char servercontext[] = { 0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e,
	 0x33, 0x2c, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43, 0x65,
	 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72,
	 0x69, 0x66, 0x79, 0x00 };
	static const char clientcontext[] = { 0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e,
	 0x33, 0x2c, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x43, 0x65,
	 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72,
	 0x69, 0x66, 0x79, 0x00 };
#else
	static const char servercontext[] = "TLS 1.3, server CertificateVerify";
	//static const char clientcontext[] = "TLS 1.3, client CertificateVerify";
#endif

	size_t hashlen;
	/* Set the first 64 bytes of to-be-signed data to octet 32
	32 is the ascii code of ' ' aka space*/
	memset(tls13tbs, 32, TLS13_TBS_START_SIZE);
	/* This copies the 33 bytes of context (servercontext) plus the 0 separator byte */
	memcpy((char *)tls13tbs + TLS13_TBS_START_SIZE, servercontext, strlen(servercontext));
	memset(tls13tbs + TLS13_TBS_PREAMBLE_SIZE - 1, 0, 1);
	//32 is fixed for SHA256 if the hash function chenges this number needs to change
	memcpy(tls13tbs + TLS13_TBS_PREAMBLE_SIZE, cert_verify_hash, cert_verify_hash_len);
	hashlen = cert_verify_hash_len;

	*hdata = tls13tbs;
	*hdatalen = TLS13_TBS_PREAMBLE_SIZE + hashlen;
	return 1;
}

int sgining_LURK(unsigned char *signature, unsigned char *to_be_signed, int sign_alg, int size_of_to_be_signed,size_t *signature_size,LURKTLS13Certificate *certificate)
{
	/* Get the data to be signed */
	unsigned char tls13tbs[TLS13_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
	void *hdata;
	size_t hdatalen = 0;
	/*getting the "TLS to be signed" data = adding the context to the hashed value that needs to be signed*/
	get_cert_verify_tbs_data(to_be_signed, size_of_to_be_signed, tls13tbs, &hdata, &hdatalen);

	*signature_size = signMessage((unsigned char*)hdata, hdatalen, signature, sign_alg,certificate);
	if (*signature_size == 0) {
		return 0 ;
	}


	return 1;
}

/*
std::string privateKey2 = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n\0";
std::string publicKey = "-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxIA2BrrnR2sIlATsp7aR\n"\
"BD/3krwZ7vt9dNeoDQAee0s6SuYP6MBx/HPnAkwNvPS90R05a7pwRkoT6Ur4PfPh\n"\
"CVlUe8lV+0Eto3ZSEeHz3HdsqlM3bso67L7Dqrc7MdVstlKcgJi8yeAoGOIL9/ig\n"\
"Ov0XBFCeznm9nznx6mnsR5cugw+1ypXelaHmBCLV7r5SeVSh57+KhvZGbQ2fFpUa\n"\
"TPegRpJZXBNS8lSeWvtOv9d6N5UBROTAJodMZT5AfX0jB0QB9IT/0I96H6BSENH0\n"\
"8NXOeXApMuLKvnAf361rS7cRAfRLrWZqERMP4u6Cnk0Cnckc3WcW27kGGIbtwbqU\n"\
"IQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";
std::string publicKey2 = "-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";
*/
