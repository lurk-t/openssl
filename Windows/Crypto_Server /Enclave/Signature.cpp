#include "Signature.h"

#include <stdio.h>      /* vsnprintf */
#include "Enclave_t.h"  /* print_string */
#include <string>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h> 


//std::string
const char* privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"\
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


const char Certificate_RUST_TLS_RSA_PSS_DER[] = { 0x30,0x82,0x04,0x00,
0x30,0x82,0x02,0x68,0xa0,0x03,0x02,0x01,0x02,0x02,0x02,0x01,0xc8,0x30,
0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b,0x05,0x00,
0x30,0x2c,0x31,0x2a,0x30,0x28,0x06,0x03,0x55,0x04,0x03,0x0c,0x21,0x70,
0x6f,0x6e,0x79,0x74,0x6f,0x77,0x6e,0x20,0x52,0x53,0x41,0x20,0x6c,0x65,
0x76,0x65,0x6c,0x20,0x32,0x20,0x69,0x6e,0x74,0x65,0x72,0x6d,0x65,0x64,
0x69,0x61,0x74,0x65,0x30,0x1e,0x17,0x0d,0x31,0x39,0x30,0x36,0x30,0x39,
0x31,0x37,0x31,0x35,0x31,0x32,0x5a,0x17,0x0d,0x32,0x34,0x31,0x31,0x32,
0x39,0x31,0x37,0x31,0x35,0x31,0x32,0x5a,0x30,0x19,0x31,0x17,0x30,0x15,
0x06,0x03,0x55,0x04,0x03,0x0c,0x0e,0x74,0x65,0x73,0x74,0x73,0x65,0x72,
0x76,0x65,0x72,0x2e,0x63,0x6f,0x6d,0x30,0x82,0x01,0x22,0x30,0x0d,0x06,
0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,
0x01,0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00,0xdd,0xc1,
0xb1,0x1c,0xe9,0x92,0xa2,0x87,0x89,0x90,0x03,0xdd,0x7a,0x27,0x07,0x2d,
0x05,0x98,0x27,0x46,0x6c,0xce,0x28,0x44,0x6b,0xce,0x51,0xe3,0x7f,0x3c,
0xbc,0x65,0xfb,0x14,0x24,0xb1,0x0d,0x40,0x13,0x7c,0xb3,0x74,0x55,0x47,
0x03,0xd3,0x85,0x17,0x87,0x76,0x9f,0x1b,0xa6,0x25,0x51,0xac,0xd9,0x8c,
0x47,0x1c,0x97,0xa1,0xae,0x68,0xab,0x15,0x83,0x8d,0x73,0xae,0xe5,0x6e,
0x21,0xa0,0x84,0x88,0x31,0xb3,0x80,0xab,0x82,0xa3,0xf0,0x6f,0x9e,0x4b,
0x45,0x0a,0xc3,0x2a,0x4a,0x1f,0x02,0x75,0x69,0x4c,0xc4,0x8d,0x64,0x06,
0x2b,0x13,0x69,0x21,0x8b,0xdc,0x1a,0xac,0x18,0xa4,0xdd,0x58,0x8b,0x5f,
0xaa,0x4e,0x02,0xe0,0xda,0xac,0x35,0x10,0xdb,0x41,0x86,0xb5,0x87,0x86,
0x64,0x2b,0xb8,0x6a,0x83,0xb5,0x04,0xd0,0x2d,0xed,0xad,0x6d,0xc3,0xae,
0x1a,0x12,0x0b,0xd1,0xcc,0x96,0x21,0x1b,0x44,0x58,0x75,0x8b,0xff,0x06,
0xf5,0x02,0x4c,0xe1,0x9b,0x7d,0x56,0x40,0x5f,0xa6,0x51,0x1b,0x58,0xbd,
0x8a,0x27,0x03,0xf4,0xda,0xec,0x4a,0xce,0x35,0x70,0xb1,0xb0,0x45,0xe7,
0x75,0x34,0x78,0x89,0x3f,0xd7,0xa2,0x09,0xe7,0x3a,0x14,0xc9,0xfa,0xe2,
0x22,0x9c,0xdc,0x27,0xe7,0x6c,0xbd,0x4d,0xee,0xcc,0x62,0x2c,0x7a,0x48,
0x30,0x44,0x55,0xe2,0x99,0xc7,0xdb,0xf7,0x88,0xe6,0x14,0xf3,0x5c,0xd7,
0x7f,0xe5,0x9a,0xc4,0xda,0x99,0xbd,0x37,0xdb,0x3e,0x39,0x0b,0xb1,0x78,
0xb2,0x98,0xe8,0x15,0x7c,0x64,0x1c,0x3b,0x88,0x62,0x41,0xe2,0xe8,0x24,
0x81,0xd7,0x02,0x03,0x01,0x00,0x01,0xa3,0x81,0xbe,0x30,0x81,0xbb,0x30,
0x0c,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x02,0x30,0x00,0x30,
0x0b,0x06,0x03,0x55,0x1d,0x0f,0x04,0x04,0x03,0x02,0x06,0xc0,0x30,0x1d,
0x06,0x03,0x55,0x1d,0x0e,0x04,0x16,0x04,0x14,0x4c,0x1e,0x5c,0x9a,0x92,
0x07,0x35,0x5c,0x7f,0xfd,0x34,0x41,0xe3,0x82,0xdb,0xd3,0xb0,0x05,0x0b,
0x33,0x30,0x42,0x06,0x03,0x55,0x1d,0x23,0x04,0x3b,0x30,0x39,0x80,0x14,
0x42,0x8f,0xcb,0xc8,0x47,0x65,0x56,0xb3,0xa6,0xf2,0x2c,0xc4,0x57,0x06,
0xa3,0x86,0x2b,0x90,0x49,0x30,0xa1,0x1e,0xa4,0x1c,0x30,0x1a,0x31,0x18,
0x30,0x16,0x06,0x03,0x55,0x04,0x03,0x0c,0x0f,0x70,0x6f,0x6e,0x79,0x74,
0x6f,0x77,0x6e,0x20,0x52,0x53,0x41,0x20,0x43,0x41,0x82,0x01,0x7b,0x30,
0x3b,0x06,0x03,0x55,0x1d,0x11,0x04,0x34,0x30,0x32,0x82,0x0e,0x74,0x65,
0x73,0x74,0x73,0x65,0x72,0x76,0x65,0x72,0x2e,0x63,0x6f,0x6d,0x82,0x15,
0x73,0x65,0x63,0x6f,0x6e,0x64,0x2e,0x74,0x65,0x73,0x74,0x73,0x65,0x72,
0x76,0x65,0x72,0x2e,0x63,0x6f,0x6d,0x82,0x09,0x6c,0x6f,0x63,0x61,0x6c,
0x68,0x6f,0x73,0x74,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x01,0x01,0x0b,0x05,0x00,0x03,0x82,0x01,0x81,0x00,0x95,0x88,0x7a,0x76,
0xa4,0xb7,0x08,0x33,0x39,0x7f,0xc0,0xdf,0xac,0x50,0xbc,0xe7,0x2d,0x86,
0x6f,0xae,0x5c,0xa7,0x53,0x80,0x07,0x9c,0xbf,0x3f,0x6d,0xae,0xa2,0x48,
0x03,0x3a,0x10,0xc9,0x6b,0x72,0xed,0x75,0xf9,0x40,0x50,0x82,0x51,0xc8,
0x37,0x60,0x44,0x9f,0xe2,0x63,0x6a,0xcf,0x87,0x4f,0x5b,0x10,0x38,0x83,
0xa2,0xc4,0xc8,0x23,0xac,0xc0,0x60,0x8a,0xb2,0xde,0xcf,0xc9,0xf9,0x0c,
0xde,0xba,0xa3,0x96,0x8a,0xe5,0xbb,0xb6,0xdc,0x68,0xd0,0xbf,0x3a,0xb9,
0x24,0x48,0x74,0xb2,0x44,0x03,0x1e,0xd4,0x85,0x5f,0x46,0x11,0xc2,0xa5,
0xc8,0x86,0x2d,0x6c,0xa4,0x6b,0x4e,0x6e,0xc9,0xe8,0xba,0x9c,0x49,0x34,
0x14,0x1b,0x74,0x07,0x03,0xbf,0x9d,0x3f,0x9b,0xaf,0xfc,0x59,0x77,0x0f,
0x6d,0x70,0x67,0x47,0xec,0x11,0xcb,0x01,0x66,0x8d,0xbe,0xbe,0x39,0x25,
0x4d,0x80,0x24,0x6d,0x04,0x54,0xdb,0x47,0x95,0xd1,0x54,0x73,0x0f,0x13,
0x0b,0xd2,0x93,0x88,0x55,0x8f,0x88,0xe2,0x9a,0x59,0xcf,0x1d,0x96,0x0b,
0xdd,0x56,0xad,0x08,0xfb,0x59,0xaf,0xa8,0x9a,0x2d,0x99,0x7d,0x13,0xae,
0x01,0x6d,0x2f,0x89,0xe2,0xf3,0xd0,0xd1,0x9f,0xf6,0x24,0xc5,0x23,0xb5,
0x70,0xae,0x8f,0x5f,0x64,0xf0,0xb3,0xb6,0x4d,0x34,0xc1,0xcf,0x9e,0x10,
0x56,0x83,0x05,0xe6,0x3a,0xd9,0xc6,0x8b,0x67,0x7a,0xaf,0xb0,0x98,0xf1,
0xf7,0x96,0x6a,0x33,0x10,0xe9,0xb2,0x8f,0x8f,0xb8,0x0a,0x6a,0x32,0x37,
0x3f,0x91,0x0e,0x1a,0xe5,0xa2,0x4f,0x38,0xc7,0x78,0x38,0x60,0x42,0x94,
0x43,0x22,0xb5,0x57,0x84,0x4e,0x8b,0xd0,0xed,0x2f,0x50,0x95,0x56,0x82,
0xdf,0x1d,0x2c,0x12,0xf5,0x28,0x83,0x74,0x3f,0xd0,0x9f,0x69,0xfb,0x44,
0x80,0xa7,0xe8,0x33,0xf6,0x94,0x7a,0x33,0x20,0x2c,0x87,0x5f,0x43,0xa9,
0xe1,0x6f,0xaf,0x11,0x31,0xe1,0xa3,0xb1,0x65,0xb3,0x0d,0xb5,0x6c,0xc8,
0xac,0x00,0x6a,0xe5,0xc3,0x04,0x3b,0x51,0x85,0x38,0x5d,0xf3,0xce,0x0b,
0xd8,0x50,0xa0,0x2b,0xd4,0xeb,0x4b,0x95,0x7b,0xbc,0xfe,0xb9,0x9b,0xe5,
0x05,0x8f,0x11,0xc2,0x67,0x16,0xe2,0x21,0x48,0x6d,0xf0,0x9c,0x3d,0x3e,
0x87,0xae,0x89,0xb9,0x17,0x55,0xf8,0x67,0xf7,0x66,0xcc,0x35,0xbc,0x66,
0x12,0xc3,0xb2,0x35,0x18,0xfc,0x3e,0x25,0x51,0xe5,0xa3,0x6c,0xed,0x51,
0x08,0x72 };


const char* ED25519_privateKey = "-----BEGIN PRIVATE KEY-----\n"\
"MC4CAQAwBQYDK2VwBCIEIO3khWR2Nc+gG4VtqO74qb7tZV81e1P8ad3zKTnu8ZEf\n"\
"-----END PRIVATE KEY-----\n\0";

const char* ED448_privateKey = "-----BEGIN PRIVATE KEY-----\n"\
"MEcCAQAwBQYDK2VxBDsEOW+W696pD6ttCUUMquXG+8ZnynpuoF007rlq3XnXYYZE\n"\
"UBOWkbJ/96IDvk67KCPeXeu292hP+z84HQ==\n"\
"-----END PRIVATE KEY-----\n\0";

const char* secp384r1_privateKey = "-----BEGIN EC PRIVATE KEY-----\n"\
"MIGkAgEBBDC58isLwEQPfc7bNbheOGr5Ln2ol3WxXevSn0c8kCT/eueFl/tDK73I\n"\
"tAY/RPhfyPmgBwYFK4EEACKhZANiAASvkO/kNMRRUxlLOemMt7hPtcDf1fKfxuD2\n"\
"0FYvUzhQgqCY6IC/MbtqRovlN8sJeio+LkkXM0zPsKh/CuZOPi+kXthcnJHS/krz\n"\
"L/Zj5giP3FuX6hwrD8tTYApgjWOnGOc=\n"\
"-----END EC PRIVATE KEY-----\n\0";


const char* secp256r1_privateKey = "-----BEGIN EC PRIVATE KEY-----\n"\
"MHcCAQEEIMz+14McIfmtVmisO0f3jSvnYemYMCKBfZUOivWP0XDZoAoGCCqGSM49\n"\
"AwEHoUQDQgAEIwC+HHl5cXkHNMyCpbQSU2+XY0RBa9hJ0N+f0ZbU3QJfsphQ4hy8\n"\
"LKiuOGMLTC0sKLEJIjSDnALk3CW10rjGVg==\n"\
"-----END EC PRIVATE KEY-----\n\0";

const char* secp521r1_privateKey = "-----BEGIN EC PRIVATE KEY-----\n"\
"MIHcAgEBBEIAq5W9/n3mgCxjX3eXSchq0EhYO/JoNuQ3c/RkCIH5L5PyGD414Pd/\n"\
"bUq7a/7GPPNlfIRyokII3fvJF0Qh0TAufRygBwYFK4EEACOhgYkDgYYABAH2m7zF\n"\
"2hAqFsIbuz59tSyBAQjY+HQc4jis/IfwbYnbcfKT1ykZ7J/WkmMhldTSjzINSiFd\n"\
"kSgj8TrXbmVsZ91wGgCg+BPCyTvr5/paxj8l0+izTsyQb7BC21YGI9KFUum0Tqvl\n"\
"F23kI0mL6cLvjv6lT4+NAd1wfTLiJEXxbGMGe3h+Mg==\n"\
"-----END EC PRIVATE KEY-----\n\0";



int LURK_tls1_lookup_md(int sig_alg, const EVP_MD **pmd)
{
	const EVP_MD *md;
	if (sig_alg == 0x0401 || sig_alg == 0x0403 || sig_alg == 0x0809 || sig_alg == 0x0804)
	{
		md = EVP_sha256();
	}
	else if (sig_alg == 0x0501 || sig_alg == 0x0503 || sig_alg == 0x080a || sig_alg == 0x0805)
	{
		md = EVP_sha384();
	}
	else if (sig_alg == 0x0601 || sig_alg == 0x0603 || sig_alg == 0x0806 || sig_alg == 0x080b)
	{
		md = EVP_sha512();
	}
	else if (sig_alg == 0x0201 || sig_alg == 0x0203)
	{
		md = EVP_sha1();
	}
	else if (sig_alg == 0x0807 || sig_alg == 0x0808)
	{
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

const void * select_private_key(int sig_alg){
	if (sig_alg == 0x0804 || sig_alg == 0x0805 || sig_alg == 0x0806)
	{
		//return (const void*)privateKey;
		return (const void*)RUST_TLS_RSA_PSS;
	}
	else if (sig_alg == 0x0807 )
	{
		return (const void*)ED25519_privateKey;
	}
	else if (sig_alg == 0x0808 )
	{
		return (const void*)ED448_privateKey;
	}
	else if (sig_alg == 0x0503 )
	{
		return (const void*)secp384r1_privateKey;
	}
	else if (sig_alg == 0x0403 )
	{
		return (const void*)secp256r1_privateKey;
	}
	else if (sig_alg == 0x0603 )
	{
		return (const void*)secp521r1_privateKey;
	}
	return NULL;
}

int LURK_get_private_key(int sig_alg, EVP_PKEY **priKey)
{
	EVP_PKEY *pkey = EVP_PKEY_new();
	if (sig_alg == 0x0804 || sig_alg == 0x0805 || sig_alg == 0x0806 || sig_alg == 0x0807 ||
		 sig_alg == 0x0808 || sig_alg == 0x0503 ||  sig_alg == 0x0403 ||sig_alg == 0x0603)
	{
		BIO *keybio;
		keybio = BIO_new_mem_buf(select_private_key(sig_alg), -1);
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
int LURK_need_padding(int sig_alg) {
	if (sig_alg == 0x0804 || sig_alg == 0x0805 || sig_alg == 0x0806)
	{
		return 1;
	}
	else {
		return 0;
	}
}


unsigned char* select_public_key(size_t &certificate_len){
	certificate_len = sizeof(Certificate_RUST_TLS_RSA_PSS);
	return (unsigned char *)Certificate_RUST_TLS_RSA_PSS;
}
unsigned char * LURK_get_right_certificate(size_t &certificate_len)
{
	int len;
	unsigned char *outbytes = NULL;
	unsigned char *buf = NULL;
	size_t certLen = 0;
	unsigned char* pemCertString = select_public_key(certLen);

	/*generate x509 object from the embeded certificate*/
	BIO* certBio = BIO_new(BIO_s_mem());
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
	if ( i2d_X509(certX509, &buf) != len) {
		return NULL;
	}
	certificate_len = (size_t)len;
	return outbytes;
}


int Sign(int signature_number, unsigned char* Msg, size_t MsgLen, unsigned char* EncMsg, size_t* MsgLenEnc)
{
	//TODO we assume that this step is only happening once (in other words signatue algorithm does not change!)
	static const EVP_MD *md = NULL;
	static EVP_PKEY *priKey = NULL;
	static int need_padding = -1;
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	EVP_PKEY_CTX *pkey_ctx = NULL; // should be newed after the key is assigend 
	
	if (need_padding == -1)
	{
		need_padding = LURK_need_padding(signature_number);
	}
	if (md == NULL)
	{
		if (!LURK_tls1_lookup_md(signature_number, &md) ) {
			return -1;
		}
	}
	if (priKey == NULL)
	{
		if (!LURK_get_private_key(signature_number, &priKey))
		{
			return -1;
		}
	}

	size_t siglen = 0;
	siglen = EVP_PKEY_size(priKey);
	//EncMsg = (unsigned char *)OPENSSL_malloc(*MsgLenEnc);
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
		return -1;
	}
	*MsgLenEnc = siglen;

	EVP_MD_CTX_free(md_ctx);
	return 1;

}


size_t signMessage(unsigned char * plainText, size_t plaintest_len, unsigned char* encMessage, int mode)
{
	//privateKey has been hardcoded so no need for it!
	size_t encMessageLength;
	//this is not for RSA only is for every thing 
	if (Sign(mode, plainText, plaintest_len, encMessage, &encMessageLength) <= 0) {
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

int sgining_LURK(unsigned char* signature, unsigned char* to_be_signed, int sign_alg, int size_of_to_be_signed,size_t *signature_size)
{
	/* Get the data to be signed */
	unsigned char tls13tbs[TLS13_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
	void *hdata;
	size_t hdatalen = 0;
	/*getting the "TLS to be signed" data = adding the context to the hashed value that needs to be signed*/
	get_cert_verify_tbs_data(to_be_signed, size_of_to_be_signed, tls13tbs, &hdata, &hdatalen);

	*signature_size = signMessage((unsigned char*)hdata, hdatalen, signature, sign_alg);
	if (*signature_size == 0){
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
