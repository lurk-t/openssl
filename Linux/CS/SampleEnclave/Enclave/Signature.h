#ifndef  SIGNATURE_H
#define SIGNATURE_H
#include <openssl/evp.h>
#include "LURK_header.h"
int sgining_LURK(unsigned char* signature, unsigned char* to_be_signed, int sign_alg, int size_of_to_be_signed, size_t *signature_size, LURKTLS13Certificate *certificate);
unsigned char * LURK_get_right_certificate(size_t &certificate_len);
#endif 
