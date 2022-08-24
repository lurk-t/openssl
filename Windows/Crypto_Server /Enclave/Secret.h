/* 
	This header file is for generation of Secrets for LURK crypto service.
	This is the only function that need to be seen from outside.  
*/
#pragma once
#include <stdint.h>
#include "LURK_header.h"

/* key_req is the type of the key that whant to be return and secret data
	is the requested secret.
*/
int test_handshake_secrets(uint16_t key_req, Secret *secret_list, unsigned char * ecdhe_secret,
	unsigned char *hashed_handshake_till_now, int size_of_ecdhe_secret, int md_index,
	int operation_mode, int &handshake_hash_size);

