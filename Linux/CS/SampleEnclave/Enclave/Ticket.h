#ifndef  TICKET_H
#define TICKET_H
#include "LURK_header.h"

#define TICKET_NONCE_SIZE       8

int construct_and_cache_new_session_ticket(struct SInitCertVerifyResponse *respons, unsigned char *tick_nonce, size_t tick_nonce_len, int md_index);
int lookup_sess_in_cache_and_do_binder(int md_index, unsigned char *session_id,
    unsigned char *hash, size_t hash_len,unsigned char *&early_secret, 
    unsigned char *binderkey);

#endif 