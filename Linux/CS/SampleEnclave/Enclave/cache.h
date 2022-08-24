#ifndef  CACHE_H
#define CACHE_H
#include "LURK_header.h"
#include "Ticket.h"

// for now we only support 100 PSK
#define CACHE_MAX_SIZE  1000
#define SESSION_ID_LEN  32

int cache_PSK(struct SInitCertVerifyResponse *respons, unsigned char* PSK, size_t PSK_len);
int lookup_sess_in_cache(unsigned char *session_id, unsigned char *&out_PSK, size_t &out_PSK_len);

struct data{
    unsigned char *session_id;
    unsigned char *PSK;
    size_t PSK_len;
};

struct local_cache{
    size_t cache_empty_spots;
    struct data data[CACHE_MAX_SIZE];
};
#endif 
