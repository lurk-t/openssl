
#include <string>
#include "cache.h"
#include "LURK_header.h"
#include "Freshness.h"

static struct local_cache mycache;

void init_cache(struct local_cache &cache){
    cache.cache_empty_spots = CACHE_MAX_SIZE;
    for (int i =0; i<CACHE_MAX_SIZE; i++){
        cache.data[i].session_id = NULL;
        cache.data[i].PSK = NULL;
        cache.data[i].PSK_len = 0;
    }
}   

int cache_not_full(struct local_cache cache)
{
    if(cache.cache_empty_spots > 0)
    {
        return 1;
    }
    return -1;
}

int get_cache_index(struct local_cache cache)
{
    for (int i =0; i<CACHE_MAX_SIZE; i++){
        if (cache.data[i].PSK_len == 0){
            return i;
        }
    }
    return -1;
}

int cache_PSK_in_index(struct local_cache &cache, unsigned char *PSK, unsigned char *session_id, size_t PSK_len,int cache_index)
{
    cache.data[cache_index].PSK = PSK;
    cache.data[cache_index].session_id = session_id; 
    cache.data[cache_index].PSK_len = PSK_len;
    cache.cache_empty_spots--;
    return 1;
}

unsigned char *get_session_id(struct SInitCertVerifyResponse *respons) 
{
    unsigned char *session_id = NULL;
    session_id = (unsigned char*) malloc (SESSIN_ID_LEN * sizeof(char));
    if (session_id == NULL)
    {
        return NULL;
    }
    memcpy(session_id,respons->session_id,SESSIN_ID_LEN);
    return session_id;

}

unsigned char *get_PSK(unsigned char * tmp_psk, size_t tmp_psk_size) 
{
    unsigned char *PSK = NULL;
    PSK = (unsigned char*) malloc (tmp_psk_size * sizeof(char));
    if (PSK == NULL)
    {
        return NULL;
    }
    memcpy(PSK,tmp_psk,tmp_psk_size);
    return PSK;

}

void free_data(struct local_cache &cache, int index)
{
    free(cache.data[index].session_id);
    free(cache.data[index].PSK);
    cache.data[index].session_id = NULL;
    cache.data[index].PSK = NULL;
    cache.data[index].PSK_len = 0;
    cache.cache_empty_spots++;
}


int cache_PSK(struct SInitCertVerifyResponse *respons, unsigned char* PSK, size_t PSK_len)
{
    
    static int first_time = 1;
    unsigned char *my_session_id = NULL;
    unsigned char *my_psk = NULL;
    int cache_index = -1;
    if (first_time == 1)
    {
        init_cache(mycache);
        first_time = 0;
    }

//! CHANGE ME MEASUREMENT
    // if (cache_not_full(mycache) != 1)
    // {
    //     return -1;
    // }

    cache_index = get_cache_index(mycache);
    if (cache_index  < 0){
        //! CHANGE ME MEASUREMENT
        free_data(mycache,90);
        cache_index = 90;
        //return -1;
    }

    my_session_id = get_session_id(respons);
    if (my_session_id == NULL)
    {
        return -1;
    }
    my_psk = get_PSK(PSK, PSK_len);
    if (my_psk == NULL)
    {
        return -1;
    }

    if (cache_PSK_in_index(mycache,my_psk, my_session_id, PSK_len, cache_index) != 1)
    {
        return -1;
    }
    
    return 1;

}



/*
* if it finds the PSK in local cache it would malloc and save it in 
* out_PSK and saved the len in out_PSK_len. It would also delete 
* the cached PSK from the local cache if it finds it.
*/
int lookup_sess_in_cache(unsigned char *session_id, unsigned char *&out_PSK, size_t &out_PSK_len)
{
    for (int i=0; i< CACHE_MAX_SIZE; i++)
    {
        if (mycache.data[i].session_id == NULL){
            continue;
        }
        if(memcmp(mycache.data[i].session_id,session_id,SESSION_ID_LEN) == 0)
        {
            out_PSK = (unsigned char *) malloc(mycache.data[i].PSK_len * sizeof(char));
            if (out_PSK == NULL){
                return -1;
            }
            memcpy(out_PSK,mycache.data[i].PSK, mycache.data[i].PSK_len);
            out_PSK_len = mycache.data[i].PSK_len;

            //TODO not sure if this is right place to free the memory
            //free_data(mycache,i);

            return 1;
        }
    }
    return -1;
}