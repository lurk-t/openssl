#include "LURK_header.h"
#include "Secret.h"
#include "Ticket.h"
#include "cache.h"
#include <openssl/evp.h> 



unsigned char* get_resumption_master_secret(struct SInitCertVerifyResponse *respons)
{ 
     return respons->conf_secrets.resumption_master_secret;
}


/*
* Create stateful ticket and return the session ID (as key) for cache
* 1-use resumption master secret and ticket nounce and generate the PSK
* 2-cache the PSK in the local cache for later use with the session ID as key for cache
* retun 1 on success 
*/
int construct_and_cache_new_session_ticket(struct SInitCertVerifyResponse *respons, unsigned char *tick_nonce, size_t tick_nonce_len, int md_index)
{
    unsigned char *resumption_master_secret = NULL; 
    
    static const unsigned char nonce_label[] = "resumption";
    unsigned char PSK[EVP_MAX_MD_SIZE] = { 0 };
    size_t PSK_len = 0;
    const EVP_MD *md = LURK_handshake_lookup_md2(md_index);
    int hashleni = EVP_MD_size(md);
    size_t hashlen;


    if ( hashleni < 0)
    {
        return -1;
    }
    hashlen = (size_t)hashleni;

    //TODO
    /*
     * If we already sent one NewSessionTicket, or we resumed then
     * s->session may already be in a cache and so we must not modify it.
     * Instead we need to take a copy of it and modify that.
    */
    
    resumption_master_secret = get_resumption_master_secret(respons);
    if (resumption_master_secret == NULL){
        return -1;
    }

    //generate_PSK
    if (tls13_hkdf_expand(md, resumption_master_secret,nonce_label,sizeof(nonce_label) - 1,tick_nonce,
        tick_nonce_len, PSK, hashlen) != 1)
    {
        return -1;
    }
    PSK_len = hashlen;

    if (cache_PSK(respons,PSK,PSK_len) != 1)
    {
        return -1;
    }
    return 1;
}

int generate_early_secret_with_PSK(const EVP_MD *md, unsigned char *PSK, size_t PSK_len,
    unsigned char* &early_secret, size_t secret_len)
{
    if (early_secret == NULL ){
        early_secret = (unsigned char *)malloc (secret_len * sizeof(char));
    }
    if (early_secret == NULL){
        return -1;
    }
    if (tls13_generate_secret(md, NULL, PSK, PSK_len,early_secret) != 1){
        return -1;
    }
    return 1;

}

int generate_binder_key(const EVP_MD *md, unsigned char *early_secret,
    unsigned char *hash, size_t hashsize, unsigned char *binderkey)
{
#ifdef CHARSET_EBCDIC
    static const unsigned char resumption_label[] = { 0x72, 0x65, 0x73, 0x20, 0x62, 0x69, 0x6E, 0x64, 0x65, 0x72, 0x00 };
    static const unsigned char external_label[]   = { 0x65, 0x78, 0x74, 0x20, 0x62, 0x69, 0x6E, 0x64, 0x65, 0x72, 0x00 };
#else
    static const unsigned char resumption_label[] = "res binder";
    static const unsigned char external_label[] = "ext binder";
#endif
    const unsigned char *label;
    size_t labelsize = 0;
    //TODO for now we do not support external
    label = resumption_label;
    labelsize = sizeof(resumption_label) - 1;


    if (tls13_hkdf_expand(md, early_secret, label, labelsize, hash,
                            hashsize, binderkey, hashsize) != 1) {
        return -1;
    }
    return 1;
}


/*
* 1- look up the session in CS DB. 
* 2- generate early secret
* 3- use early secret and PSK from DB and generate the binder. 
* 4- return the binder.
*/
int lookup_sess_in_cache_and_do_binder(int md_index, unsigned char *session_id,
    unsigned char *hash, size_t hash_len,unsigned char *&early_secret, 
    unsigned char *binderkey){

    unsigned char *cached_PSK = NULL;
    size_t cached_PSK_len = 0;
    const EVP_MD *md = LURK_handshake_lookup_md2(md_index);
    int hashsizei = EVP_MD_size(md);
    size_t hashsize = (size_t)hashsizei;


    if (hashsize != hash_len){
        return -1;
    }

    //! FRESHNESS?

    /*
    * if it finds the PSK in local cache it would malloc and save it in 
    * cached_PSK and saved the len in cached_PSK_len. It would also delete 
    * the cached PSK from the local cache if it finds it.
    */
    if (lookup_sess_in_cache(session_id,cached_PSK,cached_PSK_len) != 1){
        return -1;
    }

    if (generate_early_secret_with_PSK(md,cached_PSK,cached_PSK_len,early_secret,hashsize) != 1){
        return -1;
    }

    if (generate_binder_key(md,early_secret,hash,hashsize,binderkey) != 1)
    {
        return -1;
    }
    return 1;
}