#pragma once

void handle_ephemeral_secret_gen(unsigned char* peer_public_key, size_t peer_public_key_len, struct SInitCertVerifyResponse *respons, struct SInitCertVerifyRequest *req, int *a);
int get_size_of_share_secret(NamedGroup group_id);