#ifndef LURK_DEBUG_H
#define LURK_DEBUG_H

void InitCertificateVerifyRequest_to_string(struct SInitCertVerifyRequest req);
void InitCertificateVerifyResponse_to_string(struct SInitCertVerifyResponse resp);
void print_hex_format(unsigned char *input, int input_length);

#endif
