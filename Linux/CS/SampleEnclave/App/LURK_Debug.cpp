#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <time.h>
#include <sys/time.h>

#include "LURK-functions.h"
#include "LURK_header.h"
#include "LURK_Debug.h"

void print_hex_format(unsigned char *input, int input_length)
{

    for (int i = 0; i < input_length; i++)
    {
        printf("%02x", input[i]);
    }
}

/* This  function is for printing a InitCertificateVerifyRequest structure*/
void InitCertificateVerifyRequest_to_string(SInitCertVerifyRequest req)
{
    printf("\n \n REQUEST \n");
    printf("Here is the information about Request that is going through the Crypto Server in Intel SGX: \n");
    printf("Request -> mode: %d \n", req.operation_mode);
    printf("Request -> Seceret request: ");
    switch (req.secret_request)
    {
    case 3:
        printf("client_handshake_traffic_secret \n");
        break;
    case 4:
        printf("server_handshake_traffic_secret \n");
        break;
    case 5:
        printf("client_application_traffic_secret_0 \n");
        break;
    case 6:
        printf("server_application_traffic_secret_0 \n");
        break;
    case 9:
        printf("early secret \n ");
        break;
    case 10:
        printf("handshake \n");
        break;
    default:
        printf("OUT OF BOUND WE COVER RANGE OF 3 TO 10\n");
    }
    printf("Request -> Ephemeral Request -> type:");
    switch (req.ephemeral->method)
    {
    case 0:
        printf("no_secret \n");
        break;
    case 1:
        printf("secret_provided \n");
        break;
    case 2:
        printf("secret_generated \n");
        break;

    default:
        printf("OUT OF BOUND WE COVER RANGE OF 0 TO 2");
    }
    printf("Request -> Ephemeral Request -> group ID:");
    switch (req.ephemeral->shared_secret->group)
    {
    case secp256r1:
        printf("secp256r1 \n");
        break;
    case secp384r1:
        printf("secp384r1 \n");
        break;
    case secp521r1:
        printf("secp521r1 \n");
        break;
    case x25519:
        printf("x25519 \n");
        break;
    case x448:
        printf("x448 \n");
        break;
    case uninitialized:
        printf("uninitialized \n");
        break;
    default:
        printf("UNKNOWN EPHEMERAL \n");
        break;
    }
    printf("Request -> LURKTLS13Certificate -> type:");
    switch (req.certificate->certificate_type)
    {
    case 0:
        printf("empty \n");
        break;
    case 1:
        printf("finger_print \n");
        break;
    case 2:
        printf("uncompressed \n");
        break;
    case 3:
        printf("compressed \n");
        break;

    default:
        printf("OUT OF BOUND WE COVER RANGE OF 0 TO 3\n");
    }

    printf("Request -> Signing Algorithm: ");
    switch (req.sig_algo)
    {
    case rsa_pss_rsae_sha256:
        printf("rsa_pss_rsae_sha256");
        break;
    case rsa_pss_rsae_sha384:
        printf("rsa_pss_rsae_sha384");
        break;
    case rsa_pss_rsae_sha512:
        printf("rsa_pss_rsae_sha512");
        break;

    case rsa_pkcs1_sha256:
        printf("rsa_pkcs1_sha256");
        break;
    case rsa_pkcs1_sha384:
        printf("rsa_pkcs1_sha384");
        break;
    case rsa_pkcs1_sha512:
        printf("rsa_pkcs1_sha512");
        break;

    case ecdsa_secp256r1_sha256:
        printf("ecdsa_secp256r1_sha256");
        break;
    case ecdsa_secp384r1_sha384:
        printf("ecdsa_secp384r1_sha384");
        break;
    case ecdsa_secp521r1_sha512:
        printf("ecdsa_secp521r1_sha512");
        break;

    case ed25519:
        printf("ed25519");
        break;
    case ed448:
        printf("ed448");
        break;

    case rsa_pss_pss_sha256:
        printf("rsa_pss_pss_sha256");
        break;
    case rsa_pss_pss_sha384:
        printf("rsa_pss_pss_sha384");
        break;
    case rsa_pss_pss_sha512:
        printf("rsa_pss_pss_sha512");
        break;

    case rsa_pkcs1_sha1:
        printf("rsa_pkcs1_sha1");
        break;
    case ecdsa_sha1:
        printf("ecdsa_sha1");
        break;

    default:
        printf("UNKOWN SIGNARURE");
    }

    printf("\nRequest -> Freshness: ");
    switch (req.freshness)
    {
    case sha256:
        printf("sha256");
        break;
    default:
        printf("UNKOWN FRESHNESS FUNCTION");
    }
    printf("Request -> hashed handshake: \n");
    print_hex_format(req.handshake_hash, req.handshake_hash_size);

    //req.cert_request.signing_request.sig_algo
}

/* This  function is for printing a InitCertificateVerifyResponse structure*/
void InitCertificateVerifyResponse_to_string(SInitCertVerifyResponse resp)
{

    printf("\n \n RESPONSE \n");
    printf("Here is the information about Response that is Coming out of the Crypto Server from Intel SGX: \n");
    printf("Response-> ephemeral -> method: %d\n", (int)resp.ephemeral->method);
    if (resp.signature != NULL)
    {
        printf("Response-> Signature\n");
        printf("\t Response-> Signature -> Signature data \n");
        print_hex_format(resp.signature->signature, 0x200);
        printf("\n");
        printf("\t Response-> Signature -> algorithm \n");
        switch (resp.signature->algorithm)
        {
        case rsa_pss_rsae_sha256:
            printf("rsa_pss_rsae_sha256");
            break;
        case rsa_pss_rsae_sha384:
            printf("rsa_pss_rsae_sha384");
            break;
        case rsa_pss_rsae_sha512:
            printf("rsa_pss_rsae_sha512");
            break;

        case rsa_pkcs1_sha256:
            printf("rsa_pkcs1_sha256");
            break;
        case rsa_pkcs1_sha384:
            printf("rsa_pkcs1_sha384");
            break;
        case rsa_pkcs1_sha512:
            printf("rsa_pkcs1_sha512");
            break;

        case ecdsa_secp256r1_sha256:
            printf("ecdsa_secp256r1_sha256");
            break;
        case ecdsa_secp384r1_sha384:
            printf("ecdsa_secp384r1_sha384");
            break;
        case ecdsa_secp521r1_sha512:
            printf("ecdsa_secp521r1_sha512");
            break;

        case ed25519:
            printf("ed25519");
            break;
        case ed448:
            printf("ed448");
            break;

        case rsa_pss_pss_sha256:
            printf("rsa_pss_pss_sha256");
            break;
        case rsa_pss_pss_sha384:
            printf("rsa_pss_pss_sha384");
            break;
        case rsa_pss_pss_sha512:
            printf("rsa_pss_pss_sha512");
            break;

        case rsa_pkcs1_sha1:
            printf("rsa_pkcs1_sha1");
            break;
        case ecdsa_sha1:
            printf("ecdsa_sha1");
            break;

        default:
            printf("UNKOWN SIGNARURE");
        }
    }
    else
    {
        printf("No signature Yet! ");
    }
    printf("\n  Response ->  Secerets ");
    for (int i = 0; i < 11; i++)
    {
        printf("\n\t Response ->  Seceret type: ");
        switch (resp.secret_list[i].secret_type)
        {
        case (L_binder_key):
            printf("No data yet");
            break;
        case (L_client_early_traffic_secret):
            printf("client_early_traffic_secret");
            break;
        case (L_early_exporter_master_secret):
            printf("early_exporter_master_secret");
            break;
        case (L_client_handshake_traffic_secret):
            printf("client_handshake_traffic_secret");
            break;
        case (L_server_handshake_traffic_secret):
            printf("server_handshake_traffic_secret");
            break;
        case (L_client_application_traffic_secret_0):
            printf("client_application_traffic_secret_0");
            break;
        case (L_server_application_traffic_secret_0):
            printf("server_application_traffic_secret_0");
            break;
        case (L_exporter_master_secret):
            printf("exporter_master_secret");
            break;
        case (L_resumption_master_secret):
            printf("resumption_master_secret");
            break;
        case (LURK_early_secret):
            printf("LURK_early_secret");
            break;
        case (LURK_handshake_secret):
            printf("LURK_handshake_secret");
            break;
        case (LURK_master_secret):
            printf("LURK_master_secret");
            break;
        case (uninitialized_SecretType):
            printf("uninitialized_SecretType");
            break;
        default:
            printf("UNKOWN SECRET ");
        }
        if (resp.secret_list[i].secret_type != L_binder_key)
        {
            printf("\n\t Response ->  Seceret data: ");
            print_hex_format((unsigned char *)resp.secret_list[i].secret_data, 0x40);
        }
    }
    printf(" \n------------------------------------------------------------------ \n\n\n\n");
    //resp.cert_response.signing_response.signature
}