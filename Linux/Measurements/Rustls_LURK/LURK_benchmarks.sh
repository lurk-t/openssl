#!bin/bash

cert_path_256k1=/home/anonmous/Documents/C_projects/TLS_server/Certs/secp256k1.crt
cert_path_384r1=/home/anonmous/Documents/C_projects/TLS_server/Certs/secp384r1.crt 
cert_path_ed25519=/home/anonmous/Documents/C_projects/TLS_server/Certs/ED25519.crt
cert_path_ed448=/home/anonmous/Documents/C_projects/TLS_server/Certs/ED448.crt
cert_path_RSA2048=../rustls/test-ca/rsa/end.cert

key_path_256k1=/home/anonmous/Documents/C_projects/TLS_server/Certs/secp256k1.key
key_path_384r1=/home/anonmous/Documents/C_projects/TLS_server/Certs/secp384r1.key 
key_path_ed25519=/home/anonmous/Documents/C_projects/TLS_server/Certs/ED25519.key
key_path_ed448=/home/anonmous/Documents/C_projects/TLS_server/Certs/ED448.key
key_path_RSA2048=../rustls/test-ca/rsa/end.key

target=LURK_results.txt

exe_name=khar

execute_all_configs()
{
    echo $exe_name
    echo "ehemepral = p-256   and   cert and key = secp256k1" >> $target
    BENCH_MULTIPLIER=16 ./$exe_name handshake TLS_AES_256_GCM_SHA384 P-256 $cert_path_256k1 $key_path_256k1 >> $target
    printf "\n \n" >> $target

    echo "ehemepral = p-384  and    cert and key = secp384r1" >> $target
    BENCH_MULTIPLIER=16 ./$exe_name handshake TLS_AES_256_GCM_SHA384 P-384 $cert_path_384r1 $key_path_384r1>> $target
    printf "\n \n \n" >> $target

    echo "ehemepral = x25519  and    cert and key = x25519" >> $target
    BENCH_MULTIPLIER=16 ./$exe_name handshake TLS_AES_256_GCM_SHA384 X25519 $cert_path_ed25519 $key_path_ed25519>> $target
    printf "\n \n \n" >> $target

    echo "ehemepral = x448  and    cert and key = x448" >> $target
    BENCH_MULTIPLIER=16 ./$exe_name handshake TLS_AES_256_GCM_SHA384 X448 $cert_path_ed448 $key_path_ed448>> $target
    printf "\n \n \n" >> $target

    echo "ehemepral = p-256  and    cert and key = RSA2048" >> $target
    BENCH_MULTIPLIER=16 ./$exe_name handshake TLS_AES_256_GCM_SHA384 P-256 $cert_path_RSA2048 $key_path_RSA2048 >> $target
    printf "\n \n \n" >> $target
}
## Normal server with unmodified OpenSSL
make clean
make normal_khar_R
exe_name=normal_khar_R

echo "Normal Openssl in the Release mode" > $target
execute_all_configs


## LURK server with 2 sw no resumpion and no ECDHE (TABLE C)
make clean
make LURK_khar_R
exe_name=LURK_khar_R
rm LURK_config.txt
touch LURK_config.txt
## config the server for LURK
## no ECDHE in CS and no resumption just 2 sw for LURK
echo "0 0 5 1" > LURK_config.txt
echo "#####################################################"  >> $target
echo "0 0 5 1 => LURK config = no ECDHE in CS and no resumption just 2 sw for LURK" >> $target
execute_all_configs



## LURK server with 3 sw no resumpion and  ECDHE (TABLE B)
make clean
make LURK_khar_R
exe_name=LURK_khar_R
rm LURK_config.txt
touch LURK_config.txt
## config the server for LURK
## no ECDHE in CS and no resumption just 2 sw for LURK
echo "0 0 5 2" > LURK_config.txt
echo "#####################################################"  >> $target
echo "0 0 5 2 => LURK config = ECDHE in CS and no resumption just 3 sw for LURK" >> $target
execute_all_configs

 
## LURK server with 3 sw no resumpion and  ECDHE (TABLE A)
make clean
make LURK_khar_R
rm LURK_config.txt
touch LURK_config.txt
## config the server for LURK
## no ECDHE in CS and no resumption just 2 sw for LURK
echo "0 0 7 2" > LURK_config.txt
echo "#####################################################"  >> $target
echo "0 0 7 2 => LURK config = ECDHE in CS and resumption just 4 sw for LURK" >> $target
execute_all_configs
