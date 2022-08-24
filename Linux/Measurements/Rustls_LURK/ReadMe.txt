These measurements are related to RUSTTLS measuremets and follow the same requrements. However there have been some minor modifications to make them work with SGX and LURK. 

Running the LURK_benchmarks.sh will use the makefile to create 2 diffrent instances for the measuremests:
1-normal_khar_R: which is the nomral unmodified openssl in the relase mode this would be used as the baseline


2-LURK_khar_R: which is the LURK integrated with OpenSSL compiled using the realse mode for both SGX (enclave.signed.so , enclave.so should be in this folder bulid with Pre-realse pr relase mode look at the LURK lib for more info) and OpenSSL

Using the config file for LURK lib (LURK_config.txt), the LURK_benchmark.sh would create 3 different comparisions:
2.1 LURK server with 2 sw no resumpion and no ECDHE (TABLE C)
2.2 LURK server with 3 sw no resumpion and  ECDHE (TABLE B)
2.3 LURK server with 3 sw no resumpion and  ECDHE (TABLE A)

All the results would be in the result file > LURK_results.txt


NOTE: Path for the different cert and private key files are hardcoded here you should chang them to the right path in your computer.
