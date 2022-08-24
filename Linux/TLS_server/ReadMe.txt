
For Dynamic linking
1- set LD_LIBRARY_PATH so that OS is not using the defualt OpenSSL:
export LD_LIBRARY_PATH=/home/anonmous/Documents/C_projects/TLS_server

2-Make sure all the .so files are the same Debug Vs Release and are in 
the current folder.


Time measurements:
Which conf ? static/dynamic ?
CPU time vs Wall time ?
SGX_Debug_flag?
[in , out] vs [user_check] in edl file?
Vtune for enclave analizing

