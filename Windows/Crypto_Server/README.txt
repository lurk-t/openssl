To do list for CS: 

1- Request/Response and SSL object (This is needed for multi-threading and before releasing the code)
The request and response are separated objects from SSL object. they should be part of openssl SSL object!
this phase was escaped since it was time consuming and I wanted to make something that works frist and then
improve it. 
The functions with static arrays that work as storing unit should be deleted and be part of the req/res object

2- Linux compatible: (needed for the comparison with other paper measurements)
-insall SGX SDK, PSW, ... for Linux
-install OpenSSL SGX and OpenSSL (normally) on Linux.
-change the code specially on the TLS server and CS to work with Linux

3- Evaluating compute versus context switching  (part 7.1.1 of draft) (we must choose!)
If we want to go with option 2, it is doable but some extra work for re doing the finish + implementation. 
However, we would save 1 exchange for TEE-REE