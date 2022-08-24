


#LDLIBS+=-lssl -lcrypto -ldl -lpthread  -lsgx_usgxssl
#LDLIBS+=-lLURK
#ENV=env LD_LIBRARY_PATH=/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/Debug/static
MEMUSAGE=/usr/bin/time -f %M

#####SGX SDK and SGX SSL PATHs ##########
SGXSSL_UNTRUSTED_LIB_PATH = /home/anonmous/Documents/SGX/sgxsdk/SGX_SSL/intel-sgx-ssl/Linux/package/lib64
Urts_Library_Name := sgx_urts
SGX_SDK ?= /opt/intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

#include $(SGX_SDK)/buildenv.mk

App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -L$(SGXSSL_UNTRUSTED_LIB_PATH) -lsgx_usgxssl


CXXFLAGS+=-g -Wall -Werror #-O2


#CPPFLAGS+=-I../openssl/include
#LDFLAGS+=-L../openssl
#LDFLAGS+=-L/home/anonmous/Documents/C_projects/CS/SampleEnclave
CPPFLAGS+= -I/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/Debug/static/include -Wall -g
LDFLAGS += -L/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/Debug/static/lib -lssl -lcrypto -lpthread -ldl 
LDFLAGS_LURK = -L/home/anonmous/Documents/C_projects/CS/SampleEnclave -lLURK




L_R_CFLAGS  += -I/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/static/include -Wall 
L_R_LDFLAGS += -L/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/static/lib -lssl -lcrypto -lpthread -ldl 
L_R_LDFLAGS_LURK += -L/home/anonmous/Documents/C_projects/CS/SampleEnclave -lLURK


N_R_CFLAGS += -I/home/anonmous/Documents/OpenSSL/lib/X64/Release/include -Wall 
N_R_LDFLAGS += -L/home/anonmous/Documents/OpenSSL/lib/X64/Release/lib -lssl -lcrypto -lpthread -ldl 

LURK_LINK_FLAGS_Release = $(L_R_LDFLAGS) $(L_R_LDFLAGS_LURK) $(App_Link_Flags)
LURK_LINK_FLAGS_Debug = $(LDFLAGS) $(LDFLAGS_LURK) $(App_Link_Flags)

LURK_khar_R:bench.cc
	g++ $(L_R_CFLAGS) -o $@ $^ -Wall $(LURK_LINK_FLAGS_Release)
LURK_khar_D:bench.cc
	g++ $(CPPFLAGS) -o $@ $^ -Wall $(LURK_LINK_FLAGS_Debug)

normal_khar_R: bench.cc
	g++ $(N_R_CFLAGS) -o $@ $^ -Wall $(N_R_LDFLAGS)

bench: bench.cc
perf.data: bench
	$(ENV) perf record -F9999 --call-graph dwarf -- ./bench bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-aes128-openssl.svg

extra:
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-aes256-openssl.svg
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-chacha-openssl.svg
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-fullhs-openssl.svg
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-resume-openssl.svg
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-ticket-openssl.svg

measure: bench
	#$(ENV) ./bench bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	#$(ENV) ./bench bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	#$(ENV) ./bench bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	#$(ENV) ./bench bulk TLS_AES_256_GCM_SHA384 1048576
	#$(ENV) ./bench handshake ECDHE-RSA-AES256-GCM-SHA384
	#$(ENV) ./bench handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	#$(ENV) ./bench handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) ./bench  handshake TLS_AES_256_GCM_SHA384 
	#$(ENV) ./bench handshake-resume TLS_AES_256_GCM_SHA384
	#$(ENV) ./bench handshake-ticket TLS_AES_256_GCM_SHA384

memory: bench
	$(ENV) $(MEMUSAGE) ./bench memory ECDHE-RSA-AES256-GCM-SHA384 100
	$(ENV) $(MEMUSAGE) ./bench memory ECDHE-RSA-AES256-GCM-SHA384 1000
	$(ENV) $(MEMUSAGE) ./bench memory ECDHE-RSA-AES256-GCM-SHA384 5000
	$(ENV) $(MEMUSAGE) ./bench memory TLS_AES_256_GCM_SHA384 100
	$(ENV) $(MEMUSAGE) ./bench memory TLS_AES_256_GCM_SHA384 1000
	$(ENV) $(MEMUSAGE) ./bench memory TLS_AES_256_GCM_SHA384 5000

clean:; rm -f bench *.o *khar* 
