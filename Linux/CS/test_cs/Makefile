include .env
CFLAGS += -I$(LURK_INCLUDE_PATH) -Wall -g -O0
LDFLAGS += -L$(LIB_LURK_PATH) -lLURK

SGXSSL_UNTRUSTED_LIB_PATH = /opt/intel/sgxssl/lib64
SGX_MODE ?= HW
SGX_SDK ?= /opt/intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

#include $(SGX_SDK)/buildenv.mk
ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -L$(SGXSSL_UNTRUSTED_LIB_PATH) -lsgx_usgxssl

CS_test_C: main.c
	$(CC) $(CFLAGS) -o $@ main.c -Wall $(LDFLAGS) $(App_Link_Flags)
	@echo "LINK C =>  $@"

CS_test_CPP: main.cpp
	$(CXX) $(CFLAGS) -o $@ main.cpp -Wall $(LDFLAGS) $(App_Link_Flags)
	@echo "LINK C++ =>  $@"

CS_test_goodlib: main.cpp
	$(CXX) $(CFLAGS) -o $@ main.cpp -Wall $(LDFLAGS)

clean:
	rm -f CS_test*
