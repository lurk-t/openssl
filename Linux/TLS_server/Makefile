##LURK TLS SERVER FLAGS: (static)
CFLAGS += -I/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/Debug/static/include -Wall -g
LDFLAGS += -L/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/Debug/static/lib -lssl -lcrypto -lpthread -ldl 
LDFLAGS_LURK += -L/home/anonmous/Documents/C_projects/CS/SampleEnclave -lLURK

L_R_CFLAGS  += -I/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/static/include -Wall 
L_R_LDFLAGS += -L/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/static/lib -lssl -lcrypto -lpthread -ldl 
L_R_LDFLAGS_LURK += -L/home/anonmous/Documents/C_projects/CS/SampleEnclave -lLURK

##LURK TLS SERVER FLAGS: (dynamic)
L_D_Dy_CFLAGS += -I/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/dynamic/Debug/include -Wall -g
L_D_DY_LDFLAGS += -L/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/dynamic/Debug/lib -lssl -lcrypto -lpthread -ldl 
L_D_DY_LDFLAGS_LURK += -L/home/anonmous/Documents/C_projects/CS/SampleEnclave -lLURK

L_R_Dy_CFLAGS += -I/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/dynamic/Release/include -Wall 
L_R_DY_LDFLAGS += -L/home/anonmous/Documents/OpenSSL/Modified_OpenSSL/dynamic/Release/lib -lssl -lcrypto -lpthread -ldl 
L_R_DY_LDFLAGS_LURK += -L/home/anonmous/Documents/C_projects/CS/SampleEnclave -lLURK

##Normal TLS SERVER FLAGS:
N_D_CFLAGS += -I/home/anonmous/Documents/OpenSSL/lib/X64/Debug/include -Wall -g
N_D_LDFLAGS += -L/home/anonmous/Documents/OpenSSL/lib/X64/Debug/lib -lssl -lcrypto -lpthread -ldl 

N_R_CFLAGS += -I/home/anonmous/Documents/OpenSSL/lib/X64/Release/include -Wall 
N_R_LDFLAGS += -L/home/anonmous/Documents/OpenSSL/lib/X64/Release/lib -lssl -lcrypto -lpthread -ldl 

##Normal TLS SERVER FLAGS: (dynamic)
N_R_Dy_CFLAGS += -I/home/anonmous/Documents/OpenSSL/Shared/X64/Release/include -Wall  
N_R_Dy_LDFLAGS += -L/home/anonmous/Documents/OpenSSL/Shared/X64/Release/lib -lssl -lcrypto -lpthread -ldl 

N_D_Dy_CFLAGS += -I/home/anonmous/Documents/OpenSSL/Shared/X64/Debug/include -Wall  -g 
N_D_Dy_LDFLAGS += -L/home/anonmous/Documents/OpenSSL/Shared/X64/Debug/lib -lssl -lcrypto -lpthread -ldl 

#####SGX SDK and SGX SSL PATHs ##########
SGXSSL_UNTRUSTED_LIB_PATH = /home/anonmous/Documents/SGX/sgxsdk/SGX_SSL/intel-sgx-ssl/Linux/package/lib64
Urts_Library_Name := sgx_urts
SGX_SDK ?= /opt/intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

#include $(SGX_SDK)/buildenv.mk

App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -L$(SGXSSL_UNTRUSTED_LIB_PATH) -lsgx_usgxssl

LURK_LINK_FLAGS_Debug = $(LDFLAGS) $(LDFLAGS_LURK) $(App_Link_Flags)
LURK_LINK_FLAGS_Release = $(L_R_LDFLAGS) $(L_R_LDFLAGS_LURK) $(App_Link_Flags)

LURK_LINK_FLAGS_Debug_dynamic = $(L_D_DY_LDFLAGS) $(L_D_DY_LDFLAGS_LURK) $(App_Link_Flags) 
LURK_LINK_FLAGS_Release_dynamic = $(L_R_DY_LDFLAGS) $(L_R_DY_LDFLAGS_LURK) $(App_Link_Flags)

### static servers:
LURK_Server_Debug: main.c 
	@$(CC) $(CFLAGS) -o $@ $^ -Wall $(LURK_LINK_FLAGS_Debug)
	@echo "LURK TLS server has been made on Debug mode and named:$@"
	@echo "WARNIGN: enclave share lib (*.so) MUST be build in the DEBUGE mode"

LURK_Server_Release: main.c 
	@$(CC) $(L_R_CFLAGS) -o $@ $^ -Wall $(LURK_LINK_FLAGS_Release)
	@echo "LURK TLS server has been made Release mode and named:$@"
	@echo "WARNIGN: enclave share lib (*.so) MUST be build in the PreRelease/Release mode"

Normal_Server_Debug: main.c 
	@$(CC) $(N_D_CFLAGS) -o $@ $^ -Wall $(N_D_LDFLAGS)
	@echo "Normal TLS server has been made on Debug mode and named:$@"

Normal_Server_Release: main.c 
	@$(CC) $(N_R_CFLAGS) -o $@ $^ -Wall $(N_R_LDFLAGS)
	@echo "Normal TLS server has been made Release mode and named:$@"


###Dynamic servers:
Normal_Server_Dynamic_Release: main.c 
	@$(CC) $(N_R_Dy_CFLAGS) -o $@ $^ -Wall $(N_R_Dy_LDFLAGS)
	@echo "Normal TLS server has been made on Debug mode with DYNAMIC OPENSSL and named:$@"

Normal_Server_Dynamic_Debug: main.c 
	@$(CC) $(N_D_Dy_CFLAGS) -o $@ $^ -Wall $(N_D_Dy_LDFLAGS)
	@echo "Normal TLS server has been made on Debug mode with DYNAMIC OPENSSL and named:$@"

LURK_Server_Dynamic_Debug: main.c 
	$(CC) $(L_D_Dy_CFLAGS) -o $@ $^ -Wall $(LURK_LINK_FLAGS_Debug_dynamic)
	@echo "LURK TLS server has been made on Debug mode with DYNAMIC OPENSSL and named:$@"
	@echo "WARNIGN: enclave share lib (*.so) MUST be build in the DEBUGE mode"

LURK_Server_Dynamic_Release: main.c
	$(CC) $(L_R_Dy_CFLAGS) -o $@ $^ -Wall $(LURK_LINK_FLAGS_Release_dynamic)
	@echo "LURK TLS server has been made on Release mode with DYNAMIC OPENSSL and named:$@"
	@echo "WARNIGN: enclave share lib (*.so) MUST be build in the Pre_Release mode"

all: LURK_Server_Debug  LURK_Server_Release Normal_Server_Debug Normal_Server_Release Normal_Server_Dynamic_Release LURK_Server_Dynamic_Debug Normal_Server_Dynamic_Debug LURK_Server_Dynamic_Release
	@echo "ALL Server"
	@echo "WARNIGN: enclave shared lib must on appropriate conf (Debug for Debug mode) and (PreRelease/Release for Release mode)"

clean:
	rm -f LURK_Server_Debug  LURK_Server_Release Normal_Server_Debug Normal_Server_Release Normal_Server_Dynamic_Release LURK_Server_Dynamic_Debug Normal_Server_Dynamic_Debug LURK_Server_Dynamic_Release
