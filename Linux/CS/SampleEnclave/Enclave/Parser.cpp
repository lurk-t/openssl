//#pragma once
#include "Parser.h"
#include <math.h>
#include <string.h>


//sizeof_size is number of bytes start from 0
int pass(unsigned char *handshake, int now, int type, int sizeof_size)
{
	int size = 0;
	//checking handshake type 
	if ((int)*(handshake + now) != type && type > -1) {
		return -1;
	}
	now++;
	for (; sizeof_size >= 0; sizeof_size--) {
		size += ((int)*(handshake + now)) * (int)pow(16, sizeof_size*2);
		now++;
	}
	return size + now;
}

int client_hello_pass(unsigned char *handshake)
{
	return pass(handshake, 0, 0x01, 2);
}

int get_server_rand_index(int now)
{
	int Handshake_Header = 4;
	int version = 2;
	now = now + Handshake_Header;
	now = now + version;
	return now;
}
void get_server_rand_val(unsigned char *handshake, unsigned char *out)
{
	int size_of_server_random = 32;
	int now_index = client_hello_pass(handshake);
	now_index = get_server_rand_index(now_index);
	memcpy(out, handshake + now_index, size_of_server_random);
}

void set_server_rand_val(unsigned char *handshake, unsigned char *in)
{
	int size_of_server_random = 32;
	int now_index = client_hello_pass(handshake);
	now_index = get_server_rand_index(now_index);
	memcpy(handshake + now_index, in, size_of_server_random);
}