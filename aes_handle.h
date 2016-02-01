#ifndef AES_HANDLE_H
#define AES_HANDLE_H

#include <stdio.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
using namespace std;


void initKV();


string encrypt(string plainText,int idx);
string encrypt_Ex(char* pText,int id_x);
	
string decrypt(string cipherTextHex,int idx);


#endif//AES_HANDLE_H
