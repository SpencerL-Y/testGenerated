#ifndef Cryptor_hpp
#define Cryptor_hpp
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <memory.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <openssl/pem.h>


class Cryptor
{
private:
    /* data */
public:
    int aes_encrypt(char* in, char* key, char* out);//1
    int aes_decrypt(char* in, char* key, char* out);//2
    std::string rsa_pubkey_encrypt(const std::string &clear_text, const std::string &pub_key);
    std::string rsa_prikey_decrypt(const std::string &cipher_text, const std::string &pri_key);
    int createRSAKeyPair(std::string& pub_key_out, std::string& pri_key_out);
    std::string sha1_decrypt(const std::string& cipher_text, const std::string& pub_key);//5
    std::string sha1_encrypt(const std::string& clear_text, const std::string pri_key);//6
    int des_cbc_encrypt(char* in, char* key, char* out);//7
    int des_cbc_decrypt(char* in, char* key, char* out);//8
    int sha256(char* in, int length, char* out);//9
    int md5(char* in, char* key, char* out);//10
    int crypt(char*in, char* key, int length, char* out, int mod);
    Cryptor(/* args */);
    ~Cryptor();
};


#endif