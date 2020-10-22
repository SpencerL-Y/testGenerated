#include "../include/Cryptor.hpp"
#define KEY_LENGTH 2048
#define PUBKEY_FILE "./pubkey.pem"
#define PRIKEY_FILE "./prikey.pem"


Cryptor::Cryptor(/* args */)
{
}
/*symmetric en/decryption*/
int Cryptor::aes_encrypt(char* in, char* key, char*out){
    if(!in || !key || !out){
        return 0;
    }
    AES_KEY aes;
    if(AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0){
        return 0;
    }
    int len = strlen(in), en_len = 0;
    while(en_len < len){
        AES_encrypt((unsigned char*)in, (unsigned char*)out, &aes);
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        en_len += AES_BLOCK_SIZE;
    }
    return 1;
}

int Cryptor::aes_decrypt(char* in, char* key, char*out){
    if(!in || !key || !out){
        return 0;
    }
    AES_KEY aes;
    if(AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0){
        return 0;
    }
    int len = strlen(in), en_len = 0;
    while(en_len < len){
        AES_decrypt((unsigned char*)in, (unsigned char*)out, &aes);
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        en_len += AES_BLOCK_SIZE;
    }
    return 0;
}
/*Used as nonsymmetric en/decryption*/
std::string Cryptor::rsa_pubkey_encrypt(const std::string &clear_text, const std::string &pub_key)
{
	std::string encrypt_text;
    //std::cout << "BIO new mem buf" << std::endl;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
    //std::cout << "new RSA" << std::endl;
	RSA* rsa = RSA_new();
    //std::cout << "read bio rsa" << std::endl;
    std::string pkcs1_header = "-----BEGIN RSA PUBLIC KEY-----";
    std::string pkcs8_header = "-----BEGIN PUBLIC KEY-----";
    if(0 == strncmp(pub_key.c_str(), pkcs8_header.c_str(), pkcs8_header.size())){
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else if(0 == strncmp(pub_key.c_str(), pkcs1_header.c_str(), pkcs1_header.size())){
	    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    }
    //std::cout << "here";
	int key_len = RSA_size(rsa);
	int block_len = key_len - 11;  
	char *sub_text = new char[key_len + 1];
	memset(sub_text, 0, key_len + 1);
	int ret = 0;
	int pos = 0;
	std::string sub_str;
	while (pos < clear_text.length()) {
		sub_str = clear_text.substr(pos, block_len);
		memset(sub_text, 0, key_len + 1);
		ret = RSA_public_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
		if (ret >= 0) {
			encrypt_text.append(std::string(sub_text, ret));
		}
		pos += block_len;
	}
	
	BIO_free_all(keybio);
	RSA_free(rsa);
	delete[] sub_text;
 
	return encrypt_text;
}

std::string Cryptor::rsa_prikey_decrypt(const std::string &cipher_text, const std::string &pri_key)
{
	std::string decrypt_text;
	RSA *rsa = RSA_new();
	BIO *keybio;
	keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (rsa == nullptr) {
        std::cout << "error" << std::endl;
		return nullptr;
	}
 
	int key_len = RSA_size(rsa);
	char *sub_text = new char[key_len + 1];
	memset(sub_text, 0, key_len + 1);
	int ret = 0;
	std::string sub_str;
	int pos = 0;
	while (pos < cipher_text.length()) {
		sub_str = cipher_text.substr(pos, key_len);
		memset(sub_text, 0, key_len + 1);
		ret = RSA_private_decrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
		if (ret >= 0) {
			decrypt_text.append(std::string(sub_text, ret));
			pos += key_len;
		}
	}
	delete[] sub_text;
	BIO_free_all(keybio);
	RSA_free(rsa);
 
	return decrypt_text;
}


int Cryptor::createRSAKeyPair(std::string& pub_key_out, std::string& pri_key_out){
    char* pri_key = nullptr;
    char* pub_key = nullptr;
    RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);
    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);
    size_t prilen = BIO_pending(pri);
    size_t publen = BIO_pending(pub);
    pri_key = (char*)malloc(prilen + 1);
    pub_key = (char*)malloc(publen + 1);
    BIO_read(pri, pri_key, prilen);
    BIO_read(pub, pub_key, publen);
    pri_key[prilen] = '\0';
    pub_key[publen] = '\0';
    pub_key_out = pub_key;
    pri_key_out = pri_key;
    return 1;
}


/*Used as signature*/
std::string Cryptor::sha1_encrypt(const std::string& clear_text, const std::string pri_key){
    	std::string encrypt_text;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		BIO_free_all(keybio);
		return std::string("");
	}
	int len = RSA_size(rsa);
 
	char *text = new char[len + 1];
	memset(text, 0, len + 1);
 
	int ret = RSA_private_encrypt(clear_text.length(), (const unsigned char*)clear_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		encrypt_text = std::string(text, ret);
	}
	free(text);
	BIO_free_all(keybio);
	RSA_free(rsa);
 
	return encrypt_text;
}

std::string Cryptor::sha1_decrypt(const std::string& cipher_text, const std::string& pub_key){
    std::string decrypt_text;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
	RSA *rsa = RSA_new();
	
	std::string pkcs1_header = "-----BEGIN RSA PUBLIC KEY-----";
    std::string pkcs8_header = "-----BEGIN PUBLIC KEY-----";
    if(0 == strncmp(pub_key.c_str(), pkcs8_header.c_str(), pkcs8_header.size())){
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else if(0 == strncmp(pub_key.c_str(), pkcs1_header.c_str(), pkcs1_header.size())){
	    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    }
	if (!rsa)
	{
        std::cout << "ERROR: rsa read error" << std::endl;
		BIO_free_all(keybio);
        return decrypt_text;
	}
 
	int len = RSA_size(rsa);
	char *text = new char[len + 1];
	memset(text, 0, len + 1);
	int ret = RSA_public_decrypt(cipher_text.length(), (const unsigned char*)cipher_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		decrypt_text.append(std::string(text, ret));
	}

	delete text;
	BIO_free_all(keybio);
	RSA_free(rsa);
 
	return decrypt_text;
}

int Cryptor::sha256(char* in, int length, char* out){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    out = (char*)malloc(65*sizeof(char));
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, in, length);
    SHA256_Final(hash, &sha256);
    //SHA256((unsigned char*)in, length, (unsigned char*)out);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++){
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[64] = 0;
    return 0;
}

int Cryptor::des_cbc_encrypt(char* in, char* key, char* out){
    DES_cblock key_block;
    DES_key_schedule key_schedule;
    DES_string_to_key(key, &key_block);
    if (DES_set_key_checked(&key_block, &key_schedule) != 0) {
        printf("convert to key_schedule failed.\n");
        return -1;
    }
    unsigned char* input = (unsigned char*)in;
    size_t len = (sizeof(input) + 7)/8 * 8;
    out = (char*)malloc(len+1); 
    DES_cblock ivec;
    memset((char*)&ivec, 0, sizeof(ivec));
    DES_ncbc_encrypt(input, (unsigned char*)out, sizeof(input), &key_schedule, &ivec, DES_ENCRYPT);
    return 0;
}

int Cryptor::des_cbc_decrypt(char* in, char* key, char* out){
    DES_cblock key_block;
    DES_key_schedule key_schedule;
    DES_string_to_key(key, &key_block);
    if (DES_set_key_checked(&key_block, &key_schedule) != 0) {
        printf("convert to key_schedule failed.\n");
        return -1;
    }
    unsigned char* input = (unsigned char*)in;
    size_t len = (sizeof(input) + 7)/8 * 8;
    out = (char*)malloc(len+1); 
    DES_cblock ivec;
    memset((char*)&ivec, 0, sizeof(ivec));
    DES_ncbc_encrypt(input, (unsigned char*)out, sizeof(input), &key_schedule, &ivec, DES_ENCRYPT);
    return 0;
}

int Cryptor::md5(char* in, char* key, char* out){
    MD5_CTX ctx;
    unsigned char outmd[16];
    int i = 0;
    memset(outmd, 0, sizeof(outmd));
    MD5_Init(&ctx);
    MD5_Update(&ctx, in, sizeof(in));
    MD5_Final(outmd, &ctx);
    out = (char*)malloc(16*sizeof(char));
    memcpy(out, outmd, 16);
    return 0;
}

int Cryptor::crypt(char* in, char* key, int length, char* out, int mod){
    switch (mod)
    {
    case 1:
        return aes_encrypt(in, key, out);
        break;
    
    case 2:
        return aes_decrypt(in, key, out);
        break;
    
    case 3:
        return 0;
        break;
    case 4:
        return 0;
        break;
    case 5:
        return 0;
        break;
    case 6:
        return 0;
        break;
    case 7:
        return des_cbc_encrypt(in, key, out);
        break;
    case 8:
        return des_cbc_decrypt(in, key, out);
        break;
    case 9:
        return sha256(in, length, out);
        break;
    case 10:
        return md5(in, key, out);
        break;
    default:
        break;
    }
    return 0;
}

Cryptor::~Cryptor()
{
}
