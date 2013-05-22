#include "config.h"
#include <unistd.h>
#include "Cipher.h"
#include "CipherKey.h"
#include "openssl.h"
#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <iterator>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
using namespace std;
#include "KeyGenerator.h"
#include <typeinfo>
FileKeyGenerator::FileKeyGenerator(boost::shared_ptr<Cipher> _cipher)
:cipher(_cipher)
{


}

FileKeyGenerator::~FileKeyGenerator()
{

}


CipherKey FileKeyGenerator::createKey(const char *keyID)
{
	std::string keyIdentifier(keyID);
	CipherKey key = cipher->newKey(keyIdentifier.c_str(), keyIdentifier.length());
	return key;	
}



CipherKey FileKeyGenerator::createRandomKey()
{
	CipherKey randKey = cipher->newRandomKey();
	return randKey;	
}

/**
 \brief - this function encrypt _keyToEncode using _key and output is stored in decodedEncKey
 \param [in] _key - input key 
 \param [in] _ketToEncode - source key to be encoded 
 \param [in-out] decodedEncKey - output is stored in this.

*/
void FileKeyGenerator::encodeKey(const CipherKey &_key, const CipherKey &_keyToEncode, unsigned char **decodedEncKey)
{
	 //*decodedEncKey = new unsigned char[cipher->encodedKeySize()];
	 *decodedEncKey = (unsigned char*)malloc(cipher->encodedKeySize() + 1);
	 memset(*decodedEncKey, 0, cipher->encodedKeySize() + 1);
	 cipher->writeKey( _keyToEncode, *decodedEncKey, _key );
}


CipherKey FileKeyGenerator::decodeKey(const CipherKey &_encKey,const unsigned char *encodedEncKey)
{
	 CipherKey key = cipher->readKey(encodedEncKey, _encKey, true );
	 return key;
}


unsigned char*  FileKeyGenerator::sign(const CipherKey &_key, const unsigned char * _data, unsigned char ** _signature )
{
	//data would be blob here ....
        unsigned char *data_hash = new unsigned char [SHA1_HASH_SIZE + 1] ;
	memset(data_hash, 0 , sizeof data_hash);
        /* calculate the digest/hash */
        if (!SHA1(_data, cipher->encodedKeySize(), data_hash))
        {
         	fprintf(stderr,"Signing failed ... \n");
	        return 0;
        }
   	// *_signature = new unsigned char[ cipher->reEncodedKeySize() ];
 	 *_signature = (unsigned char*) malloc(cipher->reEncodedKeySize() + 1 );
	memset(*_signature, 0 , cipher->reEncodedKeySize() + 1);
	//Encrypt the hash using key..
	cipher->encodeWriteKey(data_hash,* _signature, _key);
	return *_signature;  
}


bool FileKeyGenerator::verify(const CipherKey &_key, const unsigned char * _signature, const unsigned char * _data)
{
	bool result = false;	
	unsigned char data_hash[SHA1_HASH_SIZE] = { 0 } ;
        /* calculate the digest/hash */
        if (!SHA1(_data, cipher->encodedKeySize(), data_hash))
        {
                fprintf(stderr,"\n* Signing failed... \n");
                return 0;
        }
	unsigned char *dBuf  = new  unsigned char [ cipher->encodedKeySize() + 1];
        memset(dBuf, 0, cipher->encodedKeySize() + 1);
	cipher->encodedReadKey( _signature, dBuf, _key, true);
	result = memcmp((const char*)dBuf, (const char*)data_hash, SHA1_HASH_SIZE) == 0;
	delete[] dBuf;
	return result;
}


int FileKeyGenerator::encryptData(const CipherKey &key, unsigned char *_cipher_out, const unsigned char *_plain_in, int _plain_in_len)
{
	return cipher->encryptData(key, _cipher_out, _plain_in, _plain_in_len);
}


int FileKeyGenerator::decryptData(const CipherKey &key, unsigned char *_plain_out, const unsigned char *_cipher_in, int _cipher_in_len)
{
	return cipher->decryptData(key, _plain_out, _cipher_in, _cipher_in_len);
}


int FileKeyGenerator::encodedKeySize()
{
       return cipher->encodedKeySize();
}


int FileKeyGenerator::reEncodedKeySize()
{
      return cipher->reEncodedKeySize();
}

bool FileKeyGenerator::compareKey(const CipherKey &lhs_key, const CipherKey &rhs_key)
{
	return cipher->compareKey(lhs_key, rhs_key);
}
