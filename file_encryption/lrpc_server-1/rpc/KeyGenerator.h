#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#define COMMON_KEY "xyratech"
#define SHA1_HASH_SIZE 20

class FileKeyGenerator
{
	public:
	FileKeyGenerator(boost::shared_ptr<Cipher>_cipher);
	~FileKeyGenerator();
	CipherKey createKey(const char *keyID);	
	CipherKey createRandomKey();	
	void encodeKey(const CipherKey &_key, const CipherKey  &_keyToEncode, unsigned char **decodedEncKey);	
	CipherKey decodeKey(const CipherKey &_key, const unsigned char *encodedEncKey);	
	unsigned char * sign(const CipherKey &_key, const unsigned char * _data, unsigned char ** _signature);
	bool verify(const CipherKey &_key, const unsigned char * _signature, const unsigned char * _data); 	
	bool compareKey(const CipherKey &lhs_key, const CipherKey &rhs_key);
	int encryptData(const CipherKey &key, unsigned char *_cipher_out, const unsigned char *_plain_in, int _plain_in_len);
 	int decryptData(const CipherKey &key, unsigned char *_plain_out, const unsigned char *_cipher_in, int _cipher_in_len);
	int encodedKeySize();
	int reEncodedKeySize();
	private:	
	boost::shared_ptr<Cipher> cipher;
};
#endif
