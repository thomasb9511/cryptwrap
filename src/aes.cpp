#include <iostream>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

#define USE_CRYPTOPP

#include "cryptwrap.h"
#include "aes.h"

namespace crypto
{
namespace aes
{
namespace cbc
{
std::string enc(CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv,
		std::string &plaintext)
{
	// Key and IV setup
	// AES encryption uses a secret key of a variable length (128-bit, 196-bit or
	// 256-
	// bit). This key is secretly exchanged between two parties before
	// communication
	// begins. DEFAULT_KEYLENGTH= 16 bytes

	//
	// String and Sink setup
	//
	std::string ciphertext;

	//
	// Create Cipher Text
	//
	CryptoPP::AES::Encryption aesEncryption(key,
			CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption,
			iv);

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption,
			new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()),
			plaintext.length());
	stfEncryptor.MessageEnd();

	return ciphertext;
}

std::string dec(CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv,
		std::string &ciphertext)
{
	// Key and IV setup
	// AES encryption uses a secret key of a variable length (128-bit, 196-bit or
	// 256-
	// bit). This key is secretly exchanged between two parties before
	// communication
	// begins. DEFAULT_KEYLENGTH= 16 bytes

	//
	// String and Sink setup
	//
	std::string decryptedtext;

	//
	// Decrypt
	//
	CryptoPP::AES::Decryption aesDecryption(key,
			CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption,
			iv);

	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption,
			new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
			ciphertext.size());
	stfDecryptor.MessageEnd();

	return decryptedtext;
}
}
}
}
