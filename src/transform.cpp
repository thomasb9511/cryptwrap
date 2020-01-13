#include <iostream>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/base32.h>
#include <cryptopp/base64.h>

#define USE_CRYPTOPP

#include "cryptwrap.h"
#include "transform.h"

namespace crypto
{
namespace transform
{
namespace hex
{
std::string to(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();

	std::string output;

	CryptoPP::HexEncoder hex(new CryptoPP::StringSink(output)); // @suppress("Abstract class cannot be instantiated")
	hex.Put(pbData, nDataLen);
	hex.MessageEnd();

	return output;
}

std::string to(CryptoPP::SecByteBlock &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.size();

	std::string output;

	CryptoPP::HexEncoder hex(new CryptoPP::StringSink(output)); // @suppress("Abstract class cannot be instantiated")
	hex.Put(pbData, nDataLen);
	hex.MessageEnd();

	return output;
}

std::string from(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();

	std::string output;

	CryptoPP::HexDecoder hex(new CryptoPP::StringSink(output)); // @suppress("Abstract class cannot be instantiated")
	hex.Put(pbData, nDataLen);
	hex.MessageEnd();

	return output;
}
}

namespace base64
{
std::string to(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();

	std::string output;

	CryptoPP::Base64Encoder hex(new CryptoPP::StringSink(output)); // @suppress("Abstract class cannot be instantiated")
	hex.Put(pbData, nDataLen);
	hex.MessageEnd();

	return output;
}
std::string from(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();

	std::string output;

	CryptoPP::Base64Decoder hex(new CryptoPP::StringSink(output)); // @suppress("Abstract class cannot be instantiated")
	hex.Put(pbData, nDataLen);
	hex.MessageEnd();

	return output;
}
}

namespace base32
{
std::string to(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();

	std::string output;

	CryptoPP::Base32Encoder hex(new CryptoPP::StringSink(output)); // @suppress("Abstract class cannot be instantiated")
	hex.Put(pbData, nDataLen);
	hex.MessageEnd();

	return output;
}
std::string from(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();

	std::string output;

	CryptoPP::Base32Decoder hex(new CryptoPP::StringSink(output)); // @suppress("Abstract class cannot be instantiated")
	hex.Put(pbData, nDataLen);
	hex.MessageEnd();

	return output;
}
}

namespace logical
{
std::string XOR(std::string &value, std::string &key)
{
	std::string retval(value);
	long unsigned int klen = key.length();
	long unsigned int vlen = value.length();
	unsigned long int k = 0;
	unsigned long int v = 0;
	for (; v < vlen; v++)
	{
		retval[v] = value[v] ^ key[k];
		k = (++k < klen ? k : 0);
	}
	return retval;
}
}
}
}
