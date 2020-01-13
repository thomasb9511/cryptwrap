#include <iostream>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/blake2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rdrand.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/filters.h>
#include <cryptopp/misc.h>
#include <cryptopp/drbg.h>
#include <cryptopp/shake.h>
#include <cryptopp/tiger.h>
#include <cryptopp/sm3.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/keccak.h>
#include <cryptopp/sha3.h>
#include <cryptopp/ripemd.h>

#define USE_CRYPTOPP

#include "cryptwrap.h"
#include "hash.h"

namespace crypto
{
namespace hash
{
namespace BLAKE2b_512
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::BLAKE2b::DIGESTSIZE];

	CryptoPP::BLAKE2b().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::BLAKE2b::DIGESTSIZE);
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::BLAKE2b> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::BLAKE2b::DIGESTSIZE];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::BLAKE2b::DIGESTSIZE);
}
}

namespace BLAKE2b_480
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b480];

	CryptoPP::BLAKE2b(b480).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b480);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b480];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b480);
}
}

namespace BLAKE2b_448
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b448];

	CryptoPP::BLAKE2b(b448).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b448);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b448];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b448);
}
}

namespace BLAKE2b_416
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b416];

	CryptoPP::BLAKE2b(b416).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b416);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b416];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b416);
}
}

namespace BLAKE2b_384
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b384];

	CryptoPP::BLAKE2b(b384).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b384);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b384];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b384);
}
}

namespace BLAKE2b_352
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b352];

	CryptoPP::BLAKE2b(b352).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b352);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b352];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b352);
}
}

namespace BLAKE2b_320
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b320];

	CryptoPP::BLAKE2b(b320).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b320);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b320];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b320);
}
}

namespace BLAKE2b_288
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b288];

	CryptoPP::BLAKE2b(b288).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b288);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b288];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b288);
}
}

namespace BLAKE2b_256
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b256];

	CryptoPP::BLAKE2b(b256).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b256);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b256];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b256);
}
}

namespace BLAKE2b_224
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b224];

	CryptoPP::BLAKE2b(b224).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b224);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b224];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b224);
}
}

namespace BLAKE2b_192
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b192];

	CryptoPP::BLAKE2b(b192).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b192);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b192];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b192);
}
}

namespace BLAKE2b_160
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b160];

	CryptoPP::BLAKE2b(b160).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b160);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b160];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b160);
}
}

namespace BLAKE2b_128
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b128];

	CryptoPP::BLAKE2b(b128).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b128);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b128];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b128);
}
}

namespace BLAKE2b_96
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b96];

	CryptoPP::BLAKE2b(b96).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b96);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b96];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b96);
}
}

namespace BLAKE2b_64
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b64];

	CryptoPP::BLAKE2b(b64).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b64);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b64];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b64);
}
}

namespace BLAKE2b_32
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b32];

	CryptoPP::BLAKE2b(b32).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b32);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b32];

	CryptoPP::HKDF<CryptoPP::BLAKE2b> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b32);
}
}

namespace BLAKE2s_256
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::BLAKE2s::DIGESTSIZE];

	CryptoPP::BLAKE2s().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::BLAKE2s::DIGESTSIZE);
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::BLAKE2s> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::BLAKE2s::DIGESTSIZE];

	CryptoPP::HKDF<CryptoPP::BLAKE2s> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::BLAKE2s::DIGESTSIZE);
}
}

namespace BLAKE2s_224
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b224];

	CryptoPP::BLAKE2s(b224).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b224);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b224];

	CryptoPP::HKDF<CryptoPP::BLAKE2s> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b224);
}
}

namespace BLAKE2s_192
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b192];

	CryptoPP::BLAKE2s(b192).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b192);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b192];

	CryptoPP::HKDF<CryptoPP::BLAKE2s> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b192);
}
}

namespace BLAKE2s_160
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b160];

	CryptoPP::BLAKE2s(b160).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b160);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b160];

	CryptoPP::HKDF<CryptoPP::BLAKE2s> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b160);
}
}

namespace BLAKE2s_128
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b128];

	CryptoPP::BLAKE2s(b128).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b128);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b128];

	CryptoPP::HKDF<CryptoPP::BLAKE2s> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b128);
}
}

namespace BLAKE2s_96
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b96];

	CryptoPP::BLAKE2s(b96).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b96);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b96];

	CryptoPP::HKDF<CryptoPP::BLAKE2s> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b96);
}
}

namespace BLAKE2s_64
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b64];

	CryptoPP::BLAKE2s(b64).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b64);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b64];

	CryptoPP::HKDF<CryptoPP::BLAKE2s> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b64);
}
}

namespace BLAKE2s_32
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[b32];

	CryptoPP::BLAKE2s(b32).CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, b32);
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[b32];

	CryptoPP::HKDF<CryptoPP::BLAKE2s> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, b32);
}
}

namespace SHAKE256
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::SHAKE256::DIGESTSIZE];

	CryptoPP::SHAKE256().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::SHAKE256::DIGESTSIZE);
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::SHAKE256> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::SHAKE256::DIGESTSIZE];

	CryptoPP::HKDF<CryptoPP::SHAKE256> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::SHAKE256::DIGESTSIZE);
}
}

namespace SHAKE128
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::SHAKE128::DIGESTSIZE];

	CryptoPP::SHAKE128(CryptoPP::SHAKE128::DIGESTSIZE).CalculateDigest(abDigest,
			pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::SHAKE128::DIGESTSIZE);
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::SHAKE128> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::SHAKE128::DIGESTSIZE];

	CryptoPP::HKDF<CryptoPP::SHAKE128> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::SHAKE128::DIGESTSIZE);
}
}

namespace Tiger
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::Tiger::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::Tiger().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::Tiger::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::Tiger> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::Tiger::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::Tiger> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::Tiger::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace SM3
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::SM3::DIGESTSIZE];

	CryptoPP::SM3().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::SM3::DIGESTSIZE);
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::SM3> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::SM3::DIGESTSIZE];

	CryptoPP::HKDF<CryptoPP::SM3> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::SM3::DIGESTSIZE);
}
}

namespace Whirlpool
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::Whirlpool::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::Whirlpool().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::Whirlpool::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::Whirlpool> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::Whirlpool::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::Whirlpool> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::Whirlpool::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace Keccak512
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::Keccak_512::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::Keccak_512().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::Keccak_512::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::Keccak_512> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::Keccak_512::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::Keccak_512> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::Keccak_512::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace Keccak384
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::Keccak_384::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::Keccak_384().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::Keccak_384::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::Keccak_384> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::Keccak_384::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::Keccak_384> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::Keccak_384::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace Keccak256
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::Keccak_256::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::Keccak_256().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::Keccak_256::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::Keccak_256> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::Keccak_256::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::Keccak_256> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::Keccak_256::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace Keccak224
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::Keccak_224::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::Keccak_224().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::Keccak_224::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::Keccak_224> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::Keccak_224::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::Keccak_224> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::Keccak_224::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace SHA3512
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::SHA3_512::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::SHA3_512().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::SHA3_512::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::SHA3_512> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::SHA3_512::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::SHA3_512> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::SHA3_512::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace SHA3384
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::SHA3_384::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::SHA3_384().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::SHA3_384::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::SHA3_384> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::SHA3_384::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::SHA3_384> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::SHA3_384::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace SHA3256
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::SHA3_256::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::SHA3_256().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::SHA3_256::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::SHA3_256> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::SHA3_256::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::SHA3_256> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::SHA3_256::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace SHA3224
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::SHA3_224::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::SHA3_224().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::SHA3_224::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::SHA3_224> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::SHA3_224::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::SHA3_224> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::SHA3_224::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace RIPEMD320
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::RIPEMD320::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::RIPEMD320().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::RIPEMD320::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::RIPEMD320> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::RIPEMD320::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::RIPEMD320> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::RIPEMD320::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace RIPEMD160
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::RIPEMD160::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::RIPEMD160().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::RIPEMD160::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::RIPEMD160> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::RIPEMD160::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::RIPEMD160> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::RIPEMD160::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace RIPEMD256
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::RIPEMD256::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::RIPEMD256().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::RIPEMD256::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::RIPEMD256> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::RIPEMD256::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::RIPEMD256> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::RIPEMD256::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}

namespace RIPEMD128
{
std::string hash(std::string &input)
{
	CryptoPP::byte const *pbData = (CryptoPP::byte*) input.data();
	unsigned int nDataLen = input.length();
	CryptoPP::byte abDigest[CryptoPP::RIPEMD128::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::RIPEMD128().CalculateDigest(abDigest, pbData, nDataLen);

	return std::string((char*) abDigest, CryptoPP::RIPEMD128::DIGESTSIZE); // @suppress("Symbol is not resolved") // @suppress("Ambiguous problem")
}

std::string hmac(std::string &input, CryptoPP::SecByteBlock key)
{
	std::string mac, encoded;

	/*********************************\
	\*********************************/

	try
	{
		CryptoPP::HMAC<CryptoPP::RIPEMD128> hmac(key, key.size());

		CryptoPP::StringSource ss2(input, true,
				new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
		);// StringSource
	} catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	encoded.clear();

	return mac;
}

std::string hkdf(std::string &password, std::string &salt, std::string &deriv)
{
	CryptoPP::byte const *password_((const CryptoPP::byte*) password.data());
	size_t plen = strlen((const char*) password_);

	CryptoPP::byte const *salt_((const CryptoPP::byte*) salt.data());
	size_t slen = strlen((const char*) salt_);

	CryptoPP::byte const *deriv_((const CryptoPP::byte*) deriv.data());
	size_t ilen = strlen((const char*) deriv_);

	CryptoPP::byte derived[CryptoPP::RIPEMD128::DIGESTSIZE]; // @suppress("Ambiguous problem")

	CryptoPP::HKDF<CryptoPP::RIPEMD128> hkdf;

	hkdf.DeriveKey(derived, sizeof(derived), password_, plen, salt_, slen,
			deriv_, ilen);

	return std::string((char*) derived, CryptoPP::RIPEMD128::DIGESTSIZE); // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
}
}
}
}
