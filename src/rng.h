#pragma once

#include "cryptwrap.h"

namespace crypto
{

namespace rng
{
#ifdef USE_CRYPTOPP
		aes_set rand_aes_set();
		CryptoPP::SecByteBlock randblock(const int bytes);
#endif
std::string randstrng(const int len);
std::string rdprime(unsigned int bytes);

namespace RDSEED
{
#ifdef USE_CRYPTOPP
			aes_set rand_aes_set();
			CryptoPP::SecByteBlock randblock(const int bytes);
#endif
std::string randstrng(const int len);
std::string rdprime(unsigned int bytes);
}

namespace RDRAND
{
#ifdef USE_CRYPTOPP
			aes_set rand_aes_set();
			CryptoPP::SecByteBlock randblock(const int bytes);
#endif
std::string randstrng(const int len);
std::string rdprime(unsigned int bytes);
}

namespace X917
{
#ifdef USE_CRYPTOPP
			aes_set rand_aes_set();
			CryptoPP::SecByteBlock randblock(const int bytes);
#endif
std::string randstrng(const int len);
std::string rdprime(unsigned int bytes);
}

namespace X931
{
#ifdef USE_CRYPTOPP
			aes_set rand_aes_set();
			CryptoPP::SecByteBlock randblock(const int bytes);
#endif
std::string randstrng(const int len);
std::string rdprime(unsigned int bytes);
}
}
}
