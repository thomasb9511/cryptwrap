#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rdrand.h>
#include <cryptopp/des.h>

#include <cryptopp/filters.h>
#include <cryptopp/integer.h>
//#include <cryptopp/files.h>
#include <cryptopp/aes.h>

#define USE_CRYPTOPP

#include "cryptwrap.h"
#include "rng.h"

namespace crypto
{
class CombinedRNG: public CryptoPP::RandomNumberGenerator
{
public:
	CombinedRNG(CryptoPP::RandomNumberGenerator &rng1,
			CryptoPP::RandomNumberGenerator &rng2) :
			m_rng1(rng1), m_rng2(rng2)
	{
	}

	bool CanIncorporateEntropy() const
	{
		return m_rng1.CanIncorporateEntropy() || m_rng2.CanIncorporateEntropy();
	}

	void IncorporateEntropy(const CryptoPP::byte *input, size_t length)
	{
		if (m_rng1.CanIncorporateEntropy())
			m_rng1.IncorporateEntropy(input, length);
		if (m_rng2.CanIncorporateEntropy())
			m_rng2.IncorporateEntropy(input, length);
	}

	void GenerateBlock(CryptoPP::byte *output, size_t size)
	{
		CryptoPP::RandomNumberSource(m_rng1, size, true,
				new CryptoPP::ArraySink(output, size));
		CryptoPP::RandomNumberSource(m_rng2, size, true,
				new CryptoPP::ArrayXorSink(output, size));
	}

private:
	CryptoPP::RandomNumberGenerator &m_rng1, &m_rng2;
};

namespace rng
{
CryptoPP::SecByteBlock randblock(const int bytes)
{
	CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), seed(
			CryptoPP::AES::BLOCKSIZE);
	CryptoPP::OS_GenerateRandomBlock(false, key, key.size());
	CryptoPP::OS_GenerateRandomBlock(false, seed, seed.size());
	CryptoPP::X917RNG xAES(
			new CryptoPP::AES::Encryption(key, CryptoPP::AES::MAX_KEYLENGTH),
			seed, NULLPTR);

	CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> x917;
	CryptoPP::AutoSeededX917RNG<CryptoPP::AES> x931;

	CryptoPP::RDRAND rdrand;

	CryptoPP::RDSEED rdseed;

	CombinedRNG rng1(x917, x931);
	CombinedRNG rng2(rdseed, rdrand);
	CombinedRNG rng3(rng1, rng2);
	CombinedRNG prng(rng3, xAES);

	CryptoPP::SecByteBlock randomBytes(bytes);

	prng.GenerateBlock(randomBytes, bytes);

	return randomBytes;
}

std::string randstrng(const int len)
{
	CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), seed(
			CryptoPP::AES::BLOCKSIZE);
	CryptoPP::OS_GenerateRandomBlock(false, key, key.size());
	CryptoPP::OS_GenerateRandomBlock(false, seed, seed.size());
	CryptoPP::X917RNG xAES(
			new CryptoPP::AES::Encryption(key, CryptoPP::AES::MAX_KEYLENGTH),
			seed, NULLPTR);

	CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> x917;
	CryptoPP::AutoSeededX917RNG<CryptoPP::AES> x931;

	CryptoPP::RDRAND rdrand;

	CryptoPP::RDSEED rdseed;

	CombinedRNG rng1(x917, x931);
	CombinedRNG rng2(rdseed, rdrand);
	CombinedRNG rng3(rng1, rng2);
	CombinedRNG prng(rng3, xAES);

	CryptoPP::SecByteBlock Bytes(len);

	prng.GenerateBlock(Bytes, len);

	std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()),
			Bytes.size());

	return randomBytes;
}

std::string rdprime(unsigned int bytes)
{
	int size8 = bytes * 8;

	CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), seed(
			CryptoPP::AES::BLOCKSIZE);
	CryptoPP::OS_GenerateRandomBlock(false, key, key.size());
	CryptoPP::OS_GenerateRandomBlock(false, seed, seed.size());
	CryptoPP::X917RNG xAES(
			new CryptoPP::AES::Encryption(key, CryptoPP::AES::MAX_KEYLENGTH),
			seed, NULLPTR);

	CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> x917;
	CryptoPP::AutoSeededX917RNG<CryptoPP::AES> x931;

	CryptoPP::RDRAND rdrand;

	CryptoPP::RDSEED rdseed;

	CombinedRNG rng1(x917, x931);
	CombinedRNG rng2(rdseed, rdrand);
	CombinedRNG rng3(rng1, rng2);
	CombinedRNG prng(rng3, xAES);

	CryptoPP::Integer x;

	CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters("BitLength",
			size8)("RandomNumberType", CryptoPP::Integer::PRIME);

	x.GenerateRandom(prng, params);

	std::stringstream tempbuf;

	tempbuf << std::hex << std::uppercase << x << std::dec;

	std::string temp(tempbuf.str());

	std::stringstream buf;

	buf << "0x" << std::setfill('0') << std::setw((bytes * 2) + 1) << temp;

	std::string str(buf.str());

	str.resize(str.size() - 1);

	return str;
}

aes_set rand_aes_set()
{
	CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH), iv(
			CryptoPP::AES::BLOCKSIZE);

	key = randblock(CryptoPP::AES::DEFAULT_KEYLENGTH);
	iv = randblock(CryptoPP::AES::BLOCKSIZE);

	aes_set a =
	{ key, iv };

	return a;
}

namespace RDRAND
{
CryptoPP::SecByteBlock randblock(const int bytes)
{
	CryptoPP::RDRAND prng;

	CryptoPP::SecByteBlock randomBytes(bytes);

	prng.GenerateBlock(randomBytes, bytes);

	return randomBytes;
}

std::string randstrng(const int len)
{
	CryptoPP::RDRAND prng;

	CryptoPP::SecByteBlock Bytes(len);

	prng.GenerateBlock(Bytes, len);

	std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()),
			Bytes.size());

	return randomBytes;
}

std::string rdprime(unsigned int bytes)
{
	int size8 = bytes * 8;

	CryptoPP::RDRAND prng;

	CryptoPP::Integer x;

	CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters("BitLength",
			size8)("RandomNumberType", CryptoPP::Integer::PRIME);

	x.GenerateRandom(prng, params);

	std::stringstream tempbuf;

	tempbuf << std::hex << std::uppercase << x << std::dec;

	std::string temp(tempbuf.str());

	std::stringstream buf;

	buf << "0x" << std::setfill('0') << std::setw((bytes * 2) + 1) << temp;

	std::string str(buf.str());

	str.resize(str.size() - 1);

	return str;
}

aes_set rand_aes_set()
{
	CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), iv(
			CryptoPP::AES::BLOCKSIZE);

	key = randblock(CryptoPP::AES::MAX_KEYLENGTH);
	iv = randblock(CryptoPP::AES::BLOCKSIZE);

	return
	{	key, iv};
}
}

namespace RDSEED
{
CryptoPP::SecByteBlock randblock(const int bytes)
{
	CryptoPP::RDSEED prng;

	CryptoPP::SecByteBlock randomBytes(bytes);

	prng.GenerateBlock(randomBytes, bytes);

	return randomBytes;
}

std::string randstrng(const int len)
{
	CryptoPP::RDSEED prng;

	CryptoPP::SecByteBlock Bytes(len);

	prng.GenerateBlock(Bytes, len);

	std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()),
			Bytes.size());

	return randomBytes;
}

std::string rdprime(unsigned int bytes)
{
	int size8 = bytes * 8;

	CryptoPP::RDSEED prng;

	CryptoPP::Integer x;

	CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters("BitLength",
			size8)("RandomNumberType", CryptoPP::Integer::PRIME);

	x.GenerateRandom(prng, params);

	std::stringstream tempbuf;

	tempbuf << std::hex << std::uppercase << x << std::dec;

	std::string temp(tempbuf.str());

	std::stringstream buf;

	buf << "0x" << std::setfill('0') << std::setw((bytes * 2) + 1) << temp;

	std::string str(buf.str());

	str.resize(str.size() - 1);

	return str;
}

aes_set rand_aes_set()
{
	CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), iv(
			CryptoPP::AES::BLOCKSIZE);

	key = randblock(CryptoPP::AES::MAX_KEYLENGTH);
	iv = randblock(CryptoPP::AES::BLOCKSIZE);

	return
	{	key, iv};
}
}

namespace X931
{
CryptoPP::SecByteBlock randblock(const int bytes)
{
	CryptoPP::AutoSeededX917RNG<CryptoPP::AES> prng;

	CryptoPP::SecByteBlock randomBytes(bytes);

	prng.GenerateBlock(randomBytes, bytes);

	return randomBytes;
}

std::string randstrng(const int len)
{
	CryptoPP::AutoSeededX917RNG<CryptoPP::AES> prng;

	CryptoPP::SecByteBlock Bytes(len);

	prng.GenerateBlock(Bytes, len);

	std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()),
			Bytes.size());

	return randomBytes;
}

std::string rdprime(unsigned int bytes)
{
	int size8 = bytes * 8;

	CryptoPP::AutoSeededX917RNG<CryptoPP::AES> prng;

	CryptoPP::Integer x;

	CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters("BitLength",
			size8)("RandomNumberType", CryptoPP::Integer::PRIME);

	x.GenerateRandom(prng, params);

	std::stringstream tempbuf;

	tempbuf << std::hex << std::uppercase << x << std::dec;

	std::string temp(tempbuf.str());

	std::stringstream buf;

	buf << "0x" << std::setfill('0') << std::setw((bytes * 2) + 1) << temp;

	std::string str(buf.str());

	str.resize(str.size() - 1);

	return str;
}

aes_set rand_aes_set()
{
	CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), iv(
			CryptoPP::AES::BLOCKSIZE);

	key = randblock(CryptoPP::AES::MAX_KEYLENGTH);
	iv = randblock(CryptoPP::AES::BLOCKSIZE);

	return
	{	key, iv};
}
}

namespace X917
{
CryptoPP::SecByteBlock randblock(const int bytes)
{
	CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> prng;

	CryptoPP::SecByteBlock randomBytes(bytes);

	prng.GenerateBlock(randomBytes, bytes);

	return randomBytes;
}

std::string randstrng(const int len)
{
	CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> prng;

	CryptoPP::SecByteBlock Bytes(len);

	prng.GenerateBlock(Bytes, len);

	std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()),
			Bytes.size());

	return randomBytes;
}

std::string rdprime(unsigned int bytes)
{
	int size8 = bytes * 8;

	CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> prng;

	CryptoPP::Integer x;

	CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters("BitLength",
			size8)("RandomNumberType", CryptoPP::Integer::PRIME);

	x.GenerateRandom(prng, params);

	std::stringstream tempbuf;

	tempbuf << std::hex << std::uppercase << x << std::dec;

	std::string temp(tempbuf.str());

	std::stringstream buf;

	buf << "0x" << std::setfill('0') << std::setw((bytes * 2) + 1) << temp;

	std::string str(buf.str());

	str.resize(str.size() - 1);

	return str;
}

aes_set rand_aes_set()
{
	CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), iv(
			CryptoPP::AES::BLOCKSIZE);

	key = randblock(CryptoPP::AES::MAX_KEYLENGTH);
	iv = randblock(CryptoPP::AES::BLOCKSIZE);

	return
	{	key, iv};
}
}
}
}
