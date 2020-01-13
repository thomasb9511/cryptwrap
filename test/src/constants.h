#pragma once

const unsigned int seed_cnt = 151;

std::string seed[] =
{
		"",
		" ",
		"1234567890",
		"password",
		"ABCDEF",
		"ABC",
		"The quick brown fox jumps over the lazy dog",
		"a",
		"ab",
		"abc",
		"abcd",
		"abcde",
		"abcdef",
		"abcdefg",
		"abcdefgh",
		"abcdefghi",
		"abcdefghij",
		"abcdefghijk",
		"abcdefghijkl",
		"abcdefghijklm",
		"abcdefghijklmn",
		"abcdefghijklmno",
		"abcdefghijklmnop",
		"abcdefghijklmnopq",
		"abcdefghijklmnopqr",
		"abcdefghijklmnopqrs",
		"abcdefghijklmnopqrst",
		"abcdefghijklmnopqrstu",
		"abcdefghijklmnopqrstuv",
		"abcdefghijklmnopqrstuvw",
		"abcdefghijklmnopqrstuvwx",
		"abcdefghijklmnopqrstuvwxy",
		"abcdefghijklmnopqrstuvwxyz",
		"abcdefghijklmnopqrstuvwxyz0",
		"abcdefghijklmnopqrstuvwxyz01",
		"abcdefghijklmnopqrstuvwxyz012",
		"abcdefghijklmnopqrstuvwxyz0123",
		"abcdefghijklmnopqrstuvwxyz01234",
		"abcdefghijklmnopqrstuvwxyz012345",
		"abcdefghijklmnopqrstuvwxyz0123456",
		"abcdefghijklmnopqrstuvwxyz01234567",
		"abcdefghijklmnopqrstuvwxyz012345678",
		"abcdefghijklmnopqrstuvwxyz0123456789",
		"abcdefghijklmnopqrstuvwxyz0123456789a",
		"abcdefghijklmnopqrstuvwxyz0123456789ab",
		"abcdefghijklmnopqrstuvwxyz0123456789abc",
		"abcdefghijklmnopqrstuvwxyz0123456789abcd",
		"abcdefghijklmnopqrstuvwxyz0123456789abcde",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdef",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefgh",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghi",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmno",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstu",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvw",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwx",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxy",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345678",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789a",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abc",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcde",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdef",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefgh",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghi",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmno",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstu",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvw",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwx",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxy",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345678",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789a",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abc",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcde",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdef",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefgh",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghi",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmno",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstu",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvw",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwx",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxy",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345678",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789"

};

#define FUNC_DEF(func) { func, #func },

typedef std::string (*Hkdf)(std::string &password, std::string &salt,
		std::string &deriv);
typedef std::string (*Hash)(std::string &input);
typedef std::string (*Hmac)(std::string &input, CryptoPP::SecByteBlock key);

typedef std::string (*aes)(CryptoPP::SecByteBlock key,
		CryptoPP::SecByteBlock iv, std::string &text);

struct
{
	Hmac func;
	const char *name;
} HMAC_func_array[] =
{
		FUNC_DEF(crypto::hash::BLAKE2b_512::hmac)
		//FUNC_DEF(crypto::hash::BLAKE2b_480::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_448::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_416::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_384::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_352::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_320::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_288::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_256::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_224::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_192::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_160::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_128::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_96::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_64::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_32::hkdf)
		FUNC_DEF(crypto::hash::BLAKE2s_256::hmac)
		//FUNC_DEF(crypto::hash::BLAKE2s_224::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_192::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_160::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_128::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_96::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_64::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_32::hkdf)
		FUNC_DEF(crypto::hash::SHAKE256::hmac)
		FUNC_DEF(crypto::hash::SHAKE128::hmac)
		FUNC_DEF(crypto::hash::SM3::hmac)
		FUNC_DEF(crypto::hash::Tiger::hmac)
		FUNC_DEF(crypto::hash::Whirlpool::hmac)
		FUNC_DEF(crypto::hash::Keccak512::hmac)
		FUNC_DEF(crypto::hash::Keccak384::hmac)
		FUNC_DEF(crypto::hash::Keccak256::hmac)
		FUNC_DEF(crypto::hash::Keccak224::hmac)
		FUNC_DEF(crypto::hash::SHA3512::hmac)
		FUNC_DEF(crypto::hash::SHA3384::hmac)
		FUNC_DEF(crypto::hash::SHA3256::hmac)
		FUNC_DEF(crypto::hash::SHA3224::hmac)
		FUNC_DEF(crypto::hash::RIPEMD320::hmac)
		FUNC_DEF(crypto::hash::RIPEMD256::hmac)
		FUNC_DEF(crypto::hash::RIPEMD160::hmac)
		FUNC_DEF(crypto::hash::RIPEMD128::hmac) };

struct
{
	Hkdf func;
	const char *name;
} HKDF_func_array[] =
{
		FUNC_DEF(crypto::hash::BLAKE2b_512::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_480::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_448::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_416::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_384::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_352::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_320::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_288::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_256::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_224::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_192::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_160::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_128::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_96::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_64::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2b_32::hkdf)
		FUNC_DEF(crypto::hash::BLAKE2s_256::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_224::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_192::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_160::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_128::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_96::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_64::hkdf)
		//FUNC_DEF(crypto::hash::BLAKE2s_32::hkdf)
		FUNC_DEF(crypto::hash::SHAKE256::hkdf)
		FUNC_DEF(crypto::hash::SHAKE128::hkdf)
		FUNC_DEF(crypto::hash::SM3::hkdf)
		FUNC_DEF(crypto::hash::Tiger::hkdf)
		FUNC_DEF(crypto::hash::Whirlpool::hkdf)
		FUNC_DEF(crypto::hash::Keccak512::hkdf)
		FUNC_DEF(crypto::hash::Keccak384::hkdf)
		FUNC_DEF(crypto::hash::Keccak256::hkdf)
		FUNC_DEF(crypto::hash::Keccak224::hkdf)
		FUNC_DEF(crypto::hash::SHA3512::hkdf)
		FUNC_DEF(crypto::hash::SHA3384::hkdf)
		FUNC_DEF(crypto::hash::SHA3256::hkdf)
		FUNC_DEF(crypto::hash::SHA3224::hkdf)
		FUNC_DEF(crypto::hash::RIPEMD320::hkdf)
		FUNC_DEF(crypto::hash::RIPEMD256::hkdf)
		FUNC_DEF(crypto::hash::RIPEMD160::hkdf)
		FUNC_DEF(crypto::hash::RIPEMD128::hkdf) };

struct
{
	Hash func;
	const char *name;
} HASH_func_array[] =
{
		FUNC_DEF(crypto::hash::BLAKE2b_512::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_480::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_448::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_416::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_384::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_352::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_320::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_288::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_256::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_224::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_192::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_160::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_128::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_96::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_64::hash)
		FUNC_DEF(crypto::hash::BLAKE2b_32::hash)
		FUNC_DEF(crypto::hash::BLAKE2s_256::hash)
		FUNC_DEF(crypto::hash::BLAKE2s_224::hash)
		FUNC_DEF(crypto::hash::BLAKE2s_192::hash)
		FUNC_DEF(crypto::hash::BLAKE2s_160::hash)
		FUNC_DEF(crypto::hash::BLAKE2s_128::hash)
		FUNC_DEF(crypto::hash::BLAKE2s_96::hash)
		FUNC_DEF(crypto::hash::BLAKE2s_64::hash)
		FUNC_DEF(crypto::hash::BLAKE2s_32::hash)
		FUNC_DEF(crypto::hash::SHAKE256::hash)
		FUNC_DEF(crypto::hash::SHAKE128::hash)
		FUNC_DEF(crypto::hash::SM3::hash)
		FUNC_DEF(crypto::hash::Tiger::hash)
		FUNC_DEF(crypto::hash::Whirlpool::hash)
		FUNC_DEF(crypto::hash::Keccak512::hash)
		FUNC_DEF(crypto::hash::Keccak384::hash)
		FUNC_DEF(crypto::hash::Keccak256::hash)
		FUNC_DEF(crypto::hash::Keccak224::hash)
		FUNC_DEF(crypto::hash::SHA3512::hash)
		FUNC_DEF(crypto::hash::SHA3384::hash)
		FUNC_DEF(crypto::hash::SHA3256::hash)
		FUNC_DEF(crypto::hash::SHA3224::hash)
		FUNC_DEF(crypto::hash::RIPEMD320::hash)
		FUNC_DEF(crypto::hash::RIPEMD256::hash)
		FUNC_DEF(crypto::hash::RIPEMD160::hash)
		FUNC_DEF(crypto::hash::RIPEMD128::hash) };

//std::string (*hash_ptr_arr[])(std::string &input) =
//{
//	crypto::hash::BLAKE2b_512::hash,
//	crypto::hash::BLAKE2b_480::hash,
//	crypto::hash::BLAKE2b_448::hash,
//	crypto::hash::BLAKE2b_416::hash,
//	crypto::hash::BLAKE2b_384::hash,
//	crypto::hash::BLAKE2b_352::hash,
//	crypto::hash::BLAKE2b_320::hash,
//	crypto::hash::BLAKE2b_288::hash,
//	crypto::hash::BLAKE2b_256::hash,
//	crypto::hash::BLAKE2b_224::hash,
//	crypto::hash::BLAKE2b_192::hash,
//	crypto::hash::BLAKE2b_160::hash,
//	crypto::hash::BLAKE2b_128::hash,
//	crypto::hash::BLAKE2b_96::hash,
//	crypto::hash::BLAKE2b_64::hash,
//	crypto::hash::BLAKE2b_32::hash,
//	crypto::hash::BLAKE2s_256::hash,
//	crypto::hash::BLAKE2s_224::hash,
//	crypto::hash::BLAKE2s_192::hash,
//	crypto::hash::BLAKE2s_160::hash,
//	crypto::hash::BLAKE2s_128::hash,
//	crypto::hash::BLAKE2s_96::hash,
//	crypto::hash::BLAKE2s_64::hash,
//	crypto::hash::BLAKE2s_32::hash,
//	crypto::hash::SHAKE256::hash,
//	crypto::hash::SHAKE128::hash,
//	crypto::hash::SM3::hash,
//	crypto::hash::Tiger::hash,
//	crypto::hash::Whirlpool::hash,
//	crypto::hash::Keccak512::hash,
//	crypto::hash::Keccak384::hash,
//	crypto::hash::Keccak256::hash,
//	crypto::hash::Keccak224::hash,
//	crypto::hash::SHA3512::hash,
//	crypto::hash::SHA3384::hash,
//	crypto::hash::SHA3256::hash,
//	crypto::hash::SHA3224::hash,
//	crypto::hash::RIPEMD320::hash,
//	crypto::hash::RIPEMD256::hash,
//	crypto::hash::RIPEMD160::hash,
//	crypto::hash::RIPEMD128::hash
//};

int hash_cnt = sizeof(HASH_func_array) / sizeof(HASH_func_array[0]);

//std::string (*hkdf_ptr_arr[])(std::string &password, std::string &salt, std::string &deriv) =
//{
//	crypto::hash::BLAKE2b_512::hkdf,
//	crypto::hash::BLAKE2b_480::hkdf,
//	crypto::hash::BLAKE2b_448::hkdf,
//	crypto::hash::BLAKE2b_416::hkdf,
//	crypto::hash::BLAKE2b_384::hkdf,
//	crypto::hash::BLAKE2b_352::hkdf,
//	crypto::hash::BLAKE2b_320::hkdf,
//	crypto::hash::BLAKE2b_288::hkdf,
//	crypto::hash::BLAKE2b_256::hkdf,
//	crypto::hash::BLAKE2b_224::hkdf,
//	crypto::hash::BLAKE2b_192::hkdf,
//	crypto::hash::BLAKE2b_160::hkdf,
//	crypto::hash::BLAKE2b_128::hkdf,
//	crypto::hash::BLAKE2b_96::hkdf,
//	crypto::hash::BLAKE2b_64::hkdf,
//	crypto::hash::BLAKE2b_32::hkdf,
//	crypto::hash::BLAKE2s_256::hkdf,
//	crypto::hash::BLAKE2s_224::hkdf,
//	crypto::hash::BLAKE2s_192::hkdf,
//	crypto::hash::BLAKE2s_160::hkdf,
//	crypto::hash::BLAKE2s_128::hkdf,
//	crypto::hash::BLAKE2s_96::hkdf,
//	crypto::hash::BLAKE2s_64::hkdf,
//	crypto::hash::BLAKE2s_32::hkdf,
//	crypto::hash::SHAKE256::hkdf,
//	crypto::hash::SHAKE128::hkdf,
//	crypto::hash::SM3::hkdf,
//	crypto::hash::Tiger::hkdf,
//	crypto::hash::Whirlpool::hkdf,
//	crypto::hash::Keccak512::hkdf,
//	crypto::hash::Keccak384::hkdf,
//	crypto::hash::Keccak256::hkdf,
//	crypto::hash::Keccak224::hkdf,
//	crypto::hash::SHA3512::hkdf,
//	crypto::hash::SHA3384::hkdf,
//	crypto::hash::SHA3256::hkdf,
//	crypto::hash::SHA3224::hkdf,
//	crypto::hash::RIPEMD320::hkdf,
//	crypto::hash::RIPEMD256::hkdf,
//	crypto::hash::RIPEMD160::hkdf,
//	crypto::hash::RIPEMD128::hkdf
//};

int hkdf_cnt = sizeof(HKDF_func_array) / sizeof(HKDF_func_array[0]);

int hmac_cnt = sizeof(HMAC_func_array) / sizeof(HMAC_func_array[0]);

