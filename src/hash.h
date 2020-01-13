#pragma once

namespace crypto
{
namespace hash
{
namespace BLAKE2b_512
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace BLAKE2b_480
{
std::string hash(std::string &input);
}
namespace BLAKE2b_448
{
std::string hash(std::string &input);
}
namespace BLAKE2b_416
{
std::string hash(std::string &input);
}
namespace BLAKE2b_384
{
std::string hash(std::string &input);
}
namespace BLAKE2b_352
{
std::string hash(std::string &input);
}
namespace BLAKE2b_320
{
std::string hash(std::string &input);
}
namespace BLAKE2b_288
{
std::string hash(std::string &input);
}
namespace BLAKE2b_256
{
std::string hash(std::string &input);
}
namespace BLAKE2b_224
{
std::string hash(std::string &input);
}
namespace BLAKE2b_192
{
std::string hash(std::string &input);
}
namespace BLAKE2b_160
{
std::string hash(std::string &input);
}
namespace BLAKE2b_128
{
std::string hash(std::string &input);
}
namespace BLAKE2b_96
{
std::string hash(std::string &input);
}
namespace BLAKE2b_64
{
std::string hash(std::string &input);
}
namespace BLAKE2b_32
{
std::string hash(std::string &input);
}

namespace BLAKE2s_256
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace BLAKE2s_224
{
std::string hash(std::string &input);
}
namespace BLAKE2s_192
{
std::string hash(std::string &input);
}
namespace BLAKE2s_160
{
std::string hash(std::string &input);
}
namespace BLAKE2s_128
{
std::string hash(std::string &input);
}
namespace BLAKE2s_96
{
std::string hash(std::string &input);
}
namespace BLAKE2s_64
{
std::string hash(std::string &input);
}
namespace BLAKE2s_32
{
std::string hash(std::string &input);
}

namespace SHAKE256
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace SHAKE128
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}

namespace SM3
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}

namespace Tiger
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}

namespace Whirlpool
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}

namespace Keccak512
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace Keccak384
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace Keccak256
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace Keccak224
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}

namespace SHA3512
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace SHA3384
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace SHA3256
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace SHA3224
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}

namespace RIPEMD320
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace RIPEMD256
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace RIPEMD160
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
namespace RIPEMD128
{
std::string hash(std::string &input);
std::string hmac(std::string &input, CryptoPP::SecByteBlock key);
std::string hkdf(std::string &password, std::string &salt, std::string &deriv);
}
}
}
