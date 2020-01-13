#pragma once

#include <string>
#include  "cryptwrap.h"

namespace crypto
{
namespace aes
{
namespace cbc
{
std::string enc(CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv,
		std::string &plaintext);
std::string dec(CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv,
		std::string &ciphertext);
}
}
}
