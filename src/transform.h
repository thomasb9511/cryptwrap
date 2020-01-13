#pragma once

namespace crypto
{
namespace transform
{
std::string aa(std::string &a);

namespace hex
{
std::string to(std::string &input);
std::string to(CryptoPP::SecByteBlock &input);
std::string from(std::string &input);
}

namespace base32
{
std::string to(std::string &input);
std::string from(std::string &input);
}

namespace base64
{
std::string to(std::string &input);
std::string from(std::string &input);
}

namespace logical
{
std::string XOR(std::string &value, std::string &key);
}
}
}
