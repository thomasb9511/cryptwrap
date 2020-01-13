#pragma once

namespace crypto
{
const unsigned int b512 = 64;
const unsigned int b480 = 60;
const unsigned int b448 = 56;
const unsigned int b416 = 52;
const unsigned int b384 = 48;
const unsigned int b352 = 44;
const unsigned int b320 = 40;
const unsigned int b288 = 36;
const unsigned int b256 = 32;
const unsigned int b224 = 28;
const unsigned int b192 = 24;
const unsigned int b160 = 20;
const unsigned int b128 = 16;
const unsigned int b96 = 12;
const unsigned int b64 = 8;
const unsigned int b32 = 4;

#ifdef USE_CRYPTOPP
	struct aes_set {
		CryptoPP::SecByteBlock key;
		CryptoPP::SecByteBlock iv;
	};
#endif
}
