#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/integer.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

#define USE_CRYPTOPP

#include "cryptwrap.h"
#include "rng.h"
#include "transform.h"
#include "hash.h"
#include "aes.h"

#include "constants.h"

std::string hash_test()
{
	std::stringstream results;

	for (int j = 0; j < hash_cnt; ++j)
		{
			for (int i = 0; i < seed_cnt; ++i)
			{
				{
					std::string hash;

					std::stringstream out;

					// Use auto keyword to avoid typing long
					// type definitions to get the timepoint
					// at this instant use function now()
					auto start = std::chrono::high_resolution_clock::now();
					hash = HASH_func_array[j].func(seed[i]);
					auto stop = std::chrono::high_resolution_clock::now();

					auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start);

					out << HASH_func_array[j].name << "\thash\t\"" << seed[i]
							<< "\"\t" << crypto::transform::hex::to(hash)
							<< "\t" << duration.count() << "\tns" << std::endl;

					std::string t = out.str();
					std::string s = "crypto::hash::";
					std::string g = "::hash";

					out.clear();
					out.str(std::string());

					std::string::size_type i = t.find(s);

					if (i != std::string::npos)
						t.erase(i, s.length());

					std::string::size_type ii = t.find(g);

					if (ii != std::string::npos)
						t.erase(ii, g.length());

					results << t;
				}
			}
		}
	for (int j = 0; j < hkdf_cnt; ++j)
		{
			for (int i = 0; i < seed_cnt; ++i)
			{
				{
					std::string hkdf;
					std::stringstream out2;

					// Use auto keyword to avoid typing long
					// type definitions to get the timepoint
					// at this instant use function now()
					auto start = std::chrono::high_resolution_clock::now();
					hkdf = HKDF_func_array[j].func(seed[i], seed[i], seed[i]);
					auto stop = std::chrono::high_resolution_clock::now();

					auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start);

					out2 << HKDF_func_array[j].name << "\thkdf\t\"" << seed[i]
							<< "\"\t" << crypto::transform::hex::to(hkdf)
					<< "\t" << duration.count() << "\tns" << std::endl;

					std::string t = out2.str();
					std::string s = "crypto::hash::";
					std::string g = "::hkdf";

					out2.clear();
					out2.str(std::string());

					std::string::size_type i = t.find(s);

					if (i != std::string::npos)
						t.erase(i, s.length());

					std::string::size_type ii = t.find(g);

					if (ii != std::string::npos)
						t.erase(ii, g.length());

					results << t;
				}
			}


		}

	for (int j = 0; j < hmac_cnt; ++j)
			{
				for (int i = 0; i < seed_cnt; ++i)
				{
					{
						std::string hkdf;
						std::stringstream out2;

						// Use auto keyword to avoid typing long
						// type definitions to get the timepoint
						// at this instant use function now()
						auto start = std::chrono::high_resolution_clock::now();
						hkdf = HKDF_func_array[j].func(seed[i], seed[i], seed[i]);
						auto stop = std::chrono::high_resolution_clock::now();

						auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start);

						out2 << HMAC_func_array[j].name << "\thmac\t\"" << seed[i]
								<< "\"\t" << crypto::transform::hex::to(hkdf)
						<< "\t" << duration.count() << "\tns" << std::endl;

						std::string t = out2.str();
						std::string s = "crypto::hash::";
						std::string g = "::hmac";

						out2.clear();
						out2.str(std::string());

						std::string::size_type i = t.find(s);

						if (i != std::string::npos)
							t.erase(i, s.length());

						std::string::size_type ii = t.find(g);

						if (ii != std::string::npos)
							t.erase(ii, g.length());

						results << t;
					}
				}
			}
	return results.str();
}

int main(int argc, char *argv[])
{
	std::string hash_res = hash_test();

	crypto::aes_set params;

	CryptoPP::SecByteBlock key(16);

	key = crypto::rng::randblock(16);

	params = crypto::rng::rand_aes_set();

	std::cout << hash_res;

	std::string hashout = crypto::hash::BLAKE2b_512::hmac(hash_res, key);

	std::cout << "0x" << crypto::transform::hex::to(key) << std::endl;

	std::cout << "0x" << crypto::transform::hex::to(hashout) << std::endl;

	return 0;
}
