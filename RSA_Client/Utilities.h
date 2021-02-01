#pragma once

#include <boost/algorithm/string.hpp>
#include <sha.h>
#include <hex.h>

#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>

#include "json.hpp"

namespace util
{
    class Utilities
    {
    public:
        static std::string slurp(std::ifstream& in);
        static std::string sha256(std::string data);
        static void genRSAKeyPair(uint32_t size);
        static std::string genIV();
        static void AESEcryptJson(nlohmann::json j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv, std::string& output);
        static void AESDecryptJson(std::string cipherText, nlohmann::json &j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv);
    };
}