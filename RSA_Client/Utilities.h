#pragma once

#include <boost/algorithm/string.hpp>
#include <sha.h>
#include <hex.h>

#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>


namespace util
{
    class Utilities
    {
    public:
        static std::string slurp(std::ifstream& in);

        static std::string sha256(std::string data);

        static void genRSAKeyPair(uint32_t size);

        static std::string genIV();

        static void RSAEncrypt(CryptoPP::RSA::PublicKey publicKey, CryptoPP::byte* plaintext, size_t plaintextLength, CryptoPP::byte* cipherText);

        static size_t RSADecrypt(CryptoPP::RSA::PrivateKey privateKey, CryptoPP::byte* cipher, size_t cipherLength, CryptoPP::byte* plaintext);

        static std::string AESEncryptData_B64(std::string plaintext, std::string key16, std::string iv16);

        static std::string AESDecryptData_B64(std::string ciphertextb64, std::string key16, std::string iv16);


    };
}