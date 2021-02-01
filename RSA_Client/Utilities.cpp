#include "Utilities.h"

#include <sstream>
#include <fstream>

#include <boost/algorithm/string.hpp>
#include <sha.h>
#include <hex.h>

#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>

#include "modes.h"
#include "aes.h"
#include "filters.h"

#include "Base64.h"


std::string util::Utilities::slurp(std::ifstream& in)
{
	std::ostringstream sstr;
	sstr << in.rdbuf();
	return sstr.str();
}

std::string util::Utilities::sha256(std::string data)
{
    CryptoPP::SHA256 hash;
    uint8_t digest[CryptoPP::SHA256::DIGESTSIZE];
    std::string message = data;

    hash.CalculateDigest(digest, (uint8_t*)message.c_str(), message.length());

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    boost::algorithm::to_lower(output);

    return output;
}

void util::Utilities::genRSAKeyPair(uint32_t size)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction privkey;
    privkey.Initialize(rng, size);

    CryptoPP::Base64Encoder privkeysink(new CryptoPP::FileSink("keys/private-key.der"));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    CryptoPP::RSAFunction pubkey(privkey);

    CryptoPP::Base64Encoder pubkeysink(new CryptoPP::FileSink("keys/public-key.der"));
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();

    std::cout << "Generated Key Pair" << std::endl;
}

std::string util::Utilities::genIV()
{
    CryptoPP::AutoSeededRandomPool rng;
    uint8_t randomBytes[16];
    rng.GenerateBlock(randomBytes, 16);
    
    CryptoPP::Base64Encoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(randomBytes, 16);
    encoder.MessageEnd();

    return output;
}

void util::Utilities::AESDecryptJson(std::string cipherText, nlohmann::json& j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv)
{
    if (key.size() < 16 || iv.size() < 16)
    {
        std::cout << "Error, key or IV too small" << std::endl;
        return;
    }
    std::string aes_data;
    CryptoPP::StringSource decryptor((CryptoPP::byte*) cipherText.c_str(), cipherText.size(), true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(aes_data)
        ));
    std::string decryptedText;
    try
    {
        CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption e;
        e.SetKeyWithIV(key.data(), 16, iv.data());

        CryptoPP::StringSource ss(aes_data, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(decryptedText)
            ) // StreamTransformationFilter      
        ); // StringSource
        try
        {
            j = nlohmann::json::parse(decryptedText);
        }
        catch (nlohmann::json::exception& e)
        {
            std::cout << e.what() << std::endl;
        }
    }
    catch (CryptoPP::Exception& ce)
    {
        std::cout << ce.what() << std::endl;
    }
}

void util::Utilities::AESEcryptJson(nlohmann::json j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv, std::string& output)
{
    std::string plaintext = j.dump();
    std::string cipherText;

    if (key.size() < 16 || iv.size() < 16)
    {
        std::cout << "Error, key or IV too small" << std::endl;
        return;
    }

    CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e;
    e.SetKeyWithIV(key.data(), 16, iv.data());

    CryptoPP::StringSource ss(plaintext, true,
        new CryptoPP::StreamTransformationFilter(e,
            new CryptoPP::StringSink(cipherText)
        ) // StreamTransformationFilter      
    ); // StringSource

    std::string b64_crypt;

    CryptoPP::Base64Encoder encoder(nullptr, 0);
    encoder.Attach(new CryptoPP::StringSink(b64_crypt));
    encoder.Put((CryptoPP::byte*) cipherText.c_str(), cipherText.size());
    encoder.MessageEnd();

    output = b64_crypt;
}