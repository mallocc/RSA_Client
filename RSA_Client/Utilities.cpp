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

void util::Utilities::RSAEncrypt(CryptoPP::RSA::PublicKey publicKey, CryptoPP::byte* plaintext, size_t plaintextLength, CryptoPP::byte* cipherText)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(publicKey);
    e.Encrypt(rng, plaintext, plaintextLength, cipherText);
}

size_t util::Utilities::RSADecrypt(CryptoPP::RSA::PrivateKey privateKey, CryptoPP::byte* cipher, size_t cipherLength, CryptoPP::byte* plaintext)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);
    auto res = d.Decrypt(rng, cipher, cipherLength, plaintext);

    if (!res.isValidCoding)
        std::cout << "RSA Crypto Error on Decryption: Invalid Coding" << std::endl;

    return res.messageLength;
}

std::string util::Utilities::AESEncryptData_B64(std::string plaintext, std::string key16, std::string iv16)
{
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];

    if (key16.size() < CryptoPP::AES::DEFAULT_KEYLENGTH)
    {
        std::cout << "Key size too small";
        return "";
    }
    if (iv16.size() < CryptoPP::AES::BLOCKSIZE)
    {
        std::cout << "IV size too small";
        return "";
    }

    for (int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; ++i)
    {
        key[i] = key16[i];
    }
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i)
    {
        iv[i] = iv16[i];
    }

    std::string ciphertext;

    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
    stfEncryptor.MessageEnd();

    return macaron::Base64::Encode(ciphertext);
}

std::string util::Utilities::AESDecryptData_B64(std::string ciphertextb64, std::string key16, std::string iv16)
{
    if (key16.size() < CryptoPP::AES::DEFAULT_KEYLENGTH)
    {
        std::cout << "Key size too small";
        return "";
    }
    if (iv16.size() < CryptoPP::AES::BLOCKSIZE)
    {
        std::cout << "IV size too small";
        return "";
    }

    std::string decryptedtext;
    std::string ciphertext;

    macaron::Base64::Decode(ciphertextb64, ciphertext);
    CryptoPP::AES::Decryption aesDecryption((CryptoPP::byte*)key16.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (CryptoPP::byte*)iv16.c_str());
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
    stfDecryptor.MessageEnd();

    return decryptedtext;
}
