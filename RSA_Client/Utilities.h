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
    const std::string ANSI_RESET = "\033[0m";
    const std::string ANSI_RED = "\033[01;31m";
    const std::string ANSI_GREEN = "\033[01;32m";
    const std::string ANSI_YELLOW = "\033[01;33m";
    const std::string ANSI_BLUE = "\033[01;34m";
    const std::string ANSI_MAGENTA = "\033[01;35m";
    const std::string ANSI_CYAN = "\033[01;36m";
    const std::string ANSI_CYAN_BG = "\033[01;46m";
    const std::string ANSI_WHITE = "\033[01;37m";

    const std::string ERROR_MSG = "[" + ANSI_RED + "ERROR" + ANSI_RESET + "]: ";
    const std::string INFO_MSG = "[" + ANSI_WHITE + "INFO" + ANSI_RESET + "]: ";
    const std::string IN_MSG = "[" + ANSI_YELLOW + "INPUT" + ANSI_RESET + "]: ";

    class Utilities
    {
    public:
        static std::string slurp(std::ifstream& in);
        static std::string sha256(std::string data);
        static void genRSAKeyPair(uint32_t size);
        static std::string genIV();
        static void AESEcryptJson(nlohmann::json j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv, std::string& output);
        static void AESDecryptJson(std::string cipherText, nlohmann::json &j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv);

        static bool yesNo(std::string question, bool defaultYes = true);
    };
}