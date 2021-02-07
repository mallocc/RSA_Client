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


#include <conio.h>


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

	CryptoPP::FileSink privkeysink("keys/private-key.der");
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();

	CryptoPP::RSAFunction pubkey(privkey);

	CryptoPP::FileSink pubkeysink("keys/public-key.der");
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();

	util::linfo << "Generated Key Pair" << util::lend;
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
		util::lerr << "Error, key or IV too small" << util::lend;
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

bool util::Utilities::yesNo(std::string question, bool defaultYes)
{
	bool success = false;

	std::string options = defaultYes ? "(Y/n)" : "(y/N)";

	bool proceed = false;
	while (!proceed)
	{
		std::cout << ANSI_YELLOW//<< IN_MSG 
			<< (question.empty() ? "" : question + " ")
			<< options << " "
			<< ANSI_RESET << "> ";
		std::string inString;
		std::getline(std::cin, inString);
		if (inString == "y" || inString == "Y" || (defaultYes && (inString.empty())))
		{
			proceed = true;
			success = true;
		}
		else if (inString == "n" || inString == "N" || (!defaultYes && (inString.empty())))
		{
			proceed = true;
		}
		else
		{
			util::lerr << "'" << inString << "' is not an option of " << options << util::lend;
		}
	}

	return success;
}

std::string util::Utilities::getInput(std::string question, std::string defaultString, bool noDefault)
{
	std::string ret = defaultString;

	std::stringstream ss;
	if (!defaultString.empty())
		ss << "(" << defaultString << ")";

	bool proceed = false;
	std::string saved;
	while (!proceed)
	{
		std::cout << ANSI_YELLOW//<< IN_MSG 
			<< (question.empty() ? "" : question + " ")
			<< (ss.str().empty() ? "" : ss.str() + " ")
			<< ANSI_RESET << "> " << saved;
		std::string inString;
		std::getline(std::cin, inString);

#ifdef custom
#define KEY_UP    72
#define KEY_LEFT  75
#define KEY_RIGHT 77
#define KEY_DOWN  80
		bool rewriteInput = false;
		char ch = 0;
		size_t cp = saved.size();
		while (true) {
			ch = _getch();
			if (ch == -32)
			{
				ch = _getch();
				if (ch == KEY_LEFT) // LEFT
				{
					if (cp > 0)
					{
						std::cout << "\033[0D";
						cp--;
					}
					continue;
				}
				else if (ch == KEY_RIGHT) // RIGHT
				{
					if (cp < saved.size())
					{
						std::cout << "\033[0C";
						cp++;
					}
					continue;
				}
			}
			else 
			{
				if (ch == 0x1b) // ESC
				{
					rewriteInput = true;
					std::cout << std::endl;
					break;
				}
				else if (ch == '\b') // BACKSPACE
				{
					if (cp > 0)
					{					
						saved.erase(cp);
						cp--; 
						
						// clear line
						std::string leftover = saved.substr(cp);
						std::cout << "\033[0D\033[0K" << leftover << "\033[" << (leftover.size()+1) << "D";
					}
					else
					{
						saved.clear();
						// clear line
						std::cout << "\033[0K";
					}
					continue;
				}
				else if (ch == '\r') // ENTER
				{
					std::cout << std::endl;
					break;
				}
				else
				{
					saved.insert(saved.begin() + cp, ch);
					cp++;
					if (cp < saved.size())
					{
						// clear line
						std::string leftover = saved.substr(cp-1);
						std::cout << leftover << "\033[" << (leftover.size()-1) << "D";
					}
					else
					{
						std::cout << ch;
					}

					
				}
			}			
		}

		if (rewriteInput)
		{
			continue;
		}

		inString = saved;
		saved.clear();

#endif

		if (inString != "")
		{
			ret = inString;
			proceed = true;
		}
		else if (defaultString != "")
		{
			proceed = true;
		}
		else if (noDefault)
		{
			proceed = true;
		}
	}

	return ret;
}

util::Args util::Utilities::extractLiteralArgs(Args args)
{
	Args newArgs;
	std::string tempArg;
	bool midArg = false;
	for (auto arg : args)
	{		
		if (!midArg && !arg.empty() && (arg[0] == '"'))
		{
			tempArg.clear();
			arg.erase(0, 1);
			tempArg += arg + " ";
			if (arg[arg.size() - 1] != '"')
				midArg = true;
		}
		else if (midArg && !arg.empty()
			&& (arg[arg.size() - 1] == '"'))
		{
			arg.erase(arg.size() - 1, 1);
			tempArg += arg;
			midArg = false;
			newArgs.push_back(tempArg);
		}
		else if (midArg)
		{
			tempArg += arg + " ";
		}
		else
		{
			newArgs.push_back(arg);
		}
	}

	return newArgs;
}

void util::Utilities::AESEcryptJson(nlohmann::json j, std::vector<CryptoPP::byte> key, std::vector<CryptoPP::byte> iv, std::string& output)
{
	std::string plaintext = j.dump();
	std::string cipherText;

	if (key.size() < 16 || iv.size() < 16)
	{
		util::lerr << "Error, key or IV too small" << util::lend;
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

std::ostream& util::Console::info()
{
	//printf("%c[2K", 27);
	std::cout << INFO_MSG;
	return std::cout;
}

std::ostream& util::Console::error()
{
	//printf("%c[2K", 27);
	std::cout << ERROR_MSG;
	return std::cout;
}

std::ostream& util::Console::out()
{
	//printf("%c[2K", 27);
	return std::cout;
}

std::ostream& util::Console::dump()
{
	//printf("%c[2K", 27);
	std::cout << DUMP_MSG;
	return std::cout;
}

std::string util::Console::note()
{
	return ""; // m_note + "\r";
}

std::string util::Console::end()
{
	return "\n";// +m_note + "\r";
}

void util::Console::setNote(std::string note)
{
	m_note = note;
}
