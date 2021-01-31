#pragma once

#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <iostream>

namespace net
{
	class Keyring
	{
	public:
		std::string privateKey;
		std::string publicKey;

		bool valid = false;

		Keyring() {}

		Keyring(std::string privateKeyFile, std::string publicKeyFile)
		{
			if (boost::filesystem::exists(privateKeyFile) && boost::filesystem::exists(publicKeyFile))
			{
				std::ifstream pub(publicKeyFile, std::ios::in);
				publicKey = slurp(pub);
				pub.close();

				std::ifstream pri(privateKeyFile, std::ios::in);
				privateKey = slurp(pri);
				pri.close();

				std::cout << "Loaded Keys" << std::endl;

				valid = true;
			}
			else
			{
				std::cout << "No RSA key-pair Found.";
			}
		}

	private:
		std::string slurp(std::ifstream& in)
		{
			std::ostringstream sstr;
			sstr << in.rdbuf();
			return sstr.str();
		}
	};
}
