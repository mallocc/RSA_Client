#pragma once

#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <iostream>
#include "Utilities.h"

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
				publicKey = util::Utilities::slurp(pub);
				pub.close();

				std::ifstream pri(privateKeyFile, std::ios::in);
				privateKey = util::Utilities::slurp(pri);
				pri.close();

				util::linfo << "Loaded Keys" << util::lend;

				valid = true;
			}
			else
			{
				util::lerr << "No RSA key-pair Found." << util::lend;
			}
		}

	private:
	};
}
