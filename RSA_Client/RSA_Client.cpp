//
// async_tcp_client.cpp
// ~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "client.h"

#include <sstream>
#include <fstream>

using net::client;

std::string slurp(std::ifstream& in) {
	std::ostringstream sstr;
	sstr << in.rdbuf();
	return sstr.str();
}

int main(int argc, char* argv[])
{
	try
	{
		boost::asio::io_context io_context;
		tcp::resolver r(io_context);
		client c(io_context);

		if (boost::filesystem::exists("keys/public-key.pem") && boost::filesystem::exists("keys/private-key.pem"))
		{
			std::ifstream pub("keys/public-key.pem", std::ios::in);
			c.clientPublicKey = slurp(pub);
			pub.close();

			std::ifstream pri("keys/private-key.pem", std::ios::in);
			c.clientPrivateKey = slurp(pri);
			pri.close();

			std::cout << "Loaded Keys" << std::endl;
		}
		else
		{
			std::cout << "No RSA key-pair Found. Shutting down.";
			exit(EXIT_FAILURE);
		}

		c.start(r.resolve("81.147.31.211", "32500"));

		io_context.run();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}