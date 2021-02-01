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
#include "Keyring.h"

#include <sstream>
#include <fstream>

using net::client;
using net::Keyring;

int main(int argc, char* argv[])
{
	try
	{
		boost::asio::io_context io_context;
		tcp::resolver r(io_context);
		client c(io_context);
		util::Utilities::genRSAKeyPair(2048);
		c.setKeys(Keyring("keys/private-key.der", "keys/public-key.der"));
		if (c.start(r.resolve("81.147.31.211", "32500")))
		{
			io_context.run();
		}
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}