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


#include <conio.h>


using net::client;
using net::Keyring;

namespace
{
	boost::asio::io_context io_context;
	tcp::resolver r(io_context);
	client c(io_context);
}

int main(int argc, char* argv[])
{
	try
	{
#if defined WIN32 || defined _WIN32 || defined WIN64 || defined _WIN64
		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		DWORD dwMode = 0;
		GetConsoleMode(hOut, &dwMode);
		dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
		SetConsoleMode(hOut, dwMode);
#endif

		//// get the saved server public key if it exists
		//std::string filename = "client.cfg";
		//if (!boost::filesystem::exists(filename))
		//{
		//	// doesnt exist so store the one we got given
		//	std::pubkeysink(filename.c_str());
		//	
		//}


		util::Utilities::genRSAKeyPair(2048);
		c.setKeys(Keyring("keys/private-key.der", "keys/public-key.der"));

		std::string ip = util::Utilities::getInput("What IP?", "81.147.31.211");
		std::string port = util::Utilities::getInput("What port?", "32500");
		c.setUsername(util::Utilities::getInput("Username?", "mallocc"));

		std::thread clientThread;

		clientThread = std::thread([&]() {
			if (c.start(r.resolve(ip, port)))
			{
				io_context.restart();
				io_context.run();
			}
			});
		clientThread.detach();

		int count = 0;
		while (true)
		{
			if (_getch() == 0x1b)
			{
				std::string input = util::Utilities::getInput("");
				if (!input.empty())
				{
					//if (input[0] == '!')
					{
						std::stringstream ss(input);
						std::istream_iterator<std::string> begin(ss);
						std::istream_iterator<std::string> end;
						util::Args args(begin, end);

						if (!args.empty())
						{
							std::string command = args[0];

							if (command == "ping")
							{
								c.handleCommandPing(args);
							}
							else if (command == "start")
							{
								clientThread = std::thread([&]() {
									if (c.start(r.resolve(ip, port)))
									{
										io_context.restart();
										io_context.run();
									}
									});
								clientThread.detach();
							}
							else if (command == "stop")
							{
								c.stop();
								io_context.stop();
							}
							else if (command == "to")
							{
								c.handleCommandTo(args);
							}
							else if (command == "online")
							{
								c.handleCommandOnline(args);
							}
							else if (command == "rooms")
							{
								c.handleCommandRooms(args);
							}
							else if (command == "subscribe")
							{
								c.handleCommandSubscribe(args);
							}
							else if (command == "unsubscribe")
							{
								c.handleCommandUnsubscribe(args);
							}
							else if (command == "create")
							{
								c.handleCommandCreate(args);
							}
							else if (command == "remove")
							{
								c.handleCommandRemove(args);
							}
							else if (command == "forget-server")
							{
								std::string ip = args[1];
								std::string filename = "keys/server/" + ip + ".der";
								boost::filesystem::remove(filename);
								util::linfo << "Removed fingerprint for server [" << ip << "]. Please reconnect to gain the key again." << std::endl;
							}
							else
							{
								util::lerr << "'" << command << "' is not a valid command." << std::endl;
							}							
						}
					}
				}
			}

			using namespace std::chrono_literals;
			std::this_thread::sleep_for(1ms);
		}
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}