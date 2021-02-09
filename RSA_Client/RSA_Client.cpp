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

		c.readConfig();
		 
		util::Utilities::genRSAKeyPair(2048);
		c.setKeys(Keyring("keys/private-key.der", "keys/public-key.der"));
		//"81.147.31.211"
		//"192.168.1.226"

		std::thread clientThread;

		if (c.autoconnect)
		{
			clientThread = std::thread([&]() {
				if (c.start(r.resolve(c.lastServer, c.port)))
				{
					io_context.restart();
					io_context.run();
				}
				});
			clientThread.detach();
		}

		int count = 0;
		std::string lastInput;
		while (true)
		{
			c.dumpConsoleStream();
			// will process input if in stream, otherwise input is triggered from ESC
			// using side effects

			char ch = _getch();
			if (ch == 27 || ch == '\r')
			{
				c.lockDump();
				std::string input = util::Utilities::getInput("","",true);
				if (!input.empty())
				{
					if (input[0] == '!')
					{
						input.erase(0, 1);
						if (input[0] == '!')
							input = lastInput;
					
						std::stringstream ss(input);
						std::istream_iterator<std::string> begin(ss);
						std::istream_iterator<std::string> end;
						util::Args args(begin, end);
						args = util::Utilities::extractLiteralArgs(args);

						if (!args.empty())
						{
							std::string command = args[0];
							
							if (command == "exit")
							{
								util::linfo << "Exiting app..." << std::endl;
								c.stop();
								io_context.stop();
								exit(0);
							}
							else if (command == "ping")
							{
								c.handleCommandPing(args);
							}
							else if (command == "set-port")
							{
								c.handleCommandSetPort(args);
							}
							else if (command == "set-ip")
							{
								c.handleCommandSetLastServer(args);
							}
							else if (command == "set-username")
							{
								c.handleCommandSetUsername(args);
							}
							else if (command == "set-autoconnect")
							{
								c.handleCommandSetAutoconnect(args);
							}
							else if (command == "start")
							{
								clientThread = std::thread([&]() {
									if (c.start(r.resolve(c.lastServer, c.port)))
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
							else if (command == "to" || command == "send" || command == "message" || command == "msg")
							{
								c.handleCommandTo(args);
							}
							else if (command == "online" || command == "who")
							{
								c.handleCommandOnline(args);
							}
							else if (command == "rooms")
							{
								c.handleCommandRooms(args);
							}
							else if (command == "subscribe" || command == "join" || command == "sub")
							{
								c.handleCommandSubscribe(args);
							}
							else if (command == "unsubscribe" || command == "leave" || command == "unsub")
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
							else if (command == "stream")
							{
								c.handleCommandSetStream(args);
							}
							else if (command == "files")
							{
								c.handleCommandFiles(args);
							}
							else if (command == "download" || command == "get")
							{
								c.handleCommandDownload(args);
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
					else if (c.isStreaming())
					{
						c.handleCommandInlineMessage(input);
					}
					else
					{
						util::lerr << "'" << input << "' is not a valid command." << std::endl;
					}
					lastInput = input;
				}
				c.unlockDump();
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