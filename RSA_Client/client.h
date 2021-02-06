#pragma once

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <functional>
#include <iostream>
#include <string>
#include <queue>

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#pragma comment(lib, "User32.lib")

#include "json.hpp"

#include "Base64.h"

#include "Keyring.h"

#include "Utilities.h"

using boost::asio::steady_timer;
using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;

namespace net
{
	class client
	{
	public:

		std::string serverPublicKey;
		Keyring clientKeys;

		client(boost::asio::io_context& io_context);

		// Called by the user of the client class to initiate the connection process.
		// The endpoints will have been obtained using a tcp::resolver.
		bool start(tcp::resolver::results_type endpoints);

		// Called by the user of the client class to initiate the connection process.
		// The endpoints will have been obtained using a tcp::resolver.
		void restart(bool ask = false);

		// This function terminates all the actors to shut down the connection. It
		// may be called by the user of the client class, or by the class itself in
		// response to graceful termination or an unrecoverable error.
		void stop();

		void disconnect();

		void setKeys(Keyring keys);
		void setUsername(std::string username);

		void start_connect(tcp::resolver::results_type::iterator endpoint_iter);

		bool isStreaming();

		void handleCommandSetStream(util::Args args);

		void handleCommandInlineMessage(std::string message);

		void handleCommandCreate(util::Args args);

		void handleCommandRemove(util::Args args);

		void handleCommandSubscribe(util::Args args);

		void handleCommandUnsubscribe(util::Args args);

		void handleCommandTo(util::Args args);

		void handleCommandOnline(util::Args args);

		void handleCommandRooms(util::Args args);

		void handleCommandPing(util::Args args);

		void handle_connect(const boost::system::error_code& error,
			tcp::resolver::results_type::iterator endpoint_iter);

		void start_read();

		void handle_read(const boost::system::error_code& error, std::size_t n);

		void dumpMessage(nlohmann::json j);

		void processWelcome(std::string data);

		void processEncryptedMessage(nlohmann::json j);

		void processMessage(std::string messageData);

		void sendJson(nlohmann::json j);

		void writePacket(std::string response);

		void writePacket(boost::asio::const_buffer response);

		void handle_write(const boost::system::error_code& error);

		void dumpConsoleStream();
	private:
		bool stopped_ = false;
		tcp::resolver::results_type endpoints_;
		tcp::socket socket_;

		const size_t max_length = 4096;
		char data_[4096];

		const size_t packet_body_length = 4096;
		char packet_body[4096];

		uint32_t expectedLength = 4;
		uint32_t messageCounter = 0;

		std::vector<CryptoPP::byte> sessionIV, sessionKey;

		std::string serverFingerPrint;

		std::string username;

		std::thread interruptThread;

		std::string stream;

		std::stringstream out;

		std::stringstream& err();
		std::stringstream& info();
		std::stringstream& in();
		std::stringstream& dump();



	};

}