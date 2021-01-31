#pragma once

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/filesystem.hpp>
#include <functional>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

#include "json.hpp"

#include "Base64.h"

using boost::asio::steady_timer;
using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;

namespace net
{
	namespace
	{
		const std::string SCHEMA_TYPE = "type";
		const std::string SCHEMA_DATA = "data";

		const std::string SCHEMA_TYPE__RSA_PUB = "RSA_PUB";
		const std::string SCHEMA_TYPE__ECHO = "echo";
		const std::string SCHEMA_TYPE__ANNOUNCE = "announce";
	}


	class client
	{
	public:

		std::string serverPublicKey;
		std::string clientPrivateKey;
		std::string clientPublicKey;

		client(boost::asio::io_context& io_context);

		// Called by the user of the client class to initiate the connection process.
		// The endpoints will have been obtained using a tcp::resolver.
		void start(tcp::resolver::results_type endpoints);

		// Called by the user of the client class to initiate the connection process.
		// The endpoints will have been obtained using a tcp::resolver.
		void restart();

		// This function terminates all the actors to shut down the connection. It
		// may be called by the user of the client class, or by the class itself in
		// response to graceful termination or an unrecoverable error.
		void stop();

	private:
		void start_connect(tcp::resolver::results_type::iterator endpoint_iter);

		void handle_connect(const boost::system::error_code& error,
			tcp::resolver::results_type::iterator endpoint_iter);

		void start_read();

		void handle_read(const boost::system::error_code& error, std::size_t n);

		void printMessage(std::string type, std::string data);

		void readMessage(std::string messageData);

		void sendMessage(std::string type, std::string message);

		void writePacket(boost::asio::const_buffer response);

		void handle_write(const boost::system::error_code& error);

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

	};

}