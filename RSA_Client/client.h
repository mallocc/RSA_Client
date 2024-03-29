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
#include <map>
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#pragma comment(lib, "User32.lib")

#include "json.hpp"

#include "Base64.h"

#include "Keyring.h"

#include "Utilities.h"

#include <mutex>

using boost::asio::steady_timer;
using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;

namespace net
{

	class File
	{
	public:
		File() {}
		File(nlohmann::json j)
		{
			if (j.contains("filename"))
			{
				filename = j["filename"];
			}
			if (j.contains("uid"))
			{
				uid = j["uid"];
			}
			if (j.contains("size"))
			{
				size = j["size"];
			}
		}

		std::string filename;
		std::string uid;
		size_t size = 0;
		size_t chunkSize = 0;
		bool downloading = false;
		std::vector<uint8_t> data;
		std::ofstream fout;
	};

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

		void getChunk(std::string uid, size_t start = 0, size_t chunkSize = 100000ULL);

		void handleCommandDownload(util::Args args);

		void handleCommandFiles(util::Args args);

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

		void dumpJson(nlohmann::json j);

		void processWelcome(std::string data);

		void processEncryptedMessage(nlohmann::json j);

		void processMessage(std::string messageData);

		void sendJson(nlohmann::json j);

		void writePacket(std::string response);

		void writePacket(boost::asio::const_buffer response);

		void handle_write(const boost::system::error_code& error);

		void lockDump();

		void unlockDump();

		bool canDump();

		void dumpConsoleStream();

		void dumpConfig();

		void readConfig();

		void handleCommandSetLastServer(util::Args args);
		void handleCommandSetAutoconnect(util::Args args);
		void handleCommandSetUsername(util::Args args);
		void handleCommandSetPort(util::Args args);

		std::string lastServer;
		bool autoconnect = true;
		std::string username;
		std::string port = "32500";
		std::string configFilename = "client.conf";
	private:
		bool stopped_ = false;
		tcp::resolver::results_type endpoints_;
		tcp::socket socket_;

		std::mutex receiveMutex;

		const size_t max_length = 2000000;
		char data_[2000000];

		const size_t packet_body_length = 2000000;
		char packet_body[2000000];

		uint32_t expectedLength = 4;
		uint32_t messageCounter = 0;

		std::vector<CryptoPP::byte> sessionIV, sessionKey;

		std::string serverFingerPrint;


		std::thread interruptThread;

		std::string stream;

		std::stringstream out;

		std::stringstream& err();
		std::stringstream& info();
		std::stringstream& in();
		std::stringstream& dump();
		std::stringstream& time();

		bool dumpLocked = false;

		std::map<std::string, File> availableFiles;
		File currentFile;
		std::chrono::high_resolution_clock::time_point lastBytesSentTS;
		size_t lastBytesSent;



	};

}