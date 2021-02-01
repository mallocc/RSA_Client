#include "client.h"

#include <rsa.h>
#include <aes.h>
#include <filters.h>
#include "modes.h"
#include <boost/filesystem.hpp>

using util::ANSI_BLUE;
using util::ANSI_YELLOW;
using util::ANSI_RED;
using util::ANSI_GREEN;
using util::ANSI_MAGENTA;
using util::ANSI_RESET;
using util::ANSI_CYAN;
using util::ANSI_CYAN_BG;
using util::ANSI_WHITE;
using util::ERROR_MSG;
using util::INFO_MSG;

namespace
{
	const std::string SCHEMA_TYPE = "type";
	const std::string SCHEMA_DATA = "data";
	const std::string SCHEMA_AES_KEY = "aes_key";
	const std::string SCHEMA_AES_IV = "aes_iv";
	const std::string SCHEMA_CRYPT = "crypt";
	const std::string SCHEMA_PUBLIC_KEY = "public_key";

	const std::string SCHEMA_TYPE__RSA_PUB = "RSA_PUB";
	const std::string SCHEMA_TYPE__WELCOME= "welcome";
	const std::string SCHEMA_TYPE__ECHO = "echo";
	const std::string SCHEMA_TYPE__ANNOUNCE = "announce";
	const std::string SCHEMA_TYPE__CRYPT = "crypt";
}

net::client::client(boost::asio::io_context& io_context)
	: socket_(io_context),
	data_(),
	packet_body()
{
}

// Called by the user of the client class to initiate the connection process.
// The endpoints will have been obtained using a tcp::resolver.

bool net::client::start(tcp::resolver::results_type endpoints)
{
	bool success = false;

	if (clientKeys.valid)
	{
		// Start the connect actor.
		endpoints_ = endpoints;
		restart();

		success = true;
	}
	else
	{
		std::cout << ANSI_RED << "RSA Keys not set\n" << ANSI_RESET;
	}

	return success;
}

// Called by the user of the client class to initiate the connection process.
// The endpoints will have been obtained using a tcp::resolver.

void net::client::restart()
{
	start_connect(endpoints_.begin());
}

// This function terminates all the actors to shut down the connection. It
// may be called by the user of the client class, or by the class itself in
// response to graceful termination or an unrecoverable error.

void net::client::stop()
{
	stopped_ = true;
	boost::system::error_code ignored_error;
	socket_.close(ignored_error);
}

void net::client::setKeys(Keyring keys)
{
	clientKeys = keys;
}

void net::client::start_connect(tcp::resolver::results_type::iterator endpoint_iter)
{
	if (endpoint_iter != endpoints_.end())
	{
		std::cout << INFO_MSG << "Reestablishing connection on " << endpoint_iter->endpoint() << "...\n";

		// Start the asynchronous connect operation.
		socket_.async_connect(endpoint_iter->endpoint(),
			std::bind(&client::handle_connect,
				this, _1, endpoint_iter));
	}
	else
	{
		//// There are no more endpoints to try. Shut down the client.
		//stop();

		restart();
	}
}

void net::client::handleInputCommand(std::string command)
{
	if (command == "ping")
	{
		std::stringstream ss;
		ss << "pinging server...";
		printClientMessage(command, ss.str());

		nlohmann::json j;
		j["type"] = "cping";
		uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch()
			).count();
		j["ts"] = ms;

		writePacket(j.dump());
	}
	else
	{
		sendEcho(command);
	}
}

void net::client::startInputThread()
{
	auto keyboardInterrupt = [&]() {
		while (true)
		{
			if (GetAsyncKeyState(VK_ESCAPE))
			{
				std::cout << "> ";
				std::string inString;
				std::getline(std::cin, inString);
				handleInputCommand(inString);
			}
			using namespace std::chrono_literals;
			std::this_thread::sleep_for(100ms);
		}
	};

	std::thread interruptThread(keyboardInterrupt);
	interruptThread.detach();
}

void net::client::handle_connect(const boost::system::error_code& error, tcp::resolver::results_type::iterator endpoint_iter)
{
	if (stopped_)
		return;

	// The async_connect() function automatically opens the socket at the start
	// of the asynchronous operation. If the socket is closed at this time then
	// the timeout handler must have run first.
	if (!socket_.is_open())
	{
		std::cout << ERROR_MSG << "Connect timed out\n";

		// Try the next available endpoint.
		start_connect(++endpoint_iter);
	}

	// Check if the connect operation failed before the deadline expired.
	else if (error)
	{
		std::cout << ERROR_MSG << "Connect error: " << error.message() << "\n";

		// We need to close the socket used in the previous connection attempt
		// before starting a new one.
		socket_.close();

		// Try the next available endpoint.
		start_connect(++endpoint_iter);
	}

	// Otherwise we have successfully established a connection.
	else
	{
		std::cout << INFO_MSG << "Connected to " << endpoint_iter->endpoint() << "\n";

		// Start the input actor.
		start_read();

		startInputThread();
	}
}

void net::client::start_read()
{
	//read start of packet
	boost::asio::async_read(socket_, boost::asio::buffer(data_, 4), std::bind(&client::handle_read, this, _1, _2));
}

void net::client::handle_read(const boost::system::error_code& error, std::size_t n)
{
	if (!error)
	{
		uint32_t dataSize = 0;
		memcpy(&dataSize, data_, 4);

		//std::cout << "Packet Size: " << dataSize << std::endl;

		if (dataSize > packet_body_length) {
			//big problem, packet too big
		}

		boost::asio::read(socket_, boost::asio::buffer(packet_body, dataSize));

		std::string message = std::string(packet_body, dataSize);

		readMessage(message);

		start_read();
	}
	else
	{
		std::cout << ERROR_MSG << "Error on receive: " << error.message() << "\n";

		//stop();

		restart();
	}

}

void net::client::printServerMessage(std::string type, std::string data)
{
	std::cout << "[" << ANSI_MAGENTA << type << ANSI_RESET << "]: " << data << std::endl;
}

void net::client::printClientMessage(std::string type, std::string data)
{
	std::cout << "[" << ANSI_CYAN << type << ANSI_RESET << "]: " << data << std::endl;
}

void net::client::handleWelcome(std::string data)
{
	serverPublicKey = data;

	// decode server public key
	std::string decoded;
	macaron::Base64::Decode(data, decoded);

	// store service finger print for checking later
	serverFingerPrint = util::Utilities::sha256(decoded);
	std::cout << INFO_MSG << "Server fingerprint <" << ANSI_CYAN_BG << serverFingerPrint << ANSI_RESET << ">" << std::endl;

	// retrieve the public key data from the message
	CryptoPP::StringSource ss((const CryptoPP::byte*) decoded.c_str(), decoded.size(), true);
	CryptoPP::RSA::PublicKey publicKey;
	publicKey.BERDecode(ss);

	// get the saved server public key if it exists
	std::string filename = "keys/server/" + socket_.remote_endpoint().address().to_string() + ".der";
	boost::filesystem::create_directory("keys/server/");
	if (!boost::filesystem::exists(filename))
	{
		// doesnt exist so store the one we got given
		CryptoPP::FileSink pubkeysink(filename.c_str());
		publicKey.DEREncode(pubkeysink);
		pubkeysink.MessageEnd();
	}
	else
	{
		// we have one stored already so we need to check it is still the same

		// get the stored server public key
		std::string fileb;
		CryptoPP::FileSource b641(filename.c_str(), true,
			new CryptoPP::StringSink(fileb)
		);
		// create a finger print to compare
		std::string serverFingerPrintFromFile = util::Utilities::sha256(fileb);
		if (serverFingerPrint != serverFingerPrintFromFile)
		{
			std::cout << ERROR_MSG << "Server fingerprint does not match keyring!" << std::endl;

			// let the user decide if they want to update the public key
			if (util::Utilities::yesNo("Are you sure you want to connect?", false))
			{
				CryptoPP::FileSink pubkeysink(filename.c_str());
				publicKey.DEREncode(pubkeysink);
				pubkeysink.MessageEnd();
				std::cout << INFO_MSG << "Keyring updated." << std::endl;
			}
			else
			{
				std::cout << ERROR_MSG << "Key rejected, not updating key." << std::endl;

				stop();
			}
		}
	}

	// now we need to create a new aes key to crypt futher message with

	// create IV and Key
	CryptoPP::AutoSeededRandomPool rng;
	std::vector<CryptoPP::byte> iv;
	iv.resize(16);
	std::vector<CryptoPP::byte> key;
	key.resize(16);
	rng.GenerateBlock((CryptoPP::byte*)iv.data(), 16);
	rng.GenerateBlock((CryptoPP::byte*)key.data(), 16);

	// we need RSA encrypt the IV and Key
	std::vector<CryptoPP::byte> iv_rsa;
	iv_rsa.resize(256);
	std::vector<CryptoPP::byte> key_rsa;
	key_rsa.resize(256);
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(publicKey);
	e.Encrypt(rng, (CryptoPP::byte*)iv.data(), iv.size(), iv_rsa.data());
	e.Encrypt(rng, (CryptoPP::byte*)key.data(), key.size(), key_rsa.data());

	// lastly, base64 encode the keys so that it can be sent with alphanumeric characters
	std::string iv_b64;
	std::string key_b64;
	CryptoPP::Base64Encoder encoder;
	encoder.Attach(new CryptoPP::StringSink(iv_b64));
	encoder.Put(iv_rsa.data(), 256);
	encoder.MessageEnd();
	CryptoPP::Base64Encoder encoder2;
	encoder2.Attach(new CryptoPP::StringSink(key_b64));
	encoder2.Put(key_rsa.data(), 256);
	encoder2.MessageEnd();

	// store for later messages
	sessionIV = iv;
	sessionKey = key;

	// create a json message to send
	nlohmann::json j;

	// load the encrypted encoded Key and IV
	j[SCHEMA_TYPE] = SCHEMA_TYPE__ANNOUNCE;
	j[SCHEMA_AES_KEY] = key_b64;
	j[SCHEMA_AES_IV] = iv_b64;

	// encrypt the client public key for the server to use
	nlohmann::json crypt;
	crypt[SCHEMA_PUBLIC_KEY] = macaron::Base64::Encode(clientKeys.publicKey);
	std::string cipherText;
	util::Utilities::AESEcryptJson(crypt, sessionKey, sessionIV, cipherText);
	// load the encrypted encoded client public key
	j[SCHEMA_CRYPT] = cipherText;

	// send it
	writePacket(j.dump());
}

void net::client::readMessage(std::string messageData)
{
	try
	{
		nlohmann::json j = nlohmann::json::parse(messageData);

		std::string type;
		std::string data;

		if (j.contains(SCHEMA_TYPE))
		{
			type = j[SCHEMA_TYPE];
		}

		if (j.contains(SCHEMA_DATA))
		{
			std::string decodedData;
			data = j[SCHEMA_DATA];
			macaron::Base64::Decode(data, decodedData);

			if (type == SCHEMA_TYPE__WELCOME)
			{
				handleWelcome(data);
			}
			else if (type == SCHEMA_TYPE__CRYPT)
			{				
				nlohmann::json crypt;
				util::Utilities::AESDecryptJson(j[SCHEMA_DATA], crypt, sessionKey, sessionIV);

				printServerMessage(type, crypt.dump(2));
			}
			else if (type == SCHEMA_TYPE__ECHO)
			{
				printServerMessage(type, decodedData);
			}
			else if (type == SCHEMA_TYPE__ANNOUNCE)
			{
				printServerMessage(type, decodedData);
			}
			else
			{
				printServerMessage(type, data);
			}
		}

		if (j.contains("ts"))
		{
			if (type == "ping")
			{
				writePacket(j.dump());
				printServerMessage(type, "ping from server");
			}			
			else if (type == "cping")
			{
				uint64_t ts_ = j["ts"];
				uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::system_clock::now().time_since_epoch()
					).count();
				std::stringstream ss;
				ss << (ms - ts_) / 2 << "ms";
				printServerMessage(type, ss.str());
			}
		}

	}
	catch (nlohmann::json::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
}

void net::client::sendEcho(std::string message)
{
	try
	{
		printClientMessage("echo", message);

		nlohmann::json j;

		j[SCHEMA_TYPE] = SCHEMA_TYPE__ECHO;
		j[SCHEMA_DATA] = macaron::Base64::Encode(message);

		writePacket(j.dump());
	}
	catch (nlohmann::json::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
}

void net::client::writePacket(std::string response)
{
	writePacket(boost::asio::const_buffer(response.c_str(), response.length()));
}

void net::client::writePacket(boost::asio::const_buffer response)
{
	uint32_t totalSize = response.size() + 4;
	char* packet = new char[totalSize];

	uint32_t size = response.size();
	memcpy(&packet[0], &size, 4);
	memcpy(&packet[4], response.data(), size);

	boost::asio::async_write(socket_, boost::asio::buffer(packet, totalSize),
		std::bind(&client::handle_write, this, _1));
}

void net::client::handle_write(const boost::system::error_code& error)
{
	if (stopped_)
		return;

	if (!error)
	{

	}
	else
	{
		std::cout << ERROR_MSG << "Error on writing: " << error.message() << "\n";

		//stop();
	}
}
