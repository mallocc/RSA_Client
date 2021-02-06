#include "client.h"

#include <rsa.h>
#include <aes.h>
#include <filters.h>
#include "modes.h"
#include <boost/filesystem.hpp>
#include <conio.h>


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
	const std::string SCHEMA_TYPE__WELCOME = "welcome";
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
		util::lerr << "RSA Keys not set" << util::lend;
	}

	return success;
}

// Called by the user of the client class to initiate the connection process.
// The endpoints will have been obtained using a tcp::resolver.

void net::client::restart(bool ask)
{
	bool success = true;

	if (success)
	{
		stopped_ = false;
		start_connect(endpoints_.begin());
	}
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

void net::client::disconnect()
{
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
		util::linfo << "Reestablishing connection on " << endpoint_iter->endpoint() << "..." << util::lend;

		// Start the asynchronous connect operation.
		socket_.async_connect(endpoint_iter->endpoint(),
			std::bind(&client::handle_connect,
				this, _1, endpoint_iter));
	}
}

bool net::client::isStreaming()
{
	return !stream.empty();
}

void net::client::handleCommandSetStream(util::Args args)
{
	if (args.size() == 1)
	{
		stream = util::Utilities::getInput("Stream", "", false);
	}
	else
	{
		util::lerr << "Incorrect argument count. Should be 1." << std::endl;
	}
}

void net::client::handleCommandInlineMessage(std::string message)
{
	if (!stream.empty())
	{
		nlohmann::json crypt;
		crypt[SCHEMA_TYPE] = "message";
		crypt["to"] = macaron::Base64::Encode(stream);
		crypt["data"] = macaron::Base64::Encode(message);

		sendJson(crypt);
	}
}

void net::client::handleCommandCreate(util::Args args)
{
	if (args.size() == 1)
	{
		nlohmann::json crypt;
		crypt[SCHEMA_TYPE] = "create";
		crypt["create"] = macaron::Base64::Encode(util::Utilities::getInput("Type", "", false));
		crypt["name"] = macaron::Base64::Encode(util::Utilities::getInput("Name", "", false));

		sendJson(crypt);
	}
	else
	{
		util::lerr << "Incorrect argument count. Should be 1." << std::endl;
	}
}

void net::client::handleCommandRemove(util::Args args)
{
	if (args.size() == 1)
	{
		nlohmann::json crypt;
		crypt[SCHEMA_TYPE] = "remove";
		crypt["remove"] = macaron::Base64::Encode(util::Utilities::getInput("Type", "", false));
		crypt["name"] = macaron::Base64::Encode(util::Utilities::getInput("Name", "", false));

		sendJson(crypt);
	}
	else
	{
		util::lerr << "Incorrect argument count. Should be 1." << std::endl;
	}
}

void net::client::handleCommandSubscribe(util::Args args)
{
	if (args.size() == 1)
	{
		nlohmann::json crypt;
		crypt[SCHEMA_TYPE] = "subscribe";

		std::string roomName = util::Utilities::getInput("Room name", "", false);
		crypt["data"] = macaron::Base64::Encode(roomName);

		sendJson(crypt);

		stream = roomName;
	}
	else
	{
		util::lerr << "Incorrect argument count. Should be 1." << std::endl;
	}
}

void net::client::handleCommandUnsubscribe(util::Args args)
{
	if (args.size() == 1)
	{
		nlohmann::json crypt;
		crypt[SCHEMA_TYPE] = "unsubscribe";
		crypt["data"] = macaron::Base64::Encode(util::Utilities::getInput("Room name", "", false));

		sendJson(crypt);

		stream.clear();
	}
	else
	{
		util::lerr << "Incorrect argument count. Should be 1." << std::endl;
	}
}

void net::client::handleCommandTo(util::Args args)
{
	if (args.size() == 2)
	{
		nlohmann::json crypt;
		crypt[SCHEMA_TYPE] = "message";
		crypt["to"] = macaron::Base64::Encode(args[1]);
		crypt["data"] = macaron::Base64::Encode(util::Utilities::getInput("Message", "", false));

		sendJson(crypt);
	}
	else
	{
		util::lerr << "Incorrect argument count. Should be 2." << std::endl;
	}
}

void net::client::handleCommandOnline(util::Args args)
{
	if (args.size() == 1)
	{
		nlohmann::json crypt;
		crypt[SCHEMA_TYPE] = "online";

		sendJson(crypt);
	}
	else
	{
		util::lerr << "Incorrect argument count. Should be 1." << std::endl;
	}
}

void net::client::handleCommandRooms(util::Args args)
{
	if (args.size() == 1)
	{
		nlohmann::json crypt;
		crypt[SCHEMA_TYPE] = "rooms";

		sendJson(crypt);
	}
	else
	{
		util::lerr << "Incorrect argument count. Should be 1." << std::endl;
	}
}

void net::client::handleCommandPing(util::Args args)
{
	auto ping = [&]() {
		util::linfo << "Sent ping to server." << std::endl;

		nlohmann::json j;
		j["type"] = "cping";
		uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch()
			).count();
		j["ts"] = ms;

		writePacket(j.dump());
	};

	if (args.size() == 1)
	{
		ping();
	}
	else
	{
		util::lerr << "Incorrect argument count. Should be 1." << std::endl;
	}
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
		util::lerr << "Connect timed out" << util::lend;

		// Try the next available endpoint.
		start_connect(++endpoint_iter);

		stop();
	}

	// Check if the connect operation failed before the deadline expired.
	else if (error)
	{
		util::lerr << "Connect error: " << error.message() << util::lend;

		// We need to close the socket used in the previous connection attempt
		// before starting a new one.
		socket_.close();

		// Try the next available endpoint.
		start_connect(++endpoint_iter);

		stop();
	}

	// Otherwise we have successfully established a connection.
	else
	{
		util::linfo << "Connected to " << endpoint_iter->endpoint() << util::lend;

		// Start the input actor.
		start_read();
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

		processMessage(message);

		start_read();
	}
	else
	{
		util::lerr << "Error on receive: " << error.message() << util::lend;

		stop();
	}

}

void net::client::dumpMessage(nlohmann::json j)
{
	util::ldump << j.dump(2) << std::endl;
}

void net::client::processWelcome(std::string data)
{
	serverPublicKey = data;

	// decode server public key
	std::string decoded;
	macaron::Base64::Decode(data, decoded);

	// store service finger print for checking later
	serverFingerPrint = util::Utilities::sha256(decoded);
	util::linfo << "Server fingerprint <" << ANSI_CYAN_BG << serverFingerPrint << ANSI_RESET << ">" << util::lend;

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
			util::lerr << "Server fingerprint does not match keyring! Use command 'forget-server <ip>' to accept new fingerprint." << util::lend;

			//// let the user decide if they want to update the public key
			//if (util::Utilities::yesNo("Are you sure you want to connect?", false))
			//{
			//	CryptoPP::FileSink pubkeysink(filename.c_str());
			//	publicKey.DEREncode(pubkeysink);
			//	pubkeysink.MessageEnd();
			//	util::linfo << "Keyring updated." << util::lend;
			//}
			//else
			//{
			//	util::lerr << "Key rejected, not updating key." << util::lend;

			//	stop();
			//}
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
	crypt["username"] = macaron::Base64::Encode(username);

	std::string cipherText;
	util::Utilities::AESEcryptJson(crypt, sessionKey, sessionIV, cipherText);
	// load the encrypted encoded client public key
	j[SCHEMA_CRYPT] = cipherText;

	// send it
	writePacket(j.dump());
}

void net::client::processEncryptedMessage(nlohmann::json j)
{
	std::string type;
	if (j.contains(SCHEMA_TYPE))
	{
		type = j[SCHEMA_TYPE];
	}

	if (type == "message")
	{
		std::string message;

		if (j.contains("data"))
		{
			macaron::Base64::Decode(j["data"], message);
		}

		std::string room;

		if (j.contains("room"))
		{
			macaron::Base64::Decode(j["room"], room);

			std::cout << room << ": ";
		}

		std::string from;

		if (j.contains("from"))
		{
			macaron::Base64::Decode(j["from"], from);

			std::cout << from << ": " << message << std::endl;
		}
	}
	else if (type == "online")
	{
		if (j.contains("users"))
		{
			std::cout << "Users online: " << std::endl;

			nlohmann::json users = j["users"];
			// range-based for
			for (auto& element : users) {
				std::string user;
				macaron::Base64::Decode(element, user);
				std::cout << '\t' << user << std::endl;
			}

			std::cout << std::endl;
		}
	}
	else if (type == "rooms")
	{
		if (j.contains("rooms"))
		{
			std::cout << "Rooms: " << std::endl;

			nlohmann::json rooms = j["rooms"];
			// range-based for
			for (auto& element : rooms) {
				std::string room;
				macaron::Base64::Decode(element, room);
				std::cout << '\t' << room << std::endl;
			}

			std::cout << std::endl;
		}
	}
	else if (type == "notice")
	{
		std::string data;

		if (j.contains("data"))
		{
			macaron::Base64::Decode(j["data"], data);
		}

		std::cout << data << std::endl;
	}

	else if (type == "announce_response")
	{
		std::string data;

		if (j.contains("data"))
		{
			data = j["data"];
		}

		if (data != "OK")
		{
			util::lerr << "Server refused login. Reason: " << data << std::endl;
		}
	}
	else
	{
		dumpMessage(j);
	}
}

void net::client::processMessage(std::string messageData)
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
			data = j[SCHEMA_DATA];

			if (type == SCHEMA_TYPE__WELCOME)
			{
				processWelcome(data);
			}
			else if (type == SCHEMA_TYPE__CRYPT)
			{
				nlohmann::json crypt;
				util::Utilities::AESDecryptJson(j[SCHEMA_DATA], crypt, sessionKey, sessionIV);

				processEncryptedMessage(crypt);
			}
			else
			{
				dumpMessage(j);
			}
		}

		if (j.contains("ts"))
		{
			if (type == "ping")
			{
				writePacket(j.dump());
			}
			else if (type == "cping")
			{
				uint64_t ts_ = j["ts"];
				uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::system_clock::now().time_since_epoch()
					).count();
				std::stringstream ss;
				ss << (ms - ts_) / 2 << "ms";
				util::linfo << "Ping returned in " << ss.str() << std::endl;
			}
		}

	}
	catch (nlohmann::json::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
}

void net::client::sendJson(nlohmann::json crypt)
{
	// create a json message to send
	nlohmann::json j;

	// load the encrypted encoded Key and IV
	j[SCHEMA_TYPE] = SCHEMA_TYPE__CRYPT;

	// encrypt the client public key for the server to use
	std::string cipherText;
	util::Utilities::AESEcryptJson(crypt, sessionKey, sessionIV, cipherText);
	// load the encrypted encoded client public key
	j[SCHEMA_DATA] = cipherText;

	// send it
	writePacket(j.dump());
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
		util::lerr << "Error on writing: " << error.message() << "\n";

		//stop();
	}
}

std::stringstream& net::client::err()
{
	out << util::ERROR_MSG;
	return out;
}

std::stringstream& net::client::info()
{
	out << util::INFO_MSG;
	return out;
}

std::stringstream& net::client::in()
{
	out << util::IN_MSG;
	return out;
}

std::stringstream& net::client::dump()
{
	out << util::DUMP_MSG;
	return out;
}

void net::client::dumpConsoleStream()
{
	std::cout << out.str();
	out.str("");
}

void net::client::setUsername(std::string username)
{
	this->username = username;
}


