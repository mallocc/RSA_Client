#include "client.h"

net::client::client(boost::asio::io_context& io_context)
	: socket_(io_context),
	data_(),
	packet_body()
{
}

// Called by the user of the client class to initiate the connection process.
// The endpoints will have been obtained using a tcp::resolver.

void net::client::start(tcp::resolver::results_type endpoints)
{
	// Start the connect actor.
	endpoints_ = endpoints;
	restart();
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

void net::client::start_connect(tcp::resolver::results_type::iterator endpoint_iter)
{
	if (endpoint_iter != endpoints_.end())
	{
		std::cout << "Trying " << endpoint_iter->endpoint() << "...\n";

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

void net::client::handle_connect(const boost::system::error_code& error, tcp::resolver::results_type::iterator endpoint_iter)
{
	if (stopped_)
		return;

	// The async_connect() function automatically opens the socket at the start
	// of the asynchronous operation. If the socket is closed at this time then
	// the timeout handler must have run first.
	if (!socket_.is_open())
	{
		std::cout << "Connect timed out\n";

		// Try the next available endpoint.
		start_connect(++endpoint_iter);
	}

	// Check if the connect operation failed before the deadline expired.
	else if (error)
	{
		std::cout << "Connect error: " << error.message() << "\n";

		// We need to close the socket used in the previous connection attempt
		// before starting a new one.
		socket_.close();

		// Try the next available endpoint.
		start_connect(++endpoint_iter);
	}

	// Otherwise we have successfully established a connection.
	else
	{
		std::cout << "Connected to " << endpoint_iter->endpoint() << "\n";

		// Start the input actor.
		start_read();

		auto keyboardInterrupt = [&]() {
			while (true)
			{
				if (GetAsyncKeyState(VK_ESCAPE))
				{
					std::cout << "> ";
					std::string inString;
					std::getline(std::cin, inString);
					sendMessage(SCHEMA_TYPE__ECHO, inString);
				}
				using namespace std::chrono_literals;
				std::this_thread::sleep_for(100ms);
			}
		};

		std::thread interruptThread(keyboardInterrupt);
		interruptThread.detach();


		sendMessage(SCHEMA_TYPE__ANNOUNCE, clientPublicKey);
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
		std::cout << "Error on receive: " << error.message() << "\n";

		//stop();
	}
}

void net::client::printMessage(std::string type, std::string data)
{
	std::cout << "[" << type << "]:" << data << std::endl;
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

			if (type == SCHEMA_TYPE__RSA_PUB)
			{
				serverPublicKey = data;
				printMessage(type, data);
			}
			else if (type == SCHEMA_TYPE__ECHO)
			{
				printMessage(type, decodedData);
			}
			else if (type == SCHEMA_TYPE__ANNOUNCE)
			{
				printMessage(type, decodedData);
			}
			else
			{
				printMessage(type, data);
			}
		}

	}
	catch (nlohmann::json::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
}

void net::client::sendMessage(std::string type, std::string message)
{
	try
	{
		nlohmann::json j;

		j[SCHEMA_TYPE] = type;
		j[SCHEMA_DATA] = macaron::Base64::Encode(message);
		j["username"] = macaron::Base64::Encode("mallocc");

		std::string jsonData = j.dump();
		writePacket(boost::asio::const_buffer(jsonData.c_str(), jsonData.length()));

	}
	catch (nlohmann::json::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
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

inline void net::client::handle_write(const boost::system::error_code& error)
{
	if (stopped_)
		return;

	if (!error)
	{

	}
	else
	{
		std::cout << "Error on writing: " << error.message() << "\n";

		//stop();
	}
}
