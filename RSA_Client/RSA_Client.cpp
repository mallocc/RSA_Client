//
// async_tcp_client.cpp
// ~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
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

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

#include "json.hpp"

#include "Base64.h"

using boost::asio::steady_timer;
using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;

//
// This class manages socket timeouts by applying the concept of a deadline.
// Some asynchronous operations are given deadlines by which they must complete.
// Deadlines are enforced by an "actor" that persists for the lifetime of the
// client object:
//
//  +----------------+
//  |                |
//  | check_deadline |<---+
//  |                |    |
//  +----------------+    | async_wait()
//              |         |
//              +---------+
//
// If the deadline actor determines that the deadline has expired, the socket
// is closed and any outstanding operations are consequently cancelled.
//
// Connection establishment involves trying each endpoint in turn until a
// connection is successful, or the available endpoints are exhausted. If the
// deadline actor closes the socket, the connect actor is woken up and moves to
// the next endpoint.
//
//  +---------------+
//  |               |
//  | start_connect |<---+
//  |               |    |
//  +---------------+    |
//           |           |
//  async_-  |    +----------------+
// connect() |    |                |
//           +--->| handle_connect |
//                |                |
//                +----------------+
//                          :
// Once a connection is     :
// made, the connect        :
// actor forks in two -     :
//                          :
// an actor for reading     :       and an actor for
// inbound messages:        :       sending heartbeats:
//                          :
//  +------------+          :          +-------------+
//  |            |<- - - - -+- - - - ->|             |
//  | start_read |                     | start_write |<---+
//  |            |<---+                |             |    |
//  +------------+    |                +-------------+    | async_wait()
//          |         |                        |          |
//  async_- |    +-------------+       async_- |    +--------------+
//   read_- |    |             |       write() |    |              |
//  until() +--->| handle_read |               +--->| handle_write |
//               |             |                    |              |
//               +-------------+                    +--------------+
//
// The input actor reads messages from the socket, where messages are delimited
// by the newline character. The deadline for a complete message is 30 seconds.
//
// The heartbeat actor sends a heartbeat (a message that consists of a single
// newline character) every 10 seconds. In this example, no deadline is applied
// to message sending.
//
class client
{
public:
    client(boost::asio::io_context& io_context)
        : socket_(io_context)
    {
    }

    // Called by the user of the client class to initiate the connection process.
    // The endpoints will have been obtained using a tcp::resolver.
    void start(tcp::resolver::results_type endpoints)
    {
        // Start the connect actor.
        endpoints_ = endpoints;
        start_connect(endpoints_.begin());
    }

    // This function terminates all the actors to shut down the connection. It
    // may be called by the user of the client class, or by the class itself in
    // response to graceful termination or an unrecoverable error.
    void stop()
    {
        stopped_ = true;
        boost::system::error_code ignored_error;
        socket_.close(ignored_error);
    }

private:
    void start_connect(tcp::resolver::results_type::iterator endpoint_iter)
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
            // There are no more endpoints to try. Shut down the client.
            stop();
        }
    }

    void handle_connect(const boost::system::error_code& error,
        tcp::resolver::results_type::iterator endpoint_iter)
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

            //std::string message = "morshu";

            //writeMessage(boost::asio::const_buffer(message.c_str(), message.length()));

            auto keyboardInterrupt = [&]() {
                while (true)
                {
                    if (GetAsyncKeyState(VK_ESCAPE))
                    {
                        std::cout << "> ";
                        std::string inString;
                        std::getline(std::cin, inString);
                        sendMessage("echo", inString);
                    }
                    using namespace std::chrono_literals;
                    std::this_thread::sleep_for(100ms);
                }
            };

            std::thread interruptThread(keyboardInterrupt);
            interruptThread.detach();
        }
    }

    void start_read()
    {
        //read start of packet
        boost::asio::async_read(socket_, boost::asio::buffer(data_, 4),  std::bind(&client::handle_read, this, _1, _2));
    }

    void handle_read(const boost::system::error_code& error, std::size_t n)
    {
        if (!error)
        {
            uint32_t dataSize = 0;
            memcpy(&dataSize, data_, 4);

            std::cout << "Packet Size: " << dataSize << std::endl;

            if(dataSize > packet_body_length) {
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

            stop();
        }
    }


    void readMessage(std::string messageData)
    {
        nlohmann::json j = nlohmann::json::parse(messageData);

        //std::cout << j.dump(2) << std::endl;

        std::string type;
        std::string data;
        std::string decodedData;

        if (j.contains("type"))
        {
            type = j["type"];
        }       

        if (j.contains("data"))
        {
            data = j["data"];
            macaron::Base64::Decode(data, decodedData);
            if (type == "RSA_PUB")
            {
                publicKey = data;

                std::cout << "[RSA_PUB]: " << std::endl << publicKey << std::endl;
            }
            else if (type == "echo")
            {
                std::cout << "[ECHO]:" << decodedData << std::endl;
            }
            else
            {
                std::cout << "[???]:" << data << std::endl;
            }            
        }

        //std::cout << "type:" << type << std::endl;
        //std::cout << "data:" << decodedData << std::endl;
    }

    void sendMessage(std::string type, std::string message)
    {
        nlohmann::json j;

        j["type"] = type;
        j["data"] = macaron::Base64::Encode(message);;

        std::string jsonData = j.dump();
        writePacket(boost::asio::const_buffer(jsonData.c_str(), jsonData.length()));
    }

    void writePacket(boost::asio::const_buffer response)
    {
        uint32_t totalSize = response.size() + 4;
        char* packet = new char[totalSize];

        uint32_t size = response.size();
        memcpy(&packet[0], &size, 4);
        memcpy(&packet[4], response.data(), size);

        boost::asio::async_write(socket_, boost::asio::buffer(packet, totalSize),
            std::bind(&client::handle_write, this, _1));

        delete[] packet;
    }

    void handle_write(const boost::system::error_code& error)
    {
        if (stopped_)
            return;

        if (!error)
        {

        }
        else
        {
            std::cout << "Error on heartbeat: " << error.message() << "\n";

            stop();
        }
    }


private:
    bool stopped_ = false;
    tcp::resolver::results_type endpoints_;
    tcp::socket socket_;
    std::string input_buffer_;
    const size_t max_length = 4096;
    char data_[4096];

    const size_t packet_body_length = 4096;
    char packet_body[4096];

    uint32_t expectedLength = 4;
    uint32_t messageCounter = 0;


    std::string publicKey;
};

int main(int argc, char* argv[])
{
    try
    {
        boost::asio::io_context io_context;
        tcp::resolver r(io_context);
        client c(io_context);

        c.start(r.resolve("81.147.31.211", "32500"));

        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}