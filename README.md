# SIGEMAIL
This application implements the [Signal Protocol](https://signal.org/docs/) in C++ to create an End-to-End Encrypted email service.
Similar to Signal, the primary communication is direct over the network, with external email import/export via SMTP/IMAP.

## Usage:
Server usage:
`./bin/sigemail_server <listening_port> <number of threads>`

Client usage:
`./bin/sigemail <server_address> <server_port>`

## Compilation:
To compile simply run the following commands:
```
cmake .
make
```

Compilation requires:
 - CMake 3.13.0 or later
 - Linux
 - C++17 compliant compiler
 - OpenSSL 1.1.1 or later
 - Curl 7.30 or later
 - Qt5
 - Boost 1.67 or later

