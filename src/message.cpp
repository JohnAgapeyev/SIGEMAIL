#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <sstream>
#include <string>

#include "crypto.h"
#include "message.h"

std::string serialize_message(const signal_message& mesg) {
    std::stringstream ss;
    boost::archive::text_oarchive arch{ss};
    arch << mesg;
    return ss.str();
}

signal_message deserialize_message(const std::string mesg) {
    try {
        std::stringstream ss{mesg};
        boost::archive::text_iarchive arch{ss};
        signal_message m;
        arch >> m;
        return m;
    } catch (const boost::archive::archive_exception&) {
        throw std::runtime_error("Archive deserialization encountered an error");
    }
}
