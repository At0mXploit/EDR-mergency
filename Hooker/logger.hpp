// logger.hpp
#ifndef LOGGER_H
#define LOGGER_H

#include <string>

namespace Logger {
    void LogMessage(const std::string& message);
    void Cleanup();

    // Optional: expose for testing
    void InitializeETW(); // You can call this early if you want
}

#endif // !LOGGER_H
