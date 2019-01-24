#ifndef LOGGING_H
#define LOGGING_H

#ifndef SPDLOG_ACTIVE_LEVEL
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_ERROR
#endif

//spdlog.h MUST be included first, so I'm putting it here to prevent any clang-format shenanigans
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#endif /* end of include guard: LOGGING_H */
