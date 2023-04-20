#pragma once

#include <map>
#include <string_view>
#include <functional>
#include <utility>

using UtilHandler = std::function<int(int, const char**)>;

const std::map<std::string_view, UtilHandler> &GetUtilHandlers();
