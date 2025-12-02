#pragma once

#include <string>
#include <drogon/HttpResponse.h>

class SecurityUtils {
public:
    static std::string hashPassword(const std::string &password, const std::string &salt);
    static std::string generateSalt(const std::string &username);
    static std::pair<bool, std::string> validatePassword(const std::string &password);
    static void addCorsHeaders(const drogon::HttpResponsePtr &resp);
};
