#include "SecurityUtils.h"
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <regex>

std::string SecurityUtils::hashPassword(const std::string &password, const std::string &salt) {
    std::string saltedPassword = salt + password;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, saltedPassword.c_str(), saltedPassword.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string SecurityUtils::generateSalt(const std::string &username) {
    return "StarLightERP_" + username + "_SALT";
}

std::pair<bool, std::string> SecurityUtils::validatePassword(const std::string &password) {
    if (password.empty()) {
        return {false, "Password cannot be empty"};
    }
    
    if (password.length() < 8) {
        return {false, "Password must be at least 8 characters long"};
    }
    
    if (!std::regex_search(password, std::regex("[A-Z]"))) {
        return {false, "Password must contain at least one uppercase letter"};
    }
    
    if (!std::regex_search(password, std::regex("[a-z]"))) {
        return {false, "Password must contain at least one lowercase letter"};
    }
    
    if (!std::regex_search(password, std::regex("[0-9]"))) {
        return {false, "Password must contain at least one number"};
    }
    
    if (!std::regex_search(password, std::regex("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]"))) {
        return {false, "Password must contain at least one special character"};
    }
    
    return {true, ""};
}

void SecurityUtils::addCorsHeaders(const drogon::HttpResponsePtr &resp) {
    resp->addHeader("Access-Control-Allow-Origin", "https://starlighterp.com");
    resp->addHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT");
    resp->addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    resp->addHeader("Access-Control-Allow-Credentials", "true");
}
