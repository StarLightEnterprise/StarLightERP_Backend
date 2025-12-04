#include "SecurityUtils.h"
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <regex>
#include <trantor/utils/Logger.h>

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

void SecurityUtils::addCorsHeaders(const drogon::HttpResponsePtr &resp, const drogon::HttpRequestPtr &req) {
    // Get the Origin header from the request
    std::string origin = req->getHeader("Origin");
    
    LOG_DEBUG << "Received Origin: " << origin;

    // List of allowed origins (add more as needed)
    std::vector<std::string> allowedOrigins = {
        "https://starlighterp.com",
        "http://localhost:5173",
        "http://localhost:4173",
        "http://localhost:3000",
        "https://127.0.0.1:8080",
        "http://127.0.0.1:8080"
    };
    
    // Check if the origin is allowed
    bool isAllowed = false;
    for (const auto& allowedOrigin : allowedOrigins) {
        if (origin == allowedOrigin) {
            isAllowed = true;
            break;
        }
    }
    
    LOG_DEBUG << "Origin allowed: " << (isAllowed ? "true" : "false");

    // Set CORS headers
    resp->addHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE");
    resp->addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    
    // IMPORTANT: Cannot use wildcard (*) with credentials:true
    // Only set origin and credentials if we have a valid, specific origin
    if (isAllowed && !origin.empty()) {
        resp->addHeader("Access-Control-Allow-Origin", origin);
        resp->addHeader("Access-Control-Allow-Credentials", "true");
    } else if (!origin.empty()) {
        // Origin provided but not in allowed list - don't set any origin header
        // This will cause CORS to fail, which is correct behavior
        LOG_DEBUG << "Origin not in allowed list, not setting Access-Control-Allow-Origin";
    }
    // If origin is empty (same-origin request), no CORS headers needed
}
