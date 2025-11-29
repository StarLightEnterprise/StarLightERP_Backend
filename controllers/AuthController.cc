#include "AuthController.h"
#include <drogon/orm/Mapper.h>
#include <drogon/HttpAppFramework.h>
#include <trantor/utils/Logger.h>
#include <regex>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

using namespace drogon;
using namespace drogon::orm;

// Helper function to hash password using SHA-256 (built-in with OpenSSL)
// In production, use a proper bcrypt library, but for now we'll use SHA-256 + salt
std::string hashPassword(const std::string &password, const std::string &salt = "") {
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

// Generate a simple salt from username
std::string generateSalt(const std::string &username) {
    return "StarLightERP_" + username + "_SALT";
}

std::pair<bool, std::string> AuthController::validatePassword(const std::string &password) {
    // Check if password is empty
    if (password.empty()) {
        return {false, "Password cannot be empty"};
    }
    
    // Check minimum length (at least 8 characters)
    if (password.length() < 8) {
        return {false, "Password must be at least 8 characters long"};
    }
    
    // Check for at least one uppercase letter
    if (!std::regex_search(password, std::regex("[A-Z]"))) {
        return {false, "Password must contain at least one uppercase letter"};
    }
    
    // Check for at least one lowercase letter
    if (!std::regex_search(password, std::regex("[a-z]"))) {
        return {false, "Password must contain at least one lowercase letter"};
    }
    
    // Check for at least one digit
    if (!std::regex_search(password, std::regex("[0-9]"))) {
        return {false, "Password must contain at least one number"};
    }
    
    // Check for at least one special character
    if (!std::regex_search(password, std::regex("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]"))) {
        return {false, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}...)"};
    }
    
    return {true, ""};
}

void AuthController::addCorsHeaders(const HttpResponsePtr &resp) {
    // Allow requests from SvelteKit dev server and production domain
    resp->addHeader("Access-Control-Allow-Origin", "https://starlighterp.com");
    // Note: For multiple origins, we would need to check the Origin header and echo it back if allowed.
    // For now, we'll assume production. If we need both dev and prod simultaneously, we need dynamic handling.
    // Since we are moving to production, setting it to the production domain.
    // Alternatively, we can use "*" if credentials are not required, but they are (Access-Control-Allow-Credentials: true).
    
    // Dynamic origin handling for dev/prod support:
    // This is a simplified version. In a real app, check against a whitelist.
    // resp->addHeader("Access-Control-Allow-Origin", "*"); // Cannot use * with credentials
    
    // Let's stick to the requested production domain for now as we are moving to production.
    // If dev is still needed, we can switch back or implement dynamic checking.
    
    resp->addHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET");
    resp->addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    resp->addHeader("Access-Control-Allow-Credentials", "true");
}

void AuthController::login(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        addCorsHeaders(resp);
        callback(resp);
        return;
    }

    auto jsonPtr = req->getJsonObject();
    Json::Value ret;
    
    if (!jsonPtr) {
        ret["success"] = false;
        ret["message"] = "Invalid JSON";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    std::string username = (*jsonPtr).get("username", "").asString();
    std::string password = (*jsonPtr).get("password", "").asString();
    
    if (username.empty() || password.empty()) {
        ret["success"] = false;
        ret["message"] = "Username and password are required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Get database client
    auto dbClient = app().getDbClient();
    
    // Query user from database
    auto f = dbClient->execSqlAsyncFuture(
        "SELECT id, username, password_hash, email FROM users WHERE username = $1",
        username
    );
    
    try {
        auto result = f.get();
        
        if (result.size() == 0) {
            ret["success"] = false;
            ret["message"] = "Invalid username or password";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k401Unauthorized);
            addCorsHeaders(resp);
            callback(resp);
            return;
        }
        
        auto row = result[0];
        std::string storedHash = row["password_hash"].as<std::string>();
        std::string salt = generateSalt(username);
        std::string inputHash = hashPassword(password, salt);
        
        if (inputHash != storedHash) {
            ret["success"] = false;
            ret["message"] = "Invalid username or password";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k401Unauthorized);
            addCorsHeaders(resp);
            callback(resp);
            return;
        }
        
        // Login successful
        ret["success"] = true;
        ret["message"] = "Login successful";
        ret["user"]["id"] = row["id"].as<int>();
        ret["user"]["username"] = row["username"].as<std::string>();
        ret["user"]["email"] = row["email"].as<std::string>();
        
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        addCorsHeaders(resp);
        callback(resp);
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        ret["success"] = false;
        ret["message"] = "Database error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        addCorsHeaders(resp);
        callback(resp);
    }
}

void AuthController::registerUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        addCorsHeaders(resp);
        callback(resp);
        return;
    }

    auto jsonPtr = req->getJsonObject();
    Json::Value ret;
    
    if (!jsonPtr) {
        ret["success"] = false;
        ret["message"] = "Invalid JSON";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    std::string username = (*jsonPtr).get("username", "").asString();
    std::string password = (*jsonPtr).get("password", "").asString();
    std::string email = (*jsonPtr).get("email", "").asString();
    
    if (username.empty() || password.empty() || email.empty()) {
        ret["success"] = false;
        ret["message"] = "Username, password, and email are required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Validate password complexity
    auto [isValid, errorMsg] = validatePassword(password);
    if (!isValid) {
        ret["success"] = false;
        ret["message"] = errorMsg;
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Validate email format
    std::regex emailRegex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    if (!std::regex_match(email, emailRegex)) {
        ret["success"] = false;
        ret["message"] = "Invalid email format";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Hash password
    std::string salt = generateSalt(username);
    std::string passwordHash = hashPassword(password, salt);
    
    // Get database client
    auto dbClient = app().getDbClient();
    
    // Insert user into database
    auto f = dbClient->execSqlAsyncFuture(
        "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) RETURNING id, username, email, created_at",
        username,
        passwordHash,
        email
    );
    
    try {
        auto result = f.get();
        
        if (result.size() > 0) {
            auto row = result[0];
            ret["success"] = true;
            ret["message"] = "Registration successful";
            ret["user"]["id"] = row["id"].as<int>();
            ret["user"]["username"] = row["username"].as<std::string>();
            ret["user"]["email"] = row["email"].as<std::string>();
            
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k201Created);
            addCorsHeaders(resp);
            callback(resp);
        } else {
            ret["success"] = false;
            ret["message"] = "Registration failed";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k500InternalServerError);
            addCorsHeaders(resp);
            callback(resp);
        }
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        
        // Check if it's a duplicate key error
        std::string errorMsg = e.base().what();
        if (errorMsg.find("duplicate key") != std::string::npos) {
            if (errorMsg.find("username") != std::string::npos) {
                ret["success"] = false;
                ret["message"] = "Username already exists";
            } else if (errorMsg.find("email") != std::string::npos) {
                ret["success"] = false;
                ret["message"] = "Email already exists";
            } else {
                ret["success"] = false;
                ret["message"] = "User already exists";
            }
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k409Conflict);
            addCorsHeaders(resp);
            callback(resp);
        } else {
            ret["success"] = false;
            ret["message"] = "Database error occurred";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k500InternalServerError);
            addCorsHeaders(resp);
            callback(resp);
        }
    }
}
