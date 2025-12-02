#include "UserController.h"
#include "JWTUtils.h"
#include "SecurityUtils.h"
#include <drogon/orm/Mapper.h>
#include <drogon/HttpAppFramework.h>
#include <trantor/utils/Logger.h>
#include <regex>
#include <regex>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <numeric>
#include <algorithm>

using namespace drogon;
using namespace drogon::orm;



int UserController::getUserIdFromRequest(const HttpRequestPtr &req) {
    // Extract and validate JWT token
    std::string authHeader = req->getHeader("Authorization");
    std::string token = JWTAuth::extractTokenFromHeader(authHeader);
    
    if (token.empty()) {
        return -1;
    }
    
    auto decoded = JWTAuth::validateAndDecode(token);
    
    if (!decoded.isValid) {
        return -1;
    }
    
    return decoded.userId;
}

void UserController::logout(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }

    Json::Value ret;
    
    // In a real application, we would:
    // 1. Invalidate the session/JWT token
    // 2. Clear server-side session data
    // 3. Blacklist the token if using JWT
    
    // For now, we just return success
    // The frontend handles clearing localStorage
    
    ret["success"] = true;
    ret["message"] = "Logged out successfully";
    
    auto resp = HttpResponse::newHttpJsonResponse(ret);
    SecurityUtils::addCorsHeaders(resp);
    callback(resp);
}

void UserController::getProfile(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }

    Json::Value ret;
    
    // Get user ID from request (would normally come from JWT/session)
    int userId = getUserIdFromRequest(req);
    
    if (userId <= 0) {
        ret["success"] = false;
        ret["message"] = "Unauthorized";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k401Unauthorized);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Get database client
    auto dbClient = app().getDbClient();
    
    // Query user profile
    auto f = dbClient->execSqlAsyncFuture(
        "SELECT id, username, email, name, phone, role, created_at, updated_at FROM users WHERE id = $1",
        userId
    );
    
    try {
        auto result = f.get();
        
        if (result.size() == 0) {
            ret["success"] = false;
            ret["message"] = "User not found";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k404NotFound);
            SecurityUtils::addCorsHeaders(resp);
            callback(resp);
            return;
        }
        
        auto row = result[0];
        ret["success"] = true;
        ret["user"]["id"] = row["id"].as<int>();
        ret["user"]["username"] = row["username"].as<std::string>();
        ret["user"]["email"] = row["email"].as<std::string>();
        ret["user"]["name"] = row["name"].isNull() ? "" : row["name"].as<std::string>();
        ret["user"]["phone"] = row["phone"].isNull() ? "" : row["phone"].as<std::string>();
        ret["user"]["role"] = row["role"].isNull() ? "User" : row["role"].as<std::string>();
        
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        ret["success"] = false;
        ret["message"] = "Database error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
    }
}

void UserController::updateProfile(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp);
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
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Get user ID from request
    int userId = getUserIdFromRequest(req);
    
    if (userId <= 0) {
        ret["success"] = false;
        ret["message"] = "Unauthorized";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k401Unauthorized);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Extract update fields (only update provided fields)
    std::vector<std::string> updates;
    std::vector<std::string> params;
    int paramCount = 1;
    
    if ((*jsonPtr).isMember("name") && !(*jsonPtr)["name"].asString().empty()) {
        updates.push_back("name = $" + std::to_string(paramCount++));
        params.push_back((*jsonPtr)["name"].asString());
    }
    
    if ((*jsonPtr).isMember("email") && !(*jsonPtr)["email"].asString().empty()) {
        std::string email = (*jsonPtr)["email"].asString();
        // Validate email
        std::regex emailRegex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
        if (!std::regex_match(email, emailRegex)) {
            ret["success"] = false;
            ret["message"] = "Invalid email format";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k400BadRequest);
            SecurityUtils::addCorsHeaders(resp);
            callback(resp);
            return;
        }
        updates.push_back("email = $" + std::to_string(paramCount++));
        params.push_back(email);
    }
    
    if ((*jsonPtr).isMember("phone") && !(*jsonPtr)["phone"].asString().empty()) {
        updates.push_back("phone = $" + std::to_string(paramCount++));
        params.push_back((*jsonPtr)["phone"].asString());
    }
    
    if (updates.empty()) {
        ret["success"] = false;
        ret["message"] = "No fields to update";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Build update query
    std::string query = "UPDATE users SET " + 
                        std::accumulate(updates.begin(), updates.end(), std::string(),
                            [](const std::string& a, const std::string& b) {
                                return a.empty() ? b : a + ", " + b;
                            }) +
                        ", updated_at = CURRENT_TIMESTAMP WHERE id = $" + std::to_string(paramCount) +
                        " RETURNING id, username, email, name, phone, role";
    
    // Get database client
    auto dbClient = app().getDbClient();
    
    // Execute update
    try {
        // Build parameter list for execSqlAsyncFuture
        // This is a bit tricky - we need to handle variadic parameters
        // For simplicity, let's handle up to 4 parameters (name, email, phone, + userId)
        
        auto executeUpdate = [&]() -> std::future<Result> {
            if (params.size() == 1) {
                return dbClient->execSqlAsyncFuture(query, params[0], userId);
            } else if (params.size() == 2) {
                return dbClient->execSqlAsyncFuture(query, params[0], params[1], userId);
            } else if (params.size() == 3) {
                return dbClient->execSqlAsyncFuture(query, params[0], params[1], params[2], userId);
            } else {
                throw std::runtime_error("Too many parameters");
            }
        };
        
        auto f = executeUpdate();
        auto result = f.get();
        
        if (result.size() > 0) {
            auto row = result[0];
            ret["success"] = true;
            ret["message"] = "Profile updated successfully";
            ret["user"]["id"] = row["id"].as<int>();
            ret["user"]["username"] = row["username"].as<std::string>();
            ret["user"]["email"] = row["email"].as<std::string>();
            ret["user"]["name"] = row["name"].isNull() ? "" : row["name"].as<std::string>();
            ret["user"]["phone"] = row["phone"].isNull() ? "" : row["phone"].as<std::string>();
            ret["user"]["role"] = row["role"].isNull() ? "User" : row["role"].as<std::string>();
            
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            SecurityUtils::addCorsHeaders(resp);
            callback(resp);
        } else {
            ret["success"] = false;
            ret["message"] = "Update failed";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k500InternalServerError);
            SecurityUtils::addCorsHeaders(resp);
            callback(resp);
        }
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        
        std::string errorMsg = e.base().what();
        if (errorMsg.find("duplicate key") != std::string::npos) {
            ret["success"] = false;
            ret["message"] = "Email already exists";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k409Conflict);
            SecurityUtils::addCorsHeaders(resp);
            callback(resp);
        } else {
            ret["success"] = false;
            ret["message"] = "Database error occurred";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k500InternalServerError);
            SecurityUtils::addCorsHeaders(resp);
            callback(resp);
        }
    } catch (const std::exception &e) {
        LOG_ERROR << "Error: " << e.what();
        ret["success"] = false;
        ret["message"] = "An error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
    }
}

void UserController::resetPassword(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp);
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
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    std::string currentPassword = (*jsonPtr).get("currentPassword", "").asString();
    std::string newPassword = (*jsonPtr).get("newPassword", "").asString();
    
    if (currentPassword.empty() || newPassword.empty()) {
        ret["success"] = false;
        ret["message"] = "Current password and new password are required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Validate new password
    auto [isValid, errorMsg] = SecurityUtils::validatePassword(newPassword);
    if (!isValid) {
        ret["success"] = false;
        ret["message"] = errorMsg;
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Get user ID from request
    int userId = getUserIdFromRequest(req);
    
    if (userId <= 0) {
        ret["success"] = false;
        ret["message"] = "Unauthorized";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k401Unauthorized);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        return;
    }
    
    // Get database client
    auto dbClient = app().getDbClient();
    
    // First, verify current password
    auto f1 = dbClient->execSqlAsyncFuture(
        "SELECT username, password_hash FROM users WHERE id = $1",
        userId
    );
    
    try {
        auto result = f1.get();
        
        if (result.size() == 0) {
            ret["success"] = false;
            ret["message"] = "User not found";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k404NotFound);
            SecurityUtils::addCorsHeaders(resp);
            callback(resp);
            return;
        }
        
        auto row = result[0];
        std::string username = row["username"].as<std::string>();
        std::string storedHash = row["password_hash"].as<std::string>();
        
        // Verify current password
        std::string salt = SecurityUtils::generateSalt(username);
        std::string currentHash = SecurityUtils::hashPassword(currentPassword, salt);
        
        if (currentHash != storedHash) {
            ret["success"] = false;
            ret["message"] = "Current password is incorrect";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k401Unauthorized);
            SecurityUtils::addCorsHeaders(resp);
            callback(resp);
            return;
        }
        
        // Hash new password
        std::string newHash = SecurityUtils::hashPassword(newPassword, salt);
        
        // Update password
        auto f2 = dbClient->execSqlAsyncFuture(
            "UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
            newHash,
            userId
        );
        
        auto updateResult = f2.get();
        
        ret["success"] = true;
        ret["message"] = "Password reset successfully";
        
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        ret["success"] = false;
        ret["message"] = "Database error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp);
        callback(resp);
    }
}
