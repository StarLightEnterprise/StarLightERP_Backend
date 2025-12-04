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

bool UserController::isSuperAdmin(const HttpRequestPtr &req) {
    std::string authHeader = req->getHeader("Authorization");
    std::string token = JWTAuth::extractTokenFromHeader(authHeader);
    
    if (token.empty()) return false;
    
    auto decoded = JWTAuth::validateAndDecode(token);
    if (!decoded.isValid) return false;
    
    auto dbClient = app().getDbClient();
    auto result = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", decoded.userId);
    
    return result.size() > 0;
}

void UserController::logout(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
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
    SecurityUtils::addCorsHeaders(resp, req);
    callback(resp);
}

void UserController::getProfile(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
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
            SecurityUtils::addCorsHeaders(resp, req);
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
        
        // Check if super admin
        auto superCheck = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", userId);
        ret["user"]["is_super_admin"] = (superCheck.size() > 0);
        
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        ret["success"] = false;
        ret["message"] = "Database error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}

void UserController::updateProfile(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
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
            SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
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
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
        } else {
            ret["success"] = false;
            ret["message"] = "Update failed";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k500InternalServerError);
            SecurityUtils::addCorsHeaders(resp, req);
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
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
        } else {
            ret["success"] = false;
            ret["message"] = "Database error occurred";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k500InternalServerError);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
        }
    } catch (const std::exception &e) {
        LOG_ERROR << "Error: " << e.what();
        ret["success"] = false;
        ret["message"] = "An error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}

void UserController::resetPassword(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
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
            SecurityUtils::addCorsHeaders(resp, req);
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
            SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        ret["success"] = false;
        ret["message"] = "Database error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}

void UserController::getUsers(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    if (!isSuperAdmin(req)) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Forbidden: Super Admin access required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k403Forbidden);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    auto dbClient = app().getDbClient();
    // Filter out super users
    auto f = dbClient->execSqlAsyncFuture(
        "SELECT id, username, email, name, role, is_active, created_at FROM users "
        "WHERE id NOT IN (SELECT user_id FROM super_users) ORDER BY created_at DESC"
    );
    
    try {
        auto result = f.get();
        Json::Value ret;
        ret["success"] = true;
        Json::Value users(Json::arrayValue);
        
        for (auto row : result) {
            Json::Value user;
            user["id"] = row["id"].as<int>();
            user["username"] = row["username"].as<std::string>();
            user["email"] = row["email"].as<std::string>();
            user["name"] = row["name"].isNull() ? "" : row["name"].as<std::string>();
            user["role"] = row["role"].isNull() ? "User" : row["role"].as<std::string>();
            user["is_active"] = row["is_active"].as<bool>();
            users.append(user);
        }
        
        ret["users"] = users;
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Database error";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}

void UserController::createUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    if (!isSuperAdmin(req)) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Forbidden: Super Admin access required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k403Forbidden);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    auto jsonPtr = req->getJsonObject();
    if (!jsonPtr) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Invalid JSON";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    if (!(*jsonPtr).isMember("username") || !(*jsonPtr).isMember("email") || !(*jsonPtr).isMember("password")) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Missing required fields";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    std::string username = (*jsonPtr)["username"].asString();
    std::string email = (*jsonPtr)["email"].asString();
    std::string password = (*jsonPtr)["password"].asString();
    std::string name = (*jsonPtr).get("name", "").asString();
    std::string role = (*jsonPtr).get("role", "User").asString();

    // Hash password
    std::string salt = SecurityUtils::generateSalt(username);
    std::string passwordHash = SecurityUtils::hashPassword(password, salt);

    auto dbClient = app().getDbClient();
    auto f = dbClient->execSqlAsyncFuture(
        "INSERT INTO users (username, email, password_hash, name, role, is_active) VALUES ($1, $2, $3, $4, $5, true) RETURNING id",
        username, email, passwordHash, name, role
    );

    try {
        auto result = f.get();
        Json::Value ret;
        ret["success"] = true;
        ret["message"] = "User created successfully";
        ret["user_id"] = result[0]["id"].as<int>();
        
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Database error (possibly duplicate username/email)";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}

void UserController::updateUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int userId) {
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    if (!isSuperAdmin(req)) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Forbidden: Super Admin access required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k403Forbidden);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    auto jsonPtr = req->getJsonObject();
    if (!jsonPtr) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Invalid JSON";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    auto dbClient = app().getDbClient();
    
    // Check if target is super admin
    auto superCheck = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", userId);
    if (superCheck.size() > 0) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Cannot modify a Super Admin user";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k403Forbidden);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    // Extract update fields
    std::vector<std::string> updates;
    std::vector<std::string> params;
    int paramCount = 1;
    
    if ((*jsonPtr).isMember("username") && !(*jsonPtr)["username"].asString().empty()) {
        updates.push_back("username = $" + std::to_string(paramCount++));
        params.push_back((*jsonPtr)["username"].asString());
    }
    
    if ((*jsonPtr).isMember("email") && !(*jsonPtr)["email"].asString().empty()) {
        std::string email = (*jsonPtr)["email"].asString();
        // Validate email
        std::regex emailRegex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
        if (!std::regex_match(email, emailRegex)) {
            Json::Value ret;
            ret["success"] = false;
            ret["message"] = "Invalid email format";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k400BadRequest);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
            return;
        }
        updates.push_back("email = $" + std::to_string(paramCount++));
        params.push_back(email);
    }
    
    if ((*jsonPtr).isMember("name")) {
        updates.push_back("name = $" + std::to_string(paramCount++));
        params.push_back((*jsonPtr)["name"].asString());
    }
    
    if ((*jsonPtr).isMember("role") && !(*jsonPtr)["role"].asString().empty()) {
        updates.push_back("role = $" + std::to_string(paramCount++));
        params.push_back((*jsonPtr)["role"].asString());
    }
    
    if ((*jsonPtr).isMember("is_active")) {
        updates.push_back("is_active = $" + std::to_string(paramCount++));
        params.push_back((*jsonPtr)["is_active"].asBool() ? "true" : "false");
    }
    
    if (updates.empty()) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "No fields to update";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
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
                        " RETURNING id, username, email, name, role, is_active";
    
    try {
        // Execute update with proper parameter count
        auto executeUpdate = [&]() -> std::future<Result> {
            params.push_back(std::to_string(userId));
            if (params.size() == 2) {
                return dbClient->execSqlAsyncFuture(query, params[0], std::stoi(params[1]));
            } else if (params.size() == 3) {
                return dbClient->execSqlAsyncFuture(query, params[0], params[1], std::stoi(params[2]));
            } else if (params.size() == 4) {
                return dbClient->execSqlAsyncFuture(query, params[0], params[1], params[2], std::stoi(params[3]));
            } else if (params.size() == 5) {
                return dbClient->execSqlAsyncFuture(query, params[0], params[1], params[2], params[3], std::stoi(params[4]));
            } else if (params.size() == 6) {
                return dbClient->execSqlAsyncFuture(query, params[0], params[1], params[2], params[3], params[4], std::stoi(params[5]));
            } else {
                throw std::runtime_error("Too many parameters");
            }
        };
        
        auto f = executeUpdate();
        auto result = f.get();
        
        if (result.size() > 0) {
            auto row = result[0];
            Json::Value ret;
            ret["success"] = true;
            ret["message"] = "User updated successfully";
            ret["user"]["id"] = row["id"].as<int>();
            ret["user"]["username"] = row["username"].as<std::string>();
            ret["user"]["email"] = row["email"].as<std::string>();
            ret["user"]["name"] = row["name"].isNull() ? "" : row["name"].as<std::string>();
            ret["user"]["role"] = row["role"].isNull() ? "User" : row["role"].as<std::string>();
            ret["user"]["is_active"] = row["is_active"].as<bool>();
            
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
        } else {
            Json::Value ret;
            ret["success"] = false;
            ret["message"] = "Update failed - user not found";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k404NotFound);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
        }
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        
        std::string errorMsg = e.base().what();
        Json::Value ret;
        ret["success"] = false;
        if (errorMsg.find("duplicate key") != std::string::npos) {
            ret["message"] = "Username or email already exists";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k409Conflict);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
        } else {
            ret["message"] = "Database error occurred";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k500InternalServerError);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
        }
    } catch (const std::exception &e) {
        LOG_ERROR << "Error: " << e.what();
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "An error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}

void UserController::deleteUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int userId) {
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    if (!isSuperAdmin(req)) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Forbidden: Super Admin access required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k403Forbidden);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    // Prevent deleting self or other super admins via this API (though query filters them out in list, direct ID access is possible)
    auto dbClient = app().getDbClient();
    
    // Check if target is super admin
    auto superCheck = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", userId);
    if (superCheck.size() > 0) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Cannot delete a Super Admin user";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k403Forbidden);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    auto f = dbClient->execSqlAsyncFuture("DELETE FROM users WHERE id=$1", userId);

    try {
        f.get();
        Json::Value ret;
        ret["success"] = true;
        ret["message"] = "User deleted successfully";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Database error";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}

void UserController::resetUserPassword(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int userId) {
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    if (!isSuperAdmin(req)) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Forbidden: Super Admin access required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k403Forbidden);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    auto jsonPtr = req->getJsonObject();
    if (!jsonPtr) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Invalid JSON";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    if (!(*jsonPtr).isMember("password")) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Password is required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    std::string newPassword = (*jsonPtr)["password"].asString();
    
    // Validate password
    auto [isValid, errorMsg] = SecurityUtils::validatePassword(newPassword);
    if (!isValid) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = errorMsg;
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    auto dbClient = app().getDbClient();
    
    // Check if target is super admin
    auto superCheck = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", userId);
    if (superCheck.size() > 0) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Cannot reset password for a Super Admin user";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k403Forbidden);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    // Get username to generate salt
    auto f1 = dbClient->execSqlAsyncFuture("SELECT username FROM users WHERE id = $1", userId);
    
    try {
        auto result = f1.get();
        
        if (result.size() == 0) {
            Json::Value ret;
            ret["success"] = false;
            ret["message"] = "User not found";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k404NotFound);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
            return;
        }
        
        std::string username = result[0]["username"].as<std::string>();
        
        // Hash new password
        std::string salt = SecurityUtils::generateSalt(username);
        std::string passwordHash = SecurityUtils::hashPassword(newPassword, salt);
        
        // Update password
        auto f2 = dbClient->execSqlAsyncFuture(
            "UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
            passwordHash,
            userId
        );
        
        f2.get();
        
        Json::Value ret;
        ret["success"] = true;
        ret["message"] = "Password reset successfully";
        
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Database error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}
