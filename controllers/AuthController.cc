#include "AuthController.h"
#include "JWTUtils.h"
#include "SecurityUtils.h"
#include <drogon/orm/Mapper.h>
#include <drogon/HttpAppFramework.h>
#include <trantor/utils/Logger.h>
#include <trantor/utils/Logger.h>
#include <regex>

using namespace drogon;
using namespace drogon::orm;



void AuthController::login(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
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
    
    std::string username = (*jsonPtr).get("username", "").asString();
    std::string password = (*jsonPtr).get("password", "").asString();
    
    if (username.empty() || password.empty()) {
        ret["success"] = false;
        ret["message"] = "Username and password are required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }
    
    // Get database client
    auto dbClient = app().getDbClient();
    
    // Query user from database
    auto f = dbClient->execSqlAsyncFuture(
        "SELECT id, username, password_hash, email, name, role FROM users WHERE username = $1",
        username
    );
    
    try {
        auto result = f.get();
        
        if (result.size() == 0) {
            ret["success"] = false;
            ret["message"] = "Invalid username or password";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k401Unauthorized);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
            return;
        }
        
        auto row = result[0];
        std::string storedHash = row["password_hash"].as<std::string>();
        std::string salt = SecurityUtils::generateSalt(username);
        std::string inputHash = SecurityUtils::hashPassword(password, salt);
        
        if (inputHash != storedHash) {
            ret["success"] = false;
            ret["message"] = "Invalid username or password";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k401Unauthorized);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
            return;
        }
        
        // Login successful - query user's tenants
        int userId = row["id"].as<int>();
        std::string userRole = row["role"].isNull() ? "User" : row["role"].as<std::string>();
        std::string userName = row["name"].isNull() ? row["username"].as<std::string>() : row["name"].as<std::string>();
        
        // Query tenant_user table to get user's tenants
        auto tenantFuture = dbClient->execSqlAsyncFuture(
            "SELECT tu.tenant_id, t.tenant_name, t.tenant_category, t.tenant_type, tu.is_primary "
            "FROM tenant_user tu "
            "JOIN tenants t ON tu.tenant_id = t.tenant_id "
            "WHERE tu.user_id = $1 AND t.is_active = true "
            "ORDER BY tu.is_primary DESC, t.tenant_name",
            userId
        );
        
        auto tenantResult = tenantFuture.get();
        
        if (tenantResult.size() == 0) {
            ret["success"] = false;
            ret["message"] = "No active tenants assigned to this user. Please contact administrator.";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k403Forbidden);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
            return;
        }
        
        if (tenantResult.size() == 1) {
            // Single tenant - auto-select and generate JWT
            int tenantId = tenantResult[0]["tenant_id"].as<int>();
            std::string tenantName = tenantResult[0]["tenant_name"].as<std::string>();
            
            auto tokens = JWTAuth::generateTokenPair(userId, username, userRole, tenantId);
        
            ret["success"] = true;
            ret["message"] = "Login successful";
            ret["accessToken"] = tokens.accessToken;
            ret["user"]["id"] = userId;
            ret["user"]["username"] = username;
            ret["user"]["email"] = row["email"].as<std::string>();
            ret["user"]["role"] = userRole;
            ret["user"]["name"] = userName;
            ret["user"]["tenantId"] = tenantId;
            ret["user"]["tenantName"] = tenantName;
            
            // Check super admin
            auto superCheck = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", userId);
            ret["user"]["is_super_admin"] = (superCheck.size() > 0);
        
            auto resp = HttpResponse::newHttpJsonResponse(ret);
        
            // Set refresh token in httpOnly cookie (secure in production)
            Cookie refreshCookie("refreshToken", tokens.refreshToken);
            refreshCookie.setMaxAge(30 * 24 * 3600); // 30 days
            refreshCookie.setPath("/");
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(true); // Use true for HTTPS in production
            resp->addCookie(refreshCookie);
        
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
            
        } else {
            // Multiple tenants - return list for selection
            ret["success"] = true;
            ret["message"] = "Please select a tenant";
            ret["requiresTenantSelection"] = true;
            ret["user"]["id"] = userId;
            ret["user"]["username"] = username;
            ret["user"]["email"] = row["email"].as<std::string>();
            ret["user"]["role"] = userRole;
            ret["user"]["name"] = userName;
            
            // Check super admin
            auto superCheck = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", userId);
            ret["user"]["is_super_admin"] = (superCheck.size() > 0);
            
            Json::Value tenants(Json::arrayValue);
            for (size_t i = 0; i < tenantResult.size(); i++) {
                Json::Value tenant;
                tenant["tenantId"] = tenantResult[i]["tenant_id"].as<int>();
                tenant["tenantName"] = tenantResult[i]["tenant_name"].as<std::string>();
                tenant["tenantCategory"] = tenantResult[i]["tenant_category"].as<std::string>();
                tenant["tenantType"] = tenantResult[i]["tenant_type"].as<std::string>();
                tenant["isPrimary"] = tenantResult[i]["is_primary"].as<bool>();
                tenants.append(tenant);
            }
            ret["tenants"] = tenants;
            
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
        }
        
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

void AuthController::registerUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
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
    
    std::string username = (*jsonPtr).get("username", "").asString();
    std::string password = (*jsonPtr).get("password", "").asString();
    std::string email = (*jsonPtr).get("email", "").asString();
    
    if (username.empty() || password.empty() || email.empty()) {
        ret["success"] = false;
        ret["message"] = "Username, password, and email are required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }
    
    // Validate password complexity
    auto [isValid, errorMsg] = SecurityUtils::validatePassword(password);
    if (!isValid) {
        ret["success"] = false;
        ret["message"] = errorMsg;
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
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
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }
    
    // Hash password
    std::string salt = SecurityUtils::generateSalt(username);
    std::string passwordHash = SecurityUtils::hashPassword(password, salt);
    
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
            int userId = row["id"].as<int>();
            std::string registeredUsername = row["username"].as<std::string>();
            std::string registeredEmail = row["email"].as<std::string>();
            
            // Generate JWT tokens for automatic login with customer_id = 0 (no customer assigned yet)
            auto tokens = JWTAuth::generateTokenPair(userId, registeredUsername, "User", 0);
            
            ret["success"] = true;
            ret["message"] = "Registration successful";
            ret["accessToken"] = tokens.accessToken;
            ret["user"]["id"] = userId;
            ret["user"]["username"] = registeredUsername;
            ret["user"]["email"] = registeredEmail;
            ret["user"]["role"] = "User";
            ret["user"]["name"] = registeredUsername;
            
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k201Created);
            
            // Set refresh token cookie
            Cookie refreshCookie("refreshToken", tokens.refreshToken);
            refreshCookie.setMaxAge(30 * 24 * 3600);
            refreshCookie.setPath("/");
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(true);
            resp->addCookie(refreshCookie);
            
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
            
        } else {
            ret["success"] = false;
            ret["message"] = "Registration failed";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k500InternalServerError);
            SecurityUtils::addCorsHeaders(resp, req);
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
    }
}

// Add to end of AuthController.cc file

void AuthController::refreshToken(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    Json::Value ret;
    
    // Get refresh token from httpOnly cookie
    std::string refreshToken = req->getCookie("refreshToken");
    
    if (refreshToken.empty()) {
        ret["success"] = false;
        ret["message"] = "No refresh token provided";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k401Unauthorized);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }
    
    // Validate refresh token
    auto decoded = JWTAuth::validateAndDecode(refreshToken);
    
    if (!decoded.isValid) {
        ret["success"] = false;
        ret["message"] = "Invalid or expired refresh token";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k401Unauthorized);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }
    
    // Generate new tokens with same tenant_id
    auto newAccessToken = JWTAuth::generateAccessToken(decoded.userId, decoded.username, decoded.role, decoded.tenantId);
    
    // Optional: Generate new refresh token for rotation (more secure)
    auto tokens = JWTAuth::generateTokenPair(decoded.userId, decoded.username, decoded.role, decoded.tenantId);
    
    // Blacklist old refresh token (token rotation)
    JWTAuth::TokenBlacklist::getInstance().addToken(refreshToken);
    
    ret["success"] = true;
    ret["accessToken"] = tokens.accessToken;
    
    auto resp = HttpResponse::newHttpJsonResponse(ret);
    
    // Set new refresh token in cookie (token rotation)
    Cookie refreshCookie("refreshToken", tokens.refreshToken);
    refreshCookie.setMaxAge(30 * 24 * 3600);
    refreshCookie.setPath("/");
    refreshCookie.setHttpOnly(true);
    refreshCookie.setSecure(true);
    resp->addCookie(refreshCookie);
    
    SecurityUtils::addCorsHeaders(resp, req);
    callback(resp);
}

void AuthController::revokeToken(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    Json::Value ret;
    
    // Get tokens from both Authorization header and cookie
    std::string authHeader = req->getHeader("Authorization");
    std::string accessToken = JWTAuth::extractTokenFromHeader(authHeader);
    std::string refreshToken = req->getCookie("refreshToken");
    
    // Blacklist both tokens
    if (!accessToken.empty()) {
        JWTAuth::TokenBlacklist::getInstance().addToken(accessToken);
    }
    
    if (!refreshToken.empty()) {
        JWTAuth::TokenBlacklist::getInstance().addToken(refreshToken);
    }
    
    ret["success"] = true;
    ret["message"] = "Tokens revoked successfully";
    
    auto resp = HttpResponse::newHttpJsonResponse(ret);
    
    // Clear refresh token cookie
    Cookie clearCookie("refreshToken", "");
    clearCookie.setMaxAge(0);
    clearCookie.setPath("/");
    clearCookie.setHttpOnly(true);
    clearCookie.setSecure(true);
    resp->addCookie(clearCookie);
    
    SecurityUtils::addCorsHeaders(resp, req);
    callback(resp);
}

// Add to end of AuthController.cc file

void AuthController::selectTenant(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
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
    
    std::string username = (*jsonPtr).get("username", "").asString();
    int tenantId = (*jsonPtr).get("tenantId", 0).asInt();
    
    if (username.empty() || tenantId == 0) {
        ret["success"] = false;
        ret["message"] = "Username and tenant ID are required";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }
    
    // Get database client
    auto dbClient = app().getDbClient();
    
    // Verify user exists and get their info
    auto userFuture = dbClient->execSqlAsyncFuture(
        "SELECT id, username, email, name, role FROM users WHERE username = $1",
        username
    );
    
    try {
        auto userResult = userFuture.get();
        
        if (userResult.size() == 0) {
            ret["success"] = false;
            ret["message"] = "User not found";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k404NotFound);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
            return;
        }
        
        auto userRow = userResult[0];
        int userId = userRow["id"].as<int>();
        std::string userRole = userRow["role"].isNull() ? "User" : userRow["role"].as<std::string>();
        std::string userName = userRow["name"].isNull() ? userRow["username"].as<std::string>() : userRow["name"].as<std::string>();
        
        // Verify user has access to this tenant
        auto tenantAccessFuture = dbClient->execSqlAsyncFuture(
            "SELECT tu.tenant_id, t.tenant_name, t.tenant_category, t.tenant_type "
            "FROM tenant_user tu "
            "JOIN tenants t ON tu.tenant_id = t.tenant_id "
            "WHERE tu.user_id = $1 AND tu.tenant_id = $2 AND t.is_active = true",
            userId,
            tenantId
        );
        
        auto tenantAccessResult = tenantAccessFuture.get();
        
        if (tenantAccessResult.size() == 0) {
            ret["success"] = false;
            ret["message"] = "You do not have access to this tenant";
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k403Forbidden);
            SecurityUtils::addCorsHeaders(resp, req);
            callback(resp);
            return;
        }
        
        // User has access - generate JWT with selected tenant_id
        std::string tenantName = tenantAccessResult[0]["tenant_name"].as<std::string>();
        
        auto tokens = JWTAuth::generateTokenPair(userId, username, userRole, tenantId);
        
        ret["success"] = true;
        ret["message"] = "Tenant selected successfully";
        ret["accessToken"] = tokens.accessToken;
        ret["user"]["id"] = userId;
        ret["user"]["username"] = username;
        ret["user"]["email"] = userRow["email"].as<std::string>();
        ret["user"]["role"] = userRole;
        ret["user"]["name"] = userName;
        ret["user"]["tenantId"] = tenantId;
        ret["user"]["tenantName"] = tenantName;
        
        // Check super admin
        auto superCheck = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", userId);
        ret["user"]["is_super_admin"] = (superCheck.size() > 0);
        
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        
        // Set refresh token in httpOnly cookie
        Cookie refreshCookie("refreshToken", tokens.refreshToken);
        refreshCookie.setMaxAge(30 * 24 * 3600); // 30 days
        refreshCookie.setPath("/");
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);
        resp->addCookie(refreshCookie);
        
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
