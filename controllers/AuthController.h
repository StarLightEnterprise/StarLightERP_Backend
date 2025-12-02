#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class AuthController : public drogon::HttpController<AuthController>
{
  public:
    METHOD_LIST_BEGIN
    // POST /api/auth/login
    ADD_METHOD_TO(AuthController::login, "/api/auth/login", Post, Options);
    // POST /api/auth/register
    ADD_METHOD_TO(AuthController::registerUser, "/api/auth/register", Post, Options);
    // POST /api/auth/refresh
    ADD_METHOD_TO(AuthController::refreshToken, "/api/auth/refresh", Post, Options);
    // POST /api/auth/revoke
    ADD_METHOD_TO(AuthController::revokeToken, "/api/auth/revoke", Post, Options);
    // POST /api/auth/select-customer
    ADD_METHOD_TO(AuthController::selectCustomer, "/api/auth/select-customer", Post, Options);
    METHOD_LIST_END

    void login(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void registerUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void refreshToken(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void revokeToken(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void selectCustomer(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);

  private:
    // Helper function to validate password complexity
    // std::pair<bool, std::string> validatePassword(const std::string &password);
    
    // Helper function to add CORS headers
    // void addCorsHeaders(const HttpResponsePtr &resp);
};
