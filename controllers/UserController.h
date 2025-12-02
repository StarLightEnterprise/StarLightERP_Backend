#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class UserController : public drogon::HttpController<UserController>
{
  public:
    METHOD_LIST_BEGIN
    // POST /api/auth/logout
    ADD_METHOD_TO(UserController::logout, "/api/auth/logout", Post, Options);
    // GET /api/user/profile
    ADD_METHOD_TO(UserController::getProfile, "/api/user/profile", Get, Options);
    // PUT /api/user/profile
    ADD_METHOD_TO(UserController::updateProfile, "/api/user/profile", Put, Options);
    // POST /api/user/reset-password
    ADD_METHOD_TO(UserController::resetPassword, "/api/user/reset-password", Post, Options);
    METHOD_LIST_END

    void logout(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void getProfile(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void updateProfile(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void resetPassword(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);

  private:
    // Helper function to validate password complexity
    // std::pair<bool, std::string> validatePassword(const std::string &password);
    
    // Helper function to add CORS headers
    // void addCorsHeaders(const HttpResponsePtr &resp);
    
    // Helper function to get user ID from session (placeholder - in real app would use JWT/session)
    // For simplicity, we'll accept user_id or username in request for now
    int getUserIdFromRequest(const HttpRequestPtr &req);
};
