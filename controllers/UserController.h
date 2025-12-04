#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class UserController : public drogon::HttpController<UserController>
{
  public:
    METHOD_LIST_BEGIN
    // POST /api/auth/logout
    ADD_METHOD_TO(UserController::logout, "/api/auth/logout", Post, Options);
    ADD_METHOD_TO(UserController::getProfile, "/api/auth/profile", Get, Options);
    ADD_METHOD_TO(UserController::updateProfile, "/api/auth/profile", Put, Options);
    ADD_METHOD_TO(UserController::resetPassword, "/api/auth/reset-password", Post, Options);
    
    // User Maintenance APIs (Super Admin only)
    ADD_METHOD_TO(UserController::getUsers, "/api/users", Get, Options);
    ADD_METHOD_TO(UserController::createUser, "/api/users", Post, Options);
    ADD_METHOD_TO(UserController::updateUser, "/api/users/{1}", Put, Options);
    ADD_METHOD_TO(UserController::deleteUser, "/api/users/{1}", Delete, Options);
    ADD_METHOD_TO(UserController::resetUserPassword, "/api/users/{1}/reset-password", Post, Options);
    
    METHOD_LIST_END

    void logout(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void getProfile(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void updateProfile(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void resetPassword(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    
    void getUsers(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void createUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void updateUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int userId);
    void deleteUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int userId);
    void resetUserPassword(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int userId);

  private:
    // Helper function to validate password complexity
    // std::pair<bool, std::string> validatePassword(const std::string &password);
    
    // Helper function to add CORS headers
    // void addCorsHeaders(const HttpResponsePtr &resp);
    
    // Helper function to get user ID from session (placeholder - in real app would use JWT/session)
    // For simplicity, we'll accept user_id or username in request for now
    int getUserIdFromRequest(const HttpRequestPtr &req);
    bool isSuperAdmin(const HttpRequestPtr &req);
};
