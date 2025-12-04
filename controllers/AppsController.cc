#include "AppsController.h"
#include "JWTUtils.h"
#include "SecurityUtils.h"
#include <drogon/orm/Mapper.h>
#include <drogon/HttpAppFramework.h>
#include <trantor/utils/Logger.h>

using namespace drogon;
using namespace drogon::orm;

void AppsController::getApps(const HttpRequestPtr &req,
                              std::function<void(const HttpResponsePtr &)> &&callback)
{
    // Handle CORS preflight
    if (req->method() == Options) {
        auto resp = HttpResponse::newHttpResponse();
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    Json::Value ret;
    
    // Get Authorization header
    auto authHeader = req->getHeader("Authorization");
    if (authHeader.empty()) {
        ret["success"] = false;
        ret["message"] = "Authorization header missing";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k401Unauthorized);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    // Extract token (remove "Bearer " prefix)
    std::string token = authHeader;
    if (token.find("Bearer ") == 0) {
        token = token.substr(7);
    }

    // Validate JWT token
    auto decoded = JWTAuth::validateAndDecode(token);
    if (!decoded.isValid) {
        ret["success"] = false;
        ret["message"] = "Invalid or expired token";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k401Unauthorized);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    // Get database client
    auto dbClient = app().getDbClient();
    
    try {
        // Check if user is a super user
        auto superCheck = dbClient->execSqlSync(
            "SELECT 1 FROM super_users WHERE user_id = $1", 
            decoded.userId
        );
        
        bool isSuperUser = (superCheck.size() > 0);
        
        // Query apps based on user type
        std::string sql;
        if (isSuperUser) {
            // Super users see all apps
            sql = "SELECT app_id, description, is_admin_app FROM apps ORDER BY app_id";
        } else {
            // Regular users only see non-admin apps
            sql = "SELECT app_id, description, is_admin_app FROM apps WHERE is_admin_app = FALSE ORDER BY app_id";
        }
        
        auto appsResult = dbClient->execSqlSync(sql);
        
        // Build response
        Json::Value apps(Json::arrayValue);
        for (const auto &row : appsResult) {
            Json::Value app;
            app["app_id"] = row["app_id"].as<std::string>();
            app["description"] = row["description"].as<std::string>();
            app["is_admin_app"] = row["is_admin_app"].as<bool>();
            apps.append(app);
        }
        
        ret["success"] = true;
        ret["apps"] = apps;
        ret["is_super_user"] = isSuperUser;
        
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error in getApps: " << e.base().what();
        ret["success"] = false;
        ret["message"] = "Database error occurred";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}
