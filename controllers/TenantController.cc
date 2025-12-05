#include "TenantController.h"
#include "JWTUtils.h"
#include "SecurityUtils.h"
#include <drogon/orm/Mapper.h>
#include <trantor/utils/Logger.h>

using namespace drogon;
using namespace drogon::orm;

bool TenantController::isSuperAdmin(const HttpRequestPtr &req) {
    std::string authHeader = req->getHeader("Authorization");
    std::string token = JWTAuth::extractTokenFromHeader(authHeader);
    
    if (token.empty()) return false;
    
    auto decoded = JWTAuth::validateAndDecode(token);
    if (!decoded.isValid) return false;
    
    auto dbClient = app().getDbClient();
    auto result = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", decoded.userId);
    
    return result.size() > 0;
}

void TenantController::getTenants(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
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
    auto f = dbClient->execSqlAsyncFuture("SELECT * FROM tenants ORDER BY created_at DESC");
    
    try {
        auto result = f.get();
        Json::Value ret;
        ret["success"] = true;
        Json::Value tenants(Json::arrayValue);
        
        for (auto row : result) {
            Json::Value tenant;
            tenant["tenant_id"] = row["tenant_id"].as<int>();
            tenant["tenant_name"] = row["tenant_name"].as<std::string>();
            tenant["tenant_category"] = row["tenant_category"].as<std::string>();
            tenant["tenant_type"] = row["tenant_type"].as<std::string>();
            tenant["email"] = row["email"].as<std::string>();
            tenant["phone"] = row["phone"].isNull() ? "" : row["phone"].as<std::string>();
            tenant["is_active"] = row["is_active"].as<bool>();
            tenants.append(tenant);
        }
        
        ret["tenants"] = tenants;
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

void TenantController::createTenant(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
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

    // Basic validation
    if (!(*jsonPtr).isMember("tenant_name") || !(*jsonPtr).isMember("email")) {
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Missing required fields";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
        return;
    }

    auto dbClient = app().getDbClient();
    auto f = dbClient->execSqlAsyncFuture(
        "INSERT INTO tenants (tenant_name, tenant_category, tenant_type, email, phone, address_line1, city, state, postal_code, country, tax_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING tenant_id",
        (*jsonPtr)["tenant_name"].asString(),
        (*jsonPtr).get("tenant_category", "SCHOOL").asString(),
        (*jsonPtr).get("tenant_type", "Contract").asString(),
        (*jsonPtr)["email"].asString(),
        (*jsonPtr).get("phone", "").asString(),
        (*jsonPtr).get("address_line1", "").asString(),
        (*jsonPtr).get("city", "").asString(),
        (*jsonPtr).get("state", "").asString(),
        (*jsonPtr).get("postal_code", "").asString(),
        (*jsonPtr).get("country", "India").asString(),
        (*jsonPtr).get("tax_id", "").asString()
    );

    try {
        auto result = f.get();
        Json::Value ret;
        ret["success"] = true;
        ret["message"] = "Tenant created successfully";
        ret["tenant_id"] = result[0]["tenant_id"].as<int>();
        
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    } catch (const DrogonDbException &e) {
        LOG_ERROR << "Database error: " << e.base().what();
        Json::Value ret;
        ret["success"] = false;
        ret["message"] = "Database error (possibly duplicate email)";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k500InternalServerError);
        SecurityUtils::addCorsHeaders(resp, req);
        callback(resp);
    }
}

void TenantController::updateTenant(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int tenantId) {
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
    // Simplified update for now
    auto f = dbClient->execSqlAsyncFuture(
        "UPDATE tenants SET tenant_name=$1, tenant_category=$2, tenant_type=$3, email=$4, phone=$5 WHERE tenant_id=$6",
        (*jsonPtr)["tenant_name"].asString(),
        (*jsonPtr).get("tenant_category", "SCHOOL").asString(),
        (*jsonPtr).get("tenant_type", "Contract").asString(),
        (*jsonPtr)["email"].asString(),
        (*jsonPtr).get("phone", "").asString(),
        tenantId
    );

    try {
        f.get();
        Json::Value ret;
        ret["success"] = true;
        ret["message"] = "Tenant updated successfully";
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

void TenantController::deleteTenant(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int tenantId) {
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
    auto f = dbClient->execSqlAsyncFuture("DELETE FROM tenants WHERE tenant_id=$1", tenantId);

    try {
        f.get();
        Json::Value ret;
        ret["success"] = true;
        ret["message"] = "Tenant deleted successfully";
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
