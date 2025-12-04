#include "CustomerController.h"
#include "JWTUtils.h"
#include "SecurityUtils.h"
#include <drogon/orm/Mapper.h>
#include <trantor/utils/Logger.h>

using namespace drogon;
using namespace drogon::orm;

bool CustomerController::isSuperAdmin(const HttpRequestPtr &req) {
    std::string authHeader = req->getHeader("Authorization");
    std::string token = JWTAuth::extractTokenFromHeader(authHeader);
    
    if (token.empty()) return false;
    
    auto decoded = JWTAuth::validateAndDecode(token);
    if (!decoded.isValid) return false;
    
    auto dbClient = app().getDbClient();
    auto result = dbClient->execSqlSync("SELECT 1 FROM super_users WHERE user_id = $1", decoded.userId);
    
    return result.size() > 0;
}

void CustomerController::getCustomers(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
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
    auto f = dbClient->execSqlAsyncFuture("SELECT * FROM customers ORDER BY created_at DESC");
    
    try {
        auto result = f.get();
        Json::Value ret;
        ret["success"] = true;
        Json::Value customers(Json::arrayValue);
        
        for (auto row : result) {
            Json::Value customer;
            customer["customer_id"] = row["customer_id"].as<int>();
            customer["customer_name"] = row["customer_name"].as<std::string>();
            customer["customer_category"] = row["customer_category"].as<std::string>();
            customer["customer_type"] = row["customer_type"].as<std::string>();
            customer["email"] = row["email"].as<std::string>();
            customer["phone"] = row["phone"].isNull() ? "" : row["phone"].as<std::string>();
            customer["is_active"] = row["is_active"].as<bool>();
            customers.append(customer);
        }
        
        ret["customers"] = customers;
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

void CustomerController::createCustomer(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
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
    if (!(*jsonPtr).isMember("customer_name") || !(*jsonPtr).isMember("email")) {
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
        "INSERT INTO customers (customer_name, customer_category, customer_type, email, phone, address_line1, city, state, postal_code, country, tax_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING customer_id",
        (*jsonPtr)["customer_name"].asString(),
        (*jsonPtr).get("customer_category", "SCHOOL").asString(),
        (*jsonPtr).get("customer_type", "Contract").asString(),
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
        ret["message"] = "Customer created successfully";
        ret["customer_id"] = result[0]["customer_id"].as<int>();
        
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

void CustomerController::updateCustomer(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int customerId) {
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
        "UPDATE customers SET customer_name=$1, customer_category=$2, customer_type=$3, email=$4, phone=$5 WHERE customer_id=$6",
        (*jsonPtr)["customer_name"].asString(),
        (*jsonPtr).get("customer_category", "SCHOOL").asString(),
        (*jsonPtr).get("customer_type", "Contract").asString(),
        (*jsonPtr)["email"].asString(),
        (*jsonPtr).get("phone", "").asString(),
        customerId
    );

    try {
        f.get();
        Json::Value ret;
        ret["success"] = true;
        ret["message"] = "Customer updated successfully";
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

void CustomerController::deleteCustomer(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int customerId) {
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
    auto f = dbClient->execSqlAsyncFuture("DELETE FROM customers WHERE customer_id=$1", customerId);

    try {
        f.get();
        Json::Value ret;
        ret["success"] = true;
        ret["message"] = "Customer deleted successfully";
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
