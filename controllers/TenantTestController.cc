#include "TenantTestController.h"

void TenantTestController::testProtected(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback)
{
    // 1. Retrieve customer_id using TenantHelper
    int customerId = TenantHelper::getCustomerId(req);
    int userId = TenantHelper::getUserId(req);
    std::string role = TenantHelper::getUserRole(req);

    // 2. Return success response with tenant info
    Json::Value ret;
    ret["success"] = true;
    ret["message"] = "Access granted to protected resource";
    ret["customerId"] = customerId;
    ret["userId"] = userId;
    ret["role"] = role;

    auto resp = HttpResponse::newHttpJsonResponse(ret);
    callback(resp);
}
