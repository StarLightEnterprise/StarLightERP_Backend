#include "TenantMiddleware.h"

void TenantMiddleware::doFilter(const HttpRequestPtr &req,
                                FilterCallback &&fcb,
                                FilterChainCallback &&fccb)
{
    // 1. Check for Authorization header
    auto token = JWTAuth::extractTokenFromHeader(req->getHeader("Authorization"));
    
    if (token.empty())
    {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value());
        resp->setStatusCode(k401Unauthorized);
        resp->setBody("{\"error\": \"Missing or invalid Authorization header\"}");
        fcb(resp);
        return;
    }

    // 2. Validate and decode token
    auto decoded = JWTAuth::validateAndDecode(token);
    
    if (decoded.userId == 0) // Invalid token
    {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value());
        resp->setStatusCode(k401Unauthorized);
        resp->setBody("{\"error\": \"Invalid or expired token\"}");
        fcb(resp);
        return;
    }

    // 3. Check for tenant_id
    if (decoded.tenantId == 0)
    {
        auto resp = HttpResponse::newHttpJsonResponse(Json::Value());
        resp->setStatusCode(k403Forbidden);
        resp->setBody("{\"error\": \"No tenant selected. Please select a tenant first.\"}");
        fcb(resp);
        return;
    }

    // 4. Store tenant_id in request attributes for controllers to use
    req->attributes()->insert("tenantId", decoded.tenantId);
    req->attributes()->insert("userId", decoded.userId);
    req->attributes()->insert("userRole", decoded.role);

    // 5. Proceed to next filter/controller
    fccb();
}
