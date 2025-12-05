#pragma once

#include <drogon/HttpController.h>
#include <drogon/orm/Mapper.h>

using namespace drogon;

class TenantController : public drogon::HttpController<TenantController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(TenantController::getTenants, "/api/tenants", Get, Options);
    ADD_METHOD_TO(TenantController::createTenant, "/api/tenants", Post, Options);
    ADD_METHOD_TO(TenantController::updateTenant, "/api/tenants/{1}", Put, Options);
    ADD_METHOD_TO(TenantController::deleteTenant, "/api/tenants/{1}", Delete, Options);
    METHOD_LIST_END

    void getTenants(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void createTenant(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void updateTenant(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int tenantId);
    void deleteTenant(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int tenantId);

private:
    bool isSuperAdmin(const HttpRequestPtr &req);
};
