#pragma once

#include <drogon/HttpController.h>
#include "TenantHelper.h"

using namespace drogon;

class TenantTestController : public drogon::HttpController<TenantTestController>
{
  public:
    METHOD_LIST_BEGIN
    // Protected by TenantMiddleware via explicit declaration
    ADD_METHOD_TO(TenantTestController::testProtected, "/api/test/protected", "TenantMiddleware", Post, Get, Options);
    METHOD_LIST_END

    void testProtected(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
};
