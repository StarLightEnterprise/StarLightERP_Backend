#pragma once

#include <drogon/HttpFilter.h>
#include "../controllers/JWTUtils.h"

using namespace drogon;

class TenantMiddleware : public HttpFilter<TenantMiddleware>
{
  public:
    TenantMiddleware() {}
    void doFilter(const HttpRequestPtr &req,
                  FilterCallback &&fcb,
                  FilterChainCallback &&fccb) override;
};
