#pragma once

#include <drogon/HttpRequest.h>

using namespace drogon;

class TenantHelper
{
  public:
    static int getCustomerId(const HttpRequestPtr &req)
    {
        try {
            return req->attributes()->get<int>("customerId");
        } catch (...) {
            return 0;
        }
    }

    static int getUserId(const HttpRequestPtr &req)
    {
        try {
            return req->attributes()->get<int>("userId");
        } catch (...) {
            return 0;
        }
    }
    
    static std::string getUserRole(const HttpRequestPtr &req)
    {
        try {
            return req->attributes()->get<std::string>("userRole");
        } catch (...) {
            return "";
        }
    }
};
