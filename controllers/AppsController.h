#pragma once

#include <drogon/HttpController.h>
#include <drogon/HttpTypes.h>

using namespace drogon;

class AppsController : public drogon::HttpController<AppsController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(AppsController::getApps, "/api/apps", Get, Options);
    METHOD_LIST_END

    void getApps(const HttpRequestPtr &req,
                 std::function<void(const HttpResponsePtr &)> &&callback);
};
