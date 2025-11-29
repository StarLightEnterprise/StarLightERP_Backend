#include "TestController.h"

void TestController::asyncHandleHttpRequest(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback)
{
    Json::Value ret;
    ret["status"] = "ok";
    ret["message"] = "Hello from Drogon!";
    auto resp = HttpResponse::newHttpJsonResponse(ret);
    callback(resp);
}
