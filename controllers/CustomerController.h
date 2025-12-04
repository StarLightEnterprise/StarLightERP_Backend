#pragma once

#include <drogon/HttpController.h>
#include <drogon/orm/Mapper.h>

using namespace drogon;

class CustomerController : public drogon::HttpController<CustomerController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(CustomerController::getCustomers, "/api/customers", Get, Options);
    ADD_METHOD_TO(CustomerController::createCustomer, "/api/customers", Post, Options);
    ADD_METHOD_TO(CustomerController::updateCustomer, "/api/customers/{1}", Put, Options);
    ADD_METHOD_TO(CustomerController::deleteCustomer, "/api/customers/{1}", Delete, Options);
    METHOD_LIST_END

    void getCustomers(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void createCustomer(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void updateCustomer(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int customerId);
    void deleteCustomer(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int customerId);

private:
    bool isSuperAdmin(const HttpRequestPtr &req);
};
