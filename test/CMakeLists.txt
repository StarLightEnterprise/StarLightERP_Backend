cmake_minimum_required(VERSION 3.5)
project(StarLightERP_Backend_Temp_test CXX)

add_executable(${PROJECT_NAME} 
    test_main.cc
    test_auth_controller.cc
    test_user_controller.cc
    test_jwt_utils.cc
    test_security_utils.cc
    test_tenant_middleware.cc
    test_performance.cc
    ../controllers/JWTUtils.cc
    ../controllers/SecurityUtils.cc
    ../controllers/AuthController.cc
    ../controllers/UserController.cc
)

# ##############################################################################
# If you include the drogon source code locally in your project, use this method
# to add drogon 
# target_link_libraries(${PROJECT_NAME} PRIVATE drogon)
#
# and comment out the following lines
target_link_libraries(${PROJECT_NAME} PRIVATE Drogon::Drogon)

# Add jwt-cpp include directory for tests
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

ParseAndAddDrogonTests(${PROJECT_NAME})
