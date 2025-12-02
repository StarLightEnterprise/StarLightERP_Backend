#include <drogon/drogon_test.h>
#include "../controllers/JWTUtils.h"
#include <thread>

using namespace drogon;

DROGON_TEST(JWTUtilsTest)
{
    int userId = 123;
    std::string username = "testuser";
    std::string role = "user";
    int customerId = 10000000;
    
    // Test Token Pair Generation
    auto tokenPair = JWTAuth::generateTokenPair(userId, username, role, customerId);
    CHECK(tokenPair.accessToken.length() > 0);
    CHECK(tokenPair.refreshToken.length() > 0);
    
    // Test Access Token Generation
    std::string accessToken = JWTAuth::generateAccessToken(userId, username, role, customerId);
    CHECK(accessToken.length() > 0);
    
    // Test Token Validation
    auto decoded = JWTAuth::validateAndDecode(accessToken);
    CHECK(decoded.isValid == true);
    CHECK(decoded.userId == userId);
    CHECK(decoded.username == username);
    CHECK(decoded.role == role);
    CHECK(decoded.customerId == customerId);
    
    // Test Invalid Token
    auto invalidDecoded = JWTAuth::validateAndDecode("invalid.token.string");
    CHECK(invalidDecoded.isValid == false);
}
