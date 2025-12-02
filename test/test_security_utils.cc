#include <drogon/drogon_test.h>
#include "../controllers/SecurityUtils.h"

using namespace drogon;

DROGON_TEST(SecurityUtilsTest)
{
    // Test Salt Generation
    std::string salt1 = SecurityUtils::generateSalt("user1");
    std::string salt2 = SecurityUtils::generateSalt("user2");
    CHECK(salt1.length() > 0);
    CHECK(salt1 != salt2);

    // Test Password Hashing
    std::string password = "mysecretpassword";
    std::string hash1 = SecurityUtils::hashPassword(password, salt1);
    std::string hash2 = SecurityUtils::hashPassword(password, salt1);
    CHECK(hash1 == hash2);
    
    std::string hash3 = SecurityUtils::hashPassword(password, salt2);
    CHECK(hash1 != hash3);

    // Test Password Validation
    // Assuming we have a validatePassword function or similar logic
    // Since SecurityUtils currently only has hashPassword and generateSalt based on file list,
    // we'll stick to those.
    
    // Verify hash length/format if applicable
    CHECK(hash1.length() > 0);
}
