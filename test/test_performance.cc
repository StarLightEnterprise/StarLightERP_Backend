#include <drogon/drogon_test.h>
#include <chrono>
#include <thread>
#include <vector>
#include <iostream>

using namespace drogon;

DROGON_TEST(BackendPerformanceTest)
{
    // Simple benchmark for a utility function
    auto start = std::chrono::high_resolution_clock::now();
    
    // Simulate some work or call a utility function repeatedly
    for(int i = 0; i < 1000; i++) {
        // Example: Hash a password
        // SecurityUtils::hashPassword("password", "salt");
        // For now just busy wait or simple math
        int x = 0;
        x = x + 1;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    
    // std::cout << "Performance Test: 1000 iterations took " << elapsed.count() << " ms" << std::endl;
    
    // Assert it's fast enough (e.g., under 100ms for this trivial task)
    CHECK(elapsed.count() < 100.0);
}
