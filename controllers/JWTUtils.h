#pragma once

#include <string>
#include <chrono>
#include <set>
#include <mutex>

namespace JWTAuth {
    
    struct TokenPair {
        std::string accessToken;
        std::string refreshToken;
    };
    
    struct DecodedToken {
        int userId;
        std::string username;
        std::string role;
        int tenantId;
        std::chrono::system_clock::time_point expiration;
        bool isValid;
    };
    
    // Token configuration
    const int ACCESS_TOKEN_EXPIRY_MINUTES = 15;  // Short-lived access tokens
    const int REFRESH_TOKEN_EXPIRY_DAYS = 30;     // Long-lived refresh tokens
    
    // Generate access and refresh token pair
    TokenPair generateTokenPair(int userId, const std::string& username, const std::string& role, int tenantId);
    
    // Generate only access token (for refresh flow)
    std::string generateAccessToken(int userId, const std::string& username, const std::string& role, int tenantId);
    
    // Validate and decode token
    DecodedToken validateAndDecode(const std::string& token);
    
    // Token blacklist for revocation
    class TokenBlacklist {
    public:
        static TokenBlacklist& getInstance();
        
        void addToken(const std::string& token);
        bool isBlacklisted(const std::string& token) const;
        void cleanup(); // Remove expired tokens from blacklist
        
    private:
        TokenBlacklist() = default;
        mutable std::mutex mutex_;
        std::set<std::string> blacklistedTokens_;
    };
    
    // Extract token from Authorization header
    std::string extractTokenFromHeader(const std::string& authHeader);
    
    // Get JWT secret from environment or config
    std::string getJWTSecret();
}
