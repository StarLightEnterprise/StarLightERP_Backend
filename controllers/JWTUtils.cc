#include "JWTUtils.h"
#include <jwt-cpp/jwt.h>
#include <trantor/utils/Logger.h>
#include <cstdlib>
#include <iomanip>

namespace JWTAuth {

// Get JWT secret from environment variable or use default (for development only)
std::string getJWTSecret() {
    const char* secret = std::getenv("JWT_SECRET");
    if (secret != nullptr) {
        return std::string(secret);
    }
    
    // DEVELOPMENT ONLY - In production, MUST set JWT_SECRET environment variable
    LOG_WARN << "JWT_SECRET not set in environment! Using default secret (INSECURE for production)";
    return "StarLightERP_JWT_Secret_Key_CHANGE_IN_PRODUCTION_12345678901234567890";
}

// Generate token pair (access + refresh)
TokenPair generateTokenPair(int userId, const std::string& username, const std::string& role) {
    auto now = std::chrono::system_clock::now();
    std::string secret = getJWTSecret();
    
    // Access Token (short-lived)
    auto accessExpiry = now + std::chrono::minutes(ACCESS_TOKEN_EXPIRY_MINUTES);
    auto accessToken = jwt::create()
        .set_issuer("StarLightERP")
        .set_type("JWT")
        .set_issued_at(now)
        .set_expires_at(accessExpiry)
        .set_subject(std::to_string(userId))
        .set_payload_claim("username", jwt::claim(username))
        .set_payload_claim("role", jwt::claim(role))
        .set_payload_claim("type", jwt::claim(std::string("access")))
        .sign(jwt::algorithm::hs256{secret});
    
    // Refresh Token (long-lived)
    auto refreshExpiry = now + std::chrono::hours(24 * REFRESH_TOKEN_EXPIRY_DAYS);
    auto refreshToken = jwt::create()
        .set_issuer("StarLightERP")
        .set_type("JWT")
        .set_issued_at(now)
        .set_expires_at(refreshExpiry)
        .set_subject(std::to_string(userId))
        .set_payload_claim("username", jwt::claim(username))
        .set_payload_claim("role", jwt::claim(role))
        .set_payload_claim("type", jwt::claim(std::string("refresh")))
        .sign(jwt::algorithm::hs256{secret});
    
    return {accessToken, refreshToken};
}

// Generate only access token (for refresh flow)
std::string generateAccessToken(int userId, const std::string& username, const std::string& role) {
    auto now = std::chrono::system_clock::now();
    auto expiry = now + std::chrono::minutes(ACCESS_TOKEN_EXPIRY_MINUTES);
    std::string secret = getJWTSecret();
    
    return jwt::create()
        .set_issuer("StarLightERP")
        .set_type("JWT")
        .set_issued_at(now)
        .set_expires_at(expiry)
        .set_subject(std::to_string(userId))
        .set_payload_claim("username", jwt::claim(username))
        .set_payload_claim("role", jwt::claim(role))
        .set_payload_claim("type", jwt::claim(std::string("access")))
        .sign(jwt::algorithm::hs256{secret});
}

// Validate and decode token
DecodedToken validateAndDecode(const std::string& token) {
    DecodedToken result = {0, "", "", std::chrono::system_clock::now(), false};
    
    try {
        std::string secret = getJWTSecret();
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{secret})
            .with_issuer("StarLightERP");
        
        auto decoded = jwt::decode(token);
        
        // Verify signature and claims
        verifier.verify(decoded);
        
        // Check if token is blacklisted
        if (TokenBlacklist::getInstance().isBlacklisted(token)) {
            LOG_INFO << "Token is blacklisted";
            return result;
        }
        
        // Extract claims
        result.userId = std::stoi(decoded.get_subject());
        result.username = decoded.get_payload_claim("username").as_string();
        result.role = decoded.get_payload_claim("role").as_string();
        result.expiration = decoded.get_expires_at();
        result.isValid = true;
        
    } catch (const jwt::error::token_verification_exception& e) {
        LOG_WARN << "Token verification failed: " << e.what();
    } catch (const jwt::error::claim_not_present_exception& e) {
        LOG_WARN << "Required claim not present: " << e.what();
    } catch (const std::exception& e) {
        LOG_ERROR << "Token decode error: " << e.what();
    }
    
    return result;
}

// Extract token from Authorization header ("Bearer <token>")
std::string extractTokenFromHeader(const std::string& authHeader) {
    const std::string bearerPrefix = "Bearer ";
    if (authHeader.size() > bearerPrefix.size() && 
        authHeader.substr(0, bearerPrefix.size()) == bearerPrefix) {
        return authHeader.substr(bearerPrefix.size());
    }
    return "";
}

// Token Blacklist Implementation
TokenBlacklist& TokenBlacklist::getInstance() {
    static TokenBlacklist instance;
    return instance;
}

void TokenBlacklist::addToken(const std::string& token) {
    std::lock_guard<std::mutex> lock(mutex_);
    blacklistedTokens_.insert(token);
    
    // Log for monitoring
    LOG_INFO << "Token added to blacklist. Total blacklisted: " << blacklistedTokens_.size();
}

bool TokenBlacklist::isBlacklisted(const std::string& token) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blacklistedTokens_.find(token) != blacklistedTokens_.end();
}

void TokenBlacklist::cleanup() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // In a production system, we'd decode each token and check expiry
    // For simplicity, we'll periodically clear the entire blacklist
    // A better approach would be to store tokens with expiry timestamps
    
    int sizeBefore = blacklistedTokens_.size();
    blacklistedTokens_.clear();
    
    LOG_INFO << "Blacklist cleanup: removed " << sizeBefore << " tokens";
}

} // namespace JWTAuth
