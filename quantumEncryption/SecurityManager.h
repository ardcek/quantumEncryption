#pragma once
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <map>
#include <openssl/bcrypt.h>
#include <openssl/evp.h>

// Security and Authentication Manager
class SecurityManager {
public:
    // Password strength levels
    enum class PasswordStrength {
        VERY_WEAK,
        WEAK, 
        MODERATE,
        STRONG,
        VERY_STRONG
    };

    // Login attempt tracking
    struct LoginAttempt {
        std::string username;
        std::string ipAddress;
        std::chrono::system_clock::time_point timestamp;
        bool successful;
        std::string failureReason;
    };

    // Secure user structure
    struct SecureUser {
        std::string username;
        std::vector<uint8_t> passwordHash;  // bcrypt hash
        std::vector<uint8_t> salt;
        bool isAdmin;
        bool isLocked;
        int failedAttempts;
        std::chrono::system_clock::time_point lastLogin;
        std::chrono::system_clock::time_point lockoutTime;
        std::vector<std::string> permissions;
        bool twoFactorEnabled;
        std::string totpSecret;
    };

    // Security configuration
    struct SecurityConfig {
        int maxFailedAttempts = 5;
        int lockoutDurationMinutes = 30;
        int passwordMinLength = 12;
        bool requireSpecialChars = true;
        bool requireNumbers = true;
        bool requireMixedCase = true;
        int sessionTimeoutMinutes = 60;
        bool auditLogging = true;
        bool enforceSecureMemory = true;
    };

    SecurityManager();
    ~SecurityManager();

    // Password security
    PasswordStrength analyzePasswordStrength(const std::string& password);
    std::vector<uint8_t> hashPassword(const std::string& password);
    bool verifyPassword(const std::string& password, const std::vector<uint8_t>& hash);
    std::string generateSecurePassword(int length = 16);
    
    // User management with enhanced security
    bool createSecureUser(const std::string& username, 
                         const std::string& password,
                         bool isAdmin = false,
                         const std::vector<std::string>& permissions = {});
    
    bool authenticateUser(const std::string& username, 
                         const std::string& password,
                         const std::string& ipAddress = "localhost");
    
    bool changePassword(const std::string& username,
                       const std::string& oldPassword,
                       const std::string& newPassword);

    // Account lockout and security
    bool isUserLocked(const std::string& username);
    void lockUser(const std::string& username, int durationMinutes = 0);
    void unlockUser(const std::string& username);
    void resetFailedAttempts(const std::string& username);

    // Two-Factor Authentication
    std::string generateTOTPSecret();
    bool enableTwoFactor(const std::string& username, const std::string& secret);
    bool verifyTOTPCode(const std::string& secret, const std::string& code);
    std::string generateQRCodeData(const std::string& username, const std::string& secret);

    // Session management
    struct SecureSession {
        std::string sessionId;
        std::string username;
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point lastActivity;
        std::string ipAddress;
        bool isValid;
        std::map<std::string, std::string> sessionData;
    };

    std::string createSession(const std::string& username, const std::string& ipAddress);
    bool validateSession(const std::string& sessionId);
    void invalidateSession(const std::string& sessionId);
    void cleanupExpiredSessions();

    // Audit and logging
    struct AuditEntry {
        std::chrono::system_clock::time_point timestamp;
        std::string username;
        std::string action;
        std::string resource;
        std::string ipAddress;
        bool success;
        std::string details;
    };

    void logSecurityEvent(const std::string& username,
                         const std::string& action,
                         const std::string& resource,
                         bool success,
                         const std::string& details = "",
                         const std::string& ipAddress = "localhost");

    std::vector<AuditEntry> getAuditLog(size_t maxEntries = 100);
    std::vector<AuditEntry> getSecurityAlerts();

    // Input validation and sanitization
    bool validateInput(const std::string& input, const std::string& pattern);
    std::string sanitizeFilePath(const std::string& path);
    std::string sanitizeString(const std::string& input);
    bool isValidEmail(const std::string& email);
    bool isValidIPAddress(const std::string& ip);

    // Memory protection
    void secureMemoryZero(void* ptr, size_t size);
    std::vector<uint8_t> generateSecureRandom(size_t size);
    
    // Crypto key management
    struct SecureKeyStore {
        std::vector<uint8_t> masterKey;
        std::map<std::string, std::vector<uint8_t>> keys;
        std::chrono::system_clock::time_point created;
    };

    bool initializeKeyStore(const std::string& masterPassword);
    bool storeKey(const std::string& keyId, const std::vector<uint8_t>& key);
    std::vector<uint8_t> retrieveKey(const std::string& keyId);
    bool rotateKey(const std::string& keyId);

    // Intrusion detection
    struct ThreatDetection {
        std::string threatType;
        std::string source;
        int severity; // 1-10
        std::chrono::system_clock::time_point detected;
        std::string description;
        bool handled;
    };

    void detectBruteForce(const std::string& username, const std::string& ipAddress);
    void detectUnusualActivity(const std::string& username);
    std::vector<ThreatDetection> getActiveThreats();

    // Configuration
    void updateSecurityConfig(const SecurityConfig& config);
    SecurityConfig getSecurityConfig() const;

    // Database security
    bool loadSecureDatabase(const std::string& filename, const std::string& masterPassword);
    bool saveSecureDatabase(const std::string& filename, const std::string& masterPassword);

private:
    SecurityConfig config_;
    std::map<std::string, SecureUser> users_;
    std::map<std::string, SecureSession> sessions_;
    std::vector<LoginAttempt> loginHistory_;
    std::vector<AuditEntry> auditLog_;
    std::vector<ThreatDetection> threats_;
    SecureKeyStore keyStore_;

    // Security implementation helpers
    std::vector<uint8_t> generateSalt(size_t size = 32);
    std::string generateSessionId();
    bool isSessionExpired(const SecureSession& session);
    void updateFailedAttempts(const std::string& username);
    
    // Crypto helpers
    std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data, 
                                    const std::vector<uint8_t>& key);
    std::vector<uint8_t> decryptData(const std::vector<uint8_t>& encryptedData,
                                    const std::vector<uint8_t>& key);
    
    // TOTP implementation
    uint32_t generateTOTP(const std::string& secret, uint64_t timeStep);
    
    // Pattern matching for validation
    bool matchesRegex(const std::string& input, const std::string& pattern);
};

// Secure String class for sensitive data
class SecureString {
public:
    SecureString(const std::string& data);
    SecureString(const SecureString& other) = delete;
    SecureString& operator=(const SecureString& other) = delete;
    SecureString(SecureString&& other) noexcept;
    SecureString& operator=(SecureString&& other) noexcept;
    ~SecureString();

    const char* c_str() const;
    size_t length() const;
    bool empty() const;
    void clear();

private:
    char* data_;
    size_t length_;
    size_t capacity_;
    
    void secureZero();
    void reallocate(size_t newSize);
};