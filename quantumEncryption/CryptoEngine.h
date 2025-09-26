#pragma once
#include <string>
#include <vector>
#include <memory>
#include <random>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Quantum-Safe Cryptography Engine
class CryptoEngine {
public:
    // Encryption Methods
    enum class EncryptionMethod {
        XOR_BASIC,
        AES_256_GCM,
        CHACHA20_POLY1305,
        CRYSTALS_KYBER,  // Post-quantum
        LATTICE_BASED    // Post-quantum
    };

    // Key sizes for different algorithms
    static const size_t AES_KEY_SIZE = 32;  // 256 bits
    static const size_t AES_IV_SIZE = 12;   // GCM IV
    static const size_t KYBER_KEY_SIZE = 32;

    // Constructor
    CryptoEngine();
    ~CryptoEngine();

    // Key Generation
    std::vector<uint8_t> generateSecureKey(size_t keySize);
    std::vector<uint8_t> generateQuantumSafeKey(size_t keySize);
    
    // AES-256-GCM Encryption/Decryption
    bool encryptAES256GCM(const std::string& inputFile, 
                         const std::string& outputFile,
                         const std::vector<uint8_t>& key,
                         std::vector<uint8_t>& iv,
                         std::vector<uint8_t>& tag);
    
    bool decryptAES256GCM(const std::string& inputFile,
                         const std::string& outputFile,
                         const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& iv,
                         const std::vector<uint8_t>& tag);

    // ChaCha20-Poly1305 (Modern stream cipher)
    bool encryptChaCha20(const std::string& inputFile,
                        const std::string& outputFile,
                        const std::vector<uint8_t>& key);

    // Post-Quantum Lattice-based simulation
    bool encryptLattice(const std::string& inputFile,
                       const std::string& outputFile,
                       const std::vector<uint8_t>& publicKey);
    
    bool decryptLattice(const std::string& inputFile,
                       const std::string& outputFile,
                       const std::vector<uint8_t>& privateKey);

    // Quantum Key Distribution (BB84) Simulation
    struct QuantumKey {
        std::vector<uint8_t> key;
        std::vector<bool> bases;
        std::vector<bool> bits;
        double errorRate;
    };

    QuantumKey simulateBB84Protocol(size_t keyLength);
    bool validateQuantumKey(const QuantumKey& key, double maxErrorRate = 0.11);

    // Secure Hash Functions
    std::string calculateSHA3_256(const std::string& filename);
    std::string calculateBlake3(const std::string& filename);

    // Key Derivation Function (for password-based encryption)
    std::vector<uint8_t> deriveKeyFromPassword(const std::string& password,
                                              const std::vector<uint8_t>& salt,
                                              size_t keyLength,
                                              int iterations = 100000);

    // Entropy Analysis
    double calculateEntropy(const std::string& filename);
    bool isFileEncrypted(const std::string& filename);

private:
    std::mt19937_64 rng_;
    
    // Helper functions
    bool initializeOpenSSL();
    void cleanupOpenSSL();
    std::vector<uint8_t> generateSalt(size_t size = 32);
    
    // Lattice-based crypto helpers (simplified implementation)
    struct LatticeParams {
        size_t dimension;
        size_t modulus;
        double sigma;
    };
    
    LatticeParams latticeParams_;
    std::vector<std::vector<int>> generateLatticeMatrix(size_t n, size_t m);
    std::vector<int> sampleGaussian(size_t size, double sigma);
};

// Utility class for secure memory management
class SecureBuffer {
public:
    SecureBuffer(size_t size);
    ~SecureBuffer();
    
    uint8_t* data() { return data_; }
    size_t size() const { return size_; }
    
    // Prevent copying
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
private:
    uint8_t* data_;
    size_t size_;
    void secureZero();
};