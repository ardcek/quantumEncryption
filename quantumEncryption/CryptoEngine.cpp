#include "CryptoEngine.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

CryptoEngine::CryptoEngine() : rng_(std::random_device{}()) {
    initializeOpenSSL();
    
    // Initialize lattice parameters for post-quantum crypto
    latticeParams_.dimension = 512;
    latticeParams_.modulus = 3329;  // Prime modulus
    latticeParams_.sigma = 3.2;     // Gaussian parameter
}

CryptoEngine::~CryptoEngine() {
    cleanupOpenSSL();
}

bool CryptoEngine::initializeOpenSSL() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return true;
}

void CryptoEngine::cleanupOpenSSL() {
    EVP_cleanup();
    ERR_free_strings();
}

std::vector<uint8_t> CryptoEngine::generateSecureKey(size_t keySize) {
    std::vector<uint8_t> key(keySize);
    if (RAND_bytes(key.data(), keySize) != 1) {
        throw std::runtime_error("Failed to generate secure random key");
    }
    return key;
}

std::vector<uint8_t> CryptoEngine::generateQuantumSafeKey(size_t keySize) {
    // Enhanced entropy for quantum resistance
    std::vector<uint8_t> key(keySize);
    
    // Combine multiple entropy sources
    std::uniform_int_distribution<> dist(0, 255);
    for (size_t i = 0; i < keySize; ++i) {
        // Mix hardware random with PRNG
        uint8_t hwRand;
        RAND_bytes(&hwRand, 1);
        uint8_t prngRand = static_cast<uint8_t>(dist(rng_));
        key[i] = hwRand ^ prngRand;
    }
    
    return key;
}

bool CryptoEngine::encryptAES256GCM(const std::string& inputFile, 
                                   const std::string& outputFile,
                                   const std::vector<uint8_t>& key,
                                   std::vector<uint8_t>& iv,
                                   std::vector<uint8_t>& tag) {
    if (key.size() != AES_KEY_SIZE) {
        std::cerr << "Invalid key size for AES-256" << std::endl;
        return false;
    }
    
    // Generate IV
    iv.resize(AES_IV_SIZE);
    if (RAND_bytes(iv.data(), AES_IV_SIZE) != 1) {
        return false;
    }
    
    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);
    
    if (!inFile || !outFile) {
        return false;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Write IV to output file first
    outFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    
    // Encrypt file in chunks
    const size_t CHUNK_SIZE = 4096;
    std::vector<uint8_t> inBuffer(CHUNK_SIZE);
    std::vector<uint8_t> outBuffer(CHUNK_SIZE + 16); // Extra space for GCM
    int outLen;
    
    while (inFile) {
        inFile.read(reinterpret_cast<char*>(inBuffer.data()), CHUNK_SIZE);
        int bytesRead = static_cast<int>(inFile.gcount());
        
        if (bytesRead > 0) {
            if (EVP_EncryptUpdate(ctx, outBuffer.data(), &outLen, 
                                inBuffer.data(), bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            outFile.write(reinterpret_cast<const char*>(outBuffer.data()), outLen);
        }
    }
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, outBuffer.data(), &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write(reinterpret_cast<const char*>(outBuffer.data()), outLen);
    
    // Get authentication tag
    tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Write tag to file
    outFile.write(reinterpret_cast<const char*>(tag.data()), tag.size());
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool CryptoEngine::decryptAES256GCM(const std::string& inputFile,
                                   const std::string& outputFile,
                                   const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& iv,
                                   const std::vector<uint8_t>& tag) {
    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);
    
    if (!inFile || !outFile) {
        return false;
    }
    
    // Skip IV in input file (already provided)
    inFile.seekg(AES_IV_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Get file size to determine encrypted data size (excluding tag)
    inFile.seekg(0, std::ios::end);
    size_t fileSize = inFile.tellg() - AES_IV_SIZE - 16; // Exclude IV and tag
    inFile.seekg(AES_IV_SIZE);
    
    // Decrypt data
    const size_t CHUNK_SIZE = 4096;
    std::vector<uint8_t> inBuffer(CHUNK_SIZE);
    std::vector<uint8_t> outBuffer(CHUNK_SIZE);
    int outLen;
    size_t processedBytes = 0;
    
    while (processedBytes < fileSize) {
        size_t bytesToRead = std::min(CHUNK_SIZE, fileSize - processedBytes);
        inFile.read(reinterpret_cast<char*>(inBuffer.data()), bytesToRead);
        int bytesRead = static_cast<int>(inFile.gcount());
        
        if (EVP_DecryptUpdate(ctx, outBuffer.data(), &outLen, 
                            inBuffer.data(), bytesRead) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuffer.data()), outLen);
        processedBytes += bytesRead;
    }
    
    // Set authentication tag for verification
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, 
                           const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Finalize decryption and verify authentication
    if (EVP_DecryptFinal_ex(ctx, outBuffer.data(), &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "Authentication verification failed!" << std::endl;
        return false;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Quantum Key Distribution BB84 Protocol Simulation
CryptoEngine::QuantumKey CryptoEngine::simulateBB84Protocol(size_t keyLength) {
    QuantumKey qkey;
    qkey.key.reserve(keyLength);
    qkey.bases.reserve(keyLength * 2); // Alice's bases
    qkey.bits.reserve(keyLength * 2);  // Alice's bits
    
    std::uniform_int_distribution<> bitDist(0, 1);
    std::uniform_real_distribution<> errorDist(0.0, 1.0);
    
    // Alice prepares quantum states
    std::vector<bool> aliceBases, aliceBits;
    std::vector<bool> bobBases, bobMeasurements;
    
    size_t totalBits = keyLength * 4; // Generate more bits than needed
    
    for (size_t i = 0; i < totalBits; ++i) {
        // Alice randomly chooses basis and bit
        bool aliceBasis = bitDist(rng_) == 1;  // 0 = rectilinear, 1 = diagonal
        bool aliceBit = bitDist(rng_) == 1;
        
        aliceBases.push_back(aliceBasis);
        aliceBits.push_back(aliceBit);
        
        // Bob randomly chooses measurement basis
        bool bobBasis = bitDist(rng_) == 1;
        bobBases.push_back(bobBasis);
        
        // Bob's measurement result
        bool measurement;
        if (aliceBasis == bobBasis) {
            // Same basis - perfect correlation (ignoring noise for now)
            measurement = aliceBit;
        } else {
            // Different basis - random result
            measurement = bitDist(rng_) == 1;
        }
        
        // Add quantum channel noise
        if (errorDist(rng_) < 0.05) { // 5% error rate
            measurement = !measurement;
        }
        
        bobMeasurements.push_back(measurement);
    }
    
    // Public basis comparison and sifting
    double errorRate = 0.0;
    size_t matchingBases = 0;
    
    for (size_t i = 0; i < totalBits && qkey.key.size() < keyLength; ++i) {
        if (aliceBases[i] == bobBases[i]) {
            matchingBases++;
            if (aliceBits[i] != bobMeasurements[i]) {
                errorRate++;
            }
            
            // Add to final key
            qkey.bits.push_back(aliceBits[i]);
            qkey.bases.push_back(aliceBases[i]);
            
            // Convert bit to byte (8 bits per byte)
            static uint8_t currentByte = 0;
            static int bitCount = 0;
            
            currentByte = (currentByte << 1) | (aliceBits[i] ? 1 : 0);
            bitCount++;
            
            if (bitCount == 8) {
                qkey.key.push_back(currentByte);
                currentByte = 0;
                bitCount = 0;
            }
        }
    }
    
    qkey.errorRate = matchingBases > 0 ? errorRate / matchingBases : 0.0;
    
    return qkey;
}

bool CryptoEngine::validateQuantumKey(const QuantumKey& key, double maxErrorRate) {
    return key.errorRate <= maxErrorRate && !key.key.empty();
}

// Lattice-based encryption (simplified Ring-LWE)
bool CryptoEngine::encryptLattice(const std::string& inputFile,
                                 const std::string& outputFile,
                                 const std::vector<uint8_t>& publicKey) {
    // Simplified implementation - in practice would use full Ring-LWE
    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);
    
    if (!inFile || !outFile) return false;
    
    // Generate random polynomial for encryption
    auto randomPoly = sampleGaussian(latticeParams_.dimension, latticeParams_.sigma);
    
    // Write lattice parameters to file
    outFile.write(reinterpret_cast<const char*>(&latticeParams_.dimension), sizeof(size_t));
    outFile.write(reinterpret_cast<const char*>(randomPoly.data()), 
                 randomPoly.size() * sizeof(int));
    
    // Encrypt file data with generated symmetric key
    std::vector<uint8_t> symmetricKey(32);
    for (size_t i = 0; i < 32; ++i) {
        symmetricKey[i] = static_cast<uint8_t>(randomPoly[i % randomPoly.size()] ^ 
                                              publicKey[i % publicKey.size()]);
    }
    
    // Use AES with derived key
    std::vector<uint8_t> iv, tag;
    return encryptAES256GCM(inputFile, outputFile + ".tmp", symmetricKey, iv, tag);
}

std::string CryptoEngine::calculateSHA3_256(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "File error";
    
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha3_256();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength;
    
    EVP_DigestInit_ex(context, md, nullptr);
    
    const size_t CHUNK_SIZE = 4096;
    std::vector<char> buffer(CHUNK_SIZE);
    
    while (file) {
        file.read(buffer.data(), CHUNK_SIZE);
        if (file.gcount() > 0) {
            EVP_DigestUpdate(context, buffer.data(), file.gcount());
        }
    }
    
    EVP_DigestFinal_ex(context, digest, &digestLength);
    EVP_MD_CTX_free(context);
    
    std::stringstream ss;
    for (unsigned int i = 0; i < digestLength; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    
    return ss.str();
}

std::vector<uint8_t> CryptoEngine::deriveKeyFromPassword(const std::string& password,
                                                        const std::vector<uint8_t>& salt,
                                                        size_t keyLength,
                                                        int iterations) {
    std::vector<uint8_t> key(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                         salt.data(), salt.size(),
                         iterations, EVP_sha256(),
                         keyLength, key.data()) != 1) {
        throw std::runtime_error("Key derivation failed");
    }
    
    return key;
}

double CryptoEngine::calculateEntropy(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return 0.0;
    
    std::vector<int> frequency(256, 0);
    int totalBytes = 0;
    char byte;
    
    while (file.get(byte)) {
        frequency[static_cast<unsigned char>(byte)]++;
        totalBytes++;
    }
    
    double entropy = 0.0;
    for (int freq : frequency) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / totalBytes;
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

bool CryptoEngine::isFileEncrypted(const std::string& filename) {
    double entropy = calculateEntropy(filename);
    return entropy > 7.5; // High entropy suggests encryption
}

// Helper functions
std::vector<uint8_t> CryptoEngine::generateSalt(size_t size) {
    std::vector<uint8_t> salt(size);
    if (RAND_bytes(salt.data(), size) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }
    return salt;
}

std::vector<std::vector<int>> CryptoEngine::generateLatticeMatrix(size_t n, size_t m) {
    std::vector<std::vector<int>> matrix(n, std::vector<int>(m));
    std::uniform_int_distribution<> dist(0, latticeParams_.modulus - 1);
    
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < m; ++j) {
            matrix[i][j] = dist(rng_);
        }
    }
    
    return matrix;
}

std::vector<int> CryptoEngine::sampleGaussian(size_t size, double sigma) {
    std::vector<int> samples(size);
    std::normal_distribution<double> dist(0.0, sigma);
    
    for (size_t i = 0; i < size; ++i) {
        samples[i] = static_cast<int>(std::round(dist(rng_))) % latticeParams_.modulus;
    }
    
    return samples;
}

// Secure Buffer Implementation
SecureBuffer::SecureBuffer(size_t size) : size_(size) {
    data_ = new uint8_t[size];
    std::memset(data_, 0, size);
}

SecureBuffer::~SecureBuffer() {
    secureZero();
    delete[] data_;
}

void SecureBuffer::secureZero() {
    if (data_) {
        volatile uint8_t* volatile_ptr = data_;
        for (size_t i = 0; i < size_; ++i) {
            volatile_ptr[i] = 0;
        }
    }
}