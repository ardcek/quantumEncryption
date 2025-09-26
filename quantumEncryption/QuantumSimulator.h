#pragma once
#include <vector>
#include <complex>
#include <random>
#include <string>
#include <memory>

// Quantum State Representation
using Complex = std::complex<double>;
using QubitState = std::vector<Complex>;
using QuantumRegister = std::vector<QubitState>;

// Quantum Key Distribution Simulator
class QuantumSimulator {
public:
    // Quantum bases for BB84 protocol
    enum class QuantumBasis {
        RECTILINEAR,  // |0⟩, |1⟩ basis (+ polarization)
        DIAGONAL      // |+⟩, |-⟩ basis (x polarization)
    };

    // Quantum photon polarization states
    struct QuantumPhoton {
        Complex amplitude0;  // |0⟩ or |+⟩ amplitude
        Complex amplitude1;  // |1⟩ or |-⟩ amplitude
        QuantumBasis preparationBasis;
        bool classicalBit;   // The bit this photon encodes
        double fidelity;     // Quality of quantum state
    };

    // BB84 Protocol Implementation
    struct BB84Session {
        std::vector<QuantumPhoton> sentPhotons;
        std::vector<QuantumBasis> aliceBases;
        std::vector<bool> aliceBits;
        std::vector<QuantumBasis> bobBases;
        std::vector<bool> bobMeasurements;
        std::vector<uint8_t> siftedKey;
        double quantumErrorRate;
        double channelNoise;
        size_t discardedBits;
    };

    // Quantum Error Correction
    struct ErrorCorrection {
        std::vector<uint8_t> originalKey;
        std::vector<uint8_t> correctedKey;
        std::vector<bool> errorPositions;
        double errorRate;
        size_t correctedErrors;
    };

    QuantumSimulator();
    ~QuantumSimulator() = default;

    // Core BB84 Protocol Functions
    BB84Session simulateCompleteBB84(size_t desiredKeyLength, 
                                    double channelNoise = 0.05,
                                    double detectorEfficiency = 0.95);

    // Alice's operations (sender)
    std::vector<QuantumPhoton> alicePreparePhotons(const std::vector<bool>& bits,
                                                  const std::vector<QuantumBasis>& bases);
    
    // Quantum channel with noise simulation
    std::vector<QuantumPhoton> quantumChannel(const std::vector<QuantumPhoton>& photons,
                                             double noiseLevel);
    
    // Bob's operations (receiver)
    std::vector<bool> bobMeasurePhotons(const std::vector<QuantumPhoton>& photons,
                                       const std::vector<QuantumBasis>& measurementBases,
                                       double detectorEfficiency = 0.95);

    // Key sifting and reconciliation
    std::vector<uint8_t> performKeySifting(const BB84Session& session);
    ErrorCorrection performErrorCorrection(const std::vector<uint8_t>& rawKey,
                                         double maxErrorRate = 0.11);

    // Privacy amplification using universal hashing
    std::vector<uint8_t> privacyAmplification(const std::vector<uint8_t>& siftedKey,
                                            size_t finalKeyLength);

    // Quantum state manipulation
    QubitState createQubitState(bool bit, QuantumBasis basis);
    QubitState applyQuantumNoise(const QubitState& state, double noiseLevel);
    bool measureQubit(const QubitState& state, QuantumBasis measurementBasis);

    // Advanced quantum protocols
    std::vector<uint8_t> simulateE91Protocol(size_t keyLength);  // Entanglement-based QKD
    std::vector<uint8_t> simulateSARGProtocol(size_t keyLength); // SARG04 protocol

    // Quantum advantage verification
    double calculateQuantumAdvantage(const BB84Session& session);
    bool detectEavesdropping(const BB84Session& session, double threshold = 0.11);

    // Security analysis
    double calculateInformationTheoreticSecurity(const BB84Session& session);
    double estimateSecretKeyRate(double channelLoss, double errorRate);

    // Quantum state tomography (for verification)
    struct StateParameters {
        double fidelity;
        double purity;
        double entanglement;
        std::vector<double> blochVector;
    };
    
    StateParameters analyzeQuantumState(const QubitState& state);

private:
    std::mt19937_64 rng_;
    
    // Quantum state constants
    static constexpr double SQRT_2 = 1.41421356237309504880;
    static const Complex I;  // Imaginary unit
    
    // Helper functions
    double calculateStateFidelity(const QubitState& state1, const QubitState& state2);
    std::vector<bool> generateRandomBits(size_t count);
    std::vector<QuantumBasis> generateRandomBases(size_t count);
    
    // Quantum gate operations
    QubitState applyPauliX(const QubitState& state);
    QubitState applyPauliZ(const QubitState& state);
    QubitState applyHadamard(const QubitState& state);
    
    // Error correction algorithms
    std::vector<uint8_t> hammingCorrection(const std::vector<uint8_t>& data);
    std::vector<uint8_t> reedSolomonCorrection(const std::vector<uint8_t>& data);
    
    // Hash functions for privacy amplification
    std::vector<uint8_t> universalHash(const std::vector<uint8_t>& input, 
                                      size_t outputLength,
                                      const std::vector<uint8_t>& hashSeed);
};

// Quantum Network Simulator (for multi-party QKD)
class QuantumNetwork {
public:
    struct QuantumNode {
        std::string nodeId;
        std::vector<uint8_t> localKey;
        double trustLevel;
        std::vector<std::string> connectedNodes;
    };

    struct NetworkTopology {
        std::vector<QuantumNode> nodes;
        std::vector<std::pair<std::string, std::string>> connections;
        double networkFidelity;
    };

    QuantumNetwork() = default;
    
    // Network QKD operations
    NetworkTopology createQuantumNetwork(const std::vector<std::string>& nodeIds);
    bool distributeKeys(NetworkTopology& network, size_t keyLength);
    std::vector<uint8_t> performMultipartyKeyAgreement(const NetworkTopology& network);
    
    // Network security analysis
    double analyzeNetworkSecurity(const NetworkTopology& network);
    std::vector<std::string> detectCompromisedNodes(const NetworkTopology& network);

private:
    QuantumSimulator qsim_;
};