#include "QuantumSimulator.h"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <iostream>
#include <random>

const Complex QuantumSimulator::I(0.0, 1.0);

QuantumSimulator::QuantumSimulator() : rng_(std::random_device{}()) {
}

// Complete BB84 Protocol Simulation
QuantumSimulator::BB84Session QuantumSimulator::simulateCompleteBB84(
    size_t desiredKeyLength, double channelNoise, double detectorEfficiency) {
    
    BB84Session session;
    session.channelNoise = channelNoise;
    
    // Generate more bits than needed (BB84 efficiency ~50% due to basis mismatch)
    size_t rawBitsNeeded = desiredKeyLength * 4; // 4x overgeneration for safety
    
    // Alice generates random bits and bases
    session.aliceBits = generateRandomBits(rawBitsNeeded);
    session.aliceBases = generateRandomBases(rawBitsNeeded);
    
    // Alice prepares quantum photons
    session.sentPhotons = alicePreparePhotons(session.aliceBits, session.aliceBases);
    
    // Photons travel through quantum channel with noise
    auto receivedPhotons = quantumChannel(session.sentPhotons, channelNoise);
    
    // Bob chooses random measurement bases
    session.bobBases = generateRandomBases(rawBitsNeeded);
    
    // Bob measures photons
    session.bobMeasurements = bobMeasurePhotons(receivedPhotons, session.bobBases, detectorEfficiency);
    
    // Perform key sifting (keep only bits where bases match)
    session.siftedKey = performKeySifting(session);
    
    // Calculate quantum error rate
    size_t errors = 0, totalSifted = 0;
    for (size_t i = 0; i < session.aliceBits.size() && session.siftedKey.size() * 8 < desiredKeyLength; ++i) {
        if (session.aliceBases[i] == session.bobBases[i]) {
            if (session.aliceBits[i] != session.bobMeasurements[i]) {
                errors++;
            }
            totalSifted++;
        }
    }
    
    session.quantumErrorRate = totalSifted > 0 ? static_cast<double>(errors) / totalSifted : 0.0;
    session.discardedBits = rawBitsNeeded - totalSifted;
    
    return session;
}

// Alice prepares quantum photons encoding her bits
std::vector<QuantumSimulator::QuantumPhoton> QuantumSimulator::alicePreparePhotons(
    const std::vector<bool>& bits, const std::vector<QuantumBasis>& bases) {
    
    std::vector<QuantumPhoton> photons;
    photons.reserve(bits.size());
    
    for (size_t i = 0; i < bits.size(); ++i) {
        QuantumPhoton photon;
        photon.preparationBasis = bases[i];
        photon.classicalBit = bits[i];
        photon.fidelity = 1.0; // Perfect preparation
        
        if (bases[i] == QuantumBasis::RECTILINEAR) {
            // Rectilinear basis: |0⟩ or |1⟩
            if (bits[i]) {
                photon.amplitude0 = 0.0;
                photon.amplitude1 = 1.0;
            } else {
                photon.amplitude0 = 1.0;
                photon.amplitude1 = 0.0;
            }
        } else {
            // Diagonal basis: |+⟩ = (|0⟩ + |1⟩)/√2, |-⟩ = (|0⟩ - |1⟩)/√2
            if (bits[i]) {
                // |-⟩ state
                photon.amplitude0 = 1.0 / SQRT_2;
                photon.amplitude1 = -1.0 / SQRT_2;
            } else {
                // |+⟩ state
                photon.amplitude0 = 1.0 / SQRT_2;
                photon.amplitude1 = 1.0 / SQRT_2;
            }
        }
        
        photons.push_back(photon);
    }
    
    return photons;
}

// Simulate quantum channel with noise and loss
std::vector<QuantumSimulator::QuantumPhoton> QuantumSimulator::quantumChannel(
    const std::vector<QuantumPhoton>& photons, double noiseLevel) {
    
    std::vector<QuantumPhoton> noisyPhotons;
    noisyPhotons.reserve(photons.size());
    
    std::uniform_real_distribution<double> noiseDist(0.0, 1.0);
    
    for (const auto& photon : photons) {
        QuantumPhoton noisyPhoton = photon;
        
        // Apply depolarization noise
        if (noiseDist(rng_) < noiseLevel) {
            double noiseStrength = noiseDist(rng_) * 0.3; // Up to 30% amplitude change
            
            // Add noise to amplitudes while preserving normalization
            Complex noise0(noiseDist(rng_) - 0.5, noiseDist(rng_) - 0.5);
            Complex noise1(noiseDist(rng_) - 0.5, noiseDist(rng_) - 0.5);
            
            noisyPhoton.amplitude0 += noise0 * noiseStrength;
            noisyPhoton.amplitude1 += noise1 * noiseStrength;
            
            // Renormalize
            double norm = sqrt(std::norm(noisyPhoton.amplitude0) + std::norm(noisyPhoton.amplitude1));
            if (norm > 0.0) {
                noisyPhoton.amplitude0 /= norm;
                noisyPhoton.amplitude1 /= norm;
            }
            
            noisyPhoton.fidelity *= (1.0 - noiseLevel);
        }
        
        noisyPhotons.push_back(noisyPhoton);
    }
    
    return noisyPhotons;
}

// Bob measures the photons in his chosen bases
std::vector<bool> QuantumSimulator::bobMeasurePhotons(
    const std::vector<QuantumPhoton>& photons,
    const std::vector<QuantumBasis>& measurementBases,
    double detectorEfficiency) {
    
    std::vector<bool> measurements;
    measurements.reserve(photons.size());
    
    std::uniform_real_distribution<double> probDist(0.0, 1.0);
    
    for (size_t i = 0; i < photons.size(); ++i) {
        const auto& photon = photons[i];
        QuantumBasis measureBasis = measurementBases[i];
        
        // Check detector efficiency
        if (probDist(rng_) > detectorEfficiency) {
            // Photon lost - use random measurement
            measurements.push_back(probDist(rng_) < 0.5);
            continue;
        }
        
        double prob0, prob1;
        
        if (measureBasis == QuantumBasis::RECTILINEAR) {
            // Measure in {|0⟩, |1⟩} basis
            prob0 = std::norm(photon.amplitude0);
            prob1 = std::norm(photon.amplitude1);
        } else {
            // Measure in {|+⟩, |-⟩} basis
            // |+⟩ = (|0⟩ + |1⟩)/√2, |-⟩ = (|0⟩ - |1⟩)/√2
            Complex plus_amp = (photon.amplitude0 + photon.amplitude1) / SQRT_2;
            Complex minus_amp = (photon.amplitude0 - photon.amplitude1) / SQRT_2;
            
            prob0 = std::norm(plus_amp);  // Probability of measuring |+⟩
            prob1 = std::norm(minus_amp); // Probability of measuring |-⟩
        }
        
        // Quantum measurement - probabilistic outcome
        measurements.push_back(probDist(rng_) >= prob0);
    }
    
    return measurements;
}

// Perform key sifting - keep only bits where Alice and Bob used same basis
std::vector<uint8_t> QuantumSimulator::performKeySifting(const BB84Session& session) {
    std::vector<bool> siftedBits;
    
    for (size_t i = 0; i < session.aliceBases.size(); ++i) {
        if (session.aliceBases[i] == session.bobBases[i]) {
            siftedBits.push_back(session.aliceBits[i]);
        }
    }
    
    // Convert bits to bytes
    std::vector<uint8_t> keyBytes;
    for (size_t i = 0; i < siftedBits.size(); i += 8) {
        uint8_t byte = 0;
        for (int j = 0; j < 8 && (i + j) < siftedBits.size(); ++j) {
            if (siftedBits[i + j]) {
                byte |= (1 << (7 - j));
            }
        }
        keyBytes.push_back(byte);
    }
    
    return keyBytes;
}

// Error correction using simple parity checking
QuantumSimulator::ErrorCorrection QuantumSimulator::performErrorCorrection(
    const std::vector<uint8_t>& rawKey, double maxErrorRate) {
    
    ErrorCorrection correction;
    correction.originalKey = rawKey;
    correction.correctedKey = rawKey; // Start with original
    correction.errorRate = 0.0;
    correction.correctedErrors = 0;
    
    // Simple bit-flip error correction
    // In practice, would use cascade protocol or LDPC codes
    
    size_t totalBits = rawKey.size() * 8;
    correction.errorPositions.resize(totalBits, false);
    
    // Simulate random errors based on quantum error rate
    std::uniform_real_distribution<double> errorDist(0.0, 1.0);
    size_t errorCount = 0;
    
    for (size_t i = 0; i < totalBits; ++i) {
        if (errorDist(rng_) < maxErrorRate) {
            correction.errorPositions[i] = true;
            errorCount++;
            
            // Flip the bit
            size_t byteIndex = i / 8;
            size_t bitIndex = i % 8;
            correction.correctedKey[byteIndex] ^= (1 << (7 - bitIndex));
            correction.correctedErrors++;
        }
    }
    
    correction.errorRate = static_cast<double>(errorCount) / totalBits;
    
    return correction;
}

// Privacy amplification using universal hashing
std::vector<uint8_t> QuantumSimulator::privacyAmplification(
    const std::vector<uint8_t>& siftedKey, size_t finalKeyLength) {
    
    if (siftedKey.size() <= finalKeyLength) {
        return siftedKey; // No amplification needed
    }
    
    // Use simple hash function for demonstration
    // In practice, would use Toeplitz matrices or other universal hash families
    
    std::vector<uint8_t> finalKey(finalKeyLength);
    std::hash<std::string> hasher;
    
    for (size_t i = 0; i < finalKeyLength; ++i) {
        std::string chunk;
        size_t chunkSize = siftedKey.size() / finalKeyLength;
        size_t start = i * chunkSize;
        
        for (size_t j = start; j < start + chunkSize && j < siftedKey.size(); ++j) {
            chunk += static_cast<char>(siftedKey[j]);
        }
        
        auto hashValue = hasher(chunk + std::to_string(i));
        finalKey[i] = static_cast<uint8_t>(hashValue & 0xFF);
    }
    
    return finalKey;
}

// E91 Protocol (Entanglement-based QKD)
std::vector<uint8_t> QuantumSimulator::simulateE91Protocol(size_t keyLength) {
    std::vector<uint8_t> key;
    key.reserve(keyLength);
    
    std::uniform_real_distribution<double> angleDist(0.0, 2.0 * M_PI);
    std::uniform_real_distribution<double> probDist(0.0, 1.0);
    
    // Generate entangled photon pairs and measure
    for (size_t i = 0; i < keyLength * 2; ++i) {
        // Alice and Bob choose random measurement angles
        double aliceAngle = angleDist(rng_);
        double bobAngle = angleDist(rng_);
        
        // Correlation based on Bell state |Φ+⟩ = (|00⟩ + |11⟩)/√2
        double correlation = cos(aliceAngle - bobAngle);
        
        // Measurements
        bool aliceResult = probDist(rng_) < (1.0 + correlation) / 2.0;
        bool bobResult = probDist(rng_) < (1.0 + correlation) / 2.0;
        
        // Use agreement for key bit
        if (aliceResult == bobResult && key.size() < keyLength) {
            key.push_back(aliceResult ? 0xFF : 0x00);
        }
    }
    
    return key;
}

// Helper functions
std::vector<bool> QuantumSimulator::generateRandomBits(size_t count) {
    std::vector<bool> bits(count);
    std::uniform_int_distribution<> bitDist(0, 1);
    
    for (size_t i = 0; i < count; ++i) {
        bits[i] = bitDist(rng_) == 1;
    }
    
    return bits;
}

std::vector<QuantumSimulator::QuantumBasis> QuantumSimulator::generateRandomBases(size_t count) {
    std::vector<QuantumBasis> bases(count);
    std::uniform_int_distribution<> basisDist(0, 1);
    
    for (size_t i = 0; i < count; ++i) {
        bases[i] = (basisDist(rng_) == 0) ? QuantumBasis::RECTILINEAR : QuantumBasis::DIAGONAL;
    }
    
    return bases;
}

// Create qubit state for given bit and basis
QubitState QuantumSimulator::createQubitState(bool bit, QuantumBasis basis) {
    QubitState state(2);
    
    if (basis == QuantumBasis::RECTILINEAR) {
        if (bit) {
            state[0] = 0.0;  // |1⟩
            state[1] = 1.0;
        } else {
            state[0] = 1.0;  // |0⟩
            state[1] = 0.0;
        }
    } else {
        if (bit) {
            state[0] = 1.0 / SQRT_2;   // |-⟩
            state[1] = -1.0 / SQRT_2;
        } else {
            state[0] = 1.0 / SQRT_2;   // |+⟩
            state[1] = 1.0 / SQRT_2;
        }
    }
    
    return state;
}

// Quantum gates
QubitState QuantumSimulator::applyHadamard(const QubitState& state) {
    QubitState result(2);
    result[0] = (state[0] + state[1]) / SQRT_2;
    result[1] = (state[0] - state[1]) / SQRT_2;
    return result;
}

bool QuantumSimulator::measureQubit(const QubitState& state, QuantumBasis measurementBasis) {
    std::uniform_real_distribution<double> probDist(0.0, 1.0);
    
    if (measurementBasis == QuantumBasis::RECTILINEAR) {
        double prob1 = std::norm(state[1]);
        return probDist(rng_) < prob1;
    } else {
        // Convert to diagonal basis
        Complex plus_amp = (state[0] + state[1]) / SQRT_2;
        double probMinus = 1.0 - std::norm(plus_amp);
        return probDist(rng_) < probMinus;
    }
}

double QuantumSimulator::calculateQuantumAdvantage(const BB84Session& session) {
    // Calculate the theoretical advantage of quantum vs classical key distribution
    double classicalSecurityLimit = 0.5; // Classical protocols limited to 50% error tolerance
    double quantumSecurityLimit = 0.11;  // BB84 can tolerate up to 11% error
    
    if (session.quantumErrorRate < quantumSecurityLimit) {
        return (classicalSecurityLimit - session.quantumErrorRate) / classicalSecurityLimit;
    }
    
    return 0.0; // No quantum advantage
}

bool QuantumSimulator::detectEavesdropping(const BB84Session& session, double threshold) {
    // If error rate exceeds threshold, eavesdropping is detected
    return session.quantumErrorRate > threshold;
}

// Quantum Network Implementation
QuantumNetwork::NetworkTopology QuantumNetwork::createQuantumNetwork(
    const std::vector<std::string>& nodeIds) {
    
    NetworkTopology network;
    network.networkFidelity = 1.0;
    
    // Create nodes
    for (const auto& id : nodeIds) {
        QuantumNode node;
        node.nodeId = id;
        node.trustLevel = 1.0;
        network.nodes.push_back(node);
    }
    
    // Create connections (all-to-all for simplicity)
    for (size_t i = 0; i < nodeIds.size(); ++i) {
        for (size_t j = i + 1; j < nodeIds.size(); ++j) {
            network.connections.emplace_back(nodeIds[i], nodeIds[j]);
            network.nodes[i].connectedNodes.push_back(nodeIds[j]);
            network.nodes[j].connectedNodes.push_back(nodeIds[i]);
        }
    }
    
    return network;
}

bool QuantumNetwork::distributeKeys(NetworkTopology& network, size_t keyLength) {
    // Distribute quantum keys between all connected node pairs
    for (auto& node : network.nodes) {
        auto session = qsim_.simulateCompleteBB84(keyLength);
        if (!session.siftedKey.empty()) {
            node.localKey = session.siftedKey;
        } else {
            return false; // Key distribution failed
        }
    }
    
    return true;
}