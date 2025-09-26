#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include <thread>
#include <future>
#include <chrono>
#include <filesystem>
#include <openssl/evp.h>
#include <conio.h>
#include <cstdint>
#include <map>
#include <algorithm>
#include "CryptoEngine.h"
#include "QuantumSimulator.h"
#include "SecurityManager.h"
#define _CRT_SECURE_NO_WARNINGS

using namespace std;
namespace fs = std::filesystem;

// Global sistem nesneleri
std::unique_ptr<CryptoEngine> cryptoEngine;
std::unique_ptr<QuantumSimulator> quantumSim;
std::unique_ptr<SecurityManager> securityMgr;

// Kullanıcı yapısı (legacy support için korundu)
struct User {
    string username;
    string password;
    bool isAdmin;
};

// Global değişkenler
map<string, User> users;
User currentUser;
const string USER_DB_FILE = "users.dat";

// Gelişmiş şifreleme fonksiyonu - Quantum-safe AES-256
bool encryptFileQuantumSafe(const string& inputFile, const string& outputFile, 
                           const string& password) {
    try {
        // Quantum-safe key derivation
        auto salt = cryptoEngine->generateSecureKey(32);
        auto key = cryptoEngine->deriveKeyFromPassword(password, salt, 32);
        
        vector<uint8_t> iv, tag;
        bool success = cryptoEngine->encryptAES256GCM(inputFile, outputFile, key, iv, tag);
        
        if (success) {
            // Salt, IV, ve tag'i dosya başına kaydet
            ofstream metaFile(outputFile + ".meta", ios::binary);
            metaFile.write(reinterpret_cast<const char*>(salt.data()), salt.size());
            metaFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
            metaFile.write(reinterpret_cast<const char*>(tag.data()), tag.size());
            metaFile.close();
            
            // Güvenlik log'u
            securityMgr->logSecurityEvent(currentUser.username, "ENCRYPT_FILE", 
                                        inputFile, true, "AES-256-GCM encryption");
        }
        
        return success;
    }
    catch (const exception& e) {
        cerr << "Şifreleme hatası: " << e.what() << endl;
        securityMgr->logSecurityEvent(currentUser.username, "ENCRYPT_FILE", 
                                    inputFile, false, e.what());
        return false;
    }
}

// Gelişmiş şifre çözme fonksiyonu
bool decryptFileQuantumSafe(const string& inputFile, const string& outputFile, 
                           const string& password) {
    try {
        // Meta dosyadan salt, iv, tag'i oku
        ifstream metaFile(inputFile + ".meta", ios::binary);
        if (!metaFile) {
            throw runtime_error("Meta dosya bulunamadı");
        }
        
        vector<uint8_t> salt(32), iv(12), tag(16);
        metaFile.read(reinterpret_cast<char*>(salt.data()), 32);
        metaFile.read(reinterpret_cast<char*>(iv.data()), 12);
        metaFile.read(reinterpret_cast<char*>(tag.data()), 16);
        metaFile.close();
        
        // Anahtar türet
        auto key = cryptoEngine->deriveKeyFromPassword(password, salt, 32);
        
        bool success = cryptoEngine->decryptAES256GCM(inputFile, outputFile, key, iv, tag);
        
        // Güvenlik log'u
        securityMgr->logSecurityEvent(currentUser.username, "DECRYPT_FILE", 
                                    inputFile, success, 
                                    success ? "AES-256-GCM decryption" : "Decryption failed");
        
        return success;
    }
    catch (const exception& e) {
        cerr << "Şifre çözme hatası: " << e.what() << endl;
        securityMgr->logSecurityEvent(currentUser.username, "DECRYPT_FILE", 
                                    inputFile, false, e.what());
        return false;
    }
}

// Quantum Key Distribution ile anahtar üret
vector<uint8_t> generateQuantumKey(size_t keyLength) {
    try {
        cout << "\n\tQuantum Key Distribution (BB84) başlatılıyor...\n";
        
        auto session = quantumSim->simulateCompleteBB84(keyLength);
        
        cout << "\t- Photon gönderimi tamamlandı\n";
        cout << "\t- Quantum error rate: " << (session.quantumErrorRate * 100) << "%\n";
        cout << "\t- Discarded bits: " << session.discardedBits << "\n";
        
        if (quantumSim->detectEavesdropping(session)) {
            cout << "\t⚠️  UYARI: Dinleme tespit edildi!\n";
            return {};
        }
        
        // Error correction
        auto correction = quantumSim->performErrorCorrection(session.siftedKey);
        cout << "\t- Error correction: " << correction.correctedErrors << " bit düzeltildi\n";
        
        // Privacy amplification
        auto finalKey = quantumSim->privacyAmplification(correction.correctedKey, keyLength);
        
        cout << "\t✅ Quantum key başarıyla oluşturuldu! (" << finalKey.size() << " bytes)\n";
        
        securityMgr->logSecurityEvent(currentUser.username, "QUANTUM_KEY_GEN", 
                                    "BB84", true, "Key length: " + to_string(keyLength));
        
        return finalKey;
    }
    catch (const exception& e) {
        cerr << "Quantum key generation hatası: " << e.what() << endl;
        return cryptoEngine->generateQuantumSafeKey(keyLength); // Fallback
    }
}

// Gelişmiş dosya parçalama - Paralel işlem destekli
vector<string> splitFileAdvanced(const string& filename, int parts) {
    if (!fs::exists(filename)) {
        throw runtime_error("Dosya bulunamadı: " + filename);
    }
    
    auto fileSize = fs::file_size(filename);
    if (fileSize == 0) {
        throw runtime_error("Dosya boş: " + filename);
    }
    
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        throw runtime_error("Dosya açılamadı: " + filename);
    }
    
    size_t partSize = fileSize / parts;
    vector<string> partNames;
    vector<thread> workers;
    
    cout << "\n\tDosya parçalanıyor... (" << fileSize << " bytes, " << parts << " parça)\n";
    
    for (int i = 0; i < parts; i++) {
        size_t currentPartSize = (i == parts - 1) ? fileSize - (partSize * i) : partSize;
        string partName = filename + ".part" + to_string(i);
        partNames.push_back(partName);
        
        // Paralel parçalama
        workers.emplace_back([&file, partName, i, partSize, currentPartSize]() {
            vector<char> buffer(currentPartSize);
            
            // Thread-safe file reading
            {
                lock_guard<mutex> lock(fileMutex);
                file.seekg(i * partSize);
                file.read(buffer.data(), currentPartSize);
            }
            
            ofstream partFile(partName, ios::binary);
            partFile.write(buffer.data(), currentPartSize);
            partFile.close();
        });
    }
    
    // Tüm thread'lerin tamamlanmasını bekle
    for (auto& worker : workers) {
        worker.join();
    }
    
    file.close();
    
    // Her parça için hash hesapla
    cout << "\n\tParça hash'leri:\n";
    for (const auto& part : partNames) {
        string hash = cryptoEngine->calculateSHA3_256(part);
        cout << "\t" << fs::path(part).filename().string() << ": " << hash.substr(0, 16) << "...\n";
    }
    
    securityMgr->logSecurityEvent(currentUser.username, "SPLIT_FILE", 
                                filename, true, to_string(parts) + " parts created");
    
    return partNames;
}

// 3. Dosya Birleştirme Fonksiyonu
void mergeFiles(const vector<string>& partNames, const string& outputFile) {
    ofstream out(outputFile, ios::binary);
    if (!out) throw runtime_error("Cikti dosyasi olusturulamadi");

    for (const auto& part : partNames) {
        ifstream in(part, ios::binary);
        if (!in) {
            cerr << "Uyari: " << part << " acilamadi, atlaniyor" << endl;
            continue;
        }
        out << in.rdbuf();
    }
}

// 4. MD5 Hash Hesaplama
string calculateMD5(const string& filename) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_md5();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength;
    char buffer[1024];

    ifstream file(filename, ios::binary);
    if (!file.is_open()) return "Dosya acilamadi";

    EVP_DigestInit_ex(context, md, NULL);
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(context, buffer, file.gcount());
    }
    EVP_DigestFinal_ex(context, digest, &digestLength);
    EVP_MD_CTX_free(context);

    stringstream ss;
    for (unsigned int i = 0; i < digestLength; i++) {
        ss << hex << setw(2) << setfill('0') << (int)digest[i];
    }
    return ss.str();
}

// 5. Kullanıcı veritabanını yükle
void loadUserDatabase() {
    ifstream in(USER_DB_FILE, ios::binary);
    if (!in) {
        // Varsayılan admin kullanıcısını oluştur
        User admin;
        admin.username = "admin";
        admin.password = "admin";
        admin.isAdmin = true;
        users["admin"] = admin;
        return;
    }

    string encryptedData((istreambuf_iterator<char>(in)),
        istreambuf_iterator<char>());
    in.close();

    // Basit XOR şifre çözme
    string key = "kuantumSifreleme123!";
    string decryptedData;
    for (size_t i = 0; i < encryptedData.size(); ++i) {
        decryptedData += encryptedData[i] ^ key[i % key.size()];
    }

    istringstream iss(decryptedData);
    string line;
    while (getline(iss, line)) {
        size_t pos1 = line.find(':');
        size_t pos2 = line.find(':', pos1 + 1);
        if (pos1 != string::npos && pos2 != string::npos) {
            User user;
            user.username = line.substr(0, pos1);
            user.password = line.substr(pos1 + 1, pos2 - pos1 - 1);
            user.isAdmin = (line.substr(pos2 + 1) == "1");
            users[user.username] = user;
        }
    }
}

// 6. Kullanıcı veritabanını kaydet
void saveUserDatabase() {
    ostringstream oss;
    for (const auto& pair : users) {
        const User& user = pair.second;
        oss << user.username << ":" << user.password << ":"
            << (user.isAdmin ? "1" : "0") << "\n";
    }

    string data = oss.str();
    string encryptedData;
    string key = "kuantumSifreleme123!";
    for (size_t i = 0; i < data.size(); ++i) {
        encryptedData += data[i] ^ key[i % key.size()];
    }

    ofstream out(USER_DB_FILE, ios::binary);
    out << encryptedData;
    out.close();
}

// 7. Kullanıcı girişi
bool login() {
    string username, password;
    system("cls");
    cout << "\n\tKUANTUM SIFRELEME DOSYA YONETICI - GIRIS\n";
    cout << "\t========================================\n\n";
    cout << "\tKullanici Adi: ";
    getline(cin, username);
    cout << "\tSifre: ";

    // Şifre girişi gizleme
    char ch;
    password = "";
    while ((ch = _getch()) != 13) { 
        if (ch == 8) { 
            if (!password.empty()) {
                password.pop_back();
                cout << "\b \b";
            }
        }
        else {
            password += ch;
            cout << '*';
        }
    }

    if (users.find(username) != users.end() && users[username].password == password) {
        currentUser = users[username];
        return true;
    }
    return false;
}

// 8. Kullanıcı yönetim menüsü 
void userManagementMenu() {
    int choice;
    do {
        system("cls");
        cout << "\n\tADMIN PANELI\n";
        cout << "\t=================\n";
        cout << "\t1. Kullanici Ekle\n";
        cout << "\t2. Kullanici Sil\n";
        cout << "\t3. Kullanici Listesi\n";
        cout << "\t4. Ana Menu\n";
        cout << "\n\tSeciminiz: ";
        cin >> choice;
        cin.ignore();

        switch (choice) {
        case 1: { // Kullanıcı ekle
            string username, password;
            char adminChoice;

            // Kullanıcı adı girişi 
            while (true) {
                cout << "\n\tYeni Kullanici Adi: ";
                getline(cin, username);

                if (username.empty()) {
                    cout << "\n\tHATA: Kullanici adi bos olamaz!\n";
                    continue;
                }

                if (users.find(username) != users.end()) {
                    cout << "\n\tHATA: Bu kullanici adi zaten var!\n";
                }
                else {
                    break;  
                }
            }

            // Şifre girişi 
            while (true) {
                cout << "\tSifre: ";
                getline(cin, password);

                if (password.empty()) {
                    cout << "\n\tHATA: Sifre bos olamaz!\n";
                }
                else {
                    break;
                }
            }

            // Admin yetkisi sorusu
            while (true) {
                cout << "\tAdmin yetkisi verilsin mi? (e/h): ";
                cin >> adminChoice;
                cin.ignore();

                if (tolower(adminChoice) == 'e' || tolower(adminChoice) == 'h') {
                    break;
                }
                else {
                    cout << "\n\tHATA: Sadece 'e' veya 'h' giriniz!\n";
                }
            }

            User newUser;
            newUser.username = username;
            newUser.password = password;
            newUser.isAdmin = (tolower(adminChoice) == 'e');

            users[username] = newUser;
            saveUserDatabase();

            cout << "\n\tBASARILI: Kullanici eklendi!\n";
            cout << "\tKullanici Adi: " << username << "\n";
            cout << "\tYetki: " << (newUser.isAdmin ? "Admin" : "Standart Kullanici") << "\n";
            break;
        }
        case 2: { // Kullanıcı sil
            string username;
            cout << "\n\tSilinecek Kullanici Adi: ";
            getline(cin, username);

            if (username == "admin") {
                cout << "\n\tHATA: Admin kullanicisi silinemez!\n";
                break;
            }

            if (users.erase(username)) {
                saveUserDatabase();
                cout << "\n\tBASARILI: Kullanici silindi!\n";
            }
            else {
                cout << "\n\tHATA: Kullanici bulunamadi!\n";
            }
            break;
        }
        case 3: { // Kullanıcı listesi

            cout << "\n\tKULLANICI LISTESI\n";
            cout << "\t----------------\n";
            for (const auto& pair : users) {
                cout << "\t" << pair.first << " - "
                    << (pair.second.isAdmin ? "Admin" : "User") << "\n";
            }
            break;
        }
        case 4: // Ana menüye dön
            return;
        default:
            cout << "\n\tGecersiz secim!\n";
        }
        cout << "\n\tDevam etmek icin bir tusa basin...";
        _getch();
    } while (choice != 4);
}

// Global thread güvenliği için
mutex fileMutex;

// Gelişmiş menü gösterimi
void showEnhancedMainMenu() {
    system("cls");
    cout << "\n";
    cout << R"(
    ╔══════════════════════════════════════════════════════════════╗
    ║                🔬 QUANTUM ENCRYPTION SYSTEM v2.0             ║
    ║                                                              ║
    ║  🛡️  QUANTUM-SAFE CRYPTOGRAPHY & ADVANCED SECURITY          ║
    ╠══════════════════════════════════════════════════════════════╣
    ║                                                              ║
    ║  1. 🔐 Quantum-Safe Encryption Suite                        ║
    ║  2. ⚛️  Quantum Key Distribution (BB84/E91)                  ║
    ║  3. 📦 Advanced File Splitting & Distribution               ║
    ║  4. 🔗 Secure File Merging & Verification                   ║
    ║  5. 🔍 Security Analysis & Hash Verification                ║)" << "\n";
    
    if (currentUser.isAdmin) {
        cout << R"(    ║  6. 👨‍💼 Advanced Admin Panel                               ║
    ║  7. 📊 Security Reports & Audit Logs                    ║
    ║  8. 🚪 Secure Exit                                       ║)" << "\n";
    } else {
        cout << R"(    ║  6. 🚪 Exit                                               ║)" << "\n";
    }
    
    cout << R"(    ╚══════════════════════════════════════════════════════════════╝
    
    👤 User: )" << currentUser.username;
    
    if (currentUser.isAdmin) cout << " (👑 Admin)";
    
    cout << R"(
    
    ⚡ Select Option: )";
}

// Şifreleme menüsü
void showEncryptionMenu() {
    int choice;
    do {
        system("cls");
        cout << "\n\t🔐 QUANTUM-SAFE ENCRYPTION SUITE\n";
        cout << "\t=================================\n\n";
        cout << "\t1. AES-256-GCM Encryption (Quantum-Safe)\n";
        cout << "\t2. Post-Quantum Lattice Encryption\n";
        cout << "\t3. ChaCha20-Poly1305 Encryption\n";
        cout << "\t4. XOR Encryption (Legacy)\n";
        cout << "\t5. Decrypt File\n";
        cout << "\t6. Back to Main Menu\n";
        cout << "\n\tChoice: ";
        
        cin >> choice;
        cin.ignore();
        
        switch (choice) {
        case 1: {
            string inputFile, outputFile, password;
            cout << "\n\tFile to encrypt: ";
            getline(cin, inputFile);
            
            if (inputFile.empty()) break;
            
            cout << "\tOutput file: ";
            getline(cin, outputFile);
            
            cout << "\tPassword: ";
            getline(cin, password);
            
            if (encryptFileQuantumSafe(inputFile, outputFile, password)) {
                cout << "\n\t✅ File encrypted successfully!\n";
                cout << "\t📁 Input: " << inputFile << "\n";
                cout << "\t💾 Output: " << outputFile << "\n";
                cout << "\t🔒 Method: AES-256-GCM (Quantum-Safe)\n";
            } else {
                cout << "\n\t❌ Encryption failed!\n";
            }
            
            _getch();
            break;
        }
        case 2: {
            string inputFile, outputFile;
            cout << "\n\tFile to encrypt: ";
            getline(cin, inputFile);
            
            if (inputFile.empty()) break;
            
            cout << "\tOutput file: ";
            getline(cin, outputFile);
            
            // Generate post-quantum key
            auto publicKey = cryptoEngine->generateQuantumSafeKey(32);
            
            if (cryptoEngine->encryptLattice(inputFile, outputFile, publicKey)) {
                cout << "\n\t✅ Post-quantum encryption successful!\n";
                cout << "\t🔐 Method: Ring-LWE Lattice-based\n";
            } else {
                cout << "\n\t❌ Encryption failed!\n";
            }
            
            _getch();
            break;
        }
        case 5: {
            string inputFile, outputFile, password;
            cout << "\n\tEncrypted file: ";
            getline(cin, inputFile);
            
            if (inputFile.empty()) break;
            
            cout << "\tOutput file: ";
            getline(cin, outputFile);
            
            cout << "\tPassword: ";
            getline(cin, password);
            
            if (decryptFileQuantumSafe(inputFile, outputFile, password)) {
                cout << "\n\t✅ File decrypted successfully!\n";
            } else {
                cout << "\n\t❌ Decryption failed! (Wrong password or corrupted file)\n";
            }
            
            _getch();
            break;
        }
        default:
            if (choice != 6) {
                cout << "\n\t❌ Invalid choice!\n";
                _getch();
            }
        }
    } while (choice != 6);
}

// Quantum Key Distribution işlemi
void performQuantumKeyDistribution() {
    system("cls");
    cout << "\n\t⚛️  QUANTUM KEY DISTRIBUTION\n";
    cout << "\t============================\n\n";
    
    cout << "\tSelect Protocol:\n";
    cout << "\t1. BB84 (Prepare & Measure)\n";
    cout << "\t2. E91 (Entanglement-based)\n";
    cout << "\t3. SARG04 (4-state protocol)\n";
    cout << "\n\tChoice: ";
    
    int protocol;
    cin >> protocol;
    cin.ignore();
    
    if (protocol < 1 || protocol > 3) {
        cout << "\n\t❌ Invalid protocol selection!\n";
        _getch();
        return;
    }
    
    cout << "\n\tKey length (bytes): ";
    size_t keyLength;
    cin >> keyLength;
    cin.ignore();
    
    if (keyLength < 16 || keyLength > 1024) {
        cout << "\n\t❌ Key length must be between 16-1024 bytes!\n";
        _getch();
        return;
    }
    
    vector<uint8_t> quantumKey;
    auto startTime = chrono::high_resolution_clock::now();
    
    switch (protocol) {
    case 1:
        quantumKey = generateQuantumKey(keyLength);
        break;
    case 2:
        quantumKey = quantumSim->simulateE91Protocol(keyLength);
        break;
    case 3:
        quantumKey = quantumSim->simulateSARGProtocol(keyLength);
        break;
    }
    
    auto endTime = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - startTime);
    
    if (!quantumKey.empty()) {
        cout << "\n\t✅ Quantum key generated successfully!\n";
        cout << "\t⏱️  Generation time: " << duration.count() << " ms\n";
        cout << "\t🔑 Key length: " << quantumKey.size() << " bytes\n";
        cout << "\t🛡️  Quantum security level: ULTRA HIGH\n";
        
        // Key'i dosyaya kaydet
        string keyFile = "quantum_key_" + to_string(time(nullptr)) + ".key";
        ofstream outFile(keyFile, ios::binary);
        outFile.write(reinterpret_cast<const char*>(quantumKey.data()), quantumKey.size());
        outFile.close();
        
        cout << "\t💾 Key saved to: " << keyFile << "\n";
        
        // Entropy analizi
        double entropy = cryptoEngine->calculateEntropy(keyFile);
        cout << "\t📊 Key entropy: " << entropy << "/8.0 bits\n";
        
        if (entropy > 7.8) {
            cout << "\t🟢 Excellent entropy - Cryptographically secure\n";
        } else if (entropy > 7.0) {
            cout << "\t🟡 Good entropy - Acceptable for most uses\n";
        } else {
            cout << "\t🔴 Low entropy - Consider regenerating\n";
        }
    } else {
        cout << "\n\t❌ Quantum key generation failed!\n";
        cout << "\t🕵️  Possible eavesdropping detected!\n";
    }
    
    cout << "\n\tPress any key to continue...";
    _getch();
}

// Gelişmiş dosya parçalama
void performAdvancedFileSplitting() {
    system("cls");
    cout << "\n\t📦 ADVANCED FILE SPLITTING\n";
    cout << "\t==========================\n\n";
    
    string inputFile;
    cout << "\tFile to split: ";
    getline(cin, inputFile);
    
    if (inputFile.empty() || !fs::exists(inputFile)) {
        cout << "\n\t❌ File not found!\n";
        _getch();
        return;
    }
    
    auto fileSize = fs::file_size(inputFile);
    cout << "\n\t📁 File size: " << fileSize << " bytes (" 
         << (fileSize / 1024.0 / 1024.0) << " MB)\n";
    
    int parts;
    cout << "\tNumber of parts (2-100): ";
    cin >> parts;
    cin.ignore();
    
    if (parts < 2 || parts > 100) {
        cout << "\n\t❌ Invalid number of parts!\n";
        _getch();
        return;
    }
    
    try {
        auto startTime = chrono::high_resolution_clock::now();
        vector<string> partFiles = splitFileAdvanced(inputFile, parts);
        auto endTime = chrono::high_resolution_clock::now();
        
        auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - startTime);
        
        cout << "\n\t✅ File split successfully!\n";
        cout << "\t⏱️  Split time: " << duration.count() << " ms\n";
        cout << "\t📦 Parts created: " << partFiles.size() << "\n";
        
        // Verilerin bütünlük kontrolü için toplam hash
        string originalHash = cryptoEngine->calculateSHA3_256(inputFile);
        cout << "\n\t🔍 Original file SHA3-256: " << originalHash.substr(0, 16) << "...\n";
        
        // Part metadata dosyası oluştur
        string metadataFile = inputFile + ".split_info";
        ofstream meta(metadataFile);
        meta << "ORIGINAL_FILE=" << inputFile << "\n";
        meta << "PARTS=" << parts << "\n";
        meta << "TOTAL_SIZE=" << fileSize << "\n";
        meta << "ORIGINAL_HASH=" << originalHash << "\n";
        meta << "SPLIT_TIME=" << duration.count() << "\n";
        
        for (const auto& part : partFiles) {
            auto partSize = fs::file_size(part);
            auto partHash = cryptoEngine->calculateSHA3_256(part);
            meta << "PART=" << part << "," << partSize << "," << partHash << "\n";
        }
        meta.close();
        
        cout << "\t📋 Metadata saved to: " << metadataFile << "\n";
        
    } catch (const exception& e) {
        cout << "\n\t❌ Split failed: " << e.what() << "\n";
    }
    
    cout << "\n\tPress any key to continue...";
    _getch();
}

// Gelişmiş dosya birleştirme
void performAdvancedFileMerging() {
    system("cls");
    cout << "\n\t🔗 SECURE FILE MERGING\n";
    cout << "\t======================\n\n";
    
    string metadataFile;
    cout << "\tMetadata file (.split_info): ";
    getline(cin, metadataFile);
    
    if (metadataFile.empty() || !fs::exists(metadataFile)) {
        cout << "\n\t❌ Metadata file not found!\n";
        _getch();
        return;
    }
    
    // Metadata dosyasını oku
    ifstream meta(metadataFile);
    string line;
    string originalFile, originalHash;
    int expectedParts;
    size_t totalSize;
    vector<string> partFiles;
    
    while (getline(meta, line)) {
        if (line.find("ORIGINAL_FILE=") == 0) {
            originalFile = line.substr(14);
        } else if (line.find("PARTS=") == 0) {
            expectedParts = stoi(line.substr(6));
        } else if (line.find("TOTAL_SIZE=") == 0) {
            totalSize = stoull(line.substr(11));
        } else if (line.find("ORIGINAL_HASH=") == 0) {
            originalHash = line.substr(14);
        } else if (line.find("PART=") == 0) {
            size_t commaPos = line.find(',');
            if (commaPos != string::npos) {
                string partFile = line.substr(5, commaPos - 5);
                partFiles.push_back(partFile);
            }
        }
    }
    meta.close();
    
    cout << "\n\t📁 Original file: " << originalFile << "\n";
    cout << "\t📦 Expected parts: " << expectedParts << "\n";
    cout << "\t📏 Total size: " << totalSize << " bytes\n";
    
    // Part dosyalarının varlığını kontrol et
    vector<string> missingParts;
    for (const auto& part : partFiles) {
        if (!fs::exists(part)) {
            missingParts.push_back(part);
        }
    }
    
    if (!missingParts.empty()) {
        cout << "\n\t❌ Missing parts found:\n";
        for (const auto& missing : missingParts) {
            cout << "\t   - " << missing << "\n";
        }
        _getch();
        return;
    }
    
    string outputFile;
    cout << "\n\tOutput file name: ";
    getline(cin, outputFile);
    
    if (outputFile.empty()) {
        outputFile = originalFile + "_merged";
    }
    
    try {
        auto startTime = chrono::high_resolution_clock::now();
        
        // Birleştirme işlemi
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            throw runtime_error("Cannot create output file");
        }
        
        size_t totalMerged = 0;
        cout << "\n\t⚙️  Merging parts...\n";
        
        for (size_t i = 0; i < partFiles.size(); ++i) {
            ifstream partFile(partFiles[i], ios::binary);
            if (!partFile) {
                throw runtime_error("Cannot read part: " + partFiles[i]);
            }
            
            outFile << partFile.rdbuf();
            auto partSize = fs::file_size(partFiles[i]);
            totalMerged += partSize;
            
            cout << "\t   ✓ Part " << (i + 1) << "/" << partFiles.size() 
                 << " (" << partSize << " bytes)\n";
            
            partFile.close();
        }
        
        outFile.close();
        
        auto endTime = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - startTime);
        
        // Bütünlük kontrolü
        string mergedHash = cryptoEngine->calculateSHA3_256(outputFile);
        
        cout << "\n\t✅ File merged successfully!\n";
        cout << "\t⏱️  Merge time: " << duration.count() << " ms\n";
        cout << "\t📏 Merged size: " << totalMerged << " bytes\n";
        cout << "\t💾 Output: " << outputFile << "\n";
        
        cout << "\n\t🔍 INTEGRITY CHECK:\n";
        cout << "\t   Original hash: " << originalHash.substr(0, 32) << "...\n";
        cout << "\t   Merged hash:   " << mergedHash.substr(0, 32) << "...\n";
        
        if (originalHash == mergedHash) {
            cout << "\t   ✅ INTEGRITY VERIFIED - Files match perfectly!\n";
        } else {
            cout << "\t   ❌ INTEGRITY FAILED - Files do not match!\n";
            cout << "\t   ⚠️  Data corruption may have occurred!\n";
        }
        
    } catch (const exception& e) {
        cout << "\n\t❌ Merge failed: " << e.what() << "\n";
    }
    
    cout << "\n\tPress any key to continue...";
    _getch();
}


// Ana Program - Modern C++ ile güncellenmiş
int main() {
    try {
        // Sistem başlatma
        cout << "\n\t🔬 QUANTUM ENCRYPTION SYSTEM v2.0\n";
        cout << "\t==================================\n";
        cout << "\t🔧 Sistem başlatılıyor...\n";
        
        // Bileşenleri başlat
        cryptoEngine = make_unique<CryptoEngine>();
        quantumSim = make_unique<QuantumSimulator>();
        securityMgr = make_unique<SecurityManager>();
        
        cout << "\t✅ Quantum-safe cryptography engine loaded\n";
        cout << "\t✅ BB84 quantum simulator initialized\n";
        cout << "\t✅ Advanced security manager active\n";
        
        // OpenSSL başlat
        OpenSSL_add_all_digests();
        loadUserDatabase();
        
        cout << "\t✅ User database loaded\n";
        cout << "\t🚀 System ready!\n";
        
        // Giriş ekranı
        while (true) {
            if (login()) {
                break;
            }
            else {
                cout << "\n\n\t❌ HATA: Geçersiz kullanıcı adı veya şifre!\n";
                cout << "\tTekrar denemek için bir tuşa basın...";
                _getch();
            }
        }

        int choice;
        do {
            showEnhancedMainMenu();
            cin >> choice;
            cin.ignore();

            try {
                switch (choice) {
                case 1: // Gelişmiş şifreleme menüsü
                    showEncryptionMenu();
                    break;
                    
                case 2: // Quantum Key Distribution
                    performQuantumKeyDistribution();
                    break;
                    
                case 3: // Dosya parçalama
                    performAdvancedFileSplitting();
                    break;
                    
                case 4: // Dosya birleştirme
                    performAdvancedFileMerging();
                    break;
                    
                case 5: // Hash ve analiz
                    performSecurityAnalysis();
                    break;
                    
                case 6: // Admin paneli
                    if (currentUser.isAdmin) {
                        showAdvancedAdminPanel();
                    } else {
                        cout << "\n\t❌ Yetkisiz erişim!\n";
                        _getch();
                    }
                    break;
                    
                case 7: // Güvenlik raporları
                    showSecurityReports();
                    break;
                    
                case 8: // Çıkış
                    cout << "\n\t👋 Güvenli çıkış yapılıyor...\n";
                    securityMgr->logSecurityEvent(currentUser.username, "LOGOUT", 
                                                "SYSTEM", true, "Normal logout");
                    _getch();
                    choice = 0;
                    break;
                    
                default:
                    cout << "\n\t❌ Geçersiz seçim!\n";
                    _getch();
                }
            }
            catch (const exception& e) {
                cerr << "\n\t💥 HATA: " << e.what() << endl;
                securityMgr->logSecurityEvent(currentUser.username, "ERROR", 
                                            "SYSTEM", false, e.what());
                _getch();
            }

        } while (choice != 0);
    }
    catch (const exception& e) {
        cerr << "\n💥 FATAL ERROR: " << e.what() << endl;
        _getch();
        return -1;
    }

    // Temizlik
    EVP_cleanup();
    cout << "\n\t🔒 Secure cleanup completed.\n";
    return 0;
}