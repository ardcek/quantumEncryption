#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <conio.h>
#include <cstdint>
#include <map>
#include <algorithm>
#define _CRT_SECURE_NO_WARNINGS

using namespace std;

// Kullanıcı yapısı
struct User {
    string username;
    string password;
    bool isAdmin;
};

// Global değişkenler
map<string, User> users;
User currentUser;
const string USER_DB_FILE = "users.dat";

// 1. XOR Tabanlı Şifreleme Fonksiyonu
void xorEncryptDecrypt(const string& inputFile, const string& outputFile, const string& key) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);
    char ch;
    size_t keyIndex = 0;

    while (in.get(ch)) {
        out.put(ch ^ key[keyIndex++ % key.size()]);
    }
}

// 2. Dosya Parçalama Fonksiyonu
vector<string> splitFile(const string& filename, int parts) {
    ifstream file(filename, ios::binary | ios::ate);
    if (!file.is_open()) throw runtime_error("Dosya acilamadi: " + filename);

    size_t fileSize = file.tellg();
    file.seekg(0, ios::beg);
    size_t partSize = fileSize / parts;

    vector<string> partNames;
    vector<char> buffer(partSize);

    for (int i = 0; i < parts; i++) {
        if (i == parts - 1) partSize = fileSize - file.tellg();
        file.read(buffer.data(), partSize);

        string partName = filename + ".part" + to_string(i);
        ofstream(partName, ios::binary).write(buffer.data(), partSize);
        partNames.push_back(partName);
    }
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

            cout << "\n\tYeni Kullanici Adi: ";
            getline(cin, username);

            if (users.find(username) != users.end()) {
                cout << "\n\tHATA: Bu kullanici adi zaten var!\n";
                break;
            }
            
            cout << "\tSifre: ";
            getline(cin, password);

            cout << "\tAdmin yetkisi verilsin mi? (e/h): ";
            cin >> adminChoice;
            cin.ignore();

            User newUser;
            newUser.username = username;
            newUser.password = password;
            newUser.isAdmin = (adminChoice == 'e' || adminChoice == 'E');

            users[username] = newUser;
            saveUserDatabase();

            cout << "\n\tBASARILI: Kullanici eklendi!\n";
            break;
        }
        case 2: { // Kullanıcı sil
            string username;
            cout << "\n\tSilinecek Kullanici Adi: ";
            getline(cin, username);

            if (username == "admin") {
                cout << "\n\tHATA: Admin kullanıcısı silinemez!\n";
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

// 9. Ana menü gösterimi
void showMainMenu() {
    system("cls");
    cout << "\n";
    cout << "\t                         _                                                      _   _             \n";
    cout << "\t  __ _ _   _  __ _ _ __ | |_ _   _ _ __ ___     ___ _ __   ___ _ __ _   _ _ __ | |_(_) ___  _ __  \n";
    cout << "\t / _` | | | |/ _` | '_ \\| __| | | | '_ ` _ \\   / _ \\ '_ \\ / __| '__| | | | '_ \\| __| |/ _ \\| '_ \\ \n";
    cout << "\t| (_| | |_| | (_| | | | | |_| |_| | | | | | | |  __/ | | | (__| |  | |_| | |_) | |_| | (_) | | | |\n";
    cout << "\t \\__, |\\__,_|\\__,_|_| |_|\\__|\\__,_|_| |_| |_|  \\___|_| |_|\\___|_|   \\__, | .__/ \\__|_|\\___/|_| |_|\n";
    cout << "\t    |_|                                                             |___/|_|                      \n";
    cout << "\n";
    cout << "\t\t\t\t\t   __            ___          __    \n";
    cout << "\t\t\t\t\t  / /  __ __    / _ | _______/ /__ _\n";
    cout << "\t\t\t\t\t / _ \\/ // /   / __ |/ __/ _  / _ `/\n";
    cout << "\t\t\t\t\t/_.__/\\_, /   /_/ |_/_/  \\_,_/\\_,_/ \n";
    cout << "\t\t\t\t\t     /___/                          \n";
    cout << "\n";
    cout << "\t\t\t\t\t======================================\n";
    cout << "\t\t\t\t\t| KUANTUM SIFRELEME DOSYA YONETICI   |\n";
    cout << "\t\t\t\t\t|------------------------------------|\n";
    cout << "\t\t\t\t\t| 1. Dosya Sifrele (XOR)             |\n";
    cout << "\t\t\t\t\t| 2. Dosya Parcala                   |\n";
    cout << "\t\t\t\t\t| 3. Dosya Birlestir                 |\n";
    cout << "\t\t\t\t\t| 4. Dosya Hash Hesapla (MD5)        |\n";
    if (currentUser.isAdmin) {
        cout << "\t\t\t\t\t| 5. Kullanici Yonetimi              |\n";
        cout << "\t\t\t\t\t| 6. Cikis                           |\n";
        cout << "\t\t\t\t\t======================================\n";
    }
    else {
        cout << "\t\t\t\t\t| 5. Cikis                         |\n";
        cout << "\t\t\t\t\t======================================\n";
    }
    cout << "\n\n\t\t\t\t\tKullanici: " << currentUser.username;
    if (currentUser.isAdmin) cout << " (Admin)";
    cout << "\n\n\t\t\t\t\tSeciminiz: ";
}


// 10. Ana Program
int main() {
    OpenSSL_add_all_digests();
    loadUserDatabase();

    // Giriş ekranı
    while (true) {
        if (login()) {
            break;
        }
        else {
            cout << "\n\n\tHATA: Gecersiz kullanici adi veya sifre!\n";
            cout << "\tTekrar denemek icin bir tusa basin...";
            _getch();
        }
    }

    int choice;
    string inputFile, outputFile, key;
    vector<string> partList;

    do {
        showMainMenu();
        cin >> choice;
        cin.ignore();

        try {
            switch (choice) {
            case 1: { // XOR ŞİFRELEME İŞLEMİ
                string inputFile, outputFile, key;

                cout << "Sifrelenecek dosya (iptal icin bos birakin): ";
                getline(cin, inputFile);

                if (inputFile.empty()) {
                    cout << "\nIslem iptal edildi. Ana menuye donuluyor...\n";
                    _getch();
                    break;
                }

                cout << "Sifrelenmis dosya adi: ";
                getline(cin, outputFile);

                if (outputFile.empty()) {
                    cout << "\nHATA: Cikti dosya adi bos olamaz!\n";
                    _getch();
                    break;
                }

                cout << "Sifre anahtari: ";
                getline(cin, key);

                if (key.empty()) {
                    cout << "\nHATA: Sifre anahtari bos olamaz!\n";
                    _getch();
                    break;
                }

                try {
                    xorEncryptDecrypt(inputFile, outputFile, key);
                    cout << "\nBASARILI: Dosya sifrelendi!\n";
                    cout << "Girdi: " << inputFile << "\n";
                    cout << "Cikti: " << outputFile << "\n";
                }
                catch (const exception& e) {
                    cout << "\nHATA: " << e.what() << "\n";
                }

                cout << "\nDevam etmek icin bir tusa basin...";
                _getch();
                break;
            }

            case 2: { // DOSYA PARÇALAMA İŞLEMİ
                string inputFile;
                int parts;

                // 1. DOSYA GİRİŞİ
                cout << "Parcalanacak dosya (iptal icin bos birakin): ";
                getline(cin, inputFile);

                if (inputFile.empty()) {
                    cout << "\nIslem iptal edildi. Ana menuye donuluyor...\n";
                    _getch();
                    break;
                }

                // 2. DOSYA KONTROLÜ
                ifstream file(inputFile, ios::binary);
                if (!file) {
                    cout << "\nHATA: \"" << inputFile << "\" dosyasi acilamadi!\n";
                    cout << "Ana menuye donmek icin bir tusa basin...";
                    _getch();
                    break;
                }
                file.close();

                // 3. PARÇA SAYISI GİRİŞİ
                while (true) {
                    cout << "Parca sayisi (en az 2): ";
                    string partsStr;
                    getline(cin, partsStr);

                    if (partsStr.empty()) {
                        cout << "\nİşlem iptal edildi.\n";
                        break;
                    }

                    try {
                        parts = stoi(partsStr);
                        if (parts >= 2) break;
                        cout << "HATA: En az 2 parça girmelisiniz!\n";
                    }
                    catch (...) {
                        cout << "HATA: Geçerli bir sayı girin!\n";
                    }
                }

                // 4. PARÇALAMA İŞLEMİ
                try {
                    vector<string> createdParts = splitFile(inputFile, parts);
                    cout << "\nBASARILI: Dosya " << parts << " parçaya bolundu:\n";
                    for (const auto& part : createdParts) {
                        cout << "->" << part << "\n";
                    }
                }
                catch (const exception& e) {
                    cout << "\nHATA: " << e.what() << "\n";
                }

                cout << "\nAna menuye donmek icin bir tusa basin...";
                _getch();
                break;
            }

            case 3: { // DOSYA BİRLEŞTİRME İŞLEMİ
                vector<string> partsToMerge;
                string outputFile;

                // 1. PARÇA SAYISI SORMA
                int partCount = 0;
                while (true) {
                    cout << "Birlestirilecek parca sayisi (iptal icin 0 girin): ";
                    string partCountStr;
                    getline(cin, partCountStr);

                    if (partCountStr.empty()) {
                        cout << "\nIslem iptal edildi. Ana menuye donuluyor...\n";
                        _getch();
                        break;
                    }

                    try {
                        partCount = stoi(partCountStr);
                        if (partCount == 0) {
                            cout << "\nIslem iptal edildi. Ana menuye donuluyor...\n";
                            _getch();
                            break;
                        }
                        else if (partCount < 1) {
                            cout << "HATA: En az 1 parca girmelisiniz!\n";
                            continue;
                        }
                        break;
                    }
                    catch (...) {
                        cout << "HATA: Gecerli bir sayi girin!\n";
                    }
                }

                if (partCount == 0) break;

                // 2. PARÇALARI TEK TEK ALMA
                for (int i = 0; i < partCount; i++) {
                    while (true) {
                        cout << i + 1 << ". parca dosya yolu: ";
                        string partPath;
                        getline(cin, partPath);

                        if (partPath.empty()) {
                            cout << "HATA: Dosya yolu bos olamaz!\n";
                            continue;
                        }

                        ifstream file(partPath, ios::binary);
                        if (!file) {
                            cout << "HATA: \"" << partPath << "\" dosyasi acilamadi!\n";
                            continue;
                        }
                        file.close();

                        partsToMerge.push_back(partPath);
                        break;
                    }
                }

                // 3. ÇIKTI DOSYASI BELİRLEME
                while (true) {
                    cout << "Birlestirilmis dosya adi (iptal icin bos birakin): ";
                    getline(cin, outputFile);

                    if (outputFile.empty()) {
                        cout << "\nIslem iptal edildi. Ana menuye donuluyor...\n";
                        _getch();
                        break;
                    }

                    // Dosya uzantısı kontrolü
                    if (outputFile.find('.') == string::npos) {
                        cout << "UYARI: Dosya uzantisi belirtilmedi (.txt, .dat vb.)\n";
                    }
                    break;
                }

                if (outputFile.empty()) break;

                // 4. BİRLEŞTİRME İŞLEMİ
                try {
                    mergeFiles(partsToMerge, outputFile);
                    cout << "\nBASARILI: " << partCount << " parca birlestirildi!\n";
                    cout << "-> Cikti dosya: " << outputFile << endl;

                    // Hash hesaplama
                    string hash = calculateMD5(outputFile);
                    cout << "-> MD5 Hash: " << hash << endl;
                }
                catch (const exception& e) {
                    cout << "\nHATA: " << e.what() << endl;
                }

                cout << "\nDevam etmek icin bir tusa basin...";
                _getch();
                break;
            }

            case 4: { // HASH HESAPLAMA İŞLEMİ
                string inputFile;

                cout << "Hash hesaplanacak dosya (iptal icin bos birakin): ";
                getline(cin, inputFile);

                if (inputFile.empty()) {
                    cout << "\nIslem iptal edildi. Ana menuye donuluyor...\n";
                    _getch();
                    break;
                }

                ifstream file(inputFile, ios::binary);
                if (!file) {
                    cout << "\nHATA: \"" << inputFile << "\" dosyasi acilamadi!\n";
                    _getch();
                    break;
                }
                file.close();

                try {
                    string hash = calculateMD5(inputFile);
                    cout << "\nBASARILI: Hash hesaplandi!\n";
                    cout << "Dosya: " << inputFile << endl;
                    cout << "MD5:   " << hash << endl;
                }
                catch (const exception& e) {
                    cout << "\nHATA: " << e.what() << endl;
                }

                cout << "\nDevam etmek icin bir tusa basin...";
                _getch();
                break;
            }

            case 5: { // ÇIKIŞ
                break;
            }

            default: {
                cout << "Gecersiz secim!\n";
                _getch();
            }
            }
        }
        catch (const exception& e) {
            cerr << "HATA: " << e.what() << endl;
            _getch();
        }

    } while (choice != 5);

    EVP_cleanup();
    return 0;
}