#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <conio.h>
#include <cstdint>
#define _CRT_SECURE_NO_WARNINGS

using namespace std;

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

// 5. Menü Gösterimi
void showMenu() {
    system("cls");

    std::cout << "======================================\n";
    std::cout << "| KUANTUM SIFRELEME DOSYA YONETICI   |\n";
    std::cout << "|------------------------------------|\n";
    std::cout << "| 1. Dosya Sifrele (XOR)             |\n";
    std::cout << "| 2. Dosya Parcala                   |\n";
    std::cout << "| 3. Dosya Birlestir                 |\n";
    std::cout << "| 4. Dosya Hash Hesapla (MD5)        |\n";
    std::cout << "| 5. Cikis                           |\n";
    std::cout << "======================================\n";
    std::cout << "Seciminiz: ";
}


// 6. Ana Program
int main() {
    OpenSSL_add_all_digests();
    int choice;
    string inputFile, outputFile, key;
    vector<string> partList;

    do {
        showMenu();
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

                    // Hash hesaplama (opsiyonel)
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