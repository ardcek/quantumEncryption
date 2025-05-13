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


int main() {

}