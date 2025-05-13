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

int main() {

}