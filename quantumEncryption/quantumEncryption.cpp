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

int main() {

}