# Quantum Encryption System

Modern quantum-safe şifreleme ve dosya yönetimi sistemi.

## Özellikler

### Şifreleme Algoritmaları
- **AES-256-GCM** - Quantum-safe encryption
- **Post-Quantum Lattice** - Gelecekteki quantum tehditlere karşı
- **ChaCha20-Poly1305** - Modern stream cipher
- **XOR** - Legacy destek

### Quantum Key Distribution
- **BB84 Protocol** - Photon simulation ile
- **E91 Protocol** - Entanglement-based
- Quantum channel gürültü simülasyonu
- Dinleme tespiti ve hata düzeltme

### Güvenlik
- Güçlü parola hash'leme
- Güvenli bellek yönetimi
- Girdi doğrulama ve güvenlik
- Audit logging sistemi

### Dosya İşlemleri
- Paralel dosya parçalama
- SHA3-256 hash doğrulaması
- Entropy analizi
- Bütünlük kontrolü

## Kurulum

### Gereksinimler
- Visual Studio 2022
- OpenSSL 3.x
- Windows 10/11 (x64)

### Kurulum Adımları

1. **OpenSSL kurulumu:**
```bash
vcpkg install openssl:x64-windows
```

2. **Projeyi derleyin:**
- `quantumEncryption.sln` dosyasını Visual Studio'da açın
- Configuration: Debug/Release
- Platform: x64
- Build → Build Solution

3. **Çalıştırın:**
```bash
.\x64\Debug\quantumEncryption.exe
```

## Kullanım

### Varsayılan Giriş
- **Kullanıcı:** `admin`
- **Şifre:** `admin`

### Temel İşlemler

**Dosya Şifrelemek için:**
1. Ana Menü → Quantum-Safe Encryption Suite
2. Dosya yolu ve şifre girin
3. AES-256-GCM otomatik olarak uygulanır

**Quantum Key Üretmek için:**
1. Ana Menü → Quantum Key Distribution
2. BB84 veya E91 protokolünü seçin
3. Key uzunluğunu belirleyin

**Dosya Parçalamak için:**
1. Ana Menü → Advanced File Splitting
2. Dosya ve parça sayısını girin
3. Paralel işleme ile hızlı parçalama

## Teknik Detaylar

### Dosya Yapısı
```
quantumEncryption/
├── CryptoEngine.h/.cpp      # Şifreleme algoritmaları
├── QuantumSimulator.h/.cpp  # Quantum protokolleri
├── SecurityManager.h        # Güvenlik yönetimi
├── MenuFunctions.cpp        # Kullanıcı arayüzü
└── quantumEncryption.cpp    # Ana uygulama
```

### Güvenlik Notları
- Bu yazılım eğitim ve araştırma amaçlıdır
- Production kullanım için güvenlik incelemesi gereklidir
- Quantum algoritmaları simüle edilmiş olup gerçek quantum güvenlik sağlamaz
- Güçlü şifreler kullanın ve key dosyalarını güvenli saklayın

## Lisans

Bu proje MIT Lisansı altında lisanslanmıştır. Detaylar için LICENSE dosyasına bakın.

## Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/yeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
4. Branch'i push edin (`git push origin feature/yeniOzellik`)
5. Pull Request oluşturun

## İletişim

- **Geliştirici:** Arda
- **GitHub:** [@ardcek](https://github.com/ardcek)

## Teşekkürler

- OpenSSL Project
- Quantum cryptography araştırma topluluğu
- Modern C++ standartları komitesi