# VakıfBank Web Application

Bu proje VakıfBank web uygulamasının Node.js ve Express.js ile çalışan versiyonudur.

## 🚀 Kurulum

### Gereksinimler
- Node.js 18.x veya üzeri
- npm veya yarn

### Yerel Geliştirme

1. Bağımlılıkları yükleyin:
```bash
npm install
```

2. Sunucuyu başlatın:
```bash
npm start
```

3. Tarayıcınızda açın:
```
http://localhost:3000
```

## 📦 Vercel'e Deploy Etme

### Yöntem 1: Vercel CLI ile

1. Vercel CLI'yi yükleyin:
```bash
npm install -g vercel
```

2. Vercel'e login olun:
```bash
vercel login
```

3. Projeyi deploy edin:
```bash
vercel
```

4. Production'a deploy edin:
```bash
vercel --prod
```

### Yöntem 2: GitHub ile

1. Projeyi GitHub'a push edin
2. [Vercel Dashboard](https://vercel.com)'a gidin
3. "New Project" butonuna tıklayın
4. GitHub repository'nizi seçin
5. "Deploy" butonuna tıklayın

Vercel otomatik olarak:
- `package.json` dosyasını algılayacak
- Bağımlılıkları yükleyecek
- `npm start` ile sunucuyu başlatacak

## 🛠️ Proje Yapısı

```
vakifba/
├── server.js              # Express.js sunucusu
├── package.json           # Node.js bağımlılıkları
├── vercel.json           # Vercel yapılandırması
├── .gitignore            # Git ignore kuralları
├── README.md             # Bu dosya
├── node_modules/         # Node.js paketleri
└── public/               # Statik dosyalar klasörü
    ├── index.html        # Ana HTML dosyası
    ├── assets/           # Statik kaynaklar
    │   ├── img/         # Resimler
    │   └── js/          # JavaScript dosyaları
    ├── styles.*.css     # CSS dosyaları
    ├── *.js             # JavaScript bundle dosyaları
    └── fonts/           # Font dosyaları
```

## ⚙️ Yapılandırma

### Environment Variables
Vercel Dashboard'dan veya `.env` dosyasından environment variable'lar ekleyebilirsiniz:

```env
PORT=3000
NODE_ENV=production
```

### Özel Domain
Vercel Dashboard'dan özel domain ekleyebilirsiniz:
1. Project Settings > Domains
2. Add Domain butonuna tıklayın
3. Domain adınızı girin ve DNS ayarlarını yapın

## 🔒 Güvenlik

Proje şu güvenlik önlemlerini içerir:
- Helmet.js ile HTTP header güvenliği
- Compression ile dosya sıkıştırma
- Static file caching
- XSS koruması
- Clickjacking koruması

## 📝 Notlar

- Tüm statik dosyalar (CSS, JS, resimler) otomatik olarak serve edilir
- Cache kontrol header'ları optimize edilmiştir
- Compression aktiftir, dosyalar otomatik olarak sıkıştırılır

## 🐛 Sorun Giderme

### Port hatası alıyorsanız:
```bash
# Farklı bir port kullanın
PORT=3001 npm start
```

### Vercel deploy hataları:
- `vercel.json` dosyasının doğru olduğundan emin olun
- Node.js versiyonunun 18.x veya üzeri olduğunu kontrol edin
- `vercel logs` ile log'ları kontrol edin

## 📞 Destek

Sorun yaşarsanız:
1. GitHub Issues'da sorun açın
2. Vercel log'larını kontrol edin: `vercel logs`
3. Build log'larını inceleyin
