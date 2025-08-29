# Cloaker System

Geo-location ve bot detection tabanlı yönlendirme sistemi. MongoDB kullanarak detaylı analytics ve admin paneli ile birlikte gelir.

## 🚀 Özellikler

- **Türkiye IP Tespiti**: Türkiye'den gelen ziyaretçileri otomatik olarak belirtilen URL'e yönlendirir
- **Mobil Cihaz Tespiti**: Mobil cihazlardan gelen trafiği yönlendirir
- **Bot/Crawler Tespiti**: Google, Bing, Facebook gibi arama motoru botlarını tespit eder
- **Admin Dashboard**: Web tabanlı yönetim paneli
- **MongoDB Analytics**: Detaylı ziyaretçi istatistikleri ve logları
- **URL Yönetimi**: Multiple yönlendirme URL'leri yönetme
- **Real-time İstatistikler**: Canlı ziyaretçi takibi

## 📋 Gereksinimler

- **Node.js** (v16 veya üstü)
- **MongoDB** (local veya cloud)

## ⚡ Kurulum

1. **Bağımlılıkları yükleyin:**
```bash
npm install
```

2. **MongoDB'yi başlatın:**
```bash
# Local MongoDB
mongod

# Veya MongoDB Atlas kullanın
```

3. **Environment değişkenlerini ayarlayın:**
```env
# .env dosyası
PORT=3000
MONGODB_URI=mongodb://localhost:27017/cloaker
SESSION_SECRET=your-secret-key-change-this-in-production-123456
REDIRECT_URL=https://example.com
```

4. **Sunucuyu başlatın:**
```bash
npm start
```

Development modunda çalıştırmak için:
```bash
npm run dev
```

## 🎛️ Admin Panel

**URL:** `http://localhost:3000/admin/login`
**Varsayılan Giriş:** admin / admin123

### Dashboard Özellikleri:
- 📊 **İstatistikler**: Toplam ziyaret, bot/mobil ziyaretler, yönlendirmeler
- 📝 **Ziyaretçi Logları**: Detaylı IP, ülke, cihaz bilgileri
- 🔗 **URL Yönetimi**: Dinamik yönlendirme URL'leri ekleme/düzenleme
- ⚙️ **Ayarlar**: Şifre değiştirme ve sistem ayarları

## 🛠️ API Endpoints

```bash
GET  /                          # Ana sayfa (cloaking logic)
GET  /test-info                 # Ziyaretçi bilgileri (JSON)
GET  /admin/login               # Admin giriş sayfası
GET  /admin/dashboard           # Admin dashboard
POST /api/login                 # Admin girişi
POST /api/logout                # Admin çıkışı
GET  /api/stats                 # İstatistikler
GET  /api/logs                  # Ziyaretçi logları
GET  /api/redirect-urls         # Yönlendirme URL'leri
POST /api/redirect-urls         # Yeni URL ekleme
POST /api/redirect-urls/:id/activate  # URL aktif etme
DELETE /api/redirect-urls/:id   # URL silme
```

## 📊 MongoDB Collections

- **users**: Admin kullanıcıları
- **visitorlogs**: Ziyaretçi kayıtları
- **redirecturls**: Yönlendirme URL'leri
- **sessions**: Oturum verileri

## 🔧 Nasıl Çalışır?

1. **Bot Tespiti**: User-Agent analizi ile bot/crawler tespiti
2. **Geo-location**: IP tabanlı ülke tespiti
3. **Mobil Tespit**: User-Agent tabanlı cihaz tespiti
4. **Akıllı Yönlendirme**: TR kullanıcıları ve mobil cihazları belirlenen URL'e yönlendirir
5. **SEO Dostu**: Botlara profesyonel HTML sayfa gösterir

## 🔒 Güvenlik

- Şifreli session yönetimi
- MongoDB injection koruması
- HTTPS ready (production için)
- Rate limiting önerisi
- Environment bazlı güvenlik

## 🌐 Production Deployment

```bash
# Environment değişkenleri
NODE_ENV=production
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/cloaker
SESSION_SECRET=very-strong-secret-key-here

# HTTPS ve reverse proxy kullanın
# Rate limiting ekleyin
# MongoDB Atlas veya güvenli MongoDB instance kullanın
```

## 📈 İstatistikler

Dashboard üzerinden erişebileceğiniz veriler:
- Toplam ziyaretçi sayısı
- Bot vs İnsan oranları
- Mobil vs Desktop dağılımı
- Ülke bazlı istatistikler
- Günlük ziyaret grafikleri
- Yönlendirme oranları

## 🔄 URL Yönetimi

Admin panelinden:
- Multiple redirect URL'leri ekleyin
- Hangi URL'nin aktif olacağını seçin
- URL'leri düzenleyin veya silin
- Real-time değişiklik (sunucu restart'ı gerektirmez)

## 📱 Responsive Design

Admin paneli tüm cihazlarda responsive olarak çalışır.