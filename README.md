# Sunucu Sağlık Raporu

Python tabanlı otomatik sunucu sağlık raporu oluşturma ve e-posta ile gönderme aracı. Sistem metrikleri, MariaDB/MySQL durumu ve yavaş sorgu analizini içeren HTML raporlar oluşturur.

## 🎯 Özellikler

- **Sistem Metrikleri**: CPU, RAM, Disk kullanımı ve yük ortalamaları
- **Süreç İzleme**: En çok kaynak kullanan süreçlerin listesi
- **MariaDB/MySQL İzleme**: Veritabanı durum metrikleri
- **Yavaş Sorgu Analizi**: Slow query log analizi ve otomatik index önerileri
- **HTML Rapor**: SVG grafikleriyle zenginleştirilmiş görsel raporlar
- **E-posta Bildirimi**: Raporları otomatik e-posta ile gönderme
- **Index Önerileri**: Yavaş sorgular için SQL index önerileri oluşturma

## 📋 Gereksinimler

### Sistem Gereksinimleri
- Python 3.6 veya üzeri
- Linux işletim sistemi (Ubuntu, Debian, CentOS, vb.)
- Root veya sudo yetkisi (bazı işlemler için)

### Python Kütüphaneleri
```bash
pip3 install psutil
```

### Opsiyonel (MariaDB/MySQL analizi için)
- MariaDB veya MySQL kurulu olmalı
- MySQL komut satırı istemcisi (`mysql`)
- Slow query log etkinleştirilmiş olmalı

## 🚀 Kurulum

### 1. Dosyayı İndirin
```bash
cd /opt
wget https://raw.githubusercontent.com/OsmanYavuz-web/server-health-report/refs/heads/main/server-health-report.py
# veya
curl -O https://raw.githubusercontent.com/OsmanYavuz-web/server-health-report/refs/heads/main/server-health-report.py
```

### 2. Çalıştırma İznini Verin
```bash
chmod +x server-health-report.py
```

### 3. Virtual Environment Oluşturun ve Bağımlılıkları Kurun
```bash
# Virtual environment oluştur
python3 -m venv /opt/venv

# Virtual environment'ı aktifleştir
source /opt/venv/bin/activate

# psutil kütüphanesini kur
pip3 install psutil

# Deaktive et
deactivate
```

### 4. Konfigürasyon Ayarlarını Yapın
Dosyayı bir metin editörü ile açın:
```bash
nano server-health-report.py
```

Aşağıdaki ayarları kendi değerlerinizle güncelleyin:

#### SMTP Ayarları (Zorunlu)
```python
SMTP_HOST = "smtp.gmail.com"          # SMTP sunucu adresi
SMTP_PORT = 587                        # 587 (STARTTLS) veya 465 (SSL)
SMTP_USER = "sizin@email.com"          # Gönderen e-posta
SMTP_PASS = "uygulama_sifreniz"        # E-posta şifresi
MAIL_TO = "alici@email.com"            # Rapor alacak e-posta
```

**Gmail için Not**: Gmail kullanıyorsanız, "Uygulama Şifresi" oluşturmanız gerekebilir:
1. Google Hesabı → Güvenlik
2. 2 Adımlı Doğrulama'yı etkinleştirin
3. Uygulama Şifreleri → Şifre oluştur

#### Veritabanı Ayarları (Opsiyonel)
```python
DB_HOST = "127.0.0.1"                  # localhost yerine 127.0.0.1 kullanın
DB_PORT = "3306"                       # MySQL port
DB_USER = "root"                       # MySQL kullanıcı adı
DB_PASS = "mysql_sifreniz"             # MySQL şifresi
DB_USE_CONFIG_FILE = False             # True yaparsanız ~/.my.cnf kullanılır
```

**MySQL Bağlantı Sorunları (N/A görüyorsanız):**

**Yöntem 1: CloudLinux/cPanel Kullanıcıları**
```bash
# Master credentials'ı öğrenin
clpctl db:show:master-credentials

# Çıktıdaki bilgileri script'e girin:
# DB_HOST = "127.0.0.1"
# DB_PORT = "3306"
# DB_USER = "root"
# DB_PASS = "gösterilen_şifre"
```

**Yöntem 2: Config Dosyası (Önerilen - Daha Güvenli)**
```bash
# ~/.my.cnf dosyası oluşturun
nano ~/.my.cnf

# İçeriği:
[client]
host=127.0.0.1
port=3306
user=root
password=YOUR_MYSQL_PASSWORD

# İzinleri düzeltin
chmod 600 ~/.my.cnf

# Script'te şunu değiştirin:
DB_USE_CONFIG_FILE = True
```

**Yöntem 3: Manuel Test**
```bash
# MySQL bağlantısını test edin (localhost yerine 127.0.0.1 kullanın)
mysql -h127.0.0.1 -P3306 -uroot -p -e "SHOW STATUS LIKE 'Threads_connected';"

# Çalışıyorsa script'teki DB_HOST, DB_PORT, DB_USER ve DB_PASS'i kontrol edin
```

#### Analiz Modu
```python
DB_ANALYZE_MODE = 2  # 1=tüm VT'ler, 2=site VT'leri (önerilen), 3=manuel liste
```

## 💻 Kullanım

### Manuel Çalıştırma
```bash
# Virtual environment Python'u ile çalıştır
sudo /opt/venv/bin/python3 /opt/server-health-report.py
```

### Çıktı
Başarılı çalıştırma sonrası:
```
Rapor başarıyla e-posta ile gönderildi.
```

## ⏰ Otomatik Çalıştırma (Cron)

### Günlük Rapor (Her gün saat 09:00)
```bash
# Crontab'ı düzenle
sudo crontab -e

# Şu satırı ekleyin:
0 9 * * * /opt/venv/bin/python3 /opt/server-health-report.py >> /var/log/server-health.log 2>&1
```

### Haftalık Rapor (Her Pazartesi 09:00)
```bash
0 9 * * 1 /opt/venv/bin/python3 /opt/server-health-report.py >> /var/log/server-health.log 2>&1
```

### Saatlik Rapor
```bash
0 * * * * /opt/venv/bin/python3 /opt/server-health-report.py >> /var/log/server-health.log 2>&1
```

## 📊 Rapor İçeriği

E-posta ile gönderilen HTML rapor şunları içerir:

### 1. Sistem Özeti
- **CPU Kullanımı**: Anlık yüzde ve grafik
- **Sistem Yükü**: 1, 5, 15 dakikalık ortalamalar
- **Bellek Kullanımı**: Toplam, kullanılan, yüzde
- **Disk Kullanımı**: Toplam, kullanılan, yüzde

### 2. Süreçler
- En çok CPU kullanan 10 süreç
- PID, isim, CPU%, RAM% bilgileri

### 3. MariaDB/MySQL Durumu
- Bağlı thread sayısı
- Uptime (çalışma süresi)
- Toplam sorgu sayısı
- Yavaş sorgu sayısı
- Çalışan thread sayısı

### 4. Yavaş Sorgu Analizi
- Tespit edilen yavaş sorgular
- Önerilen indexler
- SQL komutları

## 🔧 Index Önerilerini Uygulama

Script otomatik olarak 2 dosya oluşturur:

### 1. Öneri Dosyası
Konum: `/var/log/db_index_suggestions.sql`

Index önerilerini içerir:
```sql
-- Veritabanı index önerileri oluşturulma tarihi: 2025-11-04T... UTC
ALTER TABLE users ADD INDEX idx_email (email);
ALTER TABLE orders ADD INDEX idx_user_id (user_id);
```

### 2. Uygulama Scripti
Konum: `/usr/local/bin/apply-db-indexes.sh`

Önerileri otomatik uygular:
```bash
# Önce önerileri gözden geçirin
cat /var/log/db_index_suggestions.sql

# Uygulamadan önce yedek alın!
mysqldump -u root -p --all-databases > backup.sql

# Önerileri uygulayın
sudo /usr/local/bin/apply-db-indexes.sh
```

**⚠️ UYARI**: Büyük tablolarda index oluşturma uzun sürebilir. Bakım penceresinde çalıştırın!

## 🔍 MySQL Slow Query Log Ayarları

Yavaş sorgu analizinin çalışması için slow query log etkinleştirilmelidir:

### Geçici Etkinleştirme (Yeniden başlatmada kaybolur)
```sql
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow.log';
```

### Kalıcı Etkinleştirme
`/etc/mysql/my.cnf` veya `/etc/mysql/mariadb.conf.d/50-server.cnf` dosyasına ekleyin:

```ini
[mysqld]
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_queries_not_using_indexes = 1
```

Ardından MySQL'i yeniden başlatın:
```bash
sudo systemctl restart mysql
# veya
sudo systemctl restart mariadb
```

### Log Dosyası İzinleri
```bash
sudo mkdir -p /var/log/mysql
sudo chown mysql:mysql /var/log/mysql
sudo chmod 750 /var/log/mysql
```

## 🐛 Sorun Giderme

### E-posta Gönderilemiyor
**Hata**: `Failed to send email: [Errno 111] Connection refused`

**Çözüm**:
- SMTP ayarlarını kontrol edin
- Firewall portlarını kontrol edin (587/465)
- Gmail için "Güvenli olmayan uygulamalara izin ver" veya "Uygulama Şifresi" kullanın

### MySQL Bağlantı Hatası
**Hata**: MySQL bağlantısı başarısız

**Çözüm**:
- MySQL şifresini kontrol edin
- MySQL'in çalıştığından emin olun: `sudo systemctl status mysql`
- Script sadece sistem metriklerini rapor eder, hata vermez

### İzin Hatası
**Hata**: `Permission denied`

**Çözüm**:
```bash
sudo chmod +x server-health-report.py
sudo python3 server-health-report.py
```

### psutil Modülü Bulunamadı
**Hata**: `ModuleNotFoundError: No module named 'psutil'`

**Çözüm**:
```bash
sudo pip3 install psutil
# veya
sudo apt install python3-psutil
```

### Slow Log Dosyası Bulunamadı
Script otomatik olarak yaygın konumları kontrol eder:
- `/var/log/mysql/slow.log`
- `/var/log/mysql/mysql-slow.log`
- `/var/log/mariadb/slow.log`

Manuel konum belirtmek için `DEFAULT_SLOWLOG` değişkenini düzenleyin.

## 📁 Dosya Yapısı

```
/opt/server-health-report.py              # Ana script
/opt/venv/                                # Python virtual environment
/var/log/server-health.log                # Cron çıktı log dosyası
/var/log/db_index_suggestions.sql         # Index önerileri (otomatik oluşturulur)
/usr/local/bin/apply-db-indexes.sh        # Index uygulama scripti (otomatik)
/var/log/mysql/slow.log                   # MySQL slow query log
```

## 🔐 Güvenlik Notları

1. **Şifre Güvenliği**: Script dosyası şifreler içerir, izinleri kısıtlayın:
   ```bash
   chmod 700 server-health-report.py
   chown root:root server-health-report.py
   ```

2. **SMTP Şifresi**: Mümkünse uygulama şifresi veya SMTP relay kullanın

3. **MySQL Şifresi**: Güvenli bir şifre kullanın, script'i root okusun

4. **Log Rotasyonu**: Slow query log'ları büyüyebilir:
   ```bash
   # /etc/logrotate.d/mysql
   /var/log/mysql/slow.log {
       daily
       rotate 7
       compress
       missingok
       create 640 mysql mysql
   }
   ```

## 📧 E-posta Rapor Örneği

```
Konu: Sunucu Sağlık Raporu: web-server-01

Sunucu Sağlık Raporu — web-server-01
Rapor zamanı: 2025-11-04 09:00:00 UTC

┌─────────────────────────────────────────────┐
│ CPU: 35% [████████░░░░░░░░░░]              │
│ Yük: 1.25 / 0.98 / 0.75                    │
│ Bellek: 2.3GB / 8.0GB (28%)                │
│ Disk: 45.2GB / 100GB (45%)                 │
└─────────────────────────────────────────────┘

En Çok CPU Kullanan Süreçler
PID    İsim         CPU%   RAM%
1234   mysqld       12.5   15.3
5678   php-fpm      8.2    10.1
...

MariaDB Durumu
Threads_connected: 45
Uptime: 2592000
Slow_queries: 125

Yavaş Sorgu Analizi
• users.email — ALTER TABLE users ADD INDEX idx_email (email);
• orders.user_id — ALTER TABLE orders ADD INDEX idx_user_id (user_id);

Öneriler şuraya yazıldı: /var/log/db_index_suggestions.sql
```

## 📝 Konfigürasyon Örnekleri

### Minimal (Sadece Sistem Metrikleri)
```python
# MySQL analizi istemiyorsanız, sadece SMTP ayarlarını yapın
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "monitor@example.com"
SMTP_PASS = "uygulama_sifresi"
MAIL_TO = "admin@example.com"

# Veritabanı ayarlarını boş bırakın (script yine çalışır)
```

### Tam Özellikli
```python
# Hem sistem hem veritabanı analizi
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "monitor@example.com"
SMTP_PASS = "uygulama_sifresi"
MAIL_TO = "admin@example.com"

DB_USER = "root"
DB_PASS = "mysql_sifresi"
DB_ANALYZE_MODE = 2  # Site veritabanlarını analiz et
```

## 🤝 Katkıda Bulunma

Önerileriniz ve hata bildirimleri için issue açabilirsiniz.

## 📄 Lisans

Bu script ücretsiz olarak kullanılabilir ve değiştirilebilir.

## ⚡ Hızlı Başlangıç

```bash
# 1. Scripti indirin
cd /opt
sudo wget https://github.com/OsmanYavuz-web/server-health-report/server-health-report.py

# 2. İzin verin
sudo chmod +x server-health-report.py

# 3. Virtual environment oluşturun
sudo python3 -m venv /opt/venv

# 4. Bağımlılıkları kurun
sudo /opt/venv/bin/pip3 install psutil

# 5. Ayarları yapın
sudo nano server-health-report.py
# SMTP ve DB bilgilerini girin

# 6. Test edin
sudo /opt/venv/bin/python3 /opt/server-health-report.py

# 7. Cron ekleyin (opsiyonel)
sudo crontab -e
# Ekleyin: 0 9 * * * /opt/venv/bin/python3 /opt/server-health-report.py >> /var/log/server-health.log 2>&1
```

## 📞 Destek

Sorun yaşıyorsanız:
1. Log dosyalarını kontrol edin: `/var/log/server-health.log`, `/var/log/syslog` veya `/var/log/cron`
2. Manuel çalıştırarak hata mesajlarını görün: `sudo /opt/venv/bin/python3 /opt/server-health-report.py`
3. MySQL ve SMTP ayarlarını doğrulayın

---

## 👨‍💻 Geliştirici Bilgileri

**Geliştirici:** OSMAN YAVUZ

📧 **Email:** omnyvz.yazilim@gmail.com

📱 **Telefon:** 0541 737 35 32

---

**Not**: Bu script Linux sunucular için tasarlanmıştır. Windows'ta çalışmaz.

