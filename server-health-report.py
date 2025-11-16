#!/usr/bin/env python3
# server-health-report.py
# Python3 scripti: Sistem + MariaDB sağlık bilgilerini toplar, yavaş sorguları analiz eder,
# HTML rapor oluşturur (basit SVG barlarla), e-posta ile gönderir,
# index önerilerini /var/log/db_index_suggestions.sql dosyasına yazar,
# ve talep üzerine uygulama scripti oluşturur.
#
# ===============================
# GELİŞTİRİCİ BİLGİLERİ
# ===============================
# 👨‍💻 Geliştirici: OSMAN YAVUZ
# 📧 Email: omnyvz.yazilim@gmail.com
# 📱 Telefon: 0541 737 35 32
# ===============================

import os
import sys
import psutil
import shutil
import socket
import smtplib
import datetime
import subprocess
import time
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import html
import traceback

# ===============================
# AYARLAR - ÇALIŞTIRMADAN ÖNCE DOLDURUN
# ===============================
# SMTP ayarları
SMTP_HOST = "SMTP_HOSTNAME"
SMTP_PORT = 587  # 587 = STARTTLS, 465 = SSL
SMTP_USER = "SENDER_EMAIL"
SMTP_PASS = "SMTP_PASSWORD"
MAIL_TO = "RECEIVER_EMAIL"

# Veritabanı ayarları - mysql kontrolleri ve yavaş sorgu analizi için kullanılır
DB_HOST = "127.0.0.1"  # localhost yerine 127.0.0.1 kullanın (socket sorunu için)
DB_PORT = "3306"
DB_USER = "root"
DB_PASS = "YOUR_DB_PASSWORD"
# Alternatif: MySQL config dosyası kullan (daha güvenli)
# ~/.my.cnf dosyası oluşturun:
# [client]
# host=127.0.0.1
# port=3306
# user=root
# password=YOUR_PASSWORD
# Sonra DB_USE_CONFIG_FILE = True yapın
DB_USE_CONFIG_FILE = False  # True yaparsanız DB_USER/DB_PASS yerine ~/.my.cnf kullanılır

# Hangi veritabanları analiz edilecek: 'site' modu (önerilen) mysql/sys/performance_schema'yı otomatik atlar
DB_ANALYZE_MODE = 1  # 1=tüm VT'ler, 2=site VT'leri (önerilen), 3=aşağıdaki manuel liste
DB_MANUAL_LIST = []  # DB_ANALYZE_MODE==3 ise, VT isimlerini buraya yazın örn. ["site1_db","site2_db"]

# Yavaş sorgu log dosyasının beklenen konumu (mysql değişkeni başka yeri gösteriyorsa, script oradan okumaya çalışır)
DEFAULT_SLOWLOG = "/var/log/mysql/slow.log"

# Öneri SQL çıktı dosyası
SUGGESTION_SQL = "/var/log/db_index_suggestions.sql"
APPLY_SCRIPT = "/usr/local/bin/apply-db-indexes.sh"

# Diğer
REPORT_SUBJECT = f"Sunucu Sağlık Raporu: {socket.gethostname()}"
MAX_SLOW_QUERIES = 100   # en fazla bu kadar yavaş sorgu analiz et

# ===============================
# Yardımcı Fonksiyonlar
# ===============================
def safe_run(cmd, capture=True):
    """Komut çalıştır ve çıktısını döndür (hata durumunda boş string döner)"""
    try:
        if capture:
            return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
        else:
            return subprocess.call(cmd)
    except Exception:
        return ""

def human_bytes(n):
    """Byte değerini insan okunabilir formata çevir"""
    for unit in ['B','KB','MB','GB','TB']:
        if n < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"

def svg_bar(percent, width=200, height=12, color="#4CAF50"):
    """Yüzdelik değer için SVG bar grafiği oluştur"""
    percent = max(0, min(100, percent))
    filled_w = int(width * percent / 100)
    empty_w = width - filled_w
    svg = f"""<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
  <rect x="0" y="0" width="{filled_w}" height="{height}" fill="{color}" rx="3" ry="3"/>
  <rect x="{filled_w}" y="0" width="{empty_w}" height="{height}" fill="#e6e6e6" rx="3" ry="3"/>
</svg>"""
    return svg

# ===============================
# Sistem Metrikleri
# ===============================
def gather_system_info():
    """Sistem bilgilerini topla (CPU, RAM, Disk, süreçler)"""
    info = {}
    info['time'] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    info['uptime'] = safe_run(["uptime", "-p"]).strip()
    info['load'] = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)

    # CPU warm-up
    info['cpu_percent'] = psutil.cpu_percent(interval=1)

    procs = []
    for p in psutil.process_iter(['name']):
        try:
            cpu = p.cpu_percent(interval=None)
            mem = p.memory_percent()
            procs.append((p.pid, p.info['name'], cpu, mem))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs = [p for p in procs if p[2] is not None]

    info['top_cpu'] = sorted(procs, key=lambda x: x[2], reverse=True)[:10]
    info['top_mem'] = sorted(procs, key=lambda x: x[3], reverse=True)[:10]

    mem = psutil.virtual_memory()
    info['mem_total'] = mem.total
    info['mem_used'] = mem.used
    info['mem_percent'] = mem.percent

    disk = psutil.disk_usage('/')
    info['disk_total'] = disk.total
    info['disk_used'] = disk.used
    info['disk_percent'] = disk.percent

    return info

# ===============================
# MySQL / MariaDB Yardımcıları
# ===============================
def mysql_query_raw(query):
    """MySQL sorgusu çalıştır ve çıktıyı döndür"""
    if DB_USE_CONFIG_FILE:
        cmd = ["mysql", "-N", "-B", "-e", query]
    elif DB_PASS:
        cmd = ["mysql", f"-h{DB_HOST}", f"-P{DB_PORT}", f"-u{DB_USER}", f"-p{DB_PASS}", "-N", "-B", "-e", query]
    else:
        cmd = ["mysql", f"-h{DB_HOST}", f"-P{DB_PORT}", f"-u{DB_USER}", "-N", "-B", "-e", query]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.PIPE).decode()
        return out
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode() if e.stderr else str(e)
        print(f"MySQL Bağlantı Hatası: {err_msg}")
        print(f"Komut: mysql -h{DB_HOST} -P{DB_PORT} -u{DB_USER} -p*** -N -B -e '{query[:50]}...'")
        return ""
    except Exception as e:
        print(f"MySQL Beklenmeyen Hata: {str(e)}")
        return ""

def list_databases():
    """Veritabanlarını listele (ayara göre filtrele)"""
    out = mysql_query_raw("SHOW DATABASES;")
    if not out:
        return []
    dbs = [line.strip() for line in out.splitlines()]
    if DB_ANALYZE_MODE == 1:
        return dbs
    elif DB_ANALYZE_MODE == 2:
        skip = set(['mysql', 'information_schema', 'performance_schema', 'sys'])
        return [d for d in dbs if d not in skip]
    else:
        return DB_MANUAL_LIST

def get_mysql_status():
    """MySQL durum değişkenlerini topla"""
    keys = ["Threads_connected", "Uptime", "Questions", "Slow_queries", "Threads_running"]
    res = {}
    for k in keys:
        out = mysql_query_raw(f"SHOW GLOBAL STATUS LIKE '{k}';")
        if out:
            parts = out.split()
            if len(parts) >= 2:
                res[k] = parts[1]
            else:
                res[k] = out.strip()
        else:
            res[k] = "N/A"
    return res

# ===============================
# Yavaş Sorgu Analizi & Index Önerileri
# ===============================
def find_slow_log_file():
    """Yavaş sorgu log dosyasını bul"""
    out = mysql_query_raw("SHOW VARIABLES LIKE 'slow_query_log_file';")
    if out:
        parts = out.split('\n')[-1].split('\t')
        fpath = parts[-1].strip()
        if fpath and os.path.exists(fpath):
            return fpath

    if os.path.exists(DEFAULT_SLOWLOG):
        return DEFAULT_SLOWLOG

    for p in ["/var/log/mysql/mysql-slow.log",
              "/var/log/mysql/slow.log",
              "/var/log/slow.log",
              "/var/log/mariadb/slow.log"]:
        if os.path.exists(p):
            return p
    return None

def tail_lines(path, n=MAX_SLOW_QUERIES*5):
    """Dosyanın son N satırını oku (yaklaşık)"""
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 1024
            data = b""
            while size > 0 and data.count(b'\n') < n:
                seek = max(0, size - block)
                f.seek(seek)
                data = f.read(size - seek) + data
                size = seek
            lines = data.splitlines()[-n:]
            return [l.decode('utf-8', errors='ignore') for l in lines]
    except Exception:
        return []

def parse_slow_queries(slow_lines):
    """Yavaş sorgu loglarını ayrıştır ve SQL'leri çıkar"""
    queries = []
    cur = []
    for ln in slow_lines:
        if ln.startswith('# Time') or ln.startswith('# User@Host') or ln.startswith('# Query_time'):
            if cur:
                queries.append("\n".join(cur))
                cur = [ln]
            else:
                cur = [ln]
        else:
            cur.append(ln)
    if cur:
        queries.append("\n".join(cur))

    sqls = []
    for q in queries:
        lines = q.splitlines()
        sql = "\n".join([l for l in lines if not l.startswith('#')]).strip()
        if sql:
            sql = '\n'.join([l for l in sql.splitlines()
                             if not l.strip().lower().startswith('set timestamp')])
            sqls.append(sql)
    return sqls[-MAX_SLOW_QUERIES:]

def suggest_indexes_from_query(sql):
    """Sorgudan index önerileri çıkar (sezgisel yaklaşım)"""
    lowered = sql.lower()
    suggestions = []

    where_parts = re.split(r'where|group by|order by|limit|having', lowered)
    if len(where_parts) > 1:
        where = where_parts[1]
        cols = re.findall(r'([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)', where)
        simple_cols = re.findall(r'([a-zA-Z0-9_]+)\s*(?:=|>|<|like|in|>=|<=)', where)
        for t, c in cols:
            suggestions.append((t, c))
        for c in simple_cols:
            if c.lower() not in ('and', 'or', 'not', 'in', 'like') and len(c) > 1:
                suggestions.append((None, c))

    uniq = []
    for it in suggestions:
        if it not in uniq:
            uniq.append(it)

    sql_sugs = []
    for tbl, col in uniq:
        if tbl:
            sug = f"ALTER TABLE {tbl} ADD INDEX idx_{col} ({col});"
        else:
            continue
        sql_sugs.append((tbl, col, sug))
    return sql_sugs

def analyze_slow_log_and_suggest():
    """Yavaş sorgu logunu analiz et ve index önerileri oluştur"""
    path = find_slow_log_file()
    if not path:
        return []

    lines = tail_lines(path, n=2000)
    if not lines:
        return []

    sqls = parse_slow_queries(lines)
    suggestions = []

    tbl_re = re.compile(
        r'from\s+[`]?([A-Za-z0-9_]+)[`]?(?:\s|$)|join\s+[`]?([A-Za-z0-9_]+)[`]?',
        re.IGNORECASE
    )

    for q in sqls:
        tbls = []
        for m in tbl_re.finditer(q):
            g = m.group(1) or m.group(2)
            if g:
                tbls.append(g)

        s = suggest_indexes_from_query(q)
        for tbl, col, sug in s:
            target_tbl = tbl
            if tbl is None and tbls:
                target_tbl = tbls[0]
                sug = f"ALTER TABLE {target_tbl} ADD INDEX idx_{col} ({col});"
            if target_tbl:
                suggestions.append((target_tbl, col, sug, q))

    uniq = []
    out_sugs = []
    for t, c, sq, qtext in suggestions:
        if sq not in uniq:
            uniq.append(sq)
            out_sugs.append((t, c, sq, qtext))

    if out_sugs:
        with open(SUGGESTION_SQL, "w") as f:
            f.write("-- Veritabanı index önerileri oluşturulma tarihi: "
                    + datetime.datetime.now(datetime.timezone.utc).isoformat()
                    + " UTC\n")
            for t, c, sq, qtext in out_sugs:
                f.write(sq + "\n")
        create_apply_script()

    return out_sugs

def create_apply_script():
    """Index önerilerini uygulayacak basit bir bash script oluştur"""
    content = f"""#!/bin/bash
# Veritabanı index önerilerini uygula
# UYARI: Tablolar büyükse bakım penceresinde çalıştırın.
SQLFILE="{SUGGESTION_SQL}"
if [ ! -f "$SQLFILE" ]; then
  echo "Öneri dosyası bulunamadı: $SQLFILE"
  exit 1
fi
echo "$SQLFILE dosyasından indexler uygulanıyor..."
mysql -h{DB_HOST} -P{DB_PORT} -u{DB_USER} -p'{DB_PASS}' < "$SQLFILE"
echo "Tamamlandı."
"""
    Path(APPLY_SCRIPT).write_text(content)
    os.chmod(APPLY_SCRIPT, 0o700)

# ===============================
# HTML Rapor Oluşturucu
# ===============================
def build_html(info, mysql_status, slow_summary):
    """Güzel bir HTML rapor oluştur"""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html_parts = []

    html_parts.append(f"<h2>Sunucu Sağlık Raporu — {html.escape(socket.gethostname())}</h2>")
    html_parts.append(f"<p><em>Rapor zamanı: {now}</em></p>")

    # Özet kutuları
    html_parts.append("<table style='width:100%;border-collapse:collapse;'>")
    html_parts.append("<tr>")

    # CPU
    html_parts.append(
        "<td style='padding:8px;border:1px solid #eee'>"
        f"<strong>CPU</strong><br>{info['cpu_percent']}%<br>{svg_bar(info['cpu_percent'])}"
        "</td>"
    )

    # Yük
    load1, load5, load15 = info['load']
    html_parts.append(
        "<td style='padding:8px;border:1px solid #eee'>"
        f"<strong>Yük</strong><br>{load1:.2f} / {load5:.2f} / {load15:.2f}"
        "</td>"
    )

    # Bellek
    mem_used = human_bytes(info['mem_used'])
    mem_total = human_bytes(info['mem_total'])
    html_parts.append(
        "<td style='padding:8px;border:1px solid #eee'>"
        f"<strong>Bellek</strong><br>{mem_used} / {mem_total} ({info['mem_percent']}%)"
        f"<br>{svg_bar(info['mem_percent'], color='#2196F3')}"
        "</td>"
    )

    # Disk
    disk_used = human_bytes(info['disk_used'])
    disk_total = human_bytes(info['disk_total'])
    html_parts.append(
        "<td style='padding:8px;border:1px solid #eee'>"
        f"<strong>Disk /</strong><br>{disk_used} / {disk_total} ({info['disk_percent']}%)"
        f"<br>{svg_bar(info['disk_percent'], color='#FF9800')}"
        "</td>"
    )

    html_parts.append("</tr></table>")

    # En çok CPU kullanan süreçler
    html_parts.append("<h3>En Çok CPU Kullanan Süreçler</h3>"
                      "<table style='width:100%;border-collapse:collapse'>")
    html_parts.append("<tr style='background:#f7f7f7'>"
                      "<th>PID</th><th>İsim</th><th>CPU%</th><th>RAM%</th></tr>")
    for pid, name, cpu, memp in info['top_cpu']:
        html_parts.append(
            "<tr>"
            f"<td>{pid}</td>"
            f"<td>{html.escape(str(name))}</td>"
            f"<td>{cpu:.1f}</td>"
            f"<td>{memp:.2f}</td>"
            "</tr>"
        )
    html_parts.append("</table>")

    # En çok RAM kullanan süreçler
    html_parts.append("<h3>En Çok RAM Kullanan Süreçler</h3>"
                      "<table style='width:100%;border-collapse:collapse'>")
    html_parts.append("<tr style='background:#f7f7f7'>"
                      "<th>PID</th><th>İsim</th><th>CPU%</th><th>RAM%</th></tr>")
    for pid, name, cpu, memp in info['top_mem']:
        html_parts.append(
            "<tr>"
            f"<td>{pid}</td>"
            f"<td>{html.escape(str(name))}</td>"
            f"<td>{cpu:.1f}</td>"
            f"<td>{memp:.2f}</td>"
            "</tr>"
        )
    html_parts.append("</table>")

    # MySQL durumu
    html_parts.append("<h3>MariaDB Durumu</h3>")
    if mysql_status:
        html_parts.append("<table style='border-collapse:collapse;'><tr>")
        for k, v in mysql_status.items():
            html_parts.append(
                "<td style='padding:6px;border:1px solid #eee'>"
                f"<strong>{html.escape(k)}</strong><br>{html.escape(str(v))}"
                "</td>"
            )
        html_parts.append("</tr></table>")
    else:
        html_parts.append("<p>MariaDB durum bilgisi alınamadı.</p>")

    # Yavaş sorgu özeti
    html_parts.append("<h3>Yavaş Sorgu Analizi</h3>")
    if slow_summary:
        html_parts.append("<p>Yavaş sorgu hedefleri tespit edildi ve index önerileri oluşturuldu:</p>")
        html_parts.append("<ul>")
        for t, c, sq, qtext in slow_summary:
            html_parts.append(
                "<li><strong>"
                f"{html.escape(t)}.{html.escape(c)}</strong> — "
                f"<code>{html.escape(sq)}</code></li>"
            )
        html_parts.append("</ul>")
        html_parts.append(f"<p>Öneriler şuraya yazıldı: <code>{SUGGESTION_SQL}</code></p>")
        html_parts.append(
            f"<p>Önerileri gözden geçirdikten sonra uygulamak için şunu çalıştırın: "
            f"<code>{APPLY_SCRIPT}</code></p>"
        )
    else:
        html_parts.append("<p>Yavaş sorgu önerisi bulunamadı veya slow log dosyası eksik.</p>")

    # Alt bilgi
    html_parts.append(
        "<hr><p style='font-size:12px;color:#666'>"
        "Bu otomatik bir rapordur. server-health-report.py tarafından oluşturuldu."
        "</p>"
    )

    # Geliştirici bilgileri
    html_parts.append(
        "<div style='margin-top:20px;padding:15px;background:#f5f5f5;"
        "border-radius:5px;text-align:center'>"
    )
    html_parts.append(
        "<p style='margin:5px 0;font-size:14px;color:#333'>"
        "<strong>👨‍💻 Geliştirici: OSMAN YAVUZ</strong></p>"
    )
    html_parts.append(
        "<p style='margin:5px 0;font-size:13px;color:#666'>"
        "📧 Email: <a href='mailto:omnyvz.yazilim@gmail.com' "
        "style='color:#1976D2;text-decoration:none'>omnyvz.yazilim@gmail.com</a></p>"
    )
    html_parts.append(
        "<p style='margin:5px 0;font-size:13px;color:#666'>"
        "📱 Telefon: <a href='tel:+905417373532' "
        "style='color:#1976D2;text-decoration:none'>0541 737 35 32</a></p>"
    )
    html_parts.append("</div>")

    return "<html><body style='font-family:Arial,sans-serif'>" + "\n".join(html_parts) + "</body></html>"

# ===============================
# E-posta Gönder
# ===============================
def send_mail(html_body, subject=REPORT_SUBJECT):
    """HTML raporunu e-posta ile gönder"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = MAIL_TO

    text_body = (
        "Sunucu Sağlık Raporu\n\n"
        "Bu mail HTML içeriklidir. HTML görünmüyorsa web mail veya farklı bir istemci ile açın."
    )

    part_text = MIMEText(text_body, 'plain')
    part_html = MIMEText(html_body, 'html')

    msg.attach(part_text)
    msg.attach(part_html)

    try:
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
            server.ehlo()
            server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [MAIL_TO], msg.as_string())
        server.quit()
        return True, ""
    except Exception as e:
        return False, str(e)

# ===============================
# Ana Fonksiyon
# ===============================
def main():
    """Ana rapor oluşturma ve gönderme işlemi"""
    try:
        info = gather_system_info()

        try:
            mysql_status = get_mysql_status()
        except Exception:
            mysql_status = {}

        try:
            slow_summary = analyze_slow_log_and_suggest()
        except Exception:
            slow_summary = []

        html_body = build_html(info, mysql_status, slow_summary)
        ok, err = send_mail(html_body, subject=REPORT_SUBJECT)
        if not ok:
            print("E-posta gönderilemedi:", err)
            sys.exit(2)
        else:
            print("Rapor başarıyla e-posta ile gönderildi.")
    except Exception:
        tb = traceback.format_exc()
        print("Script hatası:", tb)
        try:
            send_mail(
                f"<pre>Script hatası:\n{html.escape(tb)}</pre>",
                subject="Sunucu Sağlık Script Hatası: " + socket.gethostname()
            )
        except Exception:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
