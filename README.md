# Catatan Perubahan Hari Ini

Dokumen ini merangkum perubahan pada dashboard OLT selama sesi hari ini. Baris file di bawah mengacu pada struktur kode saat ini dan bisa bergeser jika file diedit lagi.

## 1. Penyatuan frontend, backend, dan database

- `app/database.py` — Menjadi satu tempat untuk memuat `DATABASE_URL` dari `.env`, membuat koneksi SQLAlchemy, `Base`, `SessionLocal`, dan dependency `get_db`.
- `app/models.py` — Menjadi sumber model database yang dipakai route backend: `OnuDevice`, `OLTConfig`, `ActivityEvent`, `TrafficSample`, dan `OLTSettingEntry`.
- `app/main.py:1-35` — Menggunakan koneksi serta model bersama tersebut, membuat tabel yang belum ada, menjalankan migrasi kolom tambahan secara idempotent, dan memastikan dua konfigurasi OLT awal tersedia.
- `backend/app/main.py` — Menjadi compatibility launcher menuju aplikasi utama di folder root; bukan lagi aplikasi dengan ringkasan data statis yang berbeda.
- `README.md` — Menjelaskan aplikasi utama dan cara menjalankannya.

**Menjalankan aplikasi:** dari root proyek, jalankan `uvicorn app.main:app --reload`.

## 2. Dashboard, navbar, dan daftar ONU

- `app/templates/base.html:60-85, 187-193` — Tautan sidebar menuju halaman utama, badge DyingGasp/LOS, ikon Add ONU, dan menu halaman OLT/System/Template. Angka DyingGasp dan LOS diambil dari database melalui context di `app/main.py:52-60` dan API `/api/summary`.
- `app/templates/dashboard.html` dan `app/main.py:328-349` — Ringkasan jumlah OLT/ONU dan status ONU dihitung dari database. Detail perangkat keras yang belum ada di database ditampilkan sebagai belum tersedia.
- `app/templates/all_onus.html` dan `app/main.py:437-467` — Daftar ONU, filter status dan pencarian, detail ONU, serta persentase sinyal berdasarkan RX ONU: Good ≥ −27 dBm, Warning −30 sampai < −27 dBm, Critical < −30 dBm, dan Other untuk data yang tidak tersedia.

## 3. Add ONU

- `app/templates/add_onu.html` — Form input untuk pendaftaran ONU GPON.
- `app/main.py:370-432` — Memvalidasi serial number, lokasi, VLAN, nama pelanggan, dan data PPPoE; memilih ID ONU; mengirim perintah provisioning lewat Telnet; lalu menyimpan ONU ke database.

Proses ini membutuhkan OLT yang terdaftar dan password Telnet pada environment. Daftar ONU unconfigured belum diambil otomatis dari perangkat OLT.

## 4. OLT Management, SNMP, dan Telnet

- `app/templates/olt_management.html` — Form Add/Edit OLT, tampilan status koneksi dan tes terakhir, tombol **Test Connection**, serta tombol **Sync Now**.
- `app/main.py:67-75` — Menyajikan konfigurasi OLT dan hitungan ONU per OLT dari database.
- `app/main.py:125-178` — Menyimpan atau memperbarui konfigurasi OLT seperti IP, model, versi/port SNMP, username/port Telnet.
- `app/main.py:224-245` — Menguji SNMP v2c dan Telnet, menyimpan status tes/uptime/deskripsi yang didapat, dan menulis audit event.
- `app/main.py:246-284` — Sinkronisasi status ONU serta pembacaan nilai RX dari OLT melalui Telnet.
- `app/services/olt_client.py` dan `app/services/snmp_client.py` — Helper koneksi Telnet ZTE dan pembacaan SNMP v2c.
- `.env.example` — Contoh nama key untuk password Telnet dan community SNMP. Key yang diperlukan per OLT juga ditambahkan ke `.env` lokal dalam keadaan kosong; nilai rahasia tetap harus diisi pemilik perangkat.

## 5. Grafik trafik dan penyimpanan sampel

- `app/templates/graphs.html` — Filter OLT/card/PON/periode/pencarian; tombol **Ambil Sampel** mengambil satu pembacaan, sedangkan **Mulai Live** mengambil sampel setiap 10 detik selama halaman dibuka.
- `app/main.py:286-310` — Endpoint `POST /api/traffic/{onu_id}/sample` membaca rate interface ONU lewat Telnet, menyimpan download/upload ke tabel `traffic_samples`, dan membersihkan data lebih dari 30 hari saat sampel baru disimpan.
- `app/main.py:313-321` — Endpoint riwayat membaca sampel sesuai periode yang dipilih.

Grafik baru terisi setelah password Telnet tersedia dan pengambilan sampel berhasil. Data upload/download dipetakan dari arah input/output interface ONU.

## 6. OLT Settings

- `app/templates/olt_settings.html` — Tab Overview, Uplink, PON Cards, VLANs, ONU Types, WAN IP & Speed Profiles, dan System.
- `app/main.py:77-82, 180-222` — Menyediakan ringkasan ONU serta API baca/simpan/hapus item pengaturan lokal.
- Model `OLTSettingEntry` di `app/models.py` menyimpan item tersebut ke database aplikasi.

Data Uplink, PON, VLAN, ONU Type, profil WAN/kecepatan, dan preferensi System saat ini tersimpan sebagai pengaturan lokal aplikasi; belum diterapkan ke perangkat OLT. Backup `.DAT`, auto-sync jam, dan telemetri hardware belum dibuat.

## 7. TR-069 Profile

- `app/templates/base.html:192` — Menu sidebar diarahkan ke `/tr069-profiles`.
- `app/templates/tr069_profiles.html` — Halaman buat, daftar, edit, dan hapus profil TR-069.
- `app/main.py:102-110, 180-222` — Route daftar profil serta CRUD yang menyimpan data profil sebagai kategori `tr069_profile` pada `OLTSettingEntry`.

Password ditampilkan sebagai tersembunyi dan dipertahankan saat edit apabila kolom password dikosongkan. Pilihan Default OLT masih metadata; otomatisasi penerapan saat registrasi ONU belum terhubung.

## 8. Activity Log

- `app/templates/activity_log.html` — Ringkasan log, filter jenis/waktu, pencarian, dan ekspor CSV.
- `app/main.py:39-43, 84-92` serta route aksi — Membentuk audit event dan membaca riwayat aktivitas tersimpan dari database.

Log hanya mencakup aktivitas yang direkam aplikasi sejak fitur terkait berjalan; data aktivitas lama tidak dapat dibentuk ulang dari tabel ONU.

## Catatan kredensial dan status verifikasi

- Password Telnet dan community SNMP harus diisi sendiri di `.env`; nilainya tidak diketahui aplikasi dan tidak dimasukkan ke database.
- Setelah `.env` diubah, hentikan server dengan `Ctrl+C` dan jalankan kembali aplikasi.
- Perubahan hari ini belum diuji dengan koneksi ke OLT fisik. Status tes akan menunjukkan apakah koneksi berhasil atau detail kegagalannya.
- My Account/Sign Out, provisioning TR-069 otomatis, pengambilan daftar unconfigured ONU dari OLT, serta beberapa aksi lanjutan ONU belum menjadi fitur aktif.
