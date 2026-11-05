# Panduan penggunaan — Bahasa Indonesia

[Kembali ke README](../README.md)

## Apa yang dijalankan?

Repository ini berisi gerbang keamanan dan aplikasi pengaduan fiktif yang terpisah. Pengunjung mengakses gateway pada **localhost:8090**. Dashboard admin berada di **localhost:9000/admin/**. Origin tidak membuka port host pada mode terlindungi. Semua data pengujian harus fiktif.

## Instalasi pertama di Windows

Aktifkan Docker Desktop dengan Linux containers. Siapkan Git dan Python 3.10+.

```powershell
git clone https://github.com/Boas04/web-security-gateway.git
cd web-security-gateway/ruang-guard
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python setup.py
Copy-Item .env.example .env
docker compose -p ruang-guard config --quiet
docker compose -p ruang-guard up -d --build
docker compose -p ruang-guard ps
curl.exe -i http://localhost:8090/api/health
```

Jika berhasil, perintah terakhir menampilkan HTTP 200 dan JSON status `ok`. JSON tersebut adalah hasil, bukan perintah yang perlu diketik. Jangan menjalankan inisialisasi ulang pada instalasi yang sudah mempunyai secret dan `.env`.

Buka dashboard, lalu baca kata sandi dari file lokal `ruang-guard/secrets/initial-password.txt`. Login hanya membutuhkan kata sandi; tidak ada akun/kata sandi bawaan tetap. File tersebut tidak boleh masuk GitHub. Panduan Linux/macOS dan kendala instalasi tersedia di [Installation](INSTALLATION.md).

## Demonstrasi dasar

1. Buka portal melalui localhost:8090, buat pengaduan fiktif, dan simpan nomor serta kunci aksesnya.
2. Lacak pengaduan menggunakan kedua kode; coba kunci salah untuk memeriksa pembatasan akses.
3. Masuk dashboard dan pilih rentang waktu yang sesuai. Statistik berasal dari log nyata, sehingga instalasi baru dapat menampilkan “Belum ada data”.
4. Periksa Event keamanan, Daftar blokir, Pengaturan proteksi, Notifikasi, dan Riwayat pengaturan.
5. Gunakan ekspor CSV untuk event atau JSON untuk laporan yang juga memuat konteks kesehatan, insiden, dan ML.

Label **Diizinkan** berarti lolos pemeriksaan keamanan, **Ditolak** berarti dibatasi kebijakan/WAF, **Gagal diproses** berarti masalah teknis, dan **Perlu ditinjau** digunakan pada temuan ML. Sumber aktif dihitung dari identitas tersamarkan, bukan jumlah orang.

## Blokir dan machine learning

Default kuota publik 120 request/60 detik. Pelanggaran pertama mendapat blokir 72 detik; pelanggaran berikutnya setelah habis meningkat menjadi 144, 288, 576 detik, hingga maksimal satu jam. Request saat masih diblokir tidak memperpanjang waktunya. Admin dapat membuka/reset blokir. Pengguna yang berbagi NAT bisa terkena kuota yang sama.

ML tidak langsung aktif saat instalasi. Kumpulkan trafik normal, tinjau dan setujui baseline, latih kandidat, periksa validasi, lalu aktifkan. Data baru tidak otomatis melatih ulang model. Temuan ML perlu penilaian admin dan tidak membatalkan penolakan WAF. Lihat [panduan ML](../ruang-guard/ML_GUIDE.md) dan [koordinasi WAF/ML](../ruang-guard/COORDINATION_GUIDE.md).

## Pengujian dan penghentian

Ikuti [Testing](TESTING.md) mulai dari tes unit. Tes integrasi lengkap sengaja menghentikan sementara WAF/origin lab dan mengubah pengaturan untuk menguji pemulihan; jangan jalankan saat lab digunakan demonstrasi lain. Hasil fixture ML tidak boleh disebut akurasi produksi.

Untuk menghentikan hanya layanan proyek ini tanpa menghapus data:

```sh
docker compose -p ruang-guard stop
```

Untuk menjalankannya kembali: `docker compose -p ruang-guard start`. Jangan menggunakan penghapusan volume atau `docker system prune` untuk penghentian rutin.

Kode pada repository ini dapat direproduksi, tetapi bukan jaminan menahan semua serangan atau DDoS volumetrik. Dashboard tetap hanya untuk loopback. Rincian konfigurasi origin kedua, aturan, log, dan notifikasi ada di [Usage](USAGE.md).
