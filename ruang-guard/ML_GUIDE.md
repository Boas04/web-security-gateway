# Machine learning Ruang Guard

## Apa yang ditambahkan

Modul **Isolation Forest dari scikit-learn 1.7.2** benar-benar dilatih dari data acuan, kemudian memberi skor pada trafik baru. WAF Coraza/CRS tetap memeriksa pola SQL injection/XSS. ML ini mendeteksi penyimpangan perilaku trafik; ia tidak membaca payload, memahami isi pengaduan, atau mengklasifikasikan jenis serangan SQL/XSS.

Mode awal adalah **review_only**: ML menambahkan temuan **Perlu ditinjau**, tidak memblokir, membuka blokir, atau mengubah aturan WAF. Penilaian Normal/Mencurigakan berasal dari admin. Status tersebut tidak mengubah keputusan keamanan event yang sudah tercatat.

## Alur dan topologi

```text
Pengunjung -> Gateway -> Coraza/CRS -> Aplikasi -> Database aplikasi
                 |
                 v
          Metadata SQLite bersama
                 |
          ml-worker (terpisah)
        agregasi -> model -> temuan
                 |
          Dashboard admin
       persetujuan baseline / pelatihan / aktivasi / tinjauan
```

Gateway tetap melakukan pemeriksaan WAF yang sama. Model tidak dieksekusi pada jalur request. Pekerja ML tidak membuka port, memakai jaringan internal tersendiri, dan tidak menghubungi aplikasi atau layanan luar. Hanya metadata dibaca dari volume bersama. Kegagalan ML tidak mengizinkan bypass WAF. Pembacaan ML dashboard yang gagal ditandai kedaluwarsa tanpa menghentikan pembaruan statistik utama.

## Data dan fitur

Satu sampel adalah **jendela satu menit yang sudah selesai untuk satu identitas sumber pada satu origin**. Enam fitur: log(1+jumlah request), log(1+jumlah rute berbeda), rasio POST, rasio rute tak dikenal, rasio HTTP >=400, dan log(1+rata-rata latensi ms). Tidak ada query URL, header, token, kata sandi, isi pengaduan, IP asli, atau identitas pribadi sebagai fitur.

Identitas sumber tetap HMAC dari peer gateway. Pengguna di balik NAT/proxy yang sama bisa tergabung; hasil bukan identifikasi individu. Log baru menyimpan origin yang aktif saat request diterima. Log historis tanpa origin tetap NULL dan dikecualikan; asal historis tidak ditebak. Statistik event umum masih gabungan, sedangkan dataset/model/temuan ML dipisahkan menurut origin.

Trafik lolos WAF belum tentu normal. Kandidat baseline harus seluruhnya diizinkan dan berstatus 200–399, lalu **ditandai normal secara eksplisit oleh admin**. Data blokir/gagal dan data yang ditandai mencurigakan tidak boleh menjadi baseline. Tidak ada impor dataset atau unggah model dari pihak luar.

## Menjalankan

Dari folder ruang-guard setelah Docker Desktop siap:

```powershell
docker compose -p ruang-guard config --quiet
docker compose -p ruang-guard up -d --build
docker compose -p ruang-guard ps
```

Ada enam layanan inti, termasuk **ml-worker**, serta satu demo-app opsional. Gateway tetap 127.0.0.1:8090; admin tetap 127.0.0.1:9000; origin tetap internal 8000 tanpa port host. Tidak ada secret yang perlu diganti. Jika layanan lain sudah aktif, pembaruan terbatas dapat memakai:

```powershell
docker compose -p ruang-guard up -d --build --no-deps gateway admin ml-worker
```

Buka http://localhost:9000/admin/#machine-learning. Worker mengumpulkan/menilai tiap 15 detik, setelah jendela satu menit selesai. Pada instalasi baru status **Belum ada model aktif** adalah keadaan yang benar, bukan kegagalan. Tidak ada model demo atau log palsu yang dipasang ke database aktif.

## Melatih model pertama

1. Gunakan aplikasi secara normal pada periode yang diketahui aman. Variasikan halaman, pencarian wajar dan pengaduan fiktif.
2. Di Analisis ML pilih jendela yang sudah diperiksa pada Data acuan, lalu klik Tandai pilihan sebagai baseline normal. Maksimal 100 pilihan per operasi; tabel menampilkan 100 jendela terbaru.
3. Minimal 40 jendela diperlukan untuk percobaan lab, termasuk minimal 30 latih dan 8 validasi dengan variasi minimal lima vektor latih berbeda. Ini batas teknis PoC, bukan bukti kecukupan dataset produksi. Dengan satu sumber aktif setiap menit, pengumpulan memerlukan sedikitnya sekitar 40 menit; periode tanpa trafik tidak menghasilkan sampel.
4. Klik Latih kandidat. HTTP handler hanya mengantrekan pekerjaan; worker melatih model secara terpisah.
5. Periksa jumlah sampel dan persentase baseline validasi yang ditandai anomali. Tombol Aktifkan tersedia jika angkanya <=25%. Batas ini hanyalah pagar eksperimen lab; nilai rendah belum membuktikan kemampuan mendeteksi serangan. Kandidat buruk tidak menggantikan model aktif.
6. Aktifkan kandidat secara eksplisit. Trafik di luar periode baseline mulai dinilai. Temuan menampilkan skor, model yang dipakai, sumber tersamarkan dan jumlah request. Skor >0 berarti anomali menurut model; **bukan probabilitas serangan**.
7. Tinjau sebagai Normal atau Mencurigakan. Penilaian ini tidak otomatis melatih ulang model, mengesahkan baseline, atau memblokir sumber. Tombol Nonaktifkan menghentikan penilaian berikutnya; Kembalikan versi memungkinkan rollback. Temuan historis tetap menyimpan versi asalnya.

## Data baru dan pelatihan ulang

Request baru dinilai dengan model aktif; **tidak ada training setiap request**. Untuk memperbarui pembelajaran, tinjau dan setujui tambahan baseline normal, antrekan kandidat baru, evaluasi lalu aktifkan. Baseline yang belum berubah ditolak sebagai pelatihan duplikat. Jangan melatih dari seluruh log tanpa seleksi karena trafik serangan dapat mencemari pola acuan.

Setiap pekerjaan membekukan maksimal 2000 baseline terbaru. Sekitar 80% periode awal untuk pelatihan; periode akhir sekitar 20% untuk validasi. Sampel dalam menit yang sama tidak dibagi ke dua set. Data validasi tidak dipakai untuk fit. Parameter: 128 pohon, seed 42, contamination 0.05, satu thread. Persentase normal validasi yang ditandai anomali adalah ukuran terbatas berdasarkan label normal admin, bukan precision/recall terhadap serangan nyata.

Model disimpan sebagai spesifikasi dan vektor numerik JSON dengan checksum, bukan pickle/joblib. Saat restart, forest dibangun ulang secara deterministik dari baseline versi yang sama; proses ini tidak belajar dari request baru. Tidak ada deserialisasi objek Python dari unggahan. Versi scikit-learn yang berbeda ditolak untuk inference sampai ada kandidat baru yang dilatih/evaluasi dengan versi tersebut.

Maksimal 10.000 jendela/7 hari disimpan. Snapshot baseline model tetap tersedia untuk membangun ulang model walau log sumber sudah diretensi. Maksimal 50 versi per origin pada edisi lab ini. Ekspor JSON menyertakan ml_findings berdasarkan rentang waktu, tidak berdasarkan query event; CSV tetap event biasa. Model/dataset internal tidak ikut diekspor.

## Pengujian dan evaluasi

Untuk pemeriksaan lokal di luar Docker:

```powershell
python -m pip install -r requirements-ml.txt
python -m unittest discover -s tests -p "test_*.py" -v
python tests/evaluate_ml.py test-results/ml-evaluation.json
```

Evaluator memakai database sementara dengan **fixture sintetis**, tidak mengirim HTTP, membaca secret, atau mengubah log aktif. Ia melatih 40 jendela, memvalidasi 10, lalu menilai 30 pola normal dan 10 anomali perilaku sintetis terpisah. Lihat hasil aktual pada ml-evaluation.json. Jangan menyebut hasil fixture sebagai akurasi produksi, benchmark publik, atau kemampuan mendeteksi seluruh serangan.

Tes juga memeriksa autentikasi/CSRF, migrasi origin, pemisahan origin, sifat baca-saja status, persetujuan baseline, pembekuan dataset, inferensi nyata, tinjauan admin, ekspor, nonaktif/rollback, integritas JSON, pergantian versi library, dan kandidat gagal yang tidak mengganti model aktif.

## Kebutuhan sumber daya dan batas

Compose memberi ml-worker batas **512 MiB RAM dan 1 CPU**, serta satu thread matematika. Ini batas konfigurasi, **bukan spesifikasi minimum yang telah diukur**. Image gateway/admin tetap menggunakan requirements.txt yang ringan; dependency ML hanya dipasang pada Dockerfile.ml. Kapasitas, waktu fit di Docker, dan latensi pada beban nyata perlu diukur tersendiri.

ML bukan jaminan sistem lebih akurat. Baseline kecil, normal yang berubah, NAT, dan label keliru dapat memicu false positive/negative. Tidak ada model terlatih yang diaktifkan otomatis pada instalasi baru. Penggunaan data fiktif dan pembatasan lab lokal tetap berlaku.

## Referensi

- Isolation Forest: https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.IsolationForest.html
- Deteksi anomali: https://scikit-learn.org/1.7/modules/outlier_detection.html
- Keamanan persistensi model: https://scikit-learn.org/1.7/model_persistence.html


## Koordinasi WAF dan ML

Bukti WAF dan ML kini dikorelasikan pada sumber, origin dan menit yang sama. Hasil berbeda tidak membuka blokir WAF. ML tidak tersedia tetap memakai proteksi WAF; WAF gagal tetap menutup akses dengan 503. Admin bisa meninjau temuan, menerapkan satu blokir sementara yang dibatasi, serta mencabut baseline yang keliru untuk mengarantina model terkait.

Panduan matriks keputusan, kondisi tindakan, migrasi model schema 2, dan batas perlindungan: [COORDINATION_GUIDE.md](COORDINATION_GUIDE.md).
