# Koordinasi WAF dan ML

## Tujuan dan batas

Ruang Guard kini menggabungkan bukti pemeriksaan WAF, pembatasan kebijakan dan penilaian model pada **origin, identitas sumber tersamarkan, serta jendela satu menit yang sama**. Ini korelasi perilaku setelah request diproses; ML tidak memeriksa payload secara independen dan tidak membuktikan keputusan WAF pasti benar. Salah deteksi masih mungkin. Skor ML bukan probabilitas serangan.

## Keputusan dan cadangan perlindungan

| Kondisi | Tindakan |
| --- | --- |
| WAF mendeteksi, ML menandai anomali | Pertahankan keputusan WAF; tampilkan dua sinyal sebagai bukti pendukung untuk tinjauan. |
| WAF mendeteksi, ML tidak menandai | Tetap tolak sesuai WAF; tandai perbedaan untuk memeriksa kemungkinan false positive WAF atau blind spot ML. |
| WAF tidak mendeteksi, ML menandai | Perlu ditinjau. Bisa lonjakan normal, false positive ML, atau perilaku berbahaya yang belum cocok dengan aturan WAF. |
| Tidak ada model atau model belum valid | Gunakan WAF dan rate limit; status ML belum dapat menilai, bukan bersih. |
| ML gagal, checksum salah, versi library berbeda atau heartbeat kedaluwarsa | Hasil ML tidak dipercaya untuk tindakan; WAF/rate limit tetap berlaku. |
| WAF tidak tersedia | Gateway tetap fail-closed 503. ML tidak menggantikan pemeriksaan payload dan tidak membuka akses. |
| Origin/WAF mengalami kesalahan teknis pada jendela | Tampilkan Ada request gagal diproses; jangan menganggap gangguan sebagai serangan yang terkonfirmasi. |
| Tidak ada sinyal dari keduanya | Tetap pantau; hasil ini bukan jaminan keamanan. |

Tidak ada pemungutan suara mayoritas yang bisa membatalkan penolakan WAF. Ini pengamanan berlapis, bukan high availability atau jaminan nol kesalahan.

## Bukti yang dikumpulkan

Collector menyimpan jumlah deteksi WAF 403 dengan reason waf_rule, aturan pemicu, jumlah request yang lolos, penolakan kebijakan, kesalahan pemrosesan, serta 429 akibat blokir lanjutan/rate limit/tinjauan admin secara terpisah. Satu 403 diikuti 100 respons 429 tetap hanya satu deteksi WAF baru.

Ringkasan bukti disimpan bersama jendela sehingga tidak hilang saat event sumber diretensi. Data historis tanpa bukti hanya diisi ulang ketika seluruh jumlah event asal masih tersedia; jika tidak, status Bukti tidak lengkap. Menit tertua yang berpotensi terpotong oleh batas retensi tidak dimasukkan menjadi sampel baru. Tidak ada payload, query URL, password, token atau IP asli baru yang dicatat.

## Tinjauan dan respons admin

Buka **Analisis ML**, bagian **Koordinasi WAF dan ML**. Tabel menunjukkan bukti WAF, penilaian ML, hasil korelasi, rekomendasi dan penilaian admin. Pemeriksaan kesehatan WAF ditampilkan sebagai tersedia/tidak tersedia/belum terverifikasi berdasarkan hasil monitor, bukan request jaringan baru dari endpoint dashboard.

1. Periksa origin, sumber, menit kejadian, aturan dan kondisi layanan.
2. Pilih Normal atau Mencurigakan setelah evaluasi. Penilaian tidak otomatis membuka blokir, memasukkan data ke baseline, atau mengubah aturan.
3. Untuk temuan Mencurigakan, tombol **Blokir sementara** tersedia hanya bila temuan berumur maksimal lima menit, model aktif sehat dan tervalidasi, skor konsisten, serta tidak ada gangguan teknis pada bukti tersebut. Keputusan admin tetap diperlukan.
4. Durasi mengikuti pengaturan blokir dengan batas maksimal satu jam. Satu temuan hanya dapat menerapkan respons satu kali. Blokir WAF/rate limit yang masih aktif tidak ditimpa atau diperpanjang.
5. Respons memakai identitas sumber yang tercatat, bukan IP yang dikirim pengguna. Pengguna di balik IP/NAT sama dapat ikut terdampak. IP lain tidak diblokir secara massal.
6. Bila salah menilai, gunakan Daftar blokir untuk membuka blokir secara eksplisit; menandai Normal saja tidak mengubah proteksi aktif.

Tindakan memerlukan sesi admin, CSRF dan origin aplikasi yang sesuai. Bukti/model/dataset terbaru diperiksa ulang dalam transaksi sebelum menerapkan respons. Blokir admin tercatat sebagai ml_review dan audit ml_review_block. Tombol tidak memperpanjang blokir saat diklik ulang, termasuk sesudah masa respons sebelumnya habis.

## Validasi model berkelanjutan

Setiap siklus memeriksa checksum JSON, schema fitur, versi library, angka finite, hubungan data latih/validasi dan persetujuan baseline, termasuk saat model sudah ada di cache. Kesehatan model disimpan per versi dengan digest dan versi library, sehingga hasil pemeriksaan lama tidak berlaku untuk artifact yang berubah. Model gagal pada satu origin tidak menghentikan model sehat pada origin lain. Kandidat pelatihan gagal juga tidak menghentikan inference model aktif yang sehat.

Kesehatan model yang lebih tua dari 90 detik dianggap belum valid untuk tindakan. Status kesehatan WAF menjadi belum terverifikasi setelah 45 detik. Pengumpulan ML tetap asinkron: satu menit harus selesai terlebih dahulu, ditambah polling 15 detik dan kemungkinan antrean. Ini bukan pemeriksaan ML setiap request.

Dataset sekarang schema 2, menyimpan hubungan ID jendela latih/validasi yang tidak dipakai ulang setelah retensi. **Model schema 1 dari revisi ML sebelumnya perlu dilatih ulang** melalui kandidat baru sebelum dipakai dalam koordinasi. Skor historis tetap tersimpan tetapi tidak dianggap validasi model terkini.

Di Data acuan, **Cabut baseline** menandai data yang ternyata keliru dan mengarantina model terkait (termasuk kandidat). Model karantina tidak bisa diaktifkan ulang; latih kandidat baru dari data yang benar. Tindakan ini tidak membuka blokir WAF atau mempelajari ulang data secara diam-diam.

## Ekspor, reproduksi dan verifikasi

Ekspor JSON menyertakan coordination dengan bukti, hasil korelasi, status peninjauan dan respons yang diterapkan. Bagian ini mengikuti rentang waktu, bukan query teks event. Status kesehatan dalam ekspor adalah status saat ekspor, bukan jaminan kesehatan historis. Maksimal 10.000 kasus dalam rentang; dashboard menampilkan maksimal 100 terbaru dan mendahulukan yang belum dinilai.

```powershell
python -m pip install -r requirements-ml.txt
python -m unittest discover -s tests -p "test_*.py" -v
python tests/evaluate_ml.py test-results/ml-evaluation.json
docker compose -p ruang-guard config --quiet
docker compose -p ruang-guard up -d --build
```

Tes kebijakan memakai database sementara dan output model tetap untuk matriks deterministik; tes model lain tetap melatih Isolation Forest nyata. Pengujian in-process WAF menggunakan inspector fixture, bukan klaim menjalankan Coraza nyata. Hasil sintetis tidak menunjukkan akurasi produksi. Lihat [catatan verifikasi](../docs/VERIFICATION.md) untuk hasil aktual dan batas verifikasi Docker/browser.

Referensi: [OWASP CRS](https://coreruleset.org/docs/index.print), [pemisahan data dan konsistensi preprocessing scikit-learn](https://scikit-learn.org/1.7/common_pitfalls.html).
