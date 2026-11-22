# SentinelGrid — Enterprise Cyber Security & Real-Time SOC

Platform pemantauan keamanan jaringan real-time, deteksi ancaman siber dengan globe serangan 3D interaktif, log trafik terenkripsi AES-256-GCM + SHA-256 chain, integrasi SIEM API, laporan kepatuhan mingguan otomatis, autentikasi TOTP MFA, portal terpisah **Admin (`/admin`)** & **Pengguna (`/user`)**, serta pengiriman keluhan real-time.

## Portal & Rute Utama

- **Portal Admin**: `/admin` — Kontrol akun pengguna, persetujuan akses, dasbor SOC penuh, simulasi serangan, SIEM, laporan mingguan, dan manajemen keluhan masuk.
- **Portal Pengguna**: `/user` (atau `/pengguna`) — Pendaftaran operator, ringkasan trafik, log terenkripsi, dan formulir **Keluhan & Laporan** yang masuk langsung ke akun Admin.

Kedua portal memiliki sesi terpisah (`localStorage` per portal), sehingga Admin dapat membuka `/user` tanpa keluar dari sesi `/admin`.

## Menjalankan Secara Lokal

```bash
npm install
npm run dev
```

Aplikasi berjalan pada `http://localhost:3000`.

### Pengujian & Validasi

```bash
npm test        # Unit tests (crypto, telemetry engine, globe projection, user control & portals)
npm run lint    # TypeScript type-check (tsc --noEmit)
npm run build   # Vite production bundle -> dist/
```

## Push ke GitHub

```bash
git init
git add .
git commit -m "feat: sentinelgrid soc ready for github and vercel"
git branch -M main
git remote add origin https://github.com/<username>/<repo>.git
git push -u origin main
```

## Deploy ke Vercel

Repositori sudah dilengkapi konfigurasi siap pakai:
- `vercel.json` — Build Vite ke `dist/`, routing `/api/*` ke `api/index.ts`, dan SPA rewrite untuk `/admin` & `/user`.
- `api/index.ts` — Serverless Function Express dengan token sesi/MFA bertanda HMAC-SHA256 dan penyimpanan runtime `/tmp` saat `VERCEL=1`.
- Fallback otomatis **HTTP Live Sync** saat WebSocket tidak tersedia pada lingkungan Serverless.

### Environment Variables Disarankan di Vercel

Tambahkan pada **Project Settings → Environment Variables** di Vercel Dashboard:
- `SESSION_SECRET`: String acak panjang (mis. 64 karakter hex) agar sesi & challenge OTP konsisten di seluruh instance serverless.
- `E2E_LOG_KEY`: 64 karakter hex untuk kunci utama enkripsi AES-256-GCM.
- `ADMIN_EMAIL` *(opsional)*: Email administrator bawaan untuk login OTP (`/admin`).
- `RESEND_API_KEY` *(opsional, direkomendasikan di produksi)*: API key dari Resend agar kode OTP 6 digit Admin dikirim langsung ke kotak masuk email Admin. Tanpa variabel ini, sistem menggunakan mode preview/log.
- `OTP_FROM_EMAIL` *(opsional)*: Alamat pengirim email OTP (default `SentinelGrid SOC <onboarding@resend.dev>`).

### Deploy via Vercel CLI

```bash
npx vercel --prod
```
