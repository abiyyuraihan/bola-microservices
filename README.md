# BOLA-Secure Microservices (Node.js + Express + MySQL + JWT)

Microservices untuk Order & Invoice dengan pencegahan **BOLA (Broken Object Level Authorization)** berlapis.

## Arsitektur

```
Client ──► API Gateway :3000  (PEP #1: JWT, scope, rate limit per-user, deteksi probing)
              ├─► auth-service    :3001  (auth_db)     register / login / refresh / logout / me
              ├─► order-service   :3002  (order_db)    CRUD order        ──┐ PEP #2 (di tiap service)
              └─► invoice-service :3003  (invoice_db)  CRUD invoice + pay ──┤ memanggil
                                                                            ▼
                                                      policy-service :3004 (PDP, policy_db: audit log)
```

- Hanya **api-gateway** yang dipublish ke host. Service lain hanya bisa dijangkau lewat jaringan docker.
- Database terpisah per service, masing-masing dengan user MySQL berhak akses minimum.
- Komunikasi antar-service memakai **service token** (JWT dengan secret berbeda, `iss`/`aud` dicek, TTL 60 detik).
- `/internal/*` (order-service) tidak pernah dirouting gateway.

## Menjalankan

```bash
cp .env.example .env        # isi secret: openssl rand -hex 32
npm install                 # hanya untuk menjalankan test/scanner di host
docker compose up --build
```

Gateway: `http://localhost:3000`. Admin awal dibuat dari `ADMIN_EMAIL` / `ADMIN_PASSWORD` di `.env`.

## Pemetaan 9 metode pencegahan BOLA

| # | Metode | Implementasi | Lokasi |
|---|--------|--------------|--------|
| 1 | Indirect Object Reference (UUID) | Semua PK `CHAR(36)` UUID v4 dibuat server; param `:id` divalidasi UUID (ID berurutan -> 400) | `db/init.sql`, `shared/middleware.js` (`validateUuidParams`) |
| 2 | Ownership check | `owner_id` selalu dari token (tidak dari body); list difilter `owner_id`; UPDATE/DELETE mengunci `owner_id` di SQL; kepemilikan resource orang lain dibalas **404** (tidak membocorkan eksistensi) | `services/*/src/routes.js`, `policies.js` (`NOT_OWNER`) |
| 3 | RBAC | `admin` akses semua, `user` hanya miliknya; role tidak pernah diterima dari client (`.strict()` schema) | `policy-service/src/policies.js` |
| 4 | ABAC | Invoice `paid` tidak bisa diubah/dihapus siapapun kecuali admin; juga: hanya `issued` yang bisa dibayar, order `invoiced` terkunci, 1 order = 1 invoice | `policies.js` (`ABAC_RULES`) + guard SQL di `invoice-service` |
| 5 | API Gateway / PEP | Verifikasi JWT, allowlist route, scope kasar, header `x-request-id`, blokir `/internal` | `services/api-gateway/src/index.js` |
| 6 | Policy Engine terpisah | `policy-service` (PDP) + `shared/policyClient.js`; **fail closed** jika PDP down; semua keputusan masuk `decision_logs` | `services/policy-service` |
| 7 | Scoped token / claim-based | JWT berisi `role` + `scope`; login boleh meminta scope lebih sempit (down-scoping); `alg` di-pin HS256, `iss`/`aud` dicek | `shared/jwt.js`, `auth-service/src/routes.js` |
| 8 | Automated BOLA scanner | Skrip yang menyerang dari user B ke resource user A di semua endpoint + uji token palsu, mass assignment, ABAC, RBAC | `tools/bola-scanner.js`, `policy-service/test` |
| 9 | Rate limiting per-user | Key = user id dari JWT (bukan IP); limit tulis terpisah; **DenyTracker** memblokir user yang terus mendapat 403/404 (indikasi enumerasi) | `api-gateway/src/index.js`, `denyTracker.js` |

## Endpoint (lewat gateway)

| Method | Path | Keterangan |
|--------|------|-----------|
| POST | `/auth/register` | `{email, password}` -> role selalu `user` |
| POST | `/auth/login` | `{email, password, scope?[]}` -> `accessToken`, `refreshToken` |
| POST | `/auth/refresh` | rotasi refresh token + deteksi reuse |
| POST | `/auth/logout` | cabut refresh token milik sendiri |
| GET | `/auth/me` | profil diri sendiri |
| GET/POST | `/orders` | list (own/all) / buat order `{items:[{productName, quantity, unitPrice}]}` |
| GET/PATCH/DELETE | `/orders/:id` | hanya order `pending` yang bisa diubah/dihapus (non-admin) |
| GET/POST | `/invoices` | list / buat dari `{orderId}` (amount dihitung server dari order) |
| GET/PATCH/DELETE | `/invoices/:id` | PATCH user: `description`; admin: `description, amount, status` |
| POST | `/invoices/:id/pay` | scope `invoices:pay`, hanya status `issued` |

Scope: `orders:read`, `orders:write`, `invoices:read`, `invoices:write`, `invoices:pay`.

## Pengujian keamanan

```bash
npm run test:policy                      # unit test policy engine (tanpa DB)

# scanner end-to-end (stack harus berjalan)
BASE_URL=http://localhost:3000 \
ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='...' \
npm run scan:bola                        # tambah: -- --rate-limit untuk uji rate limit & probing
```

Scanner keluar dengan exit code 1 bila menemukan celah, sehingga bisa dipasang di CI.
Catatan: limiter in-memory; restart gateway untuk mereset hitungan jika menjalankan scanner berulang kali
(batas login/register default 30 per 15 menit per IP, ubah lewat `AUTH_RATE_LIMIT`).

## Catatan produksi

- Ganti password DB dev di `db/init.sql` & `docker-compose.yml`; simpan secret di secret manager.
- Pakai RS256/JWKS (auth-service menandatangani, service lain hanya punya public key) dan mTLS antar-service.
- Pindahkan state rate limiter & DenyTracker ke Redis bila gateway lebih dari satu instance.
- Pasang TLS di depan gateway dan set `trust proxy` sesuai topologi agar rate limit per-IP akurat.
- Tambahkan revocation list `jti` bila perlu logout langsung efektif sebelum access token kedaluwarsa.
