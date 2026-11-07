-- Menampilkan SEMUA tabel dan isinya dari 4 database.
-- Hanya untuk dilihat (SELECT), tidak mengubah data.

SELECT '===== RINGKASAN JUMLAH BARIS =====' AS info;
SELECT 'auth_db.users' AS tabel, COUNT(*) AS jumlah FROM auth_db.users
UNION ALL SELECT 'auth_db.refresh_tokens', COUNT(*) FROM auth_db.refresh_tokens
UNION ALL SELECT 'order_db.orders', COUNT(*) FROM order_db.orders
UNION ALL SELECT 'order_db.order_items', COUNT(*) FROM order_db.order_items
UNION ALL SELECT 'invoice_db.invoices', COUNT(*) FROM invoice_db.invoices
UNION ALL SELECT 'policy_db.decision_logs', COUNT(*) FROM policy_db.decision_logs;

SELECT '===== auth_db.users (password disingkat, aslinya hash bcrypt) =====' AS info;
SELECT id, email, LEFT(password_hash, 15) AS password_hash, role, created_at FROM auth_db.users ORDER BY created_at;

SELECT '===== auth_db.refresh_tokens (token disimpan sebagai hash) =====' AS info;
SELECT id, user_id, LEFT(token_hash, 12) AS token_hash, scope, expires_at, revoked, created_at FROM auth_db.refresh_tokens ORDER BY created_at;

SELECT '===== order_db.orders =====' AS info;
SELECT id, owner_id, status, total_amount, created_at, updated_at FROM order_db.orders ORDER BY created_at;

SELECT '===== order_db.order_items =====' AS info;
SELECT id, order_id, product_name, quantity, unit_price FROM order_db.order_items;

SELECT '===== invoice_db.invoices =====' AS info;
SELECT id, order_id, owner_id, amount, status, description, paid_at, created_at FROM invoice_db.invoices ORDER BY created_at;

SELECT '===== policy_db.decision_logs (200 terbaru) =====' AS info;
SELECT created_at, service, role, action, resource_type, effect, code, reason, subject_id, resource_id
FROM policy_db.decision_logs ORDER BY created_at DESC LIMIT 200;
