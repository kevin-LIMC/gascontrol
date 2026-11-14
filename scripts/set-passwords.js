// Reemplaza los "hash_demo_*" del script SQL por contraseñas reales (bcrypt).
// Uso:  npm run set-passwords -- "MiContraseña123"
// Si no das contraseña, usa GasControl2026! para los 6 usuarios de ejemplo. Cámbiala después en Administración.
require('dotenv').config();
const sql = require('mssql');
const bcrypt = require('bcryptjs');

(async () => {
  const password = process.argv[2] || 'GasControl2026!';
  if (password.length < 8) { console.error('La contraseña debe tener al menos 8 caracteres.'); process.exit(1); }
  const pool = await new sql.ConnectionPool({
    server: process.env.DB_SERVER, database: process.env.DB_NAME,
    user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    options: { encrypt: true },
  }).connect();
  const hash = await bcrypt.hash(password, 10);
  const r = await pool.request().input('h', sql.NVarChar(255), hash)
    .query(`UPDATE dbo.usuario SET password_hash = @h WHERE password_hash LIKE N'hash_demo_%'`);
  console.log(`Usuarios actualizados: ${r.rowsAffected[0]}`);
  console.log(`Contraseña establecida: ${password}`);
  await pool.close();
})().catch((e) => { console.error(e.message); process.exit(1); });
