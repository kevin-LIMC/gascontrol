require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { DB_SERVER, DB_NAME, DB_USER, DB_PASSWORD, JWT_SECRET, PORT = 3000 } = process.env;
if (!DB_SERVER || !DB_NAME || !DB_USER || !DB_PASSWORD || !JWT_SECRET) {
  console.error('Faltan variables en .env (DB_SERVER, DB_NAME, DB_USER, DB_PASSWORD, JWT_SECRET). Copia .env.example a .env.');
  process.exit(1);
}

const pool = new sql.ConnectionPool({
  server: DB_SERVER,
  database: DB_NAME,
  user: DB_USER,
  password: DB_PASSWORD,
  port: 1433,
  options: { encrypt: true, trustServerCertificate: false },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
  requestTimeout: 30000,
});

// Azure SQL trabaja en UTC; las fechas de negocio se guardan en hora de Ciudad de México.
const MX_NOW = `CAST(SYSDATETIMEOFFSET() AT TIME ZONE 'Central Standard Time (Mexico)' AS DATETIME2(0))`;
const R = { DESP: 1, SUP: 2, GER: 3, CONT: 4, ADM: 5 };

// ---------- utilidades ----------
class HttpError extends Error {
  constructor(msg, status = 400) { super(msg); this.status = status; }
}
const bad = (msg, status = 400) => { throw new HttpError(msg, status); };

// params: valor simple, o [tipo, valor] para fijar el tipo SQL.
async function run(text, params = {}, ex = pool) {
  const r = ex.request();
  for (const [k, v] of Object.entries(params)) {
    if (Array.isArray(v)) r.input(k, v[0], v[1] === undefined ? null : v[1]);
    else r.input(k, v === undefined ? null : v);
  }
  const res = await r.query(text);
  return res.recordset || [];
}

async function withTx(fn) {
  const tx = new sql.Transaction(pool);
  await tx.begin();
  try {
    const out = await fn(tx);
    await tx.commit();
    return out;
  } catch (e) {
    try { await tx.rollback(); } catch (_) { /* ya revertida */ }
    throw e;
  }
}

const cut = (v) => (v == null ? null : String(v).slice(0, 255));
const audit = (ex, user, accion, tabla, id, antes, despues) =>
  run(
    `INSERT INTO dbo.bitacora_auditoria (id_usuario, accion, tabla_afectada, id_registro, valor_anterior, valor_nuevo, fecha_hora)
     VALUES (@u, @a, @t, @i, @x, @y, ${MX_NOW})`,
    { u: user.id, a: accion, t: tabla, i: id, x: [sql.NVarChar(255), cut(antes)], y: [sql.NVarChar(255), cut(despues)] },
    ex
  );

const int = (v, name) => {
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0) bad(`${name} no es válido.`);
  return n;
};
const dec = (v, name, max = 1e9) => {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0 || n > max) bad(`${name} debe ser un número mayor que cero.`);
  return n;
};
const isDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
const round2 = (n) => Math.round((n + Number.EPSILON) * 100) / 100;

const ah = (fn) => (req, res, next) => fn(req, res).catch(next);

function auth(...roles) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    const t = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!t) return res.status(401).json({ error: 'No autenticado' });
    try { req.user = jwt.verify(t, JWT_SECRET); }
    catch { return res.status(401).json({ error: 'Sesión expirada' }); }
    if (roles.length && req.user.rol !== R.ADM && !roles.includes(req.user.rol))
      return res.status(403).json({ error: 'No tienes permiso para esta acción' });
    next();
  };
}

// ---------- app ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.requestId);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (req.path.startsWith('/api')) res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'gascontrol', time: new Date().toISOString() });
});

// ---------- login ----------
const intentos = new Map();
app.post('/api/login', ah(async (req, res) => {
  const ip = req.ip;
  const reg = intentos.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - reg.t > 15 * 60 * 1000) { reg.n = 0; reg.t = Date.now(); }
  if (reg.n >= 10) bad('Demasiados intentos. Espera unos minutos.', 429);

  const { usuario, password } = req.body || {};
  if (typeof usuario !== 'string' || typeof password !== 'string') bad('Captura usuario y contraseña.');
  const [u] = await run(
    `SELECT u.id_usuario, u.nombre, u.usuario, u.password_hash, u.id_rol, u.activo, r.nombre AS rol_nombre
     FROM dbo.usuario u JOIN dbo.rol r ON r.id_rol = u.id_rol WHERE u.usuario = @u`,
    { u: usuario.trim() }
  );
  let ok = false;
  if (u && u.activo) {
    try { ok = await bcrypt.compare(password, u.password_hash); } catch { ok = false; }
  }
  if (!ok) {
    reg.n++; intentos.set(ip, reg);
    bad('Usuario o contraseña incorrectos.', 401);
  }
  intentos.delete(ip);
  const user = { id: u.id_usuario, nombre: u.nombre, usuario: u.usuario, rol: u.id_rol, rol_nombre: u.rol_nombre };
  const token = jwt.sign(user, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, user });
}));

app.get('/api/me', auth(), (req, res) => res.json({ user: req.user }));

// ---------- catálogos ----------
app.get('/api/catalogos', auth(), ah(async (req, res) => {
  const [combustibles, bombas, metodos, tanques, proveedores, clientes, despachadores, vehiculos] = await Promise.all([
    run('SELECT id_combustible, nombre, precio_vigente FROM dbo.combustible ORDER BY id_combustible'),
    run(`SELECT b.id_bomba, b.id_isla, b.numero, b.estado, c.id_combustible, c.nombre AS combustible, c.precio_vigente
         FROM dbo.bomba b JOIN dbo.tanque t ON t.id_tanque = b.id_tanque
         JOIN dbo.combustible c ON c.id_combustible = t.id_combustible ORDER BY b.id_isla, b.numero`),
    run('SELECT id_metodo, nombre FROM dbo.metodo_pago ORDER BY id_metodo'),
    run(`SELECT t.id_tanque, c.nombre AS combustible, t.capacidad, t.nivel_actual FROM dbo.tanque t
         JOIN dbo.combustible c ON c.id_combustible = t.id_combustible ORDER BY t.id_tanque`),
    run('SELECT id_proveedor, nombre FROM dbo.proveedor ORDER BY nombre'),
    run('SELECT id_cliente, razon_social, rfc FROM dbo.cliente ORDER BY razon_social'),
    run('SELECT id_usuario, nombre FROM dbo.usuario WHERE id_rol = 1 AND activo = 1 ORDER BY nombre'),
    run(`SELECT v.id_vehiculo, v.placas, v.marca_modelo, v.capacidad_tanque, v.odometro_actual, c.razon_social AS cliente
         FROM dbo.vehiculo v LEFT JOIN dbo.cliente c ON c.id_cliente = v.id_cliente
         WHERE v.activo = 1 ORDER BY v.placas`).catch(() => []),
  ]);
  res.json({ combustibles, bombas, metodos, tanques, proveedores, clientes, despachadores, vehiculos });
}));

// ---------- turnos ----------
app.get('/api/turnos', auth(R.DESP, R.SUP, R.GER), ah(async (req, res) => {
  const estado = ['Abierto', 'Cerrado'].includes(req.query.estado) ? req.query.estado : null;
  const uid = req.user.rol === R.DESP ? req.user.id : null;
  const rows = await run(
    `SELECT TOP 60 t.id_turno, t.fecha, t.hora_inicio, t.hora_fin, t.fondo_inicial, t.estado,
            t.id_usuario, d.nombre AS despachador, s.nombre AS supervisor,
            (SELECT COUNT(*) FROM dbo.venta v WHERE v.id_turno = t.id_turno AND v.estado = N'Realizada') AS num_ventas,
            ISNULL((SELECT SUM(v.monto) FROM dbo.venta v WHERE v.id_turno = t.id_turno AND v.estado = N'Realizada'), 0) AS monto_ventas
     FROM dbo.turno t
     JOIN dbo.usuario d ON d.id_usuario = t.id_usuario
     JOIN dbo.usuario s ON s.id_usuario = t.id_supervisor
     WHERE (@estado IS NULL OR t.estado = @estado) AND (@uid IS NULL OR t.id_usuario = @uid)
     ORDER BY t.fecha DESC, t.id_turno DESC`,
    { estado: [sql.NVarChar(10), estado], uid: [sql.Int, uid] }
  );
  res.json(rows);
}));

app.post('/api/turnos', auth(R.SUP), ah(async (req, res) => {
  const idDesp = int(req.body.id_usuario, 'Despachador');
  const fondo = Number(req.body.fondo_inicial ?? 0);
  if (!Number.isFinite(fondo) || fondo < 0) bad('El fondo inicial no es válido.');
  const out = await withTx(async (tx) => {
    const d = await run('SELECT 1 AS ok FROM dbo.usuario WHERE id_usuario = @id AND id_rol = 1 AND activo = 1', { id: [sql.Int, idDesp] }, tx);
    if (!d.length) bad('El despachador no existe o está inactivo.');
    const abierto = await run(
      `SELECT 1 AS ok FROM dbo.turno WITH (UPDLOCK, HOLDLOCK) WHERE id_usuario = @id AND estado = N'Abierto'`,
      { id: [sql.Int, idDesp] }, tx);
    if (abierto.length) bad('Ese despachador ya tiene un turno abierto.', 409);
    const [t] = await run(
      `DECLARE @turno_insertado TABLE (id_turno INT);
       INSERT INTO dbo.turno (id_usuario, id_supervisor, fecha, hora_inicio, fondo_inicial)
       OUTPUT INSERTED.id_turno INTO @turno_insertado
       VALUES (@d, @s, CAST(${MX_NOW} AS DATE), CONVERT(TIME(0), ${MX_NOW}), @f);
       SELECT id_turno FROM @turno_insertado;`,
      { d: [sql.Int, idDesp], s: [sql.Int, req.user.id], f: [sql.Decimal(10, 2), round2(fondo)] }, tx);
    await audit(tx, req.user, 'ABRIR_TURNO', 'turno', t.id_turno, null, `despachador=${idDesp}; fondo=${round2(fondo)}`);
    return t;
  });
  res.status(201).json(out);
}));

app.post('/api/turnos/:id/cerrar', auth(R.SUP), ah(async (req, res) => {
  const id = int(req.params.id, 'Turno');
  const real = Number(req.body.total_real);
  if (!Number.isFinite(real) || real < 0) bad('El total real no es válido.');
  const corte = await withTx(async (tx) => {
    await run(
      `DECLARE @h TIME(0) = CONVERT(TIME(0), ${MX_NOW});
       EXEC dbo.sp_cerrar_turno @p_id_turno = @id, @p_total_real = @t, @p_hora_fin = @h;`,
      { id: [sql.Int, id], t: [sql.Decimal(12, 2), round2(real)] }, tx);
    const [c] = await run('SELECT id_corte, total_teorico, total_real, diferencia FROM dbo.corte_caja WHERE id_turno = @id', { id: [sql.Int, id] }, tx);
    await audit(tx, req.user, 'CERRAR_TURNO', 'turno', id, 'Abierto', `Cerrado; diferencia=${c.diferencia}`);
    return c;
  });
  res.json(corte);
}));

// ---------- ventas ----------
app.get('/api/ventas', auth(), ah(async (req, res) => {
  const { turno, fecha, estado, sinFactura, vehiculo } = req.query;
  if (fecha && !isDate(fecha)) bad('Fecha no válida.');
  const uid = req.user.rol === R.DESP ? req.user.id : null;
  const rows = await run(
    `SELECT TOP 200 v.id_venta, v.folio, v.fecha_hora, v.id_turno, v.litros, v.monto, v.estado,
            v.odometro, v.tanque_lleno, vh.placas AS vehiculo_placas, vh.marca_modelo AS vehiculo_modelo,
            b.id_isla, b.numero AS bomba, c.nombre AS combustible, u.nombre AS despachador,
            (SELECT STRING_AGG(m.nombre + N' ' + FORMAT(p.monto, 'N2'), N', ')
               FROM dbo.pago_venta p JOIN dbo.metodo_pago m ON m.id_metodo = p.id_metodo
              WHERE p.id_venta = v.id_venta) AS pagos,
            CASE WHEN EXISTS (SELECT 1 FROM dbo.factura f WHERE f.id_venta = v.id_venta AND f.estado = N'Emitida') THEN 1 ELSE 0 END AS facturada
     FROM dbo.venta v
     LEFT JOIN dbo.vehiculo vh ON vh.id_vehiculo = v.id_vehiculo
     JOIN dbo.bomba b ON b.id_bomba = v.id_bomba
     JOIN dbo.combustible c ON c.id_combustible = v.id_combustible
     JOIN dbo.turno t ON t.id_turno = v.id_turno
     JOIN dbo.usuario u ON u.id_usuario = t.id_usuario
     WHERE (@turno IS NULL OR v.id_turno = @turno)
       AND (@fecha IS NULL OR CAST(v.fecha_hora AS DATE) = CAST(@fecha AS DATE))
       AND (@estado IS NULL OR v.estado = @estado)
       AND (@uid IS NULL OR t.id_usuario = @uid)
       AND (@veh IS NULL OR v.id_vehiculo = @veh)
       AND (@sin = 0 OR NOT EXISTS (SELECT 1 FROM dbo.factura f WHERE f.id_venta = v.id_venta))
     ORDER BY v.fecha_hora DESC, v.id_venta DESC`,
    {
      turno: [sql.Int, turno ? int(turno, 'Turno') : null],
      fecha: [sql.VarChar(10), fecha || null],
      estado: [sql.NVarChar(12), ['Realizada', 'Cancelada'].includes(estado) ? estado : null],
      uid: [sql.Int, uid],
      veh: [sql.Int, vehiculo ? int(vehiculo, 'Vehículo') : null],
      sin: [sql.Int, sinFactura === '1' ? 1 : 0],
    }
  );
  res.json(rows);
}));

app.get('/api/ventas/resumen', auth(), ah(async (req, res) => {
  const { fecha } = req.query;
  if (fecha && !isDate(fecha)) bad('Fecha no válida.');
  const uid = req.user.rol === R.DESP ? req.user.id : null;
  const [summary] = await run(
    `SELECT COUNT(*) AS num_ventas, ISNULL(SUM(v.monto), 0) AS monto_total
       FROM dbo.venta v
       JOIN dbo.turno t ON t.id_turno = v.id_turno
      WHERE v.estado = N'Realizada'
        AND CAST(v.fecha_hora AS DATE) = ISNULL(CAST(@fecha AS DATE), CAST(${MX_NOW} AS DATE))
        AND (@uid IS NULL OR t.id_usuario = @uid)`,
    { fecha: [sql.VarChar(10), fecha || null], uid: [sql.Int, uid] }
  );
  res.json({ num_ventas: Number(summary?.num_ventas || 0), monto_total: Number(summary?.monto_total || 0) });
}));

app.get('/api/ventas/resumen-mensual', auth(), ah(async (req, res) => {
  const uid = req.user.rol === R.DESP ? req.user.id : null;
  const rows = await run(
    `SELECT CONVERT(CHAR(7), v.fecha_hora, 126) AS periodo,
            COUNT(*) AS num_ventas,
            ISNULL(SUM(v.monto), 0) AS monto_total
       FROM dbo.venta v
       JOIN dbo.turno t ON t.id_turno = v.id_turno
      WHERE v.estado = N'Realizada'
        AND v.fecha_hora >= DATEADD(MONTH, -5, DATEFROMPARTS(YEAR(${MX_NOW}), MONTH(${MX_NOW}), 1))
        AND (@uid IS NULL OR t.id_usuario = @uid)
      GROUP BY CONVERT(CHAR(7), v.fecha_hora, 126)
      ORDER BY periodo`,
    { uid: [sql.Int, uid] }
  );
  res.json(rows.map((r) => ({
    periodo: r.periodo,
    num_ventas: Number(r.num_ventas || 0),
    monto_total: Number(r.monto_total || 0),
  })));
}));

app.get('/api/ventas/consumo-mensual', auth(), ah(async (req, res) => {
  const uid = req.user.rol === R.DESP ? req.user.id : null;
  const rows = await run(
    `SELECT CONVERT(CHAR(7), v.fecha_hora, 126) AS periodo,
            ISNULL(SUM(v.litros), 0) AS litros,
            ISNULL(SUM(v.monto), 0) AS monto
       FROM dbo.venta v
       JOIN dbo.turno t ON t.id_turno = v.id_turno
      WHERE v.estado = N'Realizada'
        AND v.fecha_hora >= DATEADD(MONTH, -5, DATEFROMPARTS(YEAR(${MX_NOW}), MONTH(${MX_NOW}), 1))
        AND (@uid IS NULL OR t.id_usuario = @uid)
      GROUP BY CONVERT(CHAR(7), v.fecha_hora, 126)
      ORDER BY periodo`,
    { uid: [sql.Int, uid] }
  );
  res.json(rows.map((r) => ({
    periodo: r.periodo,
    litros: Number(r.litros || 0),
    monto: Number(r.monto || 0),
  })));
}));

app.get('/api/reportes/ventas-periodo', auth(), ah(async (req, res) => {
  const { desde, hasta } = req.query;
  if ((desde && !isDate(desde)) || (hasta && !isDate(hasta))) bad('Rango de fechas no válido.');
  const uid = req.user.rol === R.DESP ? req.user.id : null;
  const rows = await run(
    `DECLARE @d DATE = ISNULL(CAST(@desde AS DATE), DATEADD(DAY, -30, CAST(${MX_NOW} AS DATE)));
     DECLARE @h DATE = ISNULL(CAST(@hasta AS DATE), CAST(${MX_NOW} AS DATE));
     SELECT CAST(v.fecha_hora AS DATE) AS fecha,
            COUNT(*) AS num_ventas,
            ISNULL(SUM(v.litros), 0) AS litros,
            ISNULL(SUM(v.monto), 0) AS monto
       FROM dbo.venta v
       JOIN dbo.turno t ON t.id_turno = v.id_turno
      WHERE v.estado = N'Realizada'
        AND CAST(v.fecha_hora AS DATE) BETWEEN @d AND @h
        AND (@uid IS NULL OR t.id_usuario = @uid)
      GROUP BY CAST(v.fecha_hora AS DATE)
      ORDER BY fecha`,
    { desde: [sql.VarChar(10), desde || null], hasta: [sql.VarChar(10), hasta || null], uid: [sql.Int, uid] }
  );
  res.json(rows.map((r) => ({
    fecha: r.fecha,
    num_ventas: Number(r.num_ventas || 0),
    litros: Number(r.litros || 0),
    monto: Number(r.monto || 0),
  })));
}));

app.post('/api/ventas', auth(R.DESP, R.SUP), ah(async (req, res) => {
  const idTurno = int(req.body.id_turno, 'Turno');
  const idBomba = int(req.body.id_bomba, 'Bomba');
  const litros = Math.round(dec(req.body.litros, 'Los litros', 5000) * 1000) / 1000;
  const pagosIn = Array.isArray(req.body.pagos) ? req.body.pagos : [];
  if (!pagosIn.length || pagosIn.length > 4) bad('Indica de 1 a 4 formas de pago.');

  const idVehiculo = req.body.id_vehiculo ? int(req.body.id_vehiculo, 'Vehículo') : null;
  const odometro = req.body.odometro ? int(req.body.odometro, 'Odómetro') : null;
  const tanqueLleno = req.body.tanque_lleno !== false && req.body.tanque_lleno !== 0;

  const out = await withTx(async (tx) => {
    const [turno] = await run(
      'SELECT id_turno, id_usuario, estado FROM dbo.turno WHERE id_turno = @id',
      { id: [sql.Int, idTurno] }, tx);
    if (!turno) bad('El turno no existe.');
    if (turno.estado !== 'Abierto') bad('El turno está cerrado.');
    if (req.user.rol === R.DESP && turno.id_usuario !== req.user.id) bad('Ese turno no es tuyo.', 403);

    const [b] = await run(
      `SELECT b.id_bomba, c.id_combustible, c.precio_vigente
       FROM dbo.bomba b JOIN dbo.tanque t ON t.id_tanque = b.id_tanque
       JOIN dbo.combustible c ON c.id_combustible = t.id_combustible WHERE b.id_bomba = @id`,
      { id: [sql.Int, idBomba] }, tx);
    if (!b) bad('La bomba no existe.');

    let alertaVehiculo = null;
    if (idVehiculo) {
      const [veh] = await run('SELECT id_vehiculo, placas, capacidad_tanque, odometro_actual, activo FROM dbo.vehiculo WITH (UPDLOCK) WHERE id_vehiculo = @id', { id: [sql.Int, idVehiculo] }, tx);
      if (!veh) bad('El vehículo no existe.');
      if (!veh.activo) bad('El vehículo seleccionado está inactivo.');
      if (odometro && odometro < veh.odometro_actual) {
        bad(`El odómetro (${odometro.toLocaleString()} km) no puede ser menor que el actual (${veh.odometro_actual.toLocaleString()} km).`);
      }
      if (litros > Number(veh.capacidad_tanque) * 1.15) {
        alertaVehiculo = `⚠️ Carga de ${litros} L excede capacidad de tanque (${veh.capacidad_tanque} L).`;
      }
      if (odometro && odometro > veh.odometro_actual) {
        await run('UPDATE dbo.vehiculo SET odometro_actual = @o WHERE id_vehiculo = @id', { o: [sql.Int, odometro], id: [sql.Int, idVehiculo] }, tx);
      }
    }

    const monto = round2(litros * Number(b.precio_vigente));
    if (monto <= 0) bad('El monto calculado es cero.');
    const pagos = pagosIn.map((p) => ({ id_metodo: int(p.id_metodo, 'Método de pago'), monto: round2(dec(p.monto, 'El monto del pago')) }));
    const suma = round2(pagos.reduce((a, p) => a + p.monto, 0));
    if (Math.abs(suma - monto) > 0.005) bad(`Los pagos (${suma.toFixed(2)}) deben sumar el monto de la venta (${monto.toFixed(2)}).`);

    const [{ fecha }] = await run(`SELECT CONVERT(VARCHAR(8), ${MX_NOW}, 112) AS fecha`, {}, tx);
    const [{ sig }] = await run(
      `SELECT ISNULL(MAX(CAST(RIGHT(folio, 4) AS INT)), 0) + 1 AS sig
       FROM dbo.venta WITH (UPDLOCK, HOLDLOCK) WHERE folio LIKE @p`,
      { p: `GC-${fecha}-%` }, tx);
    const folio = `GC-${fecha}-${String(sig).padStart(4, '0')}`;

    const [v] = await run(
      `DECLARE @venta_insertada TABLE (id_venta INT, folio VARCHAR(30));
       INSERT INTO dbo.venta (id_turno, id_bomba, id_combustible, litros, monto, fecha_hora, folio, id_vehiculo, odometro, tanque_lleno)
       OUTPUT INSERTED.id_venta, INSERTED.folio INTO @venta_insertada
       VALUES (@t, @b, @c, @l, @m, ${MX_NOW}, @f, @veh, @odo, @lleno);
       SELECT id_venta, folio FROM @venta_insertada;`,
      {
        t: [sql.Int, idTurno], b: [sql.Int, idBomba], c: [sql.Int, b.id_combustible],
        l: [sql.Decimal(10, 3), litros], m: [sql.Decimal(10, 2), monto], f: folio,
        veh: [sql.Int, idVehiculo], odo: [sql.Int, odometro], lleno: [sql.Bit, tanqueLleno ? 1 : 0]
      }, tx);
    for (const p of pagos) {
      await run('INSERT INTO dbo.pago_venta (id_venta, id_metodo, monto) VALUES (@v, @m, @p)',
        { v: [sql.Int, v.id_venta], m: [sql.Int, p.id_metodo], p: [sql.Decimal(10, 2), p.monto] }, tx);
    }
    await audit(tx, req.user, 'REGISTRAR_VENTA', 'venta', v.id_venta, null, `${folio}; ${litros} L; $${monto.toFixed(2)}${idVehiculo ? '; vehiculo=' + idVehiculo : ''}`);
    return { id_venta: v.id_venta, folio: v.folio, monto, litros, alerta: alertaVehiculo };
  });
  res.status(201).json(out);
}));

app.post('/api/ventas/:id/cancelar', auth(R.SUP), ah(async (req, res) => {
  const id = int(req.params.id, 'Venta');
  await withTx(async (tx) => {
    const [v] = await run(
      `SELECT v.id_venta, v.folio, v.estado, t.estado AS estado_turno
       FROM dbo.venta v WITH (UPDLOCK) JOIN dbo.turno t ON t.id_turno = v.id_turno WHERE v.id_venta = @id`,
      { id: [sql.Int, id] }, tx);
    if (!v) bad('La venta no existe.', 404);
    if (v.estado !== 'Realizada') bad('La venta ya está cancelada.', 409);
    if (v.estado_turno !== 'Abierto') bad('No se puede cancelar una venta de un turno cerrado (ya tiene corte de caja).', 409);
    const f = await run(`SELECT 1 AS ok FROM dbo.factura WHERE id_venta = @id AND estado = N'Emitida'`, { id: [sql.Int, id] }, tx);
    if (f.length) bad('La venta tiene una factura emitida; cancela primero la factura.', 409);
    await run(
      `UPDATE dbo.venta SET estado = N'Cancelada', id_supervisor_autoriza = @s WHERE id_venta = @id`,
      { s: [sql.Int, req.user.id], id: [sql.Int, id] }, tx);
    await audit(tx, req.user, 'CANCELAR_VENTA', 'venta', id, 'Realizada', `Cancelada; folio=${v.folio}`);
  });
  res.json({ ok: true });
}));

// ---------- inventario y cargas ----------
app.get('/api/inventario', auth(R.SUP, R.GER, R.CONT), ah(async (req, res) => {
  res.json(await run('SELECT * FROM dbo.vw_inventario_tanques ORDER BY id_tanque'));
}));

app.get('/api/cargas', auth(R.SUP, R.GER), ah(async (req, res) => {
  res.json(await run(
    `SELECT TOP 100 cc.id_carga, cc.fecha, cc.litros, cc.documento, c.nombre AS combustible, p.nombre AS proveedor, cc.id_tanque
     FROM dbo.carga_combustible cc
     JOIN dbo.tanque t ON t.id_tanque = cc.id_tanque
     JOIN dbo.combustible c ON c.id_combustible = t.id_combustible
     JOIN dbo.proveedor p ON p.id_proveedor = cc.id_proveedor
     ORDER BY cc.fecha DESC, cc.id_carga DESC`));
}));

app.post('/api/cargas', auth(R.SUP), ah(async (req, res) => {
  const idTanque = int(req.body.id_tanque, 'Tanque');
  const idProv = int(req.body.id_proveedor, 'Proveedor');
  const litros = round2(dec(req.body.litros, 'Los litros', 100000));
  const doc = String(req.body.documento || '').trim();
  if (!doc || doc.length > 40) bad('Captura el documento (remisión), máximo 40 caracteres.');
  const out = await withTx(async (tx) => {
    const [t] = await run('SELECT capacidad, nivel_actual FROM dbo.tanque WITH (UPDLOCK, HOLDLOCK) WHERE id_tanque = @id', { id: [sql.Int, idTanque] }, tx);
    if (!t) bad('El tanque no existe.');
    const libre = Number(t.capacidad) - Number(t.nivel_actual);
    if (litros > libre) bad(`La carga excede la capacidad del tanque. Espacio disponible: ${libre.toFixed(2)} L.`);
    const [c] = await run(
      `DECLARE @carga_insertada TABLE (id_carga INT);
       INSERT INTO dbo.carga_combustible (id_tanque, id_proveedor, litros, fecha, documento)
       OUTPUT INSERTED.id_carga INTO @carga_insertada
       VALUES (@t, @p, @l, ${MX_NOW}, @d);
       SELECT id_carga FROM @carga_insertada;`,
      { t: [sql.Int, idTanque], p: [sql.Int, idProv], l: [sql.Decimal(10, 2), litros], d: doc }, tx);
    await audit(tx, req.user, 'CARGA_COMBUSTIBLE', 'carga_combustible', c.id_carga, null, `tanque=${idTanque}; ${litros} L; doc=${doc}`);
    return c;
  });
  res.status(201).json(out);
}));

// ---------- reportes ----------
const REPORTES = {
  'ventas-dia': 'SELECT * FROM dbo.vw_ventas_dia_combustible WHERE fecha BETWEEN @d AND @h ORDER BY fecha DESC, combustible',
  despachador: 'SELECT * FROM dbo.vw_ventas_despachador_turno WHERE fecha BETWEEN @d AND @h ORDER BY fecha DESC, id_turno DESC',
  'metodo-pago': 'SELECT * FROM dbo.vw_ventas_metodo_pago WHERE fecha BETWEEN @d AND @h ORDER BY fecha DESC, metodo_pago',
  cortes: 'SELECT * FROM dbo.vw_cortes_caja WHERE fecha BETWEEN @d AND @h ORDER BY fecha DESC, id_corte DESC',
  kpi: 'SELECT * FROM dbo.vw_kpi_diario WHERE fecha BETWEEN @d AND @h ORDER BY fecha DESC',
};
const REPORT_ROLES = { cortes: [R.SUP, R.GER], default: [R.SUP, R.GER, R.CONT] };
app.get('/api/reportes/:nombre', auth(), ah(async (req, res) => {
  const q = REPORTES[req.params.nombre];
  if (!q) bad('Reporte no encontrado.', 404);
  const permitidos = REPORT_ROLES[req.params.nombre] || REPORT_ROLES.default;
  if (req.user.rol !== R.ADM && !permitidos.includes(req.user.rol)) bad('No tienes permiso para este reporte.', 403);
  const { desde, hasta } = req.query;
  if ((desde && !isDate(desde)) || (hasta && !isDate(hasta))) bad('Rango de fechas no válido.');
  const hoy = `CAST(${MX_NOW} AS DATE)`;
  const text = `DECLARE @d DATE = ISNULL(CAST(@desde AS DATE), DATEADD(DAY, -30, ${hoy}));
                DECLARE @h DATE = ISNULL(CAST(@hasta AS DATE), ${hoy});
                ${q}`;
  res.json(await run(text, { desde: [sql.VarChar(10), desde || null], hasta: [sql.VarChar(10), hasta || null] }));
}));

// ---------- clientes y facturas ----------
app.get('/api/facturas', auth(R.CONT, R.GER), ah(async (req, res) => {
  res.json(await run('SELECT TOP 200 * FROM dbo.vw_control_facturas ORDER BY fecha_emision DESC, id_factura DESC'));
}));

app.post('/api/facturas', auth(R.CONT), ah(async (req, res) => {
  const idVenta = int(req.body.id_venta, 'Venta');
  const idCliente = int(req.body.id_cliente, 'Cliente');
  const out = await withTx(async (tx) => {
    const [v] = await run('SELECT folio, estado FROM dbo.venta WHERE id_venta = @id', { id: [sql.Int, idVenta] }, tx);
    if (!v) bad('La venta no existe.');
    if (v.estado !== 'Realizada') bad('Solo se factura una venta realizada.');
    const ya = await run('SELECT 1 AS ok FROM dbo.factura WITH (UPDLOCK, HOLDLOCK) WHERE id_venta = @id', { id: [sql.Int, idVenta] }, tx);
    if (ya.length) bad('Esa venta ya tiene factura.', 409);
    const folioFiscal = crypto.randomUUID().toUpperCase(); // folio de ejemplo; no es un CFDI timbrado
    const [f] = await run(
      `DECLARE @factura_insertada TABLE (id_factura INT, folio_fiscal NVARCHAR(100));
       INSERT INTO dbo.factura (id_venta, id_cliente, folio_fiscal, fecha_emision)
       OUTPUT INSERTED.id_factura, INSERTED.folio_fiscal INTO @factura_insertada
       VALUES (@v, @c, @ff, ${MX_NOW});
       SELECT id_factura, folio_fiscal FROM @factura_insertada;`,
      { v: [sql.Int, idVenta], c: [sql.Int, idCliente], ff: folioFiscal }, tx);
    await audit(tx, req.user, 'EMITIR_FACTURA', 'factura', f.id_factura, null, `venta=${v.folio}; cliente=${idCliente}`);
    return f;
  });
  res.status(201).json(out);
}));

app.post('/api/facturas/:id/cancelar', auth(R.CONT), ah(async (req, res) => {
  const id = int(req.params.id, 'Factura');
  const r = await run(
    `DECLARE @factura_cancelada TABLE (id_factura INT);
     UPDATE dbo.factura SET estado = N'Cancelada'
       OUTPUT INSERTED.id_factura INTO @factura_cancelada
       WHERE id_factura = @id AND estado = N'Emitida';
     SELECT id_factura FROM @factura_cancelada;`,
    { id: [sql.Int, id] });
  if (!r.length) bad('La factura no existe o ya está cancelada.', 409);
  await audit(pool, req.user, 'CANCELAR_FACTURA', 'factura', id, 'Emitida', 'Cancelada');
  res.json({ ok: true });
}));

app.post('/api/clientes', auth(R.CONT), ah(async (req, res) => {
  const razon = String(req.body.razon_social || '').trim();
  const rfc = String(req.body.rfc || '').trim().toUpperCase();
  const convenio = String(req.body.convenio || '').trim() || null;
  if (!razon || razon.length > 150) bad('Captura la razón social (máx. 150).');
  if (!/^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/.test(rfc)) bad('El RFC no tiene un formato válido.');
  if (convenio && convenio.length > 80) bad('El convenio es demasiado largo (máx. 80).');
  const [c] = await run(
    `DECLARE @cliente_insertado TABLE (id_cliente INT);
     INSERT INTO dbo.cliente (razon_social, rfc, convenio)
     OUTPUT INSERTED.id_cliente INTO @cliente_insertado
     VALUES (@r, @f, @c);
     SELECT id_cliente FROM @cliente_insertado`,
    { r: razon, f: rfc, c: [sql.NVarChar(80), convenio] });
  await audit(pool, req.user, 'ALTA_CLIENTE', 'cliente', c.id_cliente, null, `${razon} (${rfc})`);
  res.status(201).json(c);
}));

// ---------- administración ----------
app.get('/api/usuarios', auth(), ah(async (req, res) => {
  if (req.user.rol !== R.ADM) bad('No tienes permiso.', 403);
  res.json(await run(
    `SELECT u.id_usuario, u.nombre, u.usuario, u.activo, u.fecha_alta, r.nombre AS rol
     FROM dbo.usuario u JOIN dbo.rol r ON r.id_rol = u.id_rol ORDER BY u.id_usuario`));
}));

app.get('/api/roles', auth(), ah(async (req, res) => {
  res.json(await run('SELECT id_rol, nombre FROM dbo.rol ORDER BY id_rol'));
}));

app.post('/api/usuarios', auth(), ah(async (req, res) => {
  if (req.user.rol !== R.ADM) bad('No tienes permiso.', 403);
  const nombre = String(req.body.nombre || '').trim();
  const usuario = String(req.body.usuario || '').trim();
  const password = String(req.body.password || '');
  const idRol = int(req.body.id_rol, 'Rol');
  if (!nombre || nombre.length > 100) bad('Captura el nombre (máx. 100).');
  if (!/^[A-Za-z0-9_.]{3,30}$/.test(usuario)) bad('El usuario debe tener de 3 a 30 letras, números, punto o guion bajo.');
  if (password.length < 8) bad('La contraseña debe tener al menos 8 caracteres.');
  if (idRol > 5) bad('Rol no válido.');
  const hash = await bcrypt.hash(password, 10);
  const [u] = await run(
    `DECLARE @usuario_insertado TABLE (id_usuario INT);
     INSERT INTO dbo.usuario (nombre, usuario, password_hash, id_rol)
     OUTPUT INSERTED.id_usuario INTO @usuario_insertado
     VALUES (@n, @u, @h, @r);
     SELECT id_usuario FROM @usuario_insertado`,
    { n: nombre, u: usuario, h: hash, r: [sql.Int, idRol] });
  await audit(pool, req.user, 'ALTA_USUARIO', 'usuario', u.id_usuario, null, `${usuario}; rol=${idRol}`);
  res.status(201).json(u);
}));

app.patch('/api/usuarios/:id', auth(), ah(async (req, res) => {
  if (req.user.rol !== R.ADM) bad('No tienes permiso.', 403);
  const id = int(req.params.id, 'Usuario');
  if (req.body.activo !== undefined) {
    if (id === req.user.id && !req.body.activo) bad('No puedes desactivar tu propio usuario.');
    await run('UPDATE dbo.usuario SET activo = @a WHERE id_usuario = @id', { a: [sql.Bit, req.body.activo ? 1 : 0], id: [sql.Int, id] });
    await audit(pool, req.user, req.body.activo ? 'ACTIVAR_USUARIO' : 'DESACTIVAR_USUARIO', 'usuario', id, null, null);
  }
  if (req.body.password !== undefined) {
    const p = String(req.body.password);
    if (p.length < 8) bad('La contraseña debe tener al menos 8 caracteres.');
    await run('UPDATE dbo.usuario SET password_hash = @h WHERE id_usuario = @id', { h: await bcrypt.hash(p, 10), id: [sql.Int, id] });
    await audit(pool, req.user, 'CAMBIO_PASSWORD', 'usuario', id, null, null);
  }
  res.json({ ok: true });
}));

app.put('/api/combustibles/:id', auth(), ah(async (req, res) => {
  if (req.user.rol !== R.ADM) bad('No tienes permiso.', 403);
  const id = int(req.params.id, 'Combustible');
  const precio = round2(dec(req.body.precio, 'El precio', 1000));
  const [ant] = await run('SELECT precio_vigente FROM dbo.combustible WHERE id_combustible = @id', { id: [sql.Int, id] });
  if (!ant) bad('El combustible no existe.', 404);
  await run('UPDATE dbo.combustible SET precio_vigente = @p WHERE id_combustible = @id', { p: [sql.Decimal(8, 2), precio], id: [sql.Int, id] });
  await audit(pool, req.user, 'CAMBIO_PRECIO', 'combustible', id, ant.precio_vigente, precio);
  res.json({ ok: true });
}));

app.put('/api/bombas/:id', auth(R.SUP), ah(async (req, res) => {
  const id = int(req.params.id, 'Bomba');
  const estado = req.body.estado;
  if (!['Activa', 'Inactiva', 'Falla'].includes(estado)) bad('Estado no válido.');
  const [ant] = await run('SELECT estado FROM dbo.bomba WHERE id_bomba = @id', { id: [sql.Int, id] });
  if (!ant) bad('La bomba no existe.', 404);
  await run('UPDATE dbo.bomba SET estado = @e WHERE id_bomba = @id', { e: [sql.NVarChar(15), estado], id: [sql.Int, id] });
  await audit(pool, req.user, 'CAMBIO_ESTADO_BOMBA', 'bomba', id, ant.estado, estado);
  res.json({ ok: true });
}));

app.get('/api/bitacora', auth(R.GER), ah(async (req, res) => {
  res.json(await run(
    `SELECT TOP 200 b.id_bitacora, b.fecha_hora, u.nombre AS usuario, b.accion, b.tabla_afectada, b.id_registro, b.valor_anterior, b.valor_nuevo
     FROM dbo.bitacora_auditoria b JOIN dbo.usuario u ON u.id_usuario = b.id_usuario
     ORDER BY b.id_bitacora DESC`));
}));

// ---------- vehículos y rendimiento de flotillas ----------
app.get('/api/vehiculos', auth(), ah(async (req, res) => {
  const rows = await run(`
    SELECT v.id_vehiculo, v.placas, v.marca_modelo, v.capacidad_tanque, v.odometro_actual, v.activo, v.fecha_alta,
           c.id_cliente, c.razon_social AS cliente,
           COUNT(vt.id_venta) AS cargas_totales,
           ISNULL(SUM(vt.litros), 0) AS litros_totales,
           ISNULL(SUM(vt.monto), 0) AS gasto_total,
           MIN(vt.odometro) AS odometro_min,
           MAX(vt.odometro) AS odometro_max
    FROM dbo.vehiculo v
    LEFT JOIN dbo.cliente c ON c.id_cliente = v.id_cliente
    LEFT JOIN dbo.venta vt ON vt.id_vehiculo = v.id_vehiculo AND vt.estado = N'Realizada'
    GROUP BY v.id_vehiculo, v.placas, v.marca_modelo, v.capacidad_tanque, v.odometro_actual, v.activo, v.fecha_alta, c.id_cliente, c.razon_social
    ORDER BY v.placas
  `);

  const list = rows.map((r) => {
    const km = (r.odometro_max && r.odometro_min && r.odometro_max > r.odometro_min)
      ? (r.odometro_max - r.odometro_min) : 0;
    const l = Number(r.litros_totales) || 0;
    const g = Number(r.gasto_total) || 0;
    const kml = (km > 0 && l > 0) ? round2(km / l) : null;
    const costoKm = (km > 0 && g > 0) ? round2(g / km) : null;
    const l100 = kml ? round2(100 / kml) : null;
    return {
      ...r,
      km_recorridos: km,
      rendimiento_kml: kml,
      costo_km: costoKm,
      consumo_l100km: l100,
    };
  });
  res.json(list);
}));

app.post('/api/vehiculos', auth(R.SUP, R.GER, R.CONT), ah(async (req, res) => {
  const placas = String(req.body.placas || '').trim().toUpperCase().replace(/[^A-Z0-9-]/g, '');
  const modelo = String(req.body.marca_modelo || '').trim();
  const capacidad = dec(req.body.capacidad_tanque, 'La capacidad del tanque', 2000);
  const odometro = req.body.odometro_actual != null ? Math.max(0, parseInt(req.body.odometro_actual, 10) || 0) : 0;
  const idCliente = req.body.id_cliente ? int(req.body.id_cliente, 'Cliente') : null;

  if (!placas || placas.length < 4 || placas.length > 15) bad('Placas no válidas (4-15 caracteres alfanuméricos).');
  if (!modelo || modelo.length > 80) bad('Indica marca y modelo (máx 80 caracteres).');

  const [v] = await run(`
    DECLARE @vehiculo_insertado TABLE (id_vehiculo INT, placas VARCHAR(15));
    INSERT INTO dbo.vehiculo (id_cliente, placas, marca_modelo, capacidad_tanque, odometro_actual)
    OUTPUT INSERTED.id_vehiculo, INSERTED.placas INTO @vehiculo_insertado
    VALUES (@c, @p, @m, @cap, @o);
    SELECT id_vehiculo, placas FROM @vehiculo_insertado;
  `, {
    c: [sql.Int, idCliente],
    p: placas,
    m: modelo,
    cap: [sql.Decimal(6, 2), capacidad],
    o: [sql.Int, odometro],
  });
  await audit(pool, req.user, 'ALTA_VEHICULO', 'vehiculo', v.id_vehiculo, null, `${placas} (${modelo}); tanque=${capacidad}L; odo=${odometro}km`);
  res.status(201).json(v);
}));

app.patch('/api/vehiculos/:id', auth(R.SUP, R.GER, R.CONT), ah(async (req, res) => {
  const id = int(req.params.id, 'Vehículo');
  const [ant] = await run('SELECT id_vehiculo, placas, activo FROM dbo.vehiculo WHERE id_vehiculo = @id', { id: [sql.Int, id] });
  if (!ant) bad('El vehículo no existe.', 404);

  if (typeof req.body.activo === 'boolean') {
    await run('UPDATE dbo.vehiculo SET activo = @a WHERE id_vehiculo = @id', { a: [sql.Bit, req.body.activo ? 1 : 0], id: [sql.Int, id] });
    await audit(pool, req.user, 'ESTADO_VEHICULO', 'vehiculo', id, ant.activo, req.body.activo ? 1 : 0);
  }
  res.json({ ok: true });
}));

// No se borra físicamente para conservar las ventas e historial del vehículo.
app.delete('/api/vehiculos/:id', auth(R.SUP, R.GER, R.CONT), ah(async (req, res) => {
  const id = int(req.params.id, 'Vehículo');
  const [ant] = await run('SELECT id_vehiculo, placas, activo FROM dbo.vehiculo WHERE id_vehiculo = @id', { id: [sql.Int, id] });
  if (!ant) bad('El vehículo no existe.', 404);
  if (!ant.activo) bad('El vehículo ya está desactivado.', 409);

  await run('UPDATE dbo.vehiculo SET activo = 0 WHERE id_vehiculo = @id', { id: [sql.Int, id] });
  await audit(pool, req.user, 'BAJA_VEHICULO', 'vehiculo', id, 'Activo', `Inactivo; placas=${ant.placas}`);
  res.json({ ok: true, id_vehiculo: id, activo: false });
}));

app.get('/api/vehiculos/:id/historial', auth(), ah(async (req, res) => {
  const id = int(req.params.id, 'Vehículo');
  const [veh] = await run(
    `SELECT v.*, c.razon_social AS cliente FROM dbo.vehiculo v LEFT JOIN dbo.cliente c ON c.id_cliente = v.id_cliente WHERE v.id_vehiculo = @id`,
    { id: [sql.Int, id] });
  if (!veh) bad('Vehículo no encontrado.', 404);

  const cargas = await run(`
    SELECT v.id_venta, v.folio, v.fecha_hora, v.litros, v.monto, v.odometro, v.tanque_lleno, v.estado,
           c.nombre AS combustible, u.nombre AS despachador
    FROM dbo.venta v
    JOIN dbo.combustible c ON c.id_combustible = v.id_combustible
    JOIN dbo.turno t ON t.id_turno = v.id_turno
    JOIN dbo.usuario u ON u.id_usuario = t.id_usuario
    WHERE v.id_vehiculo = @id AND v.estado = N'Realizada'
    ORDER BY ISNULL(v.odometro, 0) ASC, v.fecha_hora ASC
  `, { id: [sql.Int, id] });

  let prevOdo = null;
  const list = cargas.map((c) => {
    const odo = c.odometro;
    const l = Number(c.litros);
    const m = Number(c.monto);
    let kmRecorridos = null;
    let kml = null;
    let costoKm = null;
    let l100 = null;
    let alerta = null;

    if (l > Number(veh.capacidad_tanque) * 1.1) {
      alerta = '⚠️ Carga sospechosa: excede la capacidad del tanque.';
    }

    if (odo != null && prevOdo != null) {
      kmRecorridos = odo - prevOdo;
      if (kmRecorridos > 0 && l > 0 && c.tanque_lleno) {
        kml = round2(kmRecorridos / l);
        costoKm = round2(m / kmRecorridos);
        l100 = round2((l / kmRecorridos) * 100);
        if (kml < 6.5) alerta = (alerta ? alerta + ' ' : '') + '⚠️ Rendimiento inusualmente bajo (<6.5 km/L).';
      } else if (kmRecorridos < 0) {
        alerta = '⚠️ Kilometraje inconsistente (menor al previo).';
      }
    }
    if (odo != null) prevOdo = odo;

    return {
      ...c,
      odometro_anterior: prevOdo != null && kmRecorridos != null ? odo - kmRecorridos : null,
      km_recorridos: kmRecorridos,
      kml,
      costo_km: costoKm,
      l_100km: l100,
      alerta,
    };
  }).reverse();

  res.json({ vehiculo: veh, cargas: list });
}));

// ---------- errores ----------
app.use('/api', (req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && Object.prototype.hasOwnProperty.call(err, 'body')) {
    return res.status(400).json({ error: 'El cuerpo de la solicitud no contiene JSON válido.' });
  }
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  const n = err.number ?? err.originalError?.info?.number;
  if (n >= 51000 && n <= 51999) return res.status(400).json({ error: err.message }); // reglas de negocio (THROW en triggers/SP)
  if (n === 2627 || n === 2601) return res.status(409).json({ error: 'Ya existe un registro con ese valor único (usuario, RFC, folio…).' });
  if (n === 547) return res.status(409).json({ error: 'La operación viola una restricción de la base de datos.' });
  console.error(`[${req.requestId}] ${req.method} ${req.originalUrl}`, {
    message: err.message,
    code: err.code,
    number: n,
    state: err.state,
    class: err.class,
    procedure: err.procName || err.originalError?.info?.procName,
    line: err.lineNumber || err.originalError?.info?.lineNumber,
    original: err.originalError?.message,
    stack: err.stack,
  });
  res.status(500).json({ error: 'Error interno del servidor', codigo: req.requestId });
});

async function initSchema() {
  const migrations = [
    [`tabla vehiculo`, `
      IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'vehiculo' AND schema_id = SCHEMA_ID('dbo'))
      BEGIN
        CREATE TABLE dbo.vehiculo (
          id_vehiculo INT IDENTITY(1,1) NOT NULL,
          id_cliente INT NULL,
          placas VARCHAR(15) NOT NULL,
          marca_modelo VARCHAR(80) NOT NULL,
          capacidad_tanque DECIMAL(6,2) NOT NULL DEFAULT 50.00,
          odometro_actual INT NOT NULL DEFAULT 0,
          activo BIT NOT NULL DEFAULT 1,
          fecha_alta DATETIME2(0) NOT NULL DEFAULT CAST(SYSDATETIMEOFFSET() AT TIME ZONE 'Central Standard Time (Mexico)' AS DATETIME2(0)),
          CONSTRAINT pk_vehiculo PRIMARY KEY (id_vehiculo),
          CONSTRAINT uq_vehiculo_placas UNIQUE (placas),
          CONSTRAINT fk_vehiculo_cliente FOREIGN KEY (id_cliente) REFERENCES dbo.cliente(id_cliente),
          CONSTRAINT ck_vehiculo_capacidad CHECK (capacidad_tanque > 0),
          CONSTRAINT ck_vehiculo_odometro CHECK (odometro_actual >= 0)
        );
      END;`],
    [`venta.id_vehiculo`, `
      IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'id_vehiculo' AND object_id = OBJECT_ID('dbo.venta'))
        ALTER TABLE dbo.venta ADD id_vehiculo INT NULL CONSTRAINT fk_venta_vehiculo FOREIGN KEY REFERENCES dbo.vehiculo(id_vehiculo);`],
    [`venta.odometro`, `
      IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'odometro' AND object_id = OBJECT_ID('dbo.venta'))
        ALTER TABLE dbo.venta ADD odometro INT NULL;`],
    [`venta.tanque_lleno`, `
      IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'tanque_lleno' AND object_id = OBJECT_ID('dbo.venta'))
        ALTER TABLE dbo.venta ADD tanque_lleno BIT NOT NULL DEFAULT 1;`],
  ];
  for (const [name, statement] of migrations) {
    try {
      await run(statement);
      console.log(`Esquema verificado: ${name}`);
    } catch (e) {
      console.warn(`Aviso al verificar ${name}:`, e.message);
    }
  }
}

pool.connect()
  .then(async () => {
    await initSchema();
    app.listen(PORT, () => console.log(`GasControl en http://localhost:${PORT}`));
  })
  .catch((e) => { console.error('No se pudo conectar a Azure SQL:', e.message); process.exit(1); });
