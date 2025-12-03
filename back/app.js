// ======================================================================
// app.js — Versión completa con función genérica para todas las estaciones
// ======================================================================

// Requisitos:
// npm i express cookie-parser express-session cors jsonwebtoken bcrypt pg dotenv
const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

// ========= Middlewares =========
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors({
  origin: ['http://localhost:5500', 'http://127.0.0.1:5500'], 
  credentials: true
}));
app.use(session({
  secret: process.env.SESSION_SECRET || 'mi_secreto',
  resave: false,
  saveUninitialized: true
}));

// Servir front (html, css, js) desde /front
app.use(express.static(path.join(__dirname, '../front')));

// ========= PostgreSQL =========
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Test rápido
pool.query('SELECT now()').then(r => {
  console.log('PostgreSQL OK:', r.rows[0].now);
}).catch(e => {
  console.error('PostgreSQL ERROR:', e);
});


// ========= Bootstrap DB =========
async function bootstrap() {
  const ddl = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    rut TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS orders (
    id BIGSERIAL PRIMARY KEY,
    customer TEXT,
    site TEXT,
    sku TEXT,
    qty_total INTEGER NOT NULL CHECK (qty_total > 0),
    status TEXT NOT NULL DEFAULT 'in_progress',
    current_station TEXT NOT NULL DEFAULT 'E1',
    created_at TIMESTAMP NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS station_tasks (
    id BIGSERIAL PRIMARY KEY,
    order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    station TEXT NOT NULL,
    qty INTEGER NOT NULL CHECK (qty > 0),
    note TEXT DEFAULT '',
    priority BOOLEAN NOT NULL DEFAULT false,
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TIMESTAMP NOT NULL DEFAULT now()
  );

  CREATE INDEX IF NOT EXISTS idx_station_tasks_station_status 
    ON station_tasks(station, status, priority DESC, created_at);

  CREATE INDEX IF NOT EXISTS idx_station_tasks_order 
    ON station_tasks(order_id);
  `;
  await pool.query(ddl);
}
bootstrap().catch(err => console.error('Bootstrap ERROR:', err));


// ========= Utils =========
function normalizeRut(rutRaw) {
  const s = String(rutRaw || '').toUpperCase().replace(/[.\s]/g, '');
  if (s.includes('-')) return s;
  const body = s.slice(0, -1);
  const dv = s.slice(-1);
  return `${body}-${dv}`;
}

function validateRut(rutRaw) {
  const rut = normalizeRut(rutRaw);
  const m = rut.match(/^(\d+)-([\dK])$/i);
  if (!m) return false;
  const body = m[1];
  const dv = m[2];

  let sum = 0, mul = 2;
  for (let i = body.length - 1; i >= 0; i--) {
    sum += parseInt(body[i], 10) * mul;
    mul = mul === 7 ? 2 : mul + 1;
  }
  const res = 11 - (sum % 11);
  const dvCalc = (res === 11) ? '0' : (res === 10 ? 'K' : String(res));
  return dvCalc === dv.toUpperCase();
}

const JWT_SECRET = process.env.JWT_SECRET || 'cambia-esto-en-produccion';
const JWT_EXPIRES_IN = '1h';

function generarToken(user) {
  return jwt.sign(
    { sub: user.id, rut: user.rut, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function verificarToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ ok: false, message: 'No autenticado' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    req.session.emailSesion = decoded.email;
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, message: 'Token inválido o expirado' });
  }
}


// ========= Front Routes =========
app.get('/login', (_req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'login.html'));
});
app.get('/register', (_req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'register.html'));
});
app.get('/', (_req, res) => res.redirect('/login'));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'admin.html'));
});

app.get('/op-estacion-1', (req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'op-estacion-1.html'));
});
app.get('/op-estacion-2', (req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'op-estacion-2.html'));
});
app.get('/op-estacion-3', (req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'op-estacion-3.html'));
});
app.get('/op-estacion-4', (req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'op-estacion-4.html'));
});
app.get('/op-estacion-5', (req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'op-estacion-5.html'));
});


// ========= Auth =========
app.post('/register', async (req, res) => {
  try {
    const { name, rut, email, password, role } = req.body || {};
    if (!name || !rut || !email || !password || !role)
      return res.status(400).json({ ok: false, message: 'Faltan campos' });

    if (!validateRut(rut))
      return res.status(400).json({ ok: false, message: 'RUT inválido' });

    const rutNorm = normalizeRut(rut);
    const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const insertSQL = `
      INSERT INTO users (name, rut, email, password_hash, role)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, name, rut, email, role, created_at;
    `;
    const { rows } = await pool.query(insertSQL, [
      name, rutNorm, email, password_hash, role
    ]);

    const token = generarToken(rows[0]);
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 3600000
    });

    return res.json({ ok: true, user: rows[0] });
  } catch (err) {
    if (err.code === '23505')
      return res.status(409).json({ ok: false, message: 'RUT o Email ya registrado' });

    console.error('Register error:', err);
    return res.status(500).json({ ok: false, message: 'Error interno' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { rut, password } = req.body || {};
    if (!rut || !password)
      return res.status(400).json({ ok: false, message: 'Faltan datos' });

    const rutNorm = normalizeRut(rut);
    const q = `SELECT * FROM users WHERE rut=$1 LIMIT 1`;
    const { rows } = await pool.query(q, [rutNorm]);

    if (rows.length === 0)
      return res.status(401).json({ ok: false, message: 'Credenciales inválidas' });

    const user = rows[0];
    const okPass = await bcrypt.compare(password, user.password_hash);
    if (!okPass)
      return res.status(401).json({ ok: false, message: 'Credenciales inválidas' });

    const token = generarToken(user);
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 3600000
    });

    return res.json({
      ok: true,
      user: {
        id: user.id, name: user.name, rut: user.rut,
        email: user.email, role: user.role
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ ok:false, message:'Error interno' });
  }
});

app.get('/me', verificarToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, rut, email, role, created_at FROM users WHERE id=$1`,
      [req.user.sub]
    );
    if (rows.length === 0)
      return res.status(404).json({ ok:false, message:'No encontrado' });

    return res.json({ ok:true, user: rows[0] });
  } catch (err) {
    console.error('/me error:', err);
    return res.status(500).json({ ok:false, message:'Error interno' });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  req.session.emailSesion = null;
  return res.json({ ok: true, message: 'Sesión cerrada' });
});


// ========= Crear pedido =========
app.post('/orders', verificarToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { customer, site, sku, qty_total } = req.body || {};
    const qty = Number(qty_total);

    if (!qty || qty <= 0)
      return res.status(400).json({ ok:false, message:'Cantidad inválida' });

    await client.query('BEGIN');

    // Pedido
    const insOrder = `
      INSERT INTO orders (customer, site, sku, qty_total, status, current_station)
      VALUES ($1,$2,$3,$4,'in_progress','E1')
      RETURNING *;
    `;
    const { rows: orderRows } = await client.query(insOrder, [
      customer, site, sku, qty
    ]);
    const order = orderRows[0];

    // Crear tarea E1
    const insTask = `
      INSERT INTO station_tasks (order_id, station, qty, note, priority, status)
      VALUES ($1,'E1',$2,'',false,'queued')
      RETURNING *;
    `;
    const { rows: taskRows } = await client.query(insTask, [order.id, qty]);

    await client.query('COMMIT');
    return res.json({ ok:true, order, task: taskRows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('/orders error:', err);
    return res.status(500).json({ ok:false, message:'Error interno' });
  } finally {
    client.release();
  }
});


// ========= GET Work Queues (todas las estaciones) =========
function crearRutaCola(estacion) {
  return async (_req, res) => {
    try {
      const sql = `
        SELECT t.*,
               o.customer, o.site, o.sku, o.qty_total, o.created_at AS order_created_at
        FROM station_tasks t
        JOIN orders o ON o.id = t.order_id
        WHERE t.station = $1 AND t.status = 'queued'
        ORDER BY t.priority DESC, t.created_at ASC;
      `;
      const { rows } = await pool.query(sql, [estacion]);
      return res.json({ ok:true, tasks: rows });
    } catch (err) {
      console.error(`Error GET queue ${estacion}:`, err);
      return res.status(500).json({ ok:false, message:'Error interno' });
    }
  };
}

app.get('/stations/E1/work-queue', verificarToken, crearRutaCola('E1'));
app.get('/stations/E2/work-queue', verificarToken, crearRutaCola('E2'));
app.get('/stations/E3/work-queue', verificarToken, crearRutaCola('E3'));
app.get('/stations/E4/work-queue', verificarToken, crearRutaCola('E4'));
app.get('/stations/E5/work-queue', verificarToken, crearRutaCola('E5'));


// ======================================================================
// FUNCIÓN GENÉRICA PARA AVANZAR TAREAS DE CUALQUIER ESTACIÓN
// ======================================================================
async function avanzarTareaGenerico(client, {
  taskId,
  estacionActual,
  estacionSiguiente,
  completedQty,
  note
}) {
  await client.query('BEGIN');

  const { rows: taskRows } = await client.query(
    `SELECT * FROM station_tasks WHERE id = $1 FOR UPDATE`,
    [taskId]
  );

  if (taskRows.length === 0) {
    await client.query('ROLLBACK');
    return { ok: false, code: 404, message: 'Tarea no encontrada' };
  }

  const task = taskRows[0];

  if (task.station !== estacionActual || task.status !== 'queued') {
    await client.query('ROLLBACK');
    return { ok: false, code: 400, message: `La tarea no está en ${estacionActual} o no está en estado queued` };
  }

  const qtyDone = Number(completedQty);
  if (!qtyDone || qtyDone <= 0 || qtyDone > task.qty) {
    await client.query('ROLLBACK');
    return { ok: false, code: 400, message: `completedQty debe ser entre 1 y ${task.qty}` };
  }

  const remaining = task.qty - qtyDone;

  // ========================
  // E5 (última estación)
  // ========================
  if (!estacionSiguiente) {
    if (remaining > 0) {
      await client.query(
        `UPDATE station_tasks SET qty=$1, note=$2, priority=true WHERE id=$3`,
        [remaining, note || task.note || '', task.id]
      );
    } else {
      await client.query(`UPDATE station_tasks SET status='done' WHERE id=$1`, [task.id]);

      const { rows: openTasks } = await client.query(
        `SELECT 1 FROM station_tasks WHERE order_id=$1 AND status='queued' LIMIT 1`,
        [task.order_id]
      );

      if (openTasks.length === 0) {
        await client.query(
          `UPDATE orders SET status='done', current_station='DONE' WHERE id=$1`,
          [task.order_id]
        );
      } else {
        await client.query(
          `UPDATE orders SET current_station='E5' WHERE id=$1`,
          [task.order_id]
        );
      }
    }

    await client.query('COMMIT');
    return { ok: true, remaining };
  }

  // ========================
  // Estaciones normales E1–E4
  // ========================
  await client.query(
    `INSERT INTO station_tasks (order_id, station, qty, note, priority, status)
     VALUES ($1,$2,$3,$4,false,'queued')`,
    [task.order_id, estacionSiguiente, qtyDone, note || task.note || '']
  );

  if (remaining > 0) {
    await client.query(
      `UPDATE station_tasks SET qty=$1, note=$2, priority=true WHERE id=$3`,
      [remaining, note || task.note || '', task.id]
    );
  } else {
    await client.query(`UPDATE station_tasks SET status='done' WHERE id=$1`, [task.id]);
  }

  const { rows: stillRows } = await client.query(
    `SELECT 1 FROM station_tasks 
     WHERE order_id=$1 AND station=$2 AND status='queued' LIMIT 1`,
    [task.order_id, estacionActual]
  );

  if (stillRows.length === 0) {
    await client.query(
      `UPDATE orders SET current_station=$2 WHERE id=$1`,
      [task.order_id, estacionSiguiente]
    );
  }

  await client.query('COMMIT');
  return { ok: true, remaining };
}


// ========= Helper para crear rutas POST por estación =========
function crearRutaAvance(estacionActual, estacionSiguiente) {
  return async (req, res) => {
    const client = await pool.connect();
    try {
      const { taskId } = req.params;
      const { completedQty, note } = req.body || {};

      const result = await avanzarTareaGenerico(client, {
        taskId,
        estacionActual,
        estacionSiguiente,
        completedQty,
        note
      });

      if (!result.ok) {
        return res.status(result.code).json({ ok:false, message: result.message });
      }

      return res.json({ ok:true, remaining: result.remaining });

    } catch (err) {
      await client.query('ROLLBACK');
      console.error(`ERROR avance ${estacionActual}:`, err);
      return res.status(500).json({ ok:false, message:'Error interno' });
    } finally {
      client.release();
    }
  };
}


// ========= POST de avance por estación =========

// E1 → E2
app.post('/stations/E1/work/:taskId/advance', verificarToken,
  crearRutaAvance('E1', 'E2')
);

// E2 → E3
app.post('/stations/E2/work/:taskId/advance', verificarToken,
  crearRutaAvance('E2', 'E3')
);

// E3 → E4
app.post('/stations/E3/work/:taskId/advance', verificarToken,
  crearRutaAvance('E3', 'E4')
);

// E4 → E5
app.post('/stations/E4/work/:taskId/advance', verificarToken,
  crearRutaAvance('E4', 'E5')
);

// E5 → cierre de pedido
app.post('/stations/E5/work/:taskId/advance', verificarToken,
  crearRutaAvance('E5', null)
);


// ========= Start Server =========
app.listen(PORT, () =>
  console.log(`API escuchando en http://localhost:${PORT}`)
);