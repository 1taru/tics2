// ============================================================
//  CONFIGURACIÓN PRINCIPAL
// ============================================================
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const pg = require("pg");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const path = require("path");
require("dotenv").config();

const { Pool } = pg;

const app = express();
app.use(express.json());
app.use(cookieParser());

app.use(cors({
  origin: "http://localhost:5500",
  credentials: true
}));

app.use(session({
  secret: "supersecretoseguro",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(express.static(path.join(__dirname, "front")));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "jwt_secret_123";

// ============================================================
//  CONEXIÓN A DATABASE (NEON / POSTGRES)
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ============================================================
//  MIDDLEWARE DE TOKEN
// ============================================================
function verificarToken(req, res, next) {
  const token = req.cookies?.token;
  if (!token)
    return res.status(401).json({ ok: false, message: "Token no encontrado" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ ok: false, message: "Token inválido" });
  }
}

// ============================================================
//  PERMISOS POR ROL
// ============================================================
function requireCorrectStation(req, res, next) {
  const role = req.user.role;
  const urlStation = req.params.station;

  const map = {
    operador_E1: "E1",
    operador_E2: "E2",
    operador_E3: "E3",
    operador_E4: "E4",
    operador_E5: "E5"
  };

  if (map[role] !== urlStation) {
    return res.status(403).json({
      ok: false,
      message: `No tienes permiso para operar en ${urlStation}`
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin")
    return res.status(403).json({ ok: false, message: "Solo Administradores" });
  next();
}

function requireLogistica(req, res, next) {
  if (req.user.role !== "logistica")
    return res.status(403).json({ ok: false, message: "Solo Logística" });
  next();
}

// ============================================================
//  SERVIR HTML
// ============================================================
app.get("/login", (_, res) => res.sendFile(path.join(__dirname, "../front/login.html")));
app.get("/register", verificarToken, requireAdmin, (_, res) =>
  res.sendFile(path.join(__dirname, "../front/register.html"))
);
app.get("/logistica", verificarToken, requireLogistica, (_, res) =>
  res.sendFile(path.join(__dirname, "../front/logistica.html"))
);
app.get("/admin", verificarToken, requireAdmin, (_, res) =>
  res.sendFile(path.join(__dirname, "../front/admin.html"))
);

["E1","E2","E3","E4","E5"].forEach(num => {
  app.get(`/op/${num[1]}`,
    verificarToken,
    (req,res)=>{
      const map={
        operador_E1:"E1", operador_E2:"E2", operador_E3:"E3",
        operador_E4:"E4", operador_E5:"E5"
      };
      if(map[req.user.role]!==num)
        return res.status(403).send("Sin permiso");
      res.sendFile(path.join(__dirname, `../front/op-estacion-${num[1]}.html`));
    }
  )
});

// ============================================================
//  MIGRACIONES
// ============================================================
async function initDB() {
  const client = await pool.connect();
  try {

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        rut TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'operador',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  customer TEXT NOT NULL,
  site TEXT,
  sku TEXT,
  qty_total INT NOT NULL,
  qty_real INT,
  merma INT,
  started_at TIMESTAMP,
  status TEXT DEFAULT 'in_progress',
  current_station TEXT DEFAULT 'E1',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  completed_at TIMESTAMP
);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS station_tasks (
        id SERIAL PRIMARY KEY,
        order_id INT REFERENCES orders(id) ON DELETE CASCADE,
        station TEXT NOT NULL,
        qty_total INT NOT NULL,
        qty_real INT,
        merma INT,
        note TEXT DEFAULT '',
        priority TEXT DEFAULT 'baja',
        status TEXT DEFAULT 'queued',
        created_at TIMESTAMP DEFAULT NOW(),
        started_at TIMESTAMP,
        completed_at TIMESTAMP
      );
    `);

    console.log("Migraciones listas.");
  } finally {
    client.release();
  }
}

initDB();

// ============================================================
//  AUTENTICACIÓN
// ============================================================
app.post("/register", verificarToken, requireAdmin, async (req, res) => {
  try {
    const { name, rut, email, password, role } = req.body;

    const exists = await pool.query(
      "SELECT id FROM users WHERE rut=$1 OR email=$2",
      [rut, email]
    );
    if (exists.rows.length)
      return res.json({ ok:false, message:"RUT o email ya registrados" });

    const hashed = await bcrypt.hash(password, 10);

    const { rows } = await pool.query(`
      INSERT INTO users (name,rut,email,password_hash,role)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING id,name,rut,email,role
    `, [name, rut, email, hashed, role]);

    res.json({ ok:true, user: rows[0] });
  } catch (err) {
    res.status(500).json({ ok:false, message:"Error registrando usuario" });
  }
});

app.post("/login", async (req, res) => {
  const { rut, password } = req.body;

  const { rows } = await pool.query(
    "SELECT * FROM users WHERE rut=$1",
    [rut]
  );

  if (!rows.length)
    return res.json({ ok:false, message:"Usuario no existe" });

  const user = rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid)
    return res.json({ ok:false, message:"Contraseña incorrecta" });

  const token = jwt.sign(
    { id:user.id, name:user.name, role:user.role, rut:user.rut },
    JWT_SECRET,
    { expiresIn:"1h" }
  );

  res.cookie("token", token, { httpOnly:true, sameSite:"lax" });
  res.json({ ok:true, user:{ id:user.id, name:user.name, role:user.role } });
});

app.get("/me", verificarToken, (req,res)=>res.json({ok:true,user:req.user}));
app.post("/logout", (req,res)=>{ res.clearCookie("token"); res.json({ok:true}); });

// ============================================================
//  HELPERS
// ============================================================
const estaciones = ["E1","E2","E3","E4","E5"];
function validarEstacion(s){ return estaciones.includes(s); }
function siguiente(s){ return estaciones[estaciones.indexOf(s)+1] || null; }

// ============================================================
//  CREAR PEDIDO
// ============================================================
app.post("/orders", verificarToken, requireLogistica, async (req, res) => {
    const { customer, site, sku, qty_total, note, details, priority } = req.body;
  
    // Si el frontend no envía prioridad, por defecto "baja"
    const prioridad = (priority || "baja").toLowerCase().trim();
  
    try {
      // Crear pedido en la tabla "orders"
      const insert = await pool.query(`
        INSERT INTO orders (customer, site, sku, qty_total, details)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
      `, [customer, site, sku, qty_total, details]);
  
      const orderId = insert.rows[0].id;
  
      // Crear la tarea en la estación E1 con la prioridad correcta
      await pool.query(`
        INSERT INTO station_tasks (order_id, station, qty_total, status, priority, note)
        VALUES ($1, 'E1', $2, 'queued', $3, $4)
      `, [orderId, qty_total, prioridad, note]);
  
      // Respuesta exitosa
      res.json({ ok: true, order_id: orderId });
    } catch (error) {
      console.error("Error al crear el pedido:", error);
      res.status(500).json({ ok: false, message: "Error al crear el pedido" });
    }
  });

// ============================================================
//  WORK QUEUE POR ESTACIÓN
// ============================================================
app.get("/stations/:station/work-queue", verificarToken, async (req, res) => {
    const st = req.params.station;
    if (!validarEstacion(st))
      return res.json({ ok: false, message: "Estación inválida" });
  
    const pending = await pool.query(`
      SELECT t.*, o.customer, o.sku, o.site, o.details, t.note
      FROM station_tasks t
      JOIN orders o ON o.id = t.order_id
      WHERE t.station = $1 AND t.status = 'queued'
      ORDER BY 
        CASE 
          WHEN t.priority = 'alto' THEN 1
          WHEN t.priority = 'medio' THEN 2
          WHEN t.priority = 'bajo' THEN 3
          ELSE 4
        END,
        t.id ASC
    `, [st]);
  
    const active = await pool.query(`
      SELECT t.*, o.customer, o.sku, o.site, o.details, t.note
      FROM station_tasks t
      JOIN orders o ON o.id = t.order_id
      WHERE t.station = $1 AND t.status = 'in_progress'
      ORDER BY 
        CASE 
          WHEN t.priority = 'alto' THEN 1
          WHEN t.priority = 'medio' THEN 2
          WHEN t.priority = 'bajo' THEN 3
          ELSE 4
        END,
        t.id ASC
    `, [st]);
  
    const done = await pool.query(`
      SELECT t.*, o.customer, o.sku, o.site, o.details, t.note
      FROM station_tasks t
      JOIN orders o ON o.id = t.order_id
      WHERE t.station = $1 AND t.status = 'done'
      ORDER BY 
        CASE 
          WHEN t.priority = 'alto' THEN 1
          WHEN t.priority = 'medio' THEN 2
          WHEN t.priority = 'bajo' THEN 3
          ELSE 4
        END,
        t.id ASC
    `, [st]);
  
    res.json({
      ok: true,
      pending: pending.rows,
      active: active.rows,
      done: done.rows
    });
  });

// ============================================================
//  START TAREA
// ============================================================
app.post("/stations/:station/work/:id/start",
  verificarToken,
  requireCorrectStation,
  async (req,res)=>{
    const { station, id } = req.params;

    const { rows } = await pool.query(`
      SELECT * FROM station_tasks WHERE id=$1
    `,[id]);

    if(!rows.length) return res.json({ok:false,message:"No existe"});

    const t = rows[0];

    if(t.station!==station)
      return res.json({ok:false,message:`Pertenece a ${t.station}`});

    if(t.status!=="queued")
      return res.json({ok:false,message:"Ya iniciada"});

    await pool.query(`
      UPDATE station_tasks
      SET status='in_progress', started_at=NOW()
      WHERE id=$1
    `,[id]);

    res.json({ok:true});
  }
);

// ============================================================
//  ADVANCE TAREA
// ============================================================
// ============================================================
//  AVANZAR TAREA (CORREGIDO COMPLETO)
// ============================================================
// ============================================================
//  AVANZAR TAREA (VERSIÓN COMPLETA Y FINAL)
// ============================================================

// ============================================================
//  AVANZAR TAREA (VERSIÓN CORREGIDA DEFINITIVA)
// ============================================================
app.post("/stations/:station/work/:id/advance",
    verificarToken,
    requireCorrectStation,
    async (req, res) => {
  
      const station = req.params.station.toUpperCase();
      const taskId = req.params.id;
      const { qty_real } = req.body;
  
      const qtyRealInt = parseInt(qty_real, 10);
  
      if (isNaN(qtyRealInt) || qtyRealInt < 0) {
        return res.status(400).json({ ok: false, message: "Cantidad real inválida" });
      }
  
      try {
        // 1. Obtener tarea actual
        const tRes = await pool.query(
          `SELECT * FROM station_tasks WHERE id=$1`,
          [taskId]
        );
  
        if (!tRes.rows.length)
          return res.status(404).json({ ok:false, message:"Tarea no encontrada" });
  
        const t = tRes.rows[0];
  
        if (t.station !== station)
          return res.status(403).json({ ok:false, message:`La tarea pertenece a ${t.station}` });
  
        if (t.status !== "in_progress")
          return res.status(400).json({ ok:false, message:"La tarea no está en progreso" });
  
        // 2. Obtener el qty_total ORIGINAL del pedido
        const oRes = await pool.query(
          `SELECT qty_total FROM orders WHERE id=$1`,
          [t.order_id]
        );
  
        const qtyTotalOriginal = oRes.rows[0].qty_total; // <-- ESTE NUNCA CAMBIA
  
        // 3. Calcular merma
        const merma = t.qty_total - qtyRealInt;
  
        // 4. Completar tarea actual (histórico)
        await pool.query(`
          UPDATE station_tasks
          SET qty_real=$1,
              merma=$2,
              status='done',
              completed_at=NOW()
          WHERE id=$3
        `, [qtyRealInt, merma, taskId]);
  
        // 5. Actualizar la tabla orders
        await pool.query(`
          UPDATE orders
          SET qty_real=$1,
              merma=$2,
              started_at=COALESCE(started_at, NOW()),
              updated_at=NOW()
          WHERE id=$3
        `, [qtyRealInt, merma, t.order_id]);
  
        // 6. Calcular siguiente estación
        const nextStations = { E1:"E2", E2:"E3", E3:"E4", E4:"E5", E5:null };
        const nextStation = nextStations[station];
  
        // 7. Si es la última estación → cerrar pedido
        if (!nextStation) {
          await pool.query(`
            UPDATE orders
            SET current_station='DONE',
                status='completed',
                updated_at=NOW(),
                completed_at=NOW()
            WHERE id=$1
          `, [t.order_id]);
  
          return res.json({
            ok:true,
            message:"Tarea finalizada — Pedido completado"
          });
        }
  
        // 8. Crear nueva tarea en la siguiente estación
        const newTask = await pool.query(`
          INSERT INTO station_tasks
            (order_id, station, qty_total, qty_real, merma, priority, note, status, created_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7,'queued',NOW())
          RETURNING id
        `, [
          t.order_id,
          nextStation,
          qtyTotalOriginal, // <-- SIEMPRE EL TOTAL ORIGINAL
          qtyRealInt,       // <-- LO PRODUCIDO
          merma,
          t.priority,
          t.note || ""
        ]);
  
        // 9. Actualizar estado del pedido
        await pool.query(`
          UPDATE orders
          SET current_station=$1, updated_at=NOW()
          WHERE id=$2
        `, [nextStation, t.order_id]);
  
        return res.json({
          ok:true,
          message:`Tarea enviada a ${nextStation}`,
          next_task_id: newTask.rows[0].id
        });
  
      } catch (err) {
        console.error("❌ ERROR advance:", err);
        return res.status(500).json({
          ok:false,
          message:"Error interno: " + err.message
        });
      }
    }
  );


// ============================================================
//  DETALLES DE PEDIDO
// ============================================================
app.get("/orders/sku/:sku/details", verificarToken, async (req, res) => {
    const sku = req.params.sku;
    const order = await pool.query(`
      SELECT *, NOW()-created_at AS tiempo_total
      FROM orders WHERE sku=$1
    `, [sku]);
  
    if (!order.rows.length)
      return res.json({ ok: false, message: "No existe pedido con ese SKU" });
  
    const history = await pool.query(`
      SELECT station, qty_total, qty_real, merma,
             created_at, completed_at,
             completed_at-started_at AS duracion_estacion
      FROM station_tasks
      WHERE order_id=$1
      ORDER BY id ASC
    `, [order.rows[0].id]);
  
    const merma = await pool.query(`
      SELECT COALESCE(SUM(merma), 0) AS total
      FROM station_tasks
      WHERE order_id=$1
    `, [order.rows[0].id]);
  
    res.json({
      ok: true,
      order: order.rows[0],
      history: history.rows,
      merma_total: merma.rows[0].total
    });
  });

// ============================================================
//  INICIAR SERVIDOR
// ============================================================
app.listen(PORT, () => {
  console.log("===========================================");
  console.log("   PolinTrack backend corriendo OK         ");
  console.log("===========================================");
  console.log("Puerto:", PORT);
});