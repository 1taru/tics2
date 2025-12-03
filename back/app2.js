// Requisitos:
// npm i express cookie-parser express-session cors jsonwebtoken bcrypt mongoose dotenv
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const isProd = process.env.NODE_ENV === 'production';

// ========= CORS =========
const ALLOWED_ORIGINS = [
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  process.env.FRONT_ORIGIN // ej: https://app.midominio.cl
].filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // permite curl / Postman
    cb(null, ALLOWED_ORIGINS.includes(origin));
  },
  credentials: false, // no usamos cookies para auth
  methods: ['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ========= MongoDB (Mongoose) =========
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('❌ Falta MONGODB_URI en .env');
  process.exit(1);
}
mongoose.set('strictQuery', true);
const needsTLS =
  MONGODB_URI.startsWith('mongodb+srv://') ||
  /[?&](ssl|tls)=true/i.test(MONGODB_URI);

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 15000,
  tls: needsTLS
}).then(() => {
  console.log('MongoDB OK');
}).catch(err => {
  console.error('MongoDB ERROR:', err);
});

// ========= Modelos =========
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  rut:  { type: String, required: true, unique: true }, // normalizado
  email:{ type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  role: { type: String, required: true, default: 'user' },
  created_at: { type: Date, default: Date.now }
}, { collection: 'users' });
const User = mongoose.model('User', userSchema);

// Pedido maestro
const orderSchema = new mongoose.Schema({
  customer: String,
  site: String,
  sku: String,
  qty_total: { type: Number, required: true },
  status: { type: String, default: 'in_progress' }, // in_progress | done | canceled
  current_station: { type: String, default: 'E1' }, // informativo
  created_at: { type: Date, default: Date.now }
}, { collection: 'orders' });
const Order = mongoose.model('Order', orderSchema);

// Tareas por estación (lotes que se mueven entre estaciones)
const stationTaskSchema = new mongoose.Schema({
  order_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
  station: { type: String, required: true }, // 'E1', 'E2', ...
  qty: { type: Number, required: true },
  note: { type: String, default: '' },
  priority: { type: Boolean, default: false },
  status: { type: String, default: 'queued' }, // queued | processing | done
  created_at: { type: Date, default: Date.now }
}, { collection: 'station_tasks' });
const StationTask = mongoose.model('StationTask', stationTaskSchema);

// ========= Utilidades RUT =========
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

// ========= JWT (solo access token) =========
const JWT_SECRET = process.env.JWT_SECRET || 'cambia-esto-en-produccion';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

function signAccess(u) {
  return jwt.sign(
    { sub: String(u._id || u.id), rut: u.rut, email: u.email, role: u.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function auth(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');
  if (!token || scheme?.toLowerCase() !== 'bearer') {
    return res.status(401).json({ ok:false, message:'Falta Authorization: Bearer <token>' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ ok:false, message:'Token inválido o expirado' });
  }
}

// ========= Rutas básicas de front (opcional) =========
app.use(express.static(path.join(__dirname, '../front')));
app.get('/login', (_req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'login.html'));
});
app.get('/register', (_req, res) => {
  res.sendFile(path.join(__dirname, '../front', 'register.html'));
});
app.get('/', (_req, res) => res.redirect('/login'));

// ========= Auth: Register & Login por RUT =========
// POST /register  { name, rut, email, password, role }
app.post('/register', async (req, res) => {
  try {
    const { name, rut, email, password, role } = req.body || {};
    if (!name || !rut || !email || !password || !role) {
      return res.status(400).json({ ok: false, message: 'Faltan campos' });
    }
    if (!validateRut(rut)) {
      return res.status(400).json({ ok: false, message: 'RUT inválido' });
    }
    const rutNorm = normalizeRut(rut);

    const exists = await User.exists({ $or: [{ rut: rutNorm }, { email }] });
    if (exists) {
      return res.status(409).json({ ok: false, message: 'RUT o Email ya registrado' });
    }

    const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const user = await User.create({ name, rut: rutNorm, email, password_hash, role });

    const token = signAccess(user);
    return res.json({
      ok: true,
      message: 'Registro OK',
      token,
      user: {
        id: String(user._id), name: user.name, rut: user.rut, email: user.email, role: user.role, created_at: user.created_at
      }
    });
  } catch (err) {
    console.error('Error /register:', err);
    return res.status(500).json({ ok: false, message: 'Error interno del servidor' });
  }
});

// POST /login  { rut, password }
app.post('/login', async (req, res) => {
  try {
    const { rut, password } = req.body || {};
    if (!rut || !password) {
      return res.status(400).json({ ok: false, message: 'Faltan datos' });
    }
    const rutNorm = normalizeRut(rut);

    const user = await User.findOne({ rut: rutNorm }).lean();
    if (!user) {
      return res.status(401).json({ ok: false, message: 'Credenciales inválidas' });
    }

    const okPass = await bcrypt.compare(password, user.password_hash);
    if (!okPass) {
      return res.status(401).json({ ok: false, message: 'Credenciales inválidas' });
    }

    const token = signAccess(user);
    return res.json({
      ok: true,
      message: 'Login OK',
      token,
      user: { id: String(user._id), name: user.name, rut: user.rut, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error('Error /login:', err);
    return res.status(500).json({ ok: false, message: 'Error interno del servidor' });
  }
});

// GET /me  (perfil, requiere Authorization: Bearer)
app.get('/me', auth, async (req, res) => {
  try {
    const u = await User.findById(req.user.sub).lean();
    if (!u) return res.status(404).json({ ok: false, message: 'Usuario no encontrado' });
    return res.json({
      ok: true,
      user: {
        id: String(u._id), name: u.name, rut: u.rut, email: u.email, role: u.role, created_at: u.created_at
      }
    });
  } catch (err) {
    console.error('Error /me:', err);
    return res.status(500).json({ ok: false, message: 'Error interno' });
  }
});

// POST /logout (stateless: el cliente simplemente descarta el token)
app.post('/logout', (_req, res) => {
  return res.json({ ok: true, message: 'Logout OK (descarta el token en el cliente)' });
});

// ========= Pedidos y Estación 1 (protegidos) =========
// POST /orders  { customer, site, sku, qty_total }
app.post('/orders', auth, async (req, res) => {
  try {
    const { customer, site, sku, qty_total } = req.body || {};
    const qty = Number(qty_total);
    if (!qty || qty <= 0) return res.status(400).json({ ok:false, message:'Cantidad inválida' });

    const order = await Order.create({ customer, site, sku, qty_total: qty, current_station:'E1' });

    // Encolar en E1 como un lote único inicialmente
    const task = await StationTask.create({
      order_id: order._id,
      station: 'E1',
      qty,
      priority: false,
      note: ''
    });

    return res.json({ ok:true, order, task });
  } catch (err) {
    console.error('Error /orders:', err);
    return res.status(500).json({ ok:false, message:'Error interno' });
  }
});

// GET /stations/E1/work-queue  -> lista de tareas en E1
app.get('/stations/E1/work-queue', auth, async (_req, res) => {
  try {
    const tasks = await StationTask.find({ station:'E1', status:'queued' })
      .sort({ priority:-1, created_at:1 })
      .populate('order_id', 'customer site sku qty_total created_at')
      .lean();

    return res.json({ ok:true, tasks });
  } catch (err) {
    console.error('Error GET /stations/E1/work-queue:', err);
    return res.status(500).json({ ok:false, message:'Error interno' });
  }
});

// POST /stations/E1/work/:taskId/advance  { completedQty, note }
app.post('/stations/E1/work/:taskId/advance', auth, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { completedQty, note } = req.body || {};
    const qtyDone = Number(completedQty);

    const task = await StationTask.findById(taskId);
    if (!task || task.station !== 'E1' || task.status !== 'queued') {
      return res.status(404).json({ ok:false, message:'Tarea no encontrada en E1' });
    }
    if (!qtyDone || qtyDone <= 0 || qtyDone > task.qty) {
      return res.status(400).json({ ok:false, message:`completedQty debe ser entre 1 y ${task.qty}` });
    }

    const remaining = task.qty - qtyDone;

    // 1) Avanzar lo completado a E2 (crea tarea en E2)
    await StationTask.create({
      order_id: task.order_id,
      station: 'E2',
      qty: qtyDone,
      note: note || task.note || '',
      priority: false,
      status: 'queued'
    });

    if (remaining > 0) {
      // 2) Dejar remanente en E1 con prioridad alta
      task.qty = remaining;
      task.note = note || task.note || '';
      task.priority = true;    // prioridad alta
      await task.save();
    } else {
      // 3) Sin remanente: cerrar tarea E1
      task.status = 'done';
      await task.save();
    }

    // (Opcional) actualizar estado del pedido a E2 si ya no quedan tareas en E1
    const stillE1 = await StationTask.exists({ order_id: task.order_id, station:'E1', status:'queued' });
    if (!stillE1) {
      await Order.findByIdAndUpdate(task.order_id, { current_station: 'E2' });
    }

    return res.json({ ok:true, message:'Avanzado correctamente', remaining });
  } catch (err) {
    console.error('Error POST /stations/E1/work/:taskId/advance:', err);
    return res.status(500).json({ ok:false, message:'Error interno' });
  }
});

app.listen(PORT, () => console.log(`API escuchando en http://localhost:${PORT}`));