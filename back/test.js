const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
app.use(express.json());

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('Falta el campo MONGODB_URI en .env');
  process.exit(1);
}
else{
    console.log('SI SE INGRESO');
}
mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 15000,
  tls: true,
}).then(() => {
  console.log('MongoDB OK');
}).catch(err => {
  console.error('MongoDB ERROR:', err);
});

// == API ===============================
app.use('/api', apiRoutes);

// == Archivos ==========================
app.use(express.static(path.join(dirname, '../frontend')));

// == Fallback ==========================
app.get('/', (req, res) => {
    res.sendFile(path.join(dirname, '../frontend/index.html'));
});

app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// == Servidor ==========================
app.listen(3042, () => {
    console.log('Servidor Express escuchando en puerto 3042');
    console.log('Dominio configurado: ${config.DOMAIN}');
});
