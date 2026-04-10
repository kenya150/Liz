require('dotenv').config();
const express = require('express');
const cors = require('cors');

const encryptionRoutes = require('./routes/encryption');
const authRoutes = require('./routes/auth');
const logsRoutes = require('./routes/logs');

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api/encryption', encryptionRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/logs', logsRoutes);

app.get('/', (req, res) => {
  res.send('API funcionando');
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
