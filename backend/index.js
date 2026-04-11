require('dotenv').config();
const https = require('https');
const fs = require('fs');
const express = require('express');
const cors = require('cors');

const encryptionRoutes = require('./routes/encryption');
const authRoutes = require('./routes/auth');
const logsRoutes = require('./routes/logs');
const signingRoutes = require('./routes/signing');

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api/encryption', encryptionRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/logs', logsRoutes);
app.use('/api/signing', signingRoutes);

app.get('/', (req, res) => {
  res.send('API funcionando');
});

const PORT = process.env.PORT || 3000;

const path = require('path');

const options = {
  key: fs.readFileSync(path.join(__dirname, '../certs/localhost-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, '../certs/localhost.pem')),
};

https.createServer(options, app).listen(3000, () => {
  console.log('Servidor HTTPS en https://localhost:3000');
});
