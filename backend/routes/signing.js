const express = require('express');
const router  = express.Router();
const { verifyUserData, getPublicKey } = require('../services/signingService');

/**
 * GET /api/signing/public-key
 * Devuelve la llave pública para que Angular pueda verificar firmas localmente.
 * Es seguro exponerla — solo sirve para verificar, nunca para firmar.
 * Puedes acceder a la llave publica entrando a https://localhost:3000/api/signing/public-key
 */
router.get('/public-key', (req, res) => {
  res.json({ publicKey: getPublicKey() });
});

/**
 * POST /api/signing/verify
 * Verifica que los datos del usuario no fueron alterados desde que se firmaron.
 *
 * Body esperado:
 * {
 *   id:        "uuid del usuario",
 *   email:     "correo del usuario",
 *   role:      "authenticated",
 *   signature: "firma base64 recibida en el login"
 * }
 *
 * ─── Simulación de ataque (ejecutar en consola del navegador) ───
 * Los valores de id, email, role y signature se obtienen del Response
 * de la petición /api/auth/login en DevTools → Network.
 *
 * fetch('https://localhost:3000/api/signing/verify', {
 *   method: 'POST',
 *   headers: { 'Content-Type': 'application/json' },
 *   body: JSON.stringify({
 *     id:        'uuid-del-usuario',
 *     email:     'correo@ejemplo.com',
 *     role:      'admin',          // ← rol manipulado (era 'authenticated')
 *     signature: 'firma-del-login' // ← firma original sin alterar
 *   })
 * }).then(r => r.json()).then(console.log);
 *
 * Resultado esperado:
 * { valid: false, message: "ALERTA: Los datos fueron manipulados. La firma no coincide." }
 *
 * Si se envía role: 'authenticated' (valor original), devuelve valid: true.
 */
router.post('/verify', (req, res) => {
  const { id, email, role, signature } = req.body;

  if (!id || !email || !role || !signature) {
    return res.status(400).json({
      valid: false,
      error: 'id, email, role y signature son requeridos.'
    });
  }

  const valid = verifyUserData(id, email, role, signature);

  if (!valid) {
    console.warn(`[SigningService] Verificación fallida para ${email} — posible manipulación de datos.`);
  }

  res.json({
    valid,
    message: valid
      ? 'Integridad verificada. Los datos no fueron alterados.'
      : 'ALERTA: Los datos fueron manipulados. La firma no coincide.'
  });
});

module.exports = router;
