const express = require('express');
const router  = express.Router();
const { verifyUserData, getPublicKey, getKeyPairStatus } = require('../services/signingService');

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
 * GET /api/signing/key-status
 * Devuelve el estado de las llaves privada y pública.
 * Útil para detectar si alguna llave fue corrompida.
 * Puedes acceder entrando a https://localhost:3000/api/signing/key-status
 * O haciendo la peticion desde la consola del navegador:
 * fetch('https://localhost:3000/api/signing/key-status')
 *   .then(r => r.json())
 *   .then(console.log);
 */
router.get('/key-status', (req, res) => {
  try {
    const status = getKeyPairStatus();
    res.json(status);
  } catch (err) {
    console.error('[SigningService] Error obteniendo estado de llaves:', err?.message);
    res.status(500).json({
      valid: false,
      message: 'Error interno al validar las llaves. Posible llave privada corrupta.'
    });
  }
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
 *   iat:       1680000000,
 *   exp:       1680003600,
 *   jti:       "uuid-único-de-la-firma",
 *   signature: "firma base64 recibida en el login"
 * }
 *
 * ─── Simulación de ataque (ejecutar en consola del navegador) ───
 * Los valores de id, email, role, iat, exp, jti y signature se obtienen del Response
 * de la petición /api/auth/login en DevTools → Network.
 *
 * fetch('https://localhost:3000/api/signing/verify', {
 *   method: 'POST',
 *   headers: { 'Content-Type': 'application/json' },
 *   body: JSON.stringify({
 *     id:        'uuid-del-usuario',
 *     email:     'correo@ejemplo.com',
 *     role:      'admin',          // ← rol manipulado (era 'authenticated')
 *     iat:       1618886400,       // ← timestamp de creación manipulado
 *     exp:       1618890000,       // ← timestamp de expiración manipulado
 *     jti:       'jti-de-la-firma',
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
  const { id, email, role, iat, exp, jti, signature } = req.body;

  if (!id || !email || !role || !iat || !exp || !jti || !signature) {
    return res.status(400).json({
      valid: false,
      error: 'id, email, role, iat, exp, jti y signature son requeridos.',
      message: 'Falta el campo jti o algún dato obligatorio. Asegúrate de enviar id, email, role, iat, exp, jti y signature.'
    });
  }

  const result = verifyUserData({ id, email, role, iat, exp, jti, signature });

  if (!result.valid) {
    console.warn(`[SigningService] Verificación fallida para ${email} — motivo: ${result.reason}`);
  }

  res.json({
    valid: result.valid,
    message: result.valid
      ? 'Integridad verificada. Los datos no fueron alterados y la firma sigue vigente.'
      : result.reason === 'expired_or_invalid_timestamp'
        ? 'La firma ya expiró o los timestamps no son válidos.'
        : result.reason === 'signature_revoked'
        ? 'La firma fue revocada (sesión cerrada).'
        : result.reason === 'missing_fields'
          ? 'Falta el campo jti o algún dato obligatorio. Verifica el payload enviado.'
          : 'ALERTA: Los datos fueron manipulados o la firma no coincide.',
    reason: result.reason
  });
});

module.exports = router;
