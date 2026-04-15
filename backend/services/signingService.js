const crypto = require('crypto');

/**
 * Las llaves se cargan una vez al iniciar el servidor.
 * La llave privada NUNCA sale del backend.
 * La llave publica puede enviarse al frontend para verificacion.
 */
const privateKey = process.env.PRIVATE_KEY?.replace(/\\n/g, '\n');
const publicKey  = process.env.PUBLIC_KEY?.replace(/\\n/g, '\n');

if (!privateKey || !publicKey) {
  throw new Error('PRIVATE_KEY y PUBLIC_KEY son requeridas en .env');
}

const DEFAULT_SIGNATURE_LIFETIME_SECONDS = 60 * 60; // 1 hora

// Lista de firmas revocadas (en memoria - en producción usar Redis/DB)
const revokedSignatures = new Set();

/**
 * Datos que se firman — los que no deben poder alterarse.
 * id, email, role, iat y exp son los campos criticos de integridad.
 * Se ordenan alfabeticamente para garantizar que la serializacion
 * sea siempre la misma sin importar el orden en que lleguen.
 */
function buildPayload({ id, email, role, iat, exp, jti }) {
  return JSON.stringify({ email, id, jti, role, iat, exp });
}

/**
 * Genera una firma digital para los datos del usuario.
 * Se llama en el login, despues de autenticar correctamente.
 *
 * @param {string} id    - UUID del usuario (auth.users.id)
 * @param {string} email - Correo del usuario
 * @param {string} role  - Rol de Supabase (normalmente 'authenticated')
 * @param {number} expiresInSeconds - Tiempo de vida de la firma en segundos
 * @returns {object}     - Firma en formato base64 y el payload
 */
function signUserData(id, email, role, expiresInSeconds = DEFAULT_SIGNATURE_LIFETIME_SECONDS) {
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID(); // ID único de la firma
  const payload = {
    id,
    email,
    role,
    iat: now,
    exp: now + expiresInSeconds,
    jti
  };
  const serializedPayload = buildPayload(payload);

  const sign = crypto.createSign('SHA256');
  sign.update(serializedPayload);
  sign.end();

  return {
    signature: sign.sign(privateKey, 'base64'),
    payload
  };
}

/**
 * Revoca una firma específica (al cerrar sesión).
 */
function revokeSignature(jti) {
  revokedSignatures.add(jti);
  console.info(`[SigningService] Firma revocada: ${jti}`);
}

/**
 * Verifica que los datos del usuario no fueron alterados y que la firma sigue vigente.
 * Usa la llave publica — no necesita la privada.
 *
 * @param {object} params
 * @param {string} params.id
 * @param {string} params.email
 * @param {string} params.role
 * @param {number} params.iat
 * @param {number} params.exp
 * @param {string} params.jti
 * @param {string} params.signature
 * @returns {{ valid: boolean, reason: string }}
 */
function verifyUserData({ id, email, role, iat, exp, jti, signature }) {
  try {
    if (!id || !email || !role || !iat || !exp || !jti || !signature) {
      return { valid: false, reason: 'missing_fields' };
    }

    // Verificar si la firma fue revocada
    if (revokedSignatures.has(jti)) {
      return { valid: false, reason: 'signature_revoked' };
    }

    const payload = buildPayload({ id, email, role, iat, exp, jti });
    const verify = crypto.createVerify('SHA256');
    verify.update(payload);
    verify.end();

    const signatureIsValid = verify.verify(publicKey, signature, 'base64');
    if (!signatureIsValid) {
      return { valid: false, reason: 'invalid_signature' };
    }

    const now = Math.floor(Date.now() / 1000);
    if (now < iat || now > exp) {
      return { valid: false, reason: 'expired_or_invalid_timestamp' };
    }

    return { valid: true, reason: 'ok' };
  } catch (err) {
    console.error(`[SigningService] Error inesperado durante la verificacion:`, err?.message);
    return { valid: false, reason: 'verification_error' };
  }
}

/**
 * Devuelve la llave publica para que el frontend pueda verificar firmas localmente.
 * Exponer la publica es seguro — solo sirve para verificar, no para firmar.
 */
function getPublicKey() {
  return publicKey;
}

/**
 * Valida que la llave privada y publica sean compatibles.
 */
function validateKeyPair() {
  try {
    const testData = 'healthtech-key-check';
    const sign = crypto.createSign('SHA256');
    sign.update(testData);
    sign.end();

    const signature = sign.sign(privateKey, 'base64');

    const verify = crypto.createVerify('SHA256');
    verify.update(testData);
    verify.end();

    return { valid: verify.verify(publicKey, signature, 'base64'), error: null };
  } catch (err) {
    console.error('[SigningService] Error validando par de llaves:', err?.message);
    return { valid: false, error: err?.message };
  }
}

/**
 * Devuelve el estado de las llaves (válidas o corruptas).
 * No expone las llaves, solo si son compatibles.
 */
function getKeyPairStatus() {
  const result = validateKeyPair();
  if (result.valid) {
    return {
      valid: true,
      message: 'Las llaves privada y pública son compatibles.'
    };
  } else {
    const message = result.error
      ? `ALERTA: Llave privada corrupta o inválida. Error: ${result.error}`
      : 'ALERTA: Las llaves privada y pública no coinciden o están corruptas.';
    return {
      valid: false,
      message
    };
  }
}

module.exports = { signUserData, verifyUserData, getPublicKey, validateKeyPair, getKeyPairStatus, revokeSignature };
