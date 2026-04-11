const crypto = require('crypto');

/**
 * Las llaves se cargan una vez al iniciar el servidor.
 * La llave privada NUNCA sale del backend.
 * La llave pública puede enviarse al frontend para verificación.
 */
const privateKey = process.env.PRIVATE_KEY?.replace(/\\n/g, '\n');
const publicKey  = process.env.PUBLIC_KEY?.replace(/\\n/g, '\n');

if (!privateKey || !publicKey) {
  throw new Error('PRIVATE_KEY y PUBLIC_KEY son requeridas en .env');
}

/**
 * Datos que se firman — los que no deben poder alterarse.
 * id, email y role son los campos críticos de identidad y autorización.
 * Se ordenan alfabéticamente para garantizar que la serialización
 * sea siempre la misma sin importar el orden en que lleguen.
 */
function buildPayload(id, email, role) {
  return JSON.stringify({ email, id, role });
}

/**
 * Genera una firma digital para los datos del usuario.
 * Se llama en el login, después de autenticar correctamente.
 *
 * @param {string} id    - UUID del usuario (auth.users.id)
 * @param {string} email - Correo del usuario
 * @param {string} role  - Rol de Supabase (normalmente 'authenticated')
 * @returns {string}     - Firma en formato base64
 */
function signUserData(id, email, role) {
  // Serializa los datos del usuario en un string JSON ordenado
  const payload = buildPayload(id, email, role);

  // Crea un objeto de firma usando SHA256 como algoritmo de hash
  const sign = crypto.createSign('SHA256');

  // Alimenta el payload al objeto de firma
  sign.update(payload);

  // Indica que no hay más datos que procesar
  sign.end();

  // Genera la firma usando la llave privada y la devuelve en base64
  return sign.sign(privateKey, 'base64');
}

/**
 * Verifica que los datos del usuario no fueron alterados.
 * Usa la llave pública — no necesita la privada.
 *
 * @param {string} id        - UUID recibido del cliente
 * @param {string} email     - Email recibido del cliente
 * @param {string} role      - Rol recibido del cliente
 * @param {string} signature - Firma base64 recibida del cliente
 * @returns {boolean}        - true si los datos son íntegros, false si fueron alterados
 */
function verifyUserData(id, email, role, signature) {
  try {
    // Reconstruye el mismo payload con los datos recibidos del cliente
    const payload = buildPayload(id, email, role);

    // Crea un objeto de verificación con el mismo algoritmo usado al firmar
    const verify = crypto.createVerify('SHA256');

    // Alimenta el payload recibido al verificador
    verify.update(payload);

    // Indica que no hay más datos que procesar
    verify.end();

    // Compara el payload reconstruido contra la firma original usando la llave pública.
    // Si un solo carácter fue alterado (id, email o role), devuelve false.
    return verify.verify(publicKey, signature, 'base64');
  } catch {
    // Si la firma tiene formato inválido o la llave falla, se trata como verificación fallida
    return false;
  }
}

/**
 * Devuelve la llave pública para que el frontend pueda verificar firmas localmente.
 * Exponer la pública es seguro — solo sirve para verificar, no para firmar.
 */
function getPublicKey() {
  return publicKey;
}

module.exports = { signUserData, verifyUserData, getPublicKey };
