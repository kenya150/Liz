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

/**
 * Datos que se firman — los que no deben poder alterarse.
 * id, email y role son los campos criticos de identidad y autorizacion.
 * Se ordenan alfabeticamente para garantizar que la serializacion
 * sea siempre la misma sin importar el orden en que lleguen.
 */
function buildPayload(id, email, role) {
  return JSON.stringify({ email, id, role });
}

/**
 * Genera una firma digital para los datos del usuario.
 * Se llama en el login, despues de autenticar correctamente.
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

  // Indica que no hay mas datos que procesar
  sign.end();

  // Genera la firma usando la llave privada y la devuelve en base64
  const signature = sign.sign(privateKey, 'base64');

  console.info(`[SigningService] Firma generada correctamente para el usuario: ${id}`);

  return signature;
}

/**
 * Verifica que los datos del usuario no fueron alterados.
 * Usa la llave publica — no necesita la privada.
 *
 * @param {string} id        - UUID recibido del cliente
 * @param {string} email     - Email recibido del cliente
 * @param {string} role      - Rol recibido del cliente
 * @param {string} signature - Firma base64 recibida del cliente
 * @returns {boolean}        - true si los datos son integros, false si fueron alterados
 */
function verifyUserData(id, email, role, signature) {
  try {
    // Reconstruye el mismo payload con los datos recibidos del cliente
    const payload = buildPayload(id, email, role);

    // Crea un objeto de verificacion con el mismo algoritmo usado al firmar
    const verify = crypto.createVerify('SHA256');

    // Alimenta el payload recibido al verificador
    verify.update(payload);

    // Indica que no hay mas datos que procesar
    verify.end();

    // Compara el payload reconstruido contra la firma original usando la llave publica.
    // Si un solo caracter fue alterado (id, email o role), devuelve false.
    const valid = verify.verify(publicKey, signature, 'base64');

    if (!valid) {
      // La firma no coincide — los datos fueron alterados despues de ser firmados
      console.warn(`[SigningService] Verificacion fallida para el usuario: ${id} — posible manipulacion de datos.`);
    }

    return valid;
  } catch (err) {
    // Si la firma tiene formato invalido o la llave falla, se trata como verificacion fallida
    console.error(`[SigningService] Error inesperado durante la verificacion:`, err?.message);
    return false;
  }
}

/**
 * Devuelve la llave publica para que el frontend pueda verificar firmas localmente.
 * Exponer la publica es seguro — solo sirve para verificar, no para firmar.
 */
function getPublicKey() {
  return publicKey;
}

module.exports = { signUserData, verifyUserData, getPublicKey };
