const crypto = require('crypto');

// Algoritmo de cifrado simétrico AES en modo GCM con clave de 256 bits
const algorithm = 'aes-256-gcm';

// Se obtiene la clave desde las variables de entorno en formato hexadecimal
const keyHex = process.env.PHONE_ENCRYPTION_KEY;

// Validación: la clave debe existir y tener 64 caracteres hex (32 bytes = 256 bits)
if (!keyHex || keyHex.length !== 64) {
  throw new Error('PHONE_ENCRYPTION_KEY debe ser hex de 64 caracteres (32 bytes)');
}

// Conversión de la clave hexadecimal a un Buffer binario utilizable por crypto
const key = Buffer.from(keyHex, 'hex');

/**
 * Función para cifrar texto plano
 * @param {string} text Texto a cifrar
 * @returns {string} Cadena en formato iv:ciphertext:tag (todo en base64)
 */
function encrypt(text) {
  // Si no hay texto, retorna vacío
  if (!text) return '';

  // Genera un vector de inicialización (IV) aleatorio de 12 bytes (recomendado para GCM)
  const iv = crypto.randomBytes(12);

  // Crea el objeto cipher con el algoritmo, la clave y el IV
  const cipher = crypto.createCipheriv(algorithm, key, iv);

  // Realiza el cifrado del texto
  const encrypted = Buffer.concat([
    cipher.update(text, 'utf8'), // procesa el texto
    cipher.final()               // finaliza el cifrado
  ]);

  // Obtiene el authentication tag (garantiza integridad y autenticidad)
  const tag = cipher.getAuthTag();

  // Retorna todo codificado en base64 separado por ":"
  // iv:ciphertext:tag
  return `${iv.toString('base64')}:${encrypted.toString('base64')}:${tag.toString('base64')}`;
}

/**
 * Función para descifrar datos previamente cifrados
 * @param {string} data Cadena en formato iv:ciphertext:tag
 * @returns {string} Texto original descifrado
 */
function decrypt(data) {
  // Si no hay datos, retorna vacío
  if (!data) return '';

  // Divide la cadena en sus tres partes
  const parts = data.split(':');

  // Validación del formato esperado
  if (parts.length !== 3) {
    throw new Error('Formato inválido. Debe ser iv:ciphertext:tag');
  }

  // Extrae cada componente
  const [ivB64, encryptedB64, tagB64] = parts;

  // Convierte de base64 a Buffer binario
  const iv = Buffer.from(ivB64, 'base64');
  const encrypted = Buffer.from(encryptedB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');

  // Crea el objeto decipher con los mismos parámetros usados en el cifrado
  const decipher = crypto.createDecipheriv(algorithm, key, iv);

  // Se establece el authentication tag para validar integridad
  decipher.setAuthTag(tag);

  // Realiza el descifrado
  const decrypted = Buffer.concat([
    decipher.update(encrypted), // procesa los datos cifrados
    decipher.final()            // finaliza el descifrado (lanza error si el tag no coincide)
  ]);

  // Convierte el resultado a texto UTF-8
  return decrypted.toString('utf8');
}

// Exporta las funciones para usarlas en otras partes del backend
module.exports = {
  encrypt,
  decrypt
};
