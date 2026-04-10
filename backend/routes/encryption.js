// Importa el framework Express
const express = require('express');

// Crea un enrutador modular para definir endpoints
const router = express.Router();

// Importa las funciones de cifrado y descifrado desde el servicio
const { encrypt, decrypt } = require('../services/encryptionService');

/**
 * Endpoint para cifrar un número telefónico
 * Método: POST
 * Ruta: /encrypt-phone
 */
router.post('/encrypt-phone', (req, res) => {
  try {
    // Extrae el campo "phone" del cuerpo de la petición
    const { phone } = req.body;

    // Validación: verifica que se haya enviado el teléfono
    if (!phone) {
      return res.status(400).json({ error: 'phone requerido' });
    }

    // Llama a la función de cifrado
    const encrypted = encrypt(phone);

    // Devuelve el resultado cifrado en formato JSON
    res.json({ encrypted });

  } catch (err) {
    // Manejo de errores internos del servidor
    res.status(500).json({ error: err.message });
  }
});

/**
 * Endpoint para descifrar un número telefónico
 * Método: POST
 * Ruta: /decrypt-phone
 */
router.post('/decrypt-phone', (req, res) => {
  try {
    // Extrae el dato cifrado del cuerpo de la petición
    const { encrypted } = req.body;

    // Validación: verifica que se haya enviado el dato cifrado
    if (!encrypted) {
      return res.status(400).json({ error: 'encrypted requerido' });
    }

    // Llama a la función de descifrado
    const decrypted = decrypt(encrypted);

    // Devuelve el texto original descifrado
    res.json({ decrypted });

  } catch (err) {
    // Manejo de errores (por ejemplo: formato inválido o fallo de autenticación)
    res.status(500).json({ error: 'Error al descifrar' });
  }
});

// Exporta el router para usarlo en index.js
module.exports = router;
