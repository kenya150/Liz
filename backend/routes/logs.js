const express = require('express');
const router  = express.Router();
const { createClient } = require('@supabase/supabase-js');

const supabase = require('../services/supabaseClient');

/**
 * POST /api/logs/security
 * Recibe eventos WARN y CRITICAL desde el SecurityLoggerService de Angular.
 * Agrega la IP real del request (imposible obtenerla desde el navegador)
 * y persiste el evento en la tabla security_logs de Supabase.
 *
 * La tabla debe existir en Supabase:
 * CREATE TABLE security_logs (
 *   id         uuid DEFAULT gen_random_uuid() PRIMARY KEY,
 *   level      text NOT NULL,
 *   message    text NOT NULL,
 *   user_id    text,
 *   user_agent text,
 *   ip         text,
 *   timestamp  timestamptz,
 *   created_at timestamptz DEFAULT now()
 * );
 */
router.post('/security', async (req, res) => {
  try {
    const { level, message, userIdentifier, userAgent, timestamp } = req.body;

    if (!level || !message) {
      return res.status(400).json({ error: 'level y message son requeridos.' });
    }

    // Solo aceptar niveles que justifican persistencia en servidor
    if (!['WARN', 'CRITICAL'].includes(level)) {
      return res.status(400).json({ error: 'Solo se aceptan niveles WARN y CRITICAL.' });
    }

    // La IP real viene del request, no del cliente
    const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';

    const { error } = await supabase.from('security_logs').insert({
      level,
      message,
      user_id:    userIdentifier || null,
      user_agent: userAgent      || null,
      ip,
      timestamp:  timestamp      || new Date().toISOString(),
    });

    if (error) {
      console.error('[LogsRoute] Error al guardar security log:', error.message);
      return res.status(500).json({ error: 'No se pudo persistir el log.' });
    }

    res.status(201).json({ success: true });
  } catch (err) {
    console.error('[LogsRoute] Error inesperado:', err.message);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

module.exports = router;
