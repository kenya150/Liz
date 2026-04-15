const express = require('express');
const router  = express.Router();
const {
  signup,
  login,
  logout,
  getProfile,
  updateProfile,
} = require('../services/authService');

/**
 * POST /auth/signup
 * Registra un nuevo usuario. Devuelve 201 en éxito, 400 en error de validación.
 */
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    const result = await signup(name, email, password, phone);
    res.status(result.success ? 201 : 400).json(result);
  } catch (err) {
    console.error('[Auth Route] /signup:', err.message);
    res.status(500).json({ success: false, message: 'Error inesperado durante el registro.' });
  }
});

/**
 * POST /auth/login
 * Autentica al usuario. Devuelve la sesión de Supabase en éxito.
 * 401 en credenciales inválidas o cuenta bloqueada.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await login(email, password);
    res.status(result.success ? 200 : 401).json(result);
  } catch (err) {
    console.error('[Auth Route] /login:', err.message);
    res.status(500).json({ success: false, message: 'Error al conectar con el servicio de autenticación.' });
  }
});

/**
 * POST /auth/logout
 * Requiere Authorization: Bearer <access_token>
 * Revoca el token en Supabase para invalidar la sesión del lado del servidor.
 */
router.post('/logout', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(400).json({ success: false, message: 'Token de autorización requerido.' });
    }
    const { jti } = req.body; // JTI opcional para revocar firma
    const result = await logout(token, jti);
    res.status(result.success ? 200 : 500).json(result);
  } catch (err) {
    console.error('[Auth Route] /logout:', err.message);
    res.status(500).json({ success: false, message: 'Error al cerrar sesión.' });
  }
});

/**
 * GET /auth/profile/:id
 * Devuelve el perfil del usuario con el teléfono ya descifrado.
 */
router.get('/profile/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) {
      return res.status(400).json({ success: false, message: 'ID de usuario requerido.' });
    }
    const result = await getProfile(id);
    res.status(result.success ? 200 : 404).json(result);
  } catch (err) {
    console.error('[Auth Route] /profile GET:', err.message);
    res.status(500).json({ success: false, message: 'Error al obtener el perfil.' });
  }
});

/**
 * PUT /auth/profile/:id
 * Actualiza nombre y teléfono del perfil (el teléfono se cifra en el servidor).
 */
router.put('/profile/:id', async (req, res) => {
  try {
    const { id }          = req.params;
    const { name, phone } = req.body;
    const result = await updateProfile(id, name, phone);
    res.status(result.success ? 200 : 400).json(result);
  } catch (err) {
    console.error('[Auth Route] /profile PUT:', err.message);
    res.status(500).json({ success: false, message: 'Error inesperado al actualizar el perfil.' });
  }
});

module.exports = router;
