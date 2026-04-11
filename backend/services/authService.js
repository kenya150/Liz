const { createClient } = require('@supabase/supabase-js');
const { encrypt, decrypt } = require('./encryptionService');
const { signUserData } = require('./signingService');

/**
 * Cliente de Supabase con service role key para operaciones de admin.
 * IMPORTANTE: esta clave NUNCA debe exponerse al frontend.
 */
const supabase = require('./supabaseClient');

/**
 * Store en memoria para el control de intentos fallidos.
 *
 * NOTA: Esto funciona correctamente en un servidor de una sola instancia.
 * Si en el futuro escalas a múltiples instancias (clustering, contenedores),
 * reemplaza este Map con Redis o una tabla en BD para que el estado sea compartido.
 *
 * Estructura por email:
 * {
 *   count: number,         — intentos fallidos desde el último éxito
 *   lockUntil: number,     — timestamp epoch ms hasta el que está bloqueado
 *   lockLevel: number,     — nivel de bloqueo escalonado (1, 2, 3...)
 *   lastBlockTime: number  — cuándo ocurrió el último bloqueo
 * }
 */
const attemptStore = new Map();

const MAX_ATTEMPTS = 5;
const RESET_LOCKLEVEL_HOURS = 2;

/**
 * Patrones para detectar posibles inyecciones SQL y XSS.
 * Esta validación ocurre en el servidor, donde sí tiene valor de seguridad real.
 */
const BLOCKED_PATTERNS = [
  /[<>"'`;\\]/,
  /--/,
  /\/\*/,
  /xp_/i, /sp_/i, /union/i, /select/i, /insert/i,
  /delete/i, /drop/i, /create/i, /alter/i, /exec/i,
  /script/i, /onclick/i, /onerror/i,
];

/**
 * Verifica si alguno de los strings de entrada contiene patrones de inyección.
 */
function containsInjection(...inputs) {
  return inputs.some(input =>
    BLOCKED_PATTERNS.some(pattern => pattern.test(String(input)))
  );
}

/**
 * Aplica un bloqueo temporal escalonado al record de intentos de un email.
 * El tiempo de bloqueo se multiplica con cada lockLevel consecutivo
 * si los bloqueos ocurren dentro de RESET_LOCKLEVEL_HOURS horas entre sí.
 */
function applyLock(record, now) {
  let lockLevel = record.lockLevel || 1;
  const hoursElapsed = (now - (record.lastBlockTime || 0)) / (1000 * 60 * 60);

  if (hoursElapsed > RESET_LOCKLEVEL_HOURS) {
    lockLevel = 1;
  } else {
    lockLevel++;
  }

  record.lockUntil = now + (lockLevel * 60 * 1000);
  record.lockLevel = lockLevel;
  record.lastBlockTime = now;
  record.count = 0;
}

/**
 * Registra un evento de auditoría en la tabla audit_logs de Supabase.
 * Si falla, solo loguea en consola: el error de auditoría no debe
 * interrumpir el flujo principal de la operación.
 *
 * Asegúrate de tener esta tabla en Supabase:
 * CREATE TABLE audit_logs (
 *   id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
 *   email text,
 *   user_id text,
 *   action text NOT NULL,
 *   success boolean NOT NULL,
 *   metadata jsonb,
 *   time timestamptz DEFAULT now()
 * );
 */
async function logAudit(entry) {
  try {
    await supabase.from('audit_logs').insert({
      email: entry.email || null,
      user_id: entry.userId || null,
      action: entry.action,
      success: entry.success,
      metadata: entry.metadata || null,
      time: new Date().toISOString(),
    });
  } catch (err) {
    console.error('[AuthService] No se pudo registrar en audit_logs:', err?.message);
  }
}

/**
 * Registra un nuevo usuario en el sistema.
 * Valida los datos, detecta inyecciones, cifra el teléfono
 * y crea el perfil en Supabase.
 */
async function signup(name, email, password, phone) {
  if (!name || !email || !password || !phone) {
    return { success: false, message: 'Todos los campos son obligatorios.' };
  }

  const sanitizedName     = name.trim();
  const sanitizedEmail    = email.trim().toLowerCase();
  const sanitizedPassword = password.trim();
  const sanitizedPhone    = phone.trim();

  if (sanitizedName.length < 3 || sanitizedName.length > 100) {
    return { success: false, message: 'El nombre debe tener entre 3 y 100 caracteres.' };
  }
  if (sanitizedPhone.length < 7 || sanitizedPhone.length > 15) {
    return { success: false, message: 'El teléfono debe tener entre 7 y 15 dígitos.' };
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedEmail)) {
    return { success: false, message: 'El formato del correo electrónico no es válido.' };
  }
  if (sanitizedPassword.length < 6) {
    return { success: false, message: 'La contraseña debe tener al menos 6 caracteres.' };
  }
  if (containsInjection(sanitizedName, sanitizedEmail, sanitizedPhone)) {
    await logAudit({ email: sanitizedEmail, action: 'signup_injection_attempt', success: false });
    return { success: false, message: 'Los datos ingresados contienen caracteres no permitidos.' };
  }

  let encryptedPhone;
  try {
    encryptedPhone = encrypt(sanitizedPhone);
  } catch {
    return { success: false, message: 'Error de seguridad al procesar la información personal.' };
  }

  const { data, error } = await supabase.auth.signUp({
    email: sanitizedEmail,
    password: sanitizedPassword,
  });

  if (error || !data.user) {
    await logAudit({ email: sanitizedEmail, action: 'signup_failed', success: false });
    return { success: false, message: error?.message || 'Error en el proceso de registro.' };
  }

  const { error: profileError } = await supabase
    .from('profiles')
    .insert({ id: data.user.id, name: sanitizedName, phone: encryptedPhone });

  if (profileError) {
    return { success: false, message: 'Usuario creado, pero hubo un problema al generar el perfil.' };
  }

  await logAudit({ email: sanitizedEmail, action: 'signup', success: true });

  return { success: true, message: 'Cuenta creada exitosamente.' };
}

/**
 * Autentica a un usuario.
 * Incluye detección de inyecciones, control de intentos fallidos
 * y bloqueos temporales escalonados, todo en memoria del servidor.
 */
async function login(email, password) {
  if (!email || !password) {
    return { success: false, message: 'Correo y contraseña son obligatorios.' };
  }

  const sanitizedEmail    = email.trim().toLowerCase();
  const sanitizedPassword = password.trim();

  if (containsInjection(sanitizedEmail, sanitizedPassword)) {
    await logAudit({ email: sanitizedEmail, action: 'login_injection_attempt', success: false });
    return { success: false, message: 'Los datos ingresados contienen caracteres no permitidos.' };
  }

  const now    = Date.now();
  const record = attemptStore.get(sanitizedEmail) || { count: 0 };

  // Verificar si el email tiene un bloqueo activo
  if (record.lockUntil && record.lockUntil > now) {
    return {
      success: false,
      message: 'Cuenta temporalmente bloqueada por seguridad.',
      lockedUntil: record.lockUntil,
    };
  }

  const { data, error } = await supabase.auth.signInWithPassword({
    email: sanitizedEmail,
    password: sanitizedPassword,
  });

  if (error || !data.user) {
    record.count = (record.count || 0) + 1;

    if (record.count >= MAX_ATTEMPTS) {
      applyLock(record, now);
      await logAudit({
        email: sanitizedEmail,
        action: 'login_blocked',
        success: false,
        metadata: { lockLevel: record.lockLevel, lockUntil: record.lockUntil },
      });
    } else {
      await logAudit({ email: sanitizedEmail, action: 'login_failed', success: false, metadata: { attempt: record.count } });
    }

    attemptStore.set(sanitizedEmail, record);

    return {
      success: false,
      message: 'Credenciales inválidas.',
      attempts: record.count,
      lockedUntil: record.lockUntil,
    };
  }

  // Login exitoso: limpiar el historial de intentos del email
  attemptStore.delete(sanitizedEmail);
  await logAudit({ email: sanitizedEmail, action: 'login', success: true });

  const signature = signUserData(
    data.user.id,
    data.user.email,
    data.user.role  // Supabase devuelve 'authenticated'
  );

  return {
    success: true,
    message: 'Acceso concedido.',
    session: data.session,
    user: data.user,
    signature,                           // firma digital
    signedPayload: {                     // datos que fueron firmados
      id:    data.user.id,
      email: data.user.email,
      role:  data.user.role
    }
  };
}

/**
 * Cierra la sesión de un usuario invalidando su token en Supabase.
 * Recibe el access token del header Authorization para identificar al usuario.
 */
async function logout(accessToken) {
  try {
    // Obtiene el usuario a partir del token para registrar en auditoría
    const { data: { user } } = await supabase.auth.getUser(accessToken);

    // Revoca todos los tokens activos del usuario usando el cliente admin
    if (user?.id) {
      await supabase.auth.admin.signOut(user.id, 'global');
      await logAudit({ email: user.email, userId: user.id, action: 'logout', success: true });
    }

    return { success: true };
  } catch (err) {
    console.error('[AuthService] Error al cerrar sesión:', err?.message);
    return { success: false };
  }
}

/**
 * Obtiene el perfil de un usuario y descifra su número de teléfono.
 */
async function getProfile(id) {
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', id)
    .single();

  if (error || !data) {
    return { success: false, message: 'No se pudo encontrar el perfil solicitado.' };
  }

  if (data.phone) {
    try {
      data.phone = decrypt(data.phone);
    } catch {
      console.warn('[AuthService] No se pudo descifrar el teléfono. Puede estar en texto plano o usar otra clave.');
    }
  }

  return { success: true, data };
}

/**
 * Actualiza el nombre y teléfono de un perfil, cifrando el teléfono antes de guardarlo.
 */
async function updateProfile(id, name, phone) {
  if (!id || !name || !phone) {
    return { success: false, message: 'Todos los campos son obligatorios para la actualización.' };
  }

  const sanitizedName  = name.trim();
  const sanitizedPhone = phone.trim();

  if (sanitizedName.length < 3 || sanitizedName.length > 100) {
    return { success: false, message: 'El nombre debe tener entre 3 y 100 caracteres.' };
  }
  if (sanitizedPhone.length < 7 || sanitizedPhone.length > 15) {
    return { success: false, message: 'El teléfono debe tener entre 7 y 15 dígitos.' };
  }

  let encryptedPhone;
  try {
    encryptedPhone = encrypt(sanitizedPhone);
  } catch {
    return { success: false, message: 'Error de seguridad al cifrar el nuevo teléfono.' };
  }

  const { error } = await supabase
    .from('profiles')
    .update({ name: sanitizedName, phone: encryptedPhone })
    .eq('id', id);

  if (error) {
    return { success: false, message: error.message || 'Error al actualizar el perfil en la base de datos.' };
  }

  await logAudit({ userId: id, action: 'update_profile', success: true });

  return { success: true, message: 'Perfil actualizado exitosamente.' };
}

module.exports = { signup, login, logout, getProfile, updateProfile };
