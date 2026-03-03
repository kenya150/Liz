// auth.service.ts
import { Injectable } from '@angular/core';
import { SupabaseService } from '../supabaseService/supabaseService';

export interface LoginResult {
  success: boolean;
  message?: string;
  attempts?: number;
  lockedUntil?: number; // epoch ms
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  constructor(private supabase: SupabaseService) {}

  // Método para registrar un nuevo usuario
  async signup(email: string, password: string, nombre: string): Promise<LoginResult> {
    console.log('[AuthService] signup iniciado');

    if (!email || !password || !nombre) {
      return { success: false, message: 'Nombre, correo y contraseña son requeridos' };
    }

    // Validaciones de seguridad
    const sanitizedEmail = (email || '').trim();
    const sanitizedPassword = (password || '').trim();
    const sanitizedNombre = (nombre || '').trim();
    
    if (sanitizedNombre.length < 3 || sanitizedNombre.length > 100) {
      return { success: false, message: 'El nombre debe tener entre 3 y 100 caracteres' };
    }
    
    if (sanitizedEmail.length < 3 || sanitizedEmail.length > 254) {
      return { success: false, message: 'Correo inválido' };
    }
    
    if (sanitizedPassword.length < 6 || sanitizedPassword.length > 500) {
      return { success: false, message: 'La contraseña debe tener al menos 6 caracteres' };
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedEmail)) {
      return { success: false, message: 'Formato de correo inválido' };
    }

    console.log('[AuthService] Iniciando signup en Supabase Auth', { email: sanitizedEmail });
    
    try {
      // 1. Registrar en Supabase Auth
      const resp = await this.supabase.signUpWithAuth(sanitizedEmail, sanitizedPassword);
      console.log('[AuthService] Respuesta de signup:', { success: resp.success });
      
      if (resp.success && resp.user) {
        // 2. Guardar perfil en tabla usuarios
        console.log('[AuthService] Guardando perfil de usuario en BD');
        const profileResp = await this.supabase.createUserProfile(
          resp.user.id,
          sanitizedEmail,
          sanitizedNombre
        );

        if (profileResp.success) {
          console.log('[AuthService] ✓ Signup y perfil exitoso');
          this.pushAudit({ email: sanitizedEmail, success: true, message: 'Usuario registrado correctamente', time: new Date().toISOString() });
          return { success: true, message: 'Cuenta creada correctamente' };
        } else {
          // Si Auth pasó pero la tabla falló, informar al usuario
          console.log('[AuthService] ✗ Perfil fallido:', profileResp.error);
          this.pushAudit({ email: sanitizedEmail, success: false, message: `Error al guardar perfil: ${profileResp.error}`, time: new Date().toISOString() });
          return { success: false, message: `Error al guardar datos: ${profileResp.error}` };
        }
      } else {
        const errorMsg = resp.error || 'Error desconocido en registro';
        console.log('[AuthService] ✗ Signup fallido:', errorMsg);
        this.pushAudit({ email: sanitizedEmail, success: false, message: `Signup fallido: ${errorMsg}`, time: new Date().toISOString() });
        return { success: false, message: errorMsg };
      }
    } catch (e) {
      console.error('[AuthService] Error en signup', e);
      return { success: false, message: `Error al registrar: ${String(e)}` };
    }
  }

  // Persistimos intentos y bloqueos en localStorage para simular un backend
  private readonly ATTEMPTS_KEY = 'auth_failed_attempts_v1';
  private readonly AUDIT_KEY = 'auth_audit_log_v1';
  private readonly MAX_ATTEMPTS = 3; // 3 intentos fallidos antes de bloquear
  private readonly RESET_LOCKEVEL_HOURS = 2; // resetear lockLevel después de 2 horas sin actividad maligna
  
  // Validación contra inyecciones
  private readonly BLOCKED_PATTERNS = [
    /[<>"'`;\\]/,           // caracteres HTML/SQL
    /--/,                   // SQL comments
    /\/\*/,                 // C-style comments
    /xp_/i,                 // SQL stored procedures
    /sp_/i,                 // SQL stored procedures
    /union/i,               // SQL union
    /select/i,              // SQL select
    /insert/i,              // SQL insert
    /delete/i,              // SQL delete
    /drop/i,                // SQL drop
    /create/i,              // SQL create
    /alter/i,               // SQL alter
    /exec/i,                // SQL exec
    /script/i,              // XSS script
    /onclick/i,             // XSS onclick
    /onerror/i,             // XSS onerror
  ];

  private readAttempts(): { [email: string]: { count: number; lockUntil?: number; lockLevel?: number; lastBlockTime?: number } } {
    try {
      const raw = localStorage.getItem(this.ATTEMPTS_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch (e) {
      return {};
    }
  }

  private writeAttempts(data: { [email: string]: { count: number; lockUntil?: number; lockLevel?: number; lastBlockTime?: number } }) {
    localStorage.setItem(this.ATTEMPTS_KEY, JSON.stringify(data));
  }

  private pushAudit(entry: { email: string; success: boolean; message: string; time: string }) {
    try {
      const raw = localStorage.getItem(this.AUDIT_KEY);
      const arr = raw ? JSON.parse(raw) : [];
      arr.push(entry);
      // mantener las últimas 200 entradas para evitar crecimiento indefinido
      const trimmed = arr.slice(-200);
      localStorage.setItem(this.AUDIT_KEY, JSON.stringify(trimmed));
    } catch (e) {
      // ignorar errores de auditoría en cliente
    }
  }

  // Intento de login; devuelve resultado detallado incluyendo información de bloqueo
  async login(email: string, password: string): Promise<LoginResult> {
    const now = Date.now();
    
    console.log('[AuthService] Intento de login iniciado');

    if (!email || !password) {
      return { success: false, message: 'Correo y contraseña son requeridos' };
    }

    // Validaciones de seguridad contra inyecciones
    const sanitizedEmail = (email || '').trim();
    const sanitizedPassword = (password || '').trim();
    
    // Validar longitud
    if (sanitizedEmail.length < 3 || sanitizedEmail.length > 254) {
      console.warn('[AuthService] Email con longitud inválida');
      this.pushAudit({ email: sanitizedEmail, success: false, message: 'Email inválido', time: new Date().toISOString() });
      return { success: false, message: 'Correo inválido' };
    }
    
    if (sanitizedPassword.length < 1 || sanitizedPassword.length > 500) {
      console.warn('[AuthService] Password con longitud inválida');
      this.pushAudit({ email: sanitizedEmail, success: false, message: 'Contraseña inválida', time: new Date().toISOString() });
      return { success: false, message: 'Contraseña inválida' };
    }
    
    // Validar contra patrones de inyección
    for (const pattern of this.BLOCKED_PATTERNS) {
      if (pattern.test(sanitizedEmail) || pattern.test(sanitizedPassword)) {
        console.warn('[AuthService] Intento de inyección detectado', { email: sanitizedEmail });
        this.pushAudit({ email: sanitizedEmail, success: false, message: 'Intento de inyección bloqueado', time: new Date().toISOString() });
        return { success: false, message: 'Entrada inválida detectada' };
      }
    }
    
    // Validar formato de email básico
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedEmail)) {
      console.warn('[AuthService] Formato de email inválido');
      return { success: false, message: 'Formato de correo inválido' };
    }

    // Normalizar email a lowercase para consistencia
    const emailNormalized = sanitizedEmail.toLowerCase();
    const passwordNormalized = sanitizedPassword;

    const attemptsStore = this.readAttempts();
    const record = attemptsStore[emailNormalized] || { count: 0 };

    // Si estaba bloqueado pero el bloqueo ya expiró, resetear contador para el nuevo ciclo
    if (record.lockUntil && record.lockUntil <= now) {
      record.count = 0; // Resetear intentos fallidos para nuevo ciclo
      record.lockUntil = undefined;
    }

    if (record.lockUntil && record.lockUntil > now) {
      const msg = 'Cuenta temporalmente bloqueada';
      console.log(`[${new Date().toISOString()}] ${msg}: ${emailNormalized}`);
      this.pushAudit({ email: emailNormalized, success: false, message: msg, time: new Date().toISOString() });
      return { success: false, message: msg, attempts: record.count, lockedUntil: record.lockUntil };
    }

    console.log('[AuthService] Iniciando verificación de credenciales con Supabase Auth', { emailNormalized });
    
    // Usar Supabase Auth para validar credenciales
    let credsMatch = false;
    let apiErrorMsg = '';
    let user: any = null;
    try {
      const resp = await this.supabase.loginWithAuth(emailNormalized, passwordNormalized);
      console.log('[AuthService] Respuesta de Supabase Auth:', { success: resp.success, hasUser: !!resp.user });
      if (resp && resp.success && resp.user) {
        credsMatch = true;
        user = resp.user;
      } else {
        credsMatch = false;
        apiErrorMsg = resp && resp.error ? String(resp.error) : 'Error desconocido';
      }
    } catch (e) {
      console.error('[AuthService] Error al verificar credenciales con Auth', e);
      apiErrorMsg = `Error al verificar credenciales: ${String(e)}`;
      credsMatch = false;
    }
    console.log('[AuthService] Resultado verificación:', { credsMatch, apiErrorMsg });

    if (credsMatch) {
      // reiniciar contador de intentos y desbloquear al hacer login exitoso
      delete attemptsStore[emailNormalized];
      this.writeAttempts(attemptsStore);
      console.log(`[${new Date().toISOString()}] Login exitoso: ${emailNormalized}`);
      this.pushAudit({ email: emailNormalized, success: true, message: 'Acceso concedido', time: new Date().toISOString() });
      return { success: true, message: 'Acceso concedido', attempts: 0 };
    }

    // En caso de fallo: incrementar contador y posiblemente aplicar bloqueo
    record.count = (record.count || 0) + 1;

    // Al alcanzar MAX_ATTEMPTS (3), aplicar bloqueo escalonado
    if (record.count >= this.MAX_ATTEMPTS) {
      // Determinar el nivel de bloqueo basado en intentos previos bloqueados
      let lockLevel = record.lockLevel || 1;
      const lastBlockTime = record.lastBlockTime || 0;
      const hoursElapsed = (now - lastBlockTime) / (1000 * 60 * 60);
      
      // Si pasaron más de RESET_LOCKLEVEL_HOURS desde el último bloqueo, resetear a nivel 1
      if (hoursElapsed > this.RESET_LOCKEVEL_HOURS) {
        lockLevel = 1;
      } else if (lastBlockTime > 0 && hoursElapsed < this.RESET_LOCKEVEL_HOURS) {
        // Si ya fue bloqueado antes recientemente, incrementar el nivel
        lockLevel = (lockLevel || 1) + 1;
      }
      
      const minutosBloqueo = lockLevel;
      record.lockUntil = now + minutosBloqueo * 60 * 1000;
      record.lockLevel = lockLevel;
      record.lastBlockTime = now;
      
      console.log(`[${new Date().toISOString()}] Bloqueo aplicado a ${emailNormalized} por ${minutosBloqueo} minuto(s) (nivel ${lockLevel})`);
    }

    attemptsStore[emailNormalized] = record;
    this.writeAttempts(attemptsStore);

    // Mapear mensaje de error a español para la UI y auditoría
    const apiLower = (apiErrorMsg || '').toLowerCase();
    let userMsg = 'Credenciales incorrectas';
    if (apiLower.includes('invalid') || apiLower.includes('credentials') || apiLower.includes('wrong')) {
      userMsg = 'Correo o contraseña incorrectos';
    } else if (apiLower.includes('user') && apiLower.includes('not')) {
      userMsg = 'Usuario no encontrado';
    } else if (apiLower.includes('blocked') || apiLower.includes('too many') || apiLower.includes('rate')) {
      userMsg = 'Cuenta temporalmente bloqueada';
    } else if (apiLower === 'error_interno') {
      userMsg = 'Error interno de autenticación';
    }

    console.log(`[${new Date().toISOString()}] Login fallido: ${emailNormalized}, intentos: ${record.count} - ${apiErrorMsg}`);
    this.pushAudit({ email: emailNormalized, success: false, message: userMsg, time: new Date().toISOString() });
    return { success: false, message: userMsg, attempts: record.count, lockedUntil: record.lockUntil };
  }
}
