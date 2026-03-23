import { Injectable } from '@angular/core';
import { SupabaseService } from '../supabaseService/supabaseService';
import { SecurityLoggerService, LogLevel } from '../securityLoggerService/securityLoggerService';
import { EncryptionService } from '../encryptionService/encryptionService';

export interface LoginResult {
  success: boolean;
  message?: string;
  attempts?: number;
  lockedUntil?: number; // epoch ms
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  /**
   * Clave para almacenar los intentos fallidos de inicio de sesion en el almacenamiento local.
   */
  private readonly ATTEMPTS_KEY = 'auth_failed_attempts_v1';

  /**
   * Clave para almacenar el log de auditoria de autenticacion en el almacenamiento local.
   */
  private readonly AUDIT_KEY = 'auth_audit_log_v1';

  /**
   * Numero maximo de intentos fallidos permitidos antes de aplicar un bloqueo temporal.
   */
  private readonly MAX_ATTEMPTS = 5;

  /**
   * Tiempo en horas tras el cual se reinicia el nivel de bloqueo si no hay actividad sospechosa.
   */
  private readonly RESET_LOCKEVEL_HOURS = 2;

  /**
   * Patrones de expresiones regulares para detectar posibles ataques de inyeccion (SQL, XSS, etc.).
   */
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

  constructor(
    private supabase: SupabaseService,
    private securityLogger: SecurityLoggerService,
    private encryptionService: EncryptionService
  ) {}

  /**
   * Registra un nuevo usuario en el sistema.
   * Realiza validaciones de seguridad, cifra el telefono y crea el perfil asociado.
   *
   * @param name Nombre completo del usuario.
   * @param email Correo electronico.
   * @param password Contrasena.
   * @param phone Numero de telefono (sera cifrado).
   * @returns Resultado de la operacion de registro.
   */
  async signup(name: string, email: string, password: string, phone: string): Promise<LoginResult> {
    if (!name || !email || !password || !phone) {
      return { success: false, message: 'Todos los campos son obligatorios.' };
    }

    const sanitizedName = name.trim();
    const sanitizedEmail = email.trim();
    const sanitizedPassword = password.trim();
    const sanitizedPhone = phone.trim();

    // Validaciones de longitud y formato
    if (sanitizedName.length < 3 || sanitizedName.length > 100) {
      return { success: false, message: 'El nombre debe tener entre 3 y 100 caracteres.' };
    }
    if (sanitizedPhone.length < 7 || sanitizedPhone.length > 15) {
      return { success: false, message: 'El telefono debe tener entre 7 y 15 digitos.' };
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedEmail)) {
      return { success: false, message: 'El formato del correo electronico no es valido.' };
    }
    if (sanitizedPassword.length < 6) {
      return { success: false, message: 'La contrasena debe tener al menos 6 caracteres.' };
    }

    try {
      // Cifrado preventivo del telefono
      let encryptedPhone: string;
      try {
        encryptedPhone = await this.encryptionService.encrypt(sanitizedPhone);
      } catch (error) {
        return { success: false, message: 'Error de seguridad al procesar la informacion personal.' };
      }

      const resp = await this.supabase.signUpWithAuth(sanitizedEmail, sanitizedPassword);

      if (resp.success && resp.user) {
        const profileResp = await this.supabase.createProfile(resp.user.id, sanitizedName, encryptedPhone);

        if (!profileResp.success) {
          return { success: false, message: 'Usuario creado, pero hubo un problema al generar el perfil.' };
        }

        this.pushAudit({
          email: sanitizedEmail,
          success: true,
          message: 'Registro de usuario exitoso con datos cifrados',
          time: new Date().toISOString()
        });

        this.securityLogger.log(LogLevel.INFO, 'Nuevo usuario registrado con exito', sanitizedEmail);

        // Se cierra la sesion automatica para requerir inicio manual
        await this.supabase.logout();

        return { success: true, message: 'Cuenta creada exitosamente.' };
      } else {
        const errorMsg = resp.error || 'Error en el proceso de registro.';
        this.pushAudit({ email: sanitizedEmail, success: false, message: errorMsg, time: new Date().toISOString() });
        return { success: false, message: errorMsg };
      }
    } catch (error) {
      console.error('[AuthService] Error critico en signup:', error);
      return { success: false, message: 'Ocurrio un error inesperado durante el registro.' };
    }
  }

  /**
   * Intenta iniciar sesion con las credenciales proporcionadas.
   * Incluye proteccion contra inyeccion, control de intentos fallidos y bloqueos temporales.
   */
  async login(email: string, password: string): Promise<LoginResult> {
    const now = Date.now();
    if (!email || !password) {
      return { success: false, message: 'Correo y contrasena son obligatorios.' };
    }

    const sanitizedEmail = email.trim();
    const sanitizedPassword = password.trim();
    const emailNormalized = sanitizedEmail.toLowerCase();

    // Verificacion de patrones maliciosos
    for (const pattern of this.BLOCKED_PATTERNS) {
      if (pattern.test(sanitizedEmail) || pattern.test(sanitizedPassword)) {
        this.securityLogger.log(LogLevel.WARN, 'Intento de inyeccion detectado y bloqueado', sanitizedEmail);
        return { success: false, message: 'Los datos ingresados contienen caracteres no permitidos.' };
      }
    }

    const attemptsStore = this.readAttempts();
    const record = attemptsStore[emailNormalized] || { count: 0 };

    // Validacion de bloqueo temporal activo
    if (record.lockUntil && record.lockUntil > now) {
      return { success: false, message: 'Cuenta temporalmente bloqueada por seguridad.', lockedUntil: record.lockUntil };
    }

    try {
      const resp = await this.supabase.loginWithAuth(emailNormalized, sanitizedPassword);

      if (resp.success && resp.user) {
        delete attemptsStore[emailNormalized];
        this.writeAttempts(attemptsStore);
        this.securityLogger.log(LogLevel.INFO, 'Inicio de sesion exitoso', emailNormalized);
        await this.supabase.getSession();
        return { success: true, message: 'Acceso concedido.' };
      }

      // Manejo de intentos fallidos
      record.count = (record.count || 0) + 1;
      this.securityLogger.log(LogLevel.WARN, `Intento de acceso fallido numero ${record.count}`, emailNormalized);

      if (record.count >= this.MAX_ATTEMPTS) {
        this.applyLock(record, now);
        this.securityLogger.log(LogLevel.CRITICAL, `Cuenta bloqueada tras ${record.count} intentos fallidos`, emailNormalized);
      }

      attemptsStore[emailNormalized] = record;
      this.writeAttempts(attemptsStore);

      return { success: false, message: 'Credenciales invalidas.', attempts: record.count, lockedUntil: record.lockUntil };
    } catch (error) {
      return { success: false, message: 'Error al conectar con el servicio de autenticacion.' };
    }
  }

  /**
   * Cierra la sesion activa del usuario y registra el evento.
   */
  async logout(): Promise<boolean> {
    try {
      const { user } = await this.supabase.getUser();
      const email = user?.email || 'usuario_desconocido';
      const resp = await this.supabase.logout();
      if (resp.success) {
        this.securityLogger.log(LogLevel.INFO, 'Sesion finalizada correctamente', email);
        return true;
      }
      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Verifica si existe una sesion activa valida.
   */
  async isAuthenticated(): Promise<boolean> {
    try {
      const { session } = await this.supabase.getSession();
      if (session) return true;
      const { user } = await this.supabase.getUser();
      return !!user;
    } catch (error) {
      return false;
    }
  }

  /**
   * Obtiene los datos del usuario actualmente autenticado.
   */
  async getCurrentUser(): Promise<any> {
    const { user } = await this.supabase.getUser();
    return user;
  }

  /**
   * Recupera el perfil de un usuario y descifra su numero de telefono.
   *
   * @param id Identificador unico del usuario.
   * @returns Promesa con el resultado de la operacion y los datos del perfil si tiene exito.
   */
  async getProfile(id: string): Promise<{ success: boolean; data?: any; message?: string }> {
    try {
      const resp = await this.supabase.getProfile(id);

      if (resp.success && resp.data) {
        const profile = resp.data;
        if (profile.phone) {
          try {
            profile.phone = await this.encryptionService.decrypt(profile.phone);
          } catch (error) {
            console.warn('[AuthService] No se pudo descifrar el telefono. Es posible que este en texto plano o use otra clave.');
          }
        }
        return { success: true, data: profile };
      } else {
        return { success: false, message: resp.error || 'No se pudo encontrar el perfil solicitado.' };
      }
    } catch (error) {
      console.error('[AuthService] Error al obtener el perfil:', error);
      return { success: false, message: 'Ocurrio un error al procesar la solicitud del perfil.' };
    }
  }

  /**
   * Actualiza la informacion del perfil de un usuario, cifrando el telefono antes de guardarlo.
   *
   * @param id Identificador unico del usuario.
   * @param name Nuevo nombre.
   * @param phone Nuevo numero de telefono.
   * @returns Promesa con el resultado de la operacion.
   */
  async updateProfile(id: string, name: string, phone: string): Promise<LoginResult> {
    if (!id || !name || !phone) {
      return { success: false, message: 'Todos los campos son obligatorios para la actualizacion.' };
    }

    const sanitizedName = name.trim();
    const sanitizedPhone = phone.trim();

    if (sanitizedName.length < 3 || sanitizedName.length > 100) {
      return { success: false, message: 'El nombre debe tener entre 3 y 100 caracteres.' };
    }
    if (sanitizedPhone.length < 7 || sanitizedPhone.length > 15) {
      return { success: false, message: 'El telefono debe tener entre 7 y 15 digitos.' };
    }

    try {
      let encryptedPhone: string;
      try {
        encryptedPhone = await this.encryptionService.encrypt(sanitizedPhone);
      } catch (error) {
        return { success: false, message: 'Error de seguridad al cifrar el nuevo telefono.' };
      }

      const resp = await this.supabase.updateProfile(id, sanitizedName, encryptedPhone);

      if (resp.success) {
        this.securityLogger.log(LogLevel.INFO, 'Perfil actualizado correctamente con datos cifrados', id);
        return { success: true, message: 'Perfil actualizado exitosamente.' };
      } else {
        return { success: false, message: resp.error || 'Error al actualizar el perfil en la base de datos.' };
      }
    } catch (error) {
      console.error('[AuthService] Error critico en updateProfile:', error);
      return { success: false, message: 'Ocurrio un error inesperado durante la actualizacion.' };
    }
  }

  /**
   * Aplica un bloqueo temporal escalonado basado en intentos previos.
   */
  private applyLock(record: any, now: number): void {
    let lockLevel = record.lockLevel || 1;
    const hoursElapsed = (now - (record.lastBlockTime || 0)) / (1000 * 60 * 60);

    if (hoursElapsed > this.RESET_LOCKEVEL_HOURS) {
      lockLevel = 1;
    } else {
      lockLevel++;
    }

    record.lockUntil = now + (lockLevel * 60 * 1000);
    record.lockLevel = lockLevel;
    record.lastBlockTime = now;
  }

  private readAttempts(): any {
    const raw = localStorage.getItem(this.ATTEMPTS_KEY);
    return raw ? JSON.parse(raw) : {};
  }

  private writeAttempts(data: any): void {
    localStorage.setItem(this.ATTEMPTS_KEY, JSON.stringify(data));
  }

  private pushAudit(entry: any): void {
    const raw = localStorage.getItem(this.AUDIT_KEY);
    const arr = raw ? JSON.parse(raw) : [];
    arr.push(entry);
    localStorage.setItem(this.AUDIT_KEY, JSON.stringify(arr.slice(-200)));
  }
}
