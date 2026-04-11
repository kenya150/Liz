import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { SupabaseService } from '../supabaseService/supabaseService';
import { environment } from '../../../environments/environment';
import { SigningService } from '../signingService/signingService';
import { SecurityLoggerService, LogLevel } from '../securityLoggerService/securityLoggerService';

export interface LoginResult {
  success: boolean;
  message?: string;
  attempts?: number;
  lockedUntil?: number;
}

/**
 * Patrones de inyeccion retenidos en el front SOLO para UX:
 * dan feedback inmediato al usuario sin esperar la red.
 * La validacion real de seguridad ocurre en el backend.
 */
const BLOCKED_PATTERNS: RegExp[] = [
  /[<>"'`;\\]/,
  /--/, /\/\*/,
  /xp_/i, /sp_/i, /union/i, /select/i, /insert/i,
  /delete/i, /drop/i, /create/i, /alter/i, /exec/i,
  /script/i, /onclick/i, /onerror/i,
];

@Injectable({ providedIn: 'root' })
export class AuthService {
  /**
   * URL base del backend. Configura environment.apiUrl en cada entorno.
   * Ejemplo: environment.apiUrl = 'https://localhost:3000'
   */
  private readonly apiUrl = `${environment.apiUrl}/auth`;

  constructor(
    private http: HttpClient,
    private supabase: SupabaseService,
    private signing: SigningService,
    private securityLogger: SecurityLoggerService
  ) {}

  /**
   * Verificacion rapida de inyeccion en el cliente (solo UX).
   */
  private containsInjection(...inputs: string[]): boolean {
    return inputs.some(input =>
      BLOCKED_PATTERNS.some(pattern => pattern.test(input))
    );
  }

  // ─────────────────────────────────────────────
  // Metodos delegados al backend
  // ─────────────────────────────────────────────

  /**
   * Registra un nuevo usuario enviando los datos al backend.
   * El cifrado del telefono y la creacion del perfil ocurren en el servidor.
   */
  async signup(name: string, email: string, password: string, phone: string): Promise<LoginResult> {
    if (!name || !email || !password || !phone) {
      return { success: false, message: 'Todos los campos son obligatorios.' };
    }
    if (this.containsInjection(name, email, phone)) {
      // Intento de inyeccion detectado en el formulario de registro
      this.securityLogger.log(LogLevel.CRITICAL, 'Intento de inyeccion detectado en signup', email);
      return { success: false, message: 'Los datos ingresados contienen caracteres no permitidos.' };
    }

    try {
      const result = await firstValueFrom(
        this.http.post<LoginResult>(`${this.apiUrl}/signup`, { name, email, password, phone })
      );

      if (result.success) {
        // Nuevo usuario registrado correctamente
        this.securityLogger.log(LogLevel.INFO, 'Registro de usuario exitoso', email);
      } else {
        // El backend rechazo el registro por algun motivo
        this.securityLogger.log(LogLevel.WARN, `Fallo en registro: ${result.message}`, email);
      }

      return result;
    } catch (err: any) {
      return err?.error ?? { success: false, message: 'Error al conectar con el servidor.' };
    }
  }

  /**
   * Inicia sesion a traves del backend.
   * Al recibir la sesion exitosa, la inyecta en el cliente de Supabase
   * para que isAuthenticated() y getCurrentUser() funcionen correctamente.
   */
  async login(email: string, password: string): Promise<LoginResult> {
    if (!email || !password) {
      return { success: false, message: 'Correo y contrasena son obligatorios.' };
    }
    if (this.containsInjection(email, password)) {
      // Intento de inyeccion detectado en el formulario de login
      this.securityLogger.log(LogLevel.CRITICAL, 'Intento de inyeccion detectado en login', email);
      return { success: false, message: 'Los datos ingresados contienen caracteres no permitidos.' };
    }

    try {
      const result = await firstValueFrom(
        this.http.post<any>(`${this.apiUrl}/login`, { email, password })
      );

      if (result.success && result.session) {
        await this.supabase.setSession(
          result.session.access_token,
          result.session.refresh_token
        );

        if (result.signature && result.signedPayload) {
          this.signing.storeSignature(result.signature, result.signedPayload);
        }

        // Usuario autenticado correctamente
        this.securityLogger.log(LogLevel.INFO, 'Inicio de sesion exitoso', email);

      } else {

        if (result.lockedUntil) {
          // Cuenta bloqueada tras multiples intentos fallidos consecutivos
          this.securityLogger.log(
            LogLevel.CRITICAL,
            `Cuenta bloqueada hasta ${new Date(result.lockedUntil).toISOString()}`,
            email
          );
        } else {
          // Fallo en credenciales, se registra el numero de intento
          this.securityLogger.log(
            LogLevel.WARN,
            `Credenciales invalidas. Intento numero: ${result.attempts ?? 1}`,
            email
          );
        }
      }

      return result;
    } catch (err: any) {
      return err?.error ?? { success: false, message: 'Error al conectar con el servidor.' };
    }
  }

  /**
   * Cierra la sesion: primero le avisa al backend para revocar el token
   * en Supabase, luego limpia el estado local del cliente.
   */
  async logout(): Promise<boolean> {
    try {
      const { session } = await this.supabase.getSession();
      const token = session?.access_token;

      // Se obtiene el email del usuario antes de cerrar la sesion para el log
      const user = await this.getCurrentUser();
      const identifier = user?.email || 'usuario_desconocido';

      if (token) {
        await firstValueFrom(
          this.http.post(`${this.apiUrl}/logout`, {}, {
            headers: { Authorization: `Bearer ${token}` }
          })
        );
      }

      await this.supabase.logout();
      this.signing.clearSignature();

      // Sesion cerrada correctamente
      this.securityLogger.log(LogLevel.INFO, 'Sesion cerrada correctamente', identifier);

      return true;
    } catch {
      this.signing.clearSignature();
      return false;
    }
  }

  /**
   * Obtiene el perfil del usuario. El telefono llega ya descifrado desde el backend.
   */
  async getProfile(id: string): Promise<{ success: boolean; data?: any; message?: string }> {
    try {
      const result = await firstValueFrom(
        this.http.get<any>(`${this.apiUrl}/profile/${id}`)
      );

      if (result.success) {
        // Consulta de perfil realizada correctamente
        this.securityLogger.log(LogLevel.INFO, 'Perfil de usuario consultado', id);
      }

      return result;
    } catch (err: any) {
      return err?.error ?? { success: false, message: 'Error al obtener el perfil.' };
    }
  }

  /**
   * Actualiza el perfil. El cifrado del telefono ocurre en el servidor.
   */
  async updateProfile(id: string, name: string, phone: string): Promise<LoginResult> {
    if (!id || !name || !phone) {
      return { success: false, message: 'Todos los campos son obligatorios para la actualizacion.' };
    }

    try {
      const result = await firstValueFrom(
        this.http.put<LoginResult>(`${this.apiUrl}/profile/${id}`, { name, phone })
      );

      if (result.success) {
        // Perfil actualizado correctamente con datos cifrados en el servidor
        this.securityLogger.log(LogLevel.INFO, 'Perfil actualizado correctamente', id);
      } else {
        // El backend rechazo la actualizacion del perfil
        this.securityLogger.log(LogLevel.WARN, `Fallo al actualizar perfil: ${result.message}`, id);
      }

      return result;
    } catch (err: any) {
      return err?.error ?? { success: false, message: 'Error al actualizar el perfil.' };
    }
  }

  // ─────────────────────────────────────────────
  // Metodos que permanecen en Angular
  // (son estado local del navegador / guards de rutas)
  // ─────────────────────────────────────────────

  /**
   * Verifica si existe una sesion activa valida.
   * Lo usan los AuthGuards de Angular para proteger rutas.
   */
  async isAuthenticated(): Promise<boolean> {
    try {
      const { session } = await this.supabase.getSession();
      if (session) return true;
      const { user } = await this.supabase.getUser();
      return !!user;
    } catch {
      return false;
    }
  }

  /**
   * Devuelve el usuario autenticado actual desde la sesion local de Supabase.
   * Util para mostrar datos del usuario en la UI sin hacer una peticion extra.
   */
  async getCurrentUser(): Promise<any> {
    const { user } = await this.supabase.getUser();
    return user;
  }
}
