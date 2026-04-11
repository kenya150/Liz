import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { SupabaseService } from '../supabaseService/supabaseService';
import { environment } from '../../../environments/environment';
import { SigningService } from '../signingService/signingService';

export interface LoginResult {
  success: boolean;
  message?: string;
  attempts?: number;
  lockedUntil?: number;
}

/**
 * Patrones de inyección retenidos en el front SOLO para UX:
 * dan feedback inmediato al usuario sin esperar la red.
 * La validación real de seguridad ocurre en el backend.
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
    private signing: SigningService
  ) {}

  /**
   * Verificación rápida de inyección en el cliente (solo UX).
   */
  private containsInjection(...inputs: string[]): boolean {
    return inputs.some(input =>
      BLOCKED_PATTERNS.some(pattern => pattern.test(input))
    );
  }

  // ─────────────────────────────────────────────
  // Métodos delegados al backend
  // ─────────────────────────────────────────────

  /**
   * Registra un nuevo usuario enviando los datos al backend.
   * El cifrado del teléfono y la creación del perfil ocurren en el servidor.
   */
  async signup(name: string, email: string, password: string, phone: string): Promise<LoginResult> {
    if (!name || !email || !password || !phone) {
      return { success: false, message: 'Todos los campos son obligatorios.' };
    }
    if (this.containsInjection(name, email, phone)) {
      return { success: false, message: 'Los datos ingresados contienen caracteres no permitidos.' };
    }

    try {
      return await firstValueFrom(
        this.http.post<LoginResult>(`${this.apiUrl}/signup`, { name, email, password, phone })
      );
    } catch (err: any) {
      return err?.error ?? { success: false, message: 'Error al conectar con el servidor.' };
    }
  }

  /**
   * Inicia sesión a través del backend.
   * Al recibir la sesión exitosa, la inyecta en el cliente de Supabase
   * para que isAuthenticated() y getCurrentUser() funcionen correctamente.
   */
  async login(email: string, password: string): Promise<LoginResult> {
    if (!email || !password) {
      return { success: false, message: 'Correo y contraseña son obligatorios.' };
    }
    if (this.containsInjection(email, password)) {
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
      }

      if (result.signature && result.signedPayload) {
        this.signing.storeSignature(result.signature, result.signedPayload);
      }

      return result;
    } catch (err: any) {
      return err?.error ?? { success: false, message: 'Error al conectar con el servidor.' };
    }
  }

  /**
   * Cierra la sesión: primero le avisa al backend para revocar el token
   * en Supabase, luego limpia el estado local del cliente.
   */
  async logout(): Promise<boolean> {
    try {
      const { session } = await this.supabase.getSession();
      const token = session?.access_token;

      if (token) {
        await firstValueFrom(
          this.http.post(`${this.apiUrl}/logout`, {}, {
            headers: { Authorization: `Bearer ${token}` }
          })
        );
      }

      await this.supabase.logout();
      this.signing.clearSignature();
      return true;
    } catch {
      this.signing.clearSignature();
      return false;
    }
  }

  /**
   * Obtiene el perfil del usuario. El teléfono llega ya descifrado desde el backend.
   */
  async getProfile(id: string): Promise<{ success: boolean; data?: any; message?: string }> {
    try {
      return await firstValueFrom(
        this.http.get<any>(`${this.apiUrl}/profile/${id}`)
      );
    } catch (err: any) {
      return err?.error ?? { success: false, message: 'Error al obtener el perfil.' };
    }
  }

  /**
   * Actualiza el perfil. El cifrado del teléfono ocurre en el servidor.
   */
  async updateProfile(id: string, name: string, phone: string): Promise<LoginResult> {
    if (!id || !name || !phone) {
      return { success: false, message: 'Todos los campos son obligatorios para la actualización.' };
    }

    try {
      return await firstValueFrom(
        this.http.put<LoginResult>(`${this.apiUrl}/profile/${id}`, { name, phone })
      );
    } catch (err: any) {
      return err?.error ?? { success: false, message: 'Error al actualizar el perfil.' };
    }
  }

  // ─────────────────────────────────────────────
  // Métodos que permanecen en Angular
  // (son estado local del navegador / guards de rutas)
  // ─────────────────────────────────────────────

  /**
   * Verifica si existe una sesión activa válida.
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
   * Devuelve el usuario autenticado actual desde la sesión local de Supabase.
   * Útil para mostrar datos del usuario en la UI sin hacer una petición extra.
   */
  async getCurrentUser(): Promise<any> {
    const { user } = await this.supabase.getUser();
    return user;
  }
}
