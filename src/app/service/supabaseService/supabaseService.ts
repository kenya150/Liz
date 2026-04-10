import { Injectable } from '@angular/core';
import { createClient, SupabaseClient, AuthError } from '@supabase/supabase-js';

@Injectable({
  providedIn: 'root'
})
export class SupabaseService {
  /**
   * Cliente de Supabase para interactuar con la base de datos y autenticacion.
   */
  private client: SupabaseClient | null = null;

  constructor() {
    const win = window as any;
    if (win && win.SUPABASE_URL && win.SUPABASE_ANON_KEY) {
      this.init(win.SUPABASE_URL, win.SUPABASE_ANON_KEY);
    }
  }

  /**
   * Inicializa el cliente de Supabase con la URL y clave anonima proporcionadas.
   * Configura la persistencia de sesion y un manejador de bloqueos personalizado para entornos web.
   */
  init(url: string, anonKey: string) {
    if (!url || !anonKey) throw new Error('La URL y la clave anonima de Supabase son obligatorias.');

    this.client = createClient(url, anonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
        // Manejador de bloqueo personalizado para evitar errores de Navigator Lock en navegadores
        lock: async (name: string, acquireTimeout: number, callback: () => Promise<any>) => {
          try {
            return await callback();
          } catch (error) {
            console.warn(`[SupabaseService] Error en operacion bloqueada '${name}':`, error);
            throw error;
          }
        }
      }
    });
  }

  /**
   * Asegura que el cliente este inicializado antes de realizar operaciones.
   */
  private ensureClient(): SupabaseClient {
    if (!this.client) {
      throw new Error('El cliente de Supabase no ha sido inicializado correctamente.');
    }
    return this.client;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Gestión de sesión — permanecen en Angular
  // Estas operaciones son estado local del navegador y las usan los guards,
  // interceptors HTTP y componentes de UI.
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Inyecta una sesion recibida del backend en el cliente local de Supabase.
   * Llamado por AuthService.login() tras recibir la sesion del servidor,
   * para que getSession(), getUser() e isAuthenticated() funcionen correctamente.
   */
  async setSession(accessToken: string, refreshToken: string): Promise<void> {
    const client = this.ensureClient();
    const { error } = await client.auth.setSession({
      access_token: accessToken,
      refresh_token: refreshToken
    });
    if (error) {
      throw new Error(`[SupabaseService] Error al establecer la sesion: ${error.message}`);
    }
  }

  /**
   * Obtiene la sesion activa actual.
   */
  public async getSession(): Promise<{ session: any; error?: string }> {
    try {
      const client = this.ensureClient();
      const { data, error } = await client.auth.getSession();
      if (error) return { session: null, error: error.message };
      return { session: data.session };
    } catch (error) {
      return { session: null, error: String(error) };
    }
  }

  /**
   * Obtiene la informacion del usuario autenticado desde la sesion local.
   */
  public async getUser(): Promise<{ user: any; error?: string }> {
    try {
      const client = this.ensureClient();
      const { data, error } = await client.auth.getUser();
      if (error) return { user: null, error: error.message };
      return { user: data.user };
    } catch (error) {
      return { user: null, error: String(error) };
    }
  }

  /**
   * Finaliza la sesion activa del usuario en el cliente local.
   * AuthService.logout() llama a este metodo despues de notificar al backend.
   */
  async logout(): Promise<{ success: boolean; error?: string }> {
    try {
      const client = this.ensureClient();
      const { error } = await client.auth.signOut();
      if (error) return { success: false, error: error.message };
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Métodos delegados al backend (Node.js)
  // Se conservan por compatibilidad con otras partes de la app que pudieran
  // usarlos directamente, pero el AuthService ya no los invoca — toda esa
  // lógica ahora pasa por los endpoints /api/auth del servidor.
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * @deprecated Usar POST /api/auth/signup desde AuthService.
   * El backend maneja el registro, el cifrado del telefono y la creacion del perfil.
   */
  async signUpWithAuth(email: string, password: string): Promise<{
    success: boolean;
    user?: any;
    error?: string;
  }> {
    try {
      const client = this.ensureClient();
      const { data, error } = await client.auth.signUp({
        email: email.trim(),
        password: password.trim(),
      });

      if (error) return { success: false, error: this.mapAuthError(error) };
      if (data.user) return { success: true, user: data.user };

      return { success: false, error: 'Error inesperado durante el registro de la cuenta.' };
    } catch (error) {
      return { success: false, error: 'Fallo al conectar con el servicio de registro.' };
    }
  }

  /**
   * @deprecated Usar POST /api/auth/login desde AuthService.
   * El backend maneja la autenticacion, el control de intentos y los bloqueos.
   */
  async loginWithAuth(email: string, password: string): Promise<{
    success: boolean;
    user?: any;
    session?: any;
    error?: string;
  }> {
    try {
      const client = this.ensureClient();
      const { data, error } = await client.auth.signInWithPassword({
        email: email.trim(),
        password: password.trim()
      });

      if (error) return { success: false, error: this.mapAuthError(error) };
      if (data.user && data.session) return { success: true, user: data.user, session: data.session };

      return { success: false, error: 'No se pudo establecer la sesion de usuario.' };
    } catch (error) {
      return { success: false, error: 'Error de conexion con el servidor de autenticacion.' };
    }
  }

  /**
   * @deprecated Usar GET /api/auth/profile/:id desde AuthService.
   * El backend descifra el telefono antes de devolver el perfil.
   */
  public async getProfile(id: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const client = this.ensureClient();
      const { data, error } = await client
        .from('profiles')
        .select('*')
        .eq('id', id)
        .single();

      if (error) return { success: false, error: error.message };
      return { success: true, data };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  /**
   * @deprecated Usar PUT /api/auth/profile/:id desde AuthService.
   * El backend cifra el telefono antes de guardarlo.
   */
  public async updateProfile(id: string, name: string, phone: string): Promise<{ success: boolean; error?: string }> {
    try {
      const client = this.ensureClient();
      const { error } = await client
        .from('profiles')
        .update({ name, phone })
        .eq('id', id);

      if (error) return { success: false, error: error.message };
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  /**
   * @deprecated Usar POST /api/auth/signup desde AuthService.
   * El backend crea el perfil junto con el registro del usuario.
   */
  public async createProfile(id: string, name: string, phone: string): Promise<{ success: boolean; error?: string }> {
    try {
      const client = this.ensureClient();
      const { error } = await client.from('profiles').insert({ id, name, phone });

      if (error) return { success: false, error: error.message };
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utilidades — permanecen en Angular
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Traduce los errores tecnicos de autenticacion a mensajes amigables para el usuario.
   */
  mapAuthError(error: AuthError): string {
    const message = error.message.toLowerCase();

    if (message.includes('invalid login credentials')) {
      return 'El correo o la contrasena son incorrectos.';
    }
    if (message.includes('user not found')) {
      return 'No se encontro ninguna cuenta con estos datos.';
    }
    if (message.includes('invalid email')) {
      return 'El formato del correo electronico no es valido.';
    }
    if (message.includes('email already registered')) {
      return 'Esta direccion de correo ya se encuentra registrada.';
    }
    if (message.includes('password should be at least')) {
      return 'La contrasena debe tener una longitud minima de 6 caracteres.';
    }
    if (message.includes('too many requests')) {
      return 'Se ha excedido el limite de intentos. Por favor, intente mas tarde.';
    }

    return 'Ocurrio un error durante la autenticacion. Por favor, verifique sus datos.';
  }
}
