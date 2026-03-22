import { Injectable } from '@angular/core';
import { createClient, SupabaseClient, AuthError } from '@supabase/supabase-js';

@Injectable({
  providedIn: 'root'
})
export class SupabaseService {
  private client: SupabaseClient | null = null;

  constructor() {
    const win = window as any;
    if (win && win.SUPABASE_URL && win.SUPABASE_ANON_KEY) {
      this.init(win.SUPABASE_URL, win.SUPABASE_ANON_KEY);
    }
  }

  init(url: string, anonKey: string) {
    if (!url || !anonKey) throw new Error('Supabase url y anonKey son requeridas');
    this.client = createClient(url, anonKey, { auth: { persistSession: false } });
  }

  private ensureClient(): SupabaseClient {
    if (!this.client) {
      throw new Error('Cliente Supabase no inicializado. Call init(url, anonKey) o set window.SUPABASE_URL/ANON_KEY');
    }
    return this.client;
  }
  // Nuevo método público para insertar perfil
  public async createProfile(id: string, name: string, phone: string): Promise<{ success: boolean; error?: string }> {
    try {
      const client = this.ensureClient();
      const { error } = await client.from('profiles').insert({ id, name, phone });
      if (error) {
        console.error('[SupabaseService] Error al crear perfil:', error);
        return { success: false, error: error.message };
      }
      console.log('[SupabaseService] ✓ Perfil creado en public.profiles');
      return { success: true };
    } catch (e) {
      console.error('[SupabaseService] Error en createProfile', e);
      return { success: false, error: String(e) };
    }
  }

  // Nuevo método público para actualizar perfil
  public async updateProfile(id: string, name: string, phone: string): Promise<{ success: boolean; error?: string }> {
    try {
      const client = this.ensureClient();
      const { error } = await client
        .from('profiles')
        .update({ name, phone })
        .eq('id', id);
      
      if (error) {
        console.error('[SupabaseService] Error al actualizar perfil:', error);
        return { success: false, error: error.message };
      }
      console.log('[SupabaseService] ✓ Perfil actualizado en public.profiles');
      return { success: true };
    } catch (e) {
      console.error('[SupabaseService] Error en updateProfile', e);
      return { success: false, error: String(e) };
    }
  }

  // Nuevo método para obtener el perfil y descifrar el teléfono si es necesario
  public async getProfile(id: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const client = this.ensureClient();
      const { data, error } = await client
        .from('profiles')
        .select('*')
        .eq('id', id)
        .single();

      if (error) {
        console.error('[SupabaseService] Error al obtener perfil:', error);
        return { success: false, error: error.message };
      }
      return { success: true, data };
    } catch (e) {
      console.error('[SupabaseService] Error en getProfile', e);
      return { success: false, error: String(e) };
    }
  }

  // Métodos de auth reconstruidos
  async loginWithAuth(email: string, password: string): Promise<{
    success: boolean;
    user?: any;
    session?: any;
    error?: string;
  }> {
    try {
      const client = this.ensureClient();
      console.log('[SupabaseService] loginWithAuth iniciado', { email });

      const { data, error } = await client.auth.signInWithPassword({
        email: email.trim(),
        password: password.trim()
      });

      if (error) {
        console.error('[SupabaseService] Error en signInWithPassword:', error);
        return {
          success: false,
          error: this.mapAuthError(error)
        };
      }

      if (data.user && data.session) {
        console.log('[SupabaseService] ✓ Login exitoso con Auth');
        return {
          success: true,
          user: data.user,
          session: data.session
        };
      }

      return {
        success: false,
        error: 'Error desconocido en autenticación'
      };
    } catch (e) {
      console.error('[SupabaseService] Error en loginWithAuth', e);
      return {
        success: false,
        error: `Error al conectar con servidor: ${String(e)}`
      };
    }
  }

  async signUpWithAuth(email: string, password: string): Promise<{
    success: boolean;
    user?: any;
    error?: string;
  }> {
    try {
      const client = this.ensureClient();
      console.log('[SupabaseService] signUpWithAuth iniciado', { email, password });

      const { data, error } = await client.auth.signUp({
        email: email.trim(),
        password: password.trim(),
      });

      if (error) {
        console.error('[SupabaseService] Error en signUp:', error);
        return {
          success: false,
          error: this.mapAuthError(error)
        };
      }

      if (data.user) {
        console.log('[SupabaseService] ✓ Registro exitoso');
        return {
          success: true,
          user: data.user
        };
      }

      return {
        success: false,
        error: 'Error desconocido en registro'
      };
    } catch (e) {
      console.error('[SupabaseService] Error en signUpWithAuth', e);
      return {
        success: false,
        error: `Error al conectar con servidor: ${String(e)}`
      };
    }
  }

  async logout(): Promise<{ success: boolean; error?: string }> {
    try {
      const client = this.ensureClient();
      console.log('[SupabaseService] logout iniciado');

      const { error } = await client.auth.signOut();

      if (error) {
        console.error('[SupabaseService] Error en signOut:', error);
        return { success: false, error: error.message };
      }

      console.log('[SupabaseService] ✓ Logout exitoso');
      return { success: true };
    } catch (e) {
      console.error('[SupabaseService] Error en logout', e);
      return { success: false, error: String(e) };
    }
  }

  private mapAuthError(error: AuthError): string {
    const message = error.message.toLowerCase();

    if (message.includes('invalid login credentials')) {
      return 'Correo o contraseña incorrectos';
    }
    if (message.includes('user not found')) {
      return 'Usuario no encontrado';
    }
    if (message.includes('invalid email')) {
      return 'Formato de correo inválido';
    }
    if (message.includes('password')) {
      return 'Contraseña incorrecta';
    }
    if (message.includes('email already registered')) {
      return 'Este correo ya está registrado';
    }
    if (message.includes('password should be at least')) {
      return 'La contraseña debe tener al menos 6 caracteres';
    }
    if (message.includes('too many requests')) {
      return 'Demasiados intentos. Intenta más tarde';
    }

    return error.message || 'Error en la autenticación';
  }

}
