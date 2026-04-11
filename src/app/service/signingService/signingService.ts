import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface SignedPayload {
  id: string;
  email: string;
  role: string;
}

export interface VerificationResult {
  valid: boolean;
  message: string;
}

@Injectable({ providedIn: 'root' })
export class SigningService {
  private readonly apiUrl = `${environment.apiUrl}/signing`;

  /**
   * Firma y payload firmado se guardan en memoria mientras dura la sesión.
   * No se guardan en localStorage para que no sean accesibles ni manipulables
   * entre sesiones desde DevTools.
   */
  private signature: string | null = null;
  private signedPayload: SignedPayload | null = null;

  constructor(private http: HttpClient) {}

  /**
   * Guarda la firma recibida del backend al hacer login.
   * Llamar desde AuthService.login() al recibir la respuesta exitosa.
   */
  storeSignature(signature: string, payload: SignedPayload): void {
    this.signature = signature;
    this.signedPayload = payload;
  }

  /**
   * Devuelve la firma y el payload actualmente almacenados.
   */
  getSignature(): { signature: string | null; payload: SignedPayload | null } {
    return { signature: this.signature, payload: this.signedPayload };
  }

  /**
   * Limpia la firma al cerrar sesión.
   */
  clearSignature(): void {
    this.signature = null;
    this.signedPayload = null;
  }

  /**
   * Verifica en el servidor que los datos actuales coincidan con la firma.
   * Si un atacante modifica el rol o email en memoria, la verificación falla.
   */
  async verify(): Promise<VerificationResult> {
    if (!this.signature || !this.signedPayload) {
      return { valid: false, message: 'No hay firma activa para verificar.' };
    }

    try {
      return await firstValueFrom(
        this.http.post<VerificationResult>(`${this.apiUrl}/verify`, {
          ...this.signedPayload,
          signature: this.signature
        })
      );
    } catch (err: any) {
      return err?.error ?? { valid: false, message: 'Error al conectar con el servidor de verificación.' };
    }
  }

  /**
   * Obtiene la llave pública del servidor.
   * Útil para mostrarla en la UI como parte de la práctica.
   */
  async getPublicKey(): Promise<string> {
    try {
      const res = await firstValueFrom(
        this.http.get<{ publicKey: string }>(`${this.apiUrl}/public-key`)
      );
      return res.publicKey;
    } catch {
      return 'No se pudo obtener la llave pública.';
    }
  }
}
