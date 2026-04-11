import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../../environments/environment';
import { SecurityLoggerService, LogLevel } from '../securityLoggerService/securityLoggerService';

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
   * Firma y payload firmado se guardan en memoria mientras dura la sesion.
   * No se guardan en localStorage para que no sean accesibles ni manipulables
   * entre sesiones desde DevTools.
   */
  private signature: string | null = null;
  private signedPayload: SignedPayload | null = null;

  constructor(
    private http: HttpClient,
    private securityLogger: SecurityLoggerService
  ) {}

  /**
   * Guarda la firma recibida del backend al hacer login.
   * Llamar desde AuthService.login() al recibir la respuesta exitosa.
   */
  storeSignature(signature: string, payload: SignedPayload): void {
    this.signature = signature;
    this.signedPayload = payload;

    // Confirmacion de que la firma digital fue recibida y almacenada en memoria
    this.securityLogger.log(LogLevel.INFO, 'Firma digital almacenada en sesion', payload.id);
  }

  /**
   * Devuelve la firma y el payload actualmente almacenados.
   */
  getSignature(): { signature: string | null; payload: SignedPayload | null } {
    return { signature: this.signature, payload: this.signedPayload };
  }

  /**
   * Limpia la firma al cerrar sesion.
   * El identificador se captura antes de limpiar el payload para poder incluirlo en el log.
   */
  clearSignature(): void {
    const identifier = this.signedPayload?.id || 'usuario_desconocido';

    this.signature = null;
    this.signedPayload = null;

    // Confirmacion de que la firma fue eliminada de memoria al cerrar sesion
    this.securityLogger.log(LogLevel.INFO, 'Firma digital eliminada de memoria', identifier);
  }

  /**
   * Verifica en el servidor que los datos actuales coincidan con la firma.
   * Si un atacante modifica el rol o email en memoria, la verificacion falla.
   */
  async verify(): Promise<VerificationResult> {
    if (!this.signature || !this.signedPayload) {
      return { valid: false, message: 'No hay firma activa para verificar.' };
    }

    // Se captura el UUID antes de la peticion para usarlo en el log
    const identifier = this.signedPayload.id;

    try {
      const result = await firstValueFrom(
        this.http.post<VerificationResult>(`${this.apiUrl}/verify`, {
          ...this.signedPayload,
          signature: this.signature
        })
      );

      if (result.valid) {
        // Verificacion de integridad exitosa, los datos no fueron alterados
        this.securityLogger.log(LogLevel.INFO, 'Verificacion de firma digital exitosa', identifier);
      } else {
        // La firma no coincide con los datos recibidos, posible manipulacion de datos
        this.securityLogger.log(LogLevel.CRITICAL, 'Verificacion de firma fallida: posible manipulacion de datos', identifier);
      }

      return result;
    } catch (err: any) {
      return err?.error ?? { valid: false, message: 'Error al conectar con el servidor de verificacion.' };
    }
  }

  /**
   * Obtiene la llave publica del servidor.
   * Util para mostrarla en la UI como parte de la practica.
   */
  async getPublicKey(): Promise<string> {
    try {
      const res = await firstValueFrom(
        this.http.get<{ publicKey: string }>(`${this.apiUrl}/public-key`)
      );
      return res.publicKey;
    } catch {
      return 'No se pudo obtener la llave publica.';
    }
  }
}
