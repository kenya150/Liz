import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class EncryptionService {
  private readonly algorithm = 'AES-GCM';
  private readonly keyLength = 256;
  private readonly encryptionKeyHex = environment.phoneEncryptionKey || '';

  constructor() {
    if (!this.encryptionKeyHex) {
      console.warn('[EncryptionService] PHONE_ENCRYPTION_KEY no encontrada en el entorno.');
    }
  }

  /**
   * Cifra un texto utilizando AES-256-GCM.
   * Retorna una cadena en formato "iv:encryptedData" en base64.
   */
  async encrypt(text: string): Promise<string> {
    try {
      if (!text) return '';

      const key = await this.importKey(this.encryptionKeyHex);
      const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes es estándar para GCM
      const encodedText = new TextEncoder().encode(text);

      const encryptedContent = await window.crypto.subtle.encrypt(
        {
          name: this.algorithm,
          iv: iv
        },
        key,
        encodedText
      );

      const ivBase64 = this.arrayBufferToBase64(iv);
      const encryptedBase64 = this.arrayBufferToBase64(encryptedContent);

      return `${ivBase64}:${encryptedBase64}`;
    } catch (error) {
      console.error('[EncryptionService] Error al cifrar:', error);
      throw new Error('Fallo en el proceso de cifrado');
    }
  }

  /**
   * Descifra un texto en formato "iv:encryptedData".
   */
  async decrypt(encryptedDataWithIv: string): Promise<string> {
    try {
      if (!encryptedDataWithIv) return '';

      const [ivBase64, encryptedBase64] = encryptedDataWithIv.split(':');
      if (!ivBase64 || !encryptedBase64) {
        throw new Error('Formato de datos cifrados inválido');
      }

      const key = await this.importKey(this.encryptionKeyHex);
      const iv = this.base64ToArrayBuffer(ivBase64);
      const encryptedContent = this.base64ToArrayBuffer(encryptedBase64);

      const decryptedContent = await window.crypto.subtle.decrypt(
        {
          name: this.algorithm,
          iv: iv
        },
        key,
        encryptedContent
      );

      return new TextDecoder().decode(decryptedContent);
    } catch (error) {
      console.error('[EncryptionService] Error al descifrar:', error);
      throw new Error('Fallo en el proceso de descifrado. Es posible que la clave sea incorrecta o los datos estén corruptos.');
    }
  }

  private async importKey(hexKey: string): Promise<CryptoKey> {
    const keyBuffer = this.hexToArrayBuffer(hexKey);
    return await window.crypto.subtle.importKey(
      'raw',
      keyBuffer,
      this.algorithm,
      false,
      ['encrypt', 'decrypt']
    );
  }

  private hexToArrayBuffer(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
  }

  private arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
