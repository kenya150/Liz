import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class EncryptionService {
  /**
   * Algoritmo de cifrado simetrico AES-GCM
   */
  private readonly algorithm = 'AES-GCM';

  /**
   * Longitud de la clave en bits (256 bits para AES-256)
   */
  private readonly keyLength = 256;

  /**
   * Clave de cifrado en formato hexadecimal obtenida de la configuracion
   */
  private readonly encryptionKeyHex = environment.phoneEncryptionKey || '';

  constructor() {
    if (!this.encryptionKeyHex) {
      console.warn('[EncryptionService] Clave de cifrado no encontrada en el entorno de configuracion.');
    }
  }

  /**
   * Cifra una cadena de texto utilizando el algoritmo AES-256-GCM.
   * Genera un vector de inicializacion (IV) aleatorio para cada operacion.
   *
   * @param text Texto en plano que se desea cifrar.
   * @returns Una promesa que resuelve en una cadena con el formato "ivBase64:datosCifradosBase64".
   * @throws Error si el proceso de cifrado falla o la clave es invalida.
   */
  async encrypt(text: string): Promise<string> {
    try {
      if (!text) return '';

      const key = await this.importKey(this.encryptionKeyHex);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
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
      console.error('[EncryptionService] Error durante el proceso de cifrado:', error);
      throw new Error('No se pudo completar el cifrado de la informacion.');
    }
  }

  /**
   * Descifra una cadena de texto previamente cifrada.
   * El texto debe estar en el formato generado por la funcion encrypt.
   *
   * @param encryptedDataWithIv Cadena con el formato "ivBase64:datosCifradosBase64".
   * @returns Una promesa que resuelve en el texto original descifrado.
   * @throws Error si el formato es incorrecto o el descifrado falla.
   */
  async decrypt(encryptedDataWithIv: string): Promise<string> {
    try {
      if (!encryptedDataWithIv) return '';

      const parts = encryptedDataWithIv.split(':');
      if (parts.length !== 2) {
        throw new Error('El formato de los datos cifrados no es valido.');
      }

      const [ivBase64, encryptedBase64] = parts;
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
      console.error('[EncryptionService] Error durante el proceso de descifrado:', error);
      throw new Error('Fallo al descifrar los datos. Verifique la integridad de la informacion y la clave configurada.');
    }
  }

  /**
   * Importa una clave hexadecimal a un objeto CryptoKey utilizable por Web Crypto API.
   *
   * @param hexKey Clave en formato hexadecimal.
   * @returns Promesa que resuelve en un objeto CryptoKey.
   */
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

  /**
   * Convierte una cadena hexadecimal a un ArrayBuffer.
   */
  private hexToArrayBuffer(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
  }

  /**
   * Convierte un ArrayBuffer o Uint8Array a una cadena codificada en Base64.
   */
  private arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  /**
   * Convierte una cadena codificada en Base64 a un ArrayBuffer.
   */
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
