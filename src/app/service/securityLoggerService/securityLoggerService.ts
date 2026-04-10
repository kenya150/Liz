import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../../environments/environment';

export enum LogLevel {
  INFO = 'INFO',
  WARN = 'WARN',
  CRITICAL = 'CRITICAL'
}

@Injectable({
  providedIn: 'root'
})
export class SecurityLoggerService {
  /**
   * Clave local para el log secundario en localStorage.
   * Este log es solo para debug y exportación manual.
   * El log de seguridad real vive en el servidor.
   */
  private readonly LOG_KEY = 'security_audit_log';
  private readonly apiUrl = `${environment.apiUrl}/logs/security`;

  constructor(private http: HttpClient) {
    // Exponer el comando globalmente para auditoría manual fácil
    (window as any).downloadLogs = () => this.exportToPhysicalFile();
  }

  /**
   * Registra un evento de seguridad.
   *
   * - INFO:     solo consola + localStorage local (debug).
   * - WARN:     consola + localStorage + envío al backend.
   * - CRITICAL: consola + localStorage + envío al backend.
   *
   * La IP real la obtiene el servidor desde req.ip — desde el navegador
   * no es posible conocerla con certeza, por eso ya no se recibe como parámetro.
   *
   * REGLA DE ORO: Nunca registrar contraseñas.
   */
  log(level: LogLevel, message: string, userIdentifier: string): void {
    const timestamp = new Date().toISOString();
    const userAgent = window.navigator.userAgent;
    const logEntry = `[${timestamp}] [${level}] [User: ${userIdentifier}] [UA: ${userAgent}] - ${message}`;

    this.saveToLocalStorage(logEntry);
    this.printToConsole(level, logEntry);

    // WARN y CRITICAL se persisten en el servidor donde no pueden ser manipulados
    if (level === LogLevel.WARN || level === LogLevel.CRITICAL) {
      this.sendToBackend(level, message, userIdentifier, timestamp);
    }
  }

  private sendToBackend(
    level: LogLevel,
    message: string,
    userIdentifier: string,
    timestamp: string
  ): void {
    // fire-and-forget: el log no debe interrumpir el flujo principal si falla
    this.http.post(this.apiUrl, {
      level,
      message,
      userIdentifier,
      userAgent: window.navigator.userAgent,
      timestamp,
    }).subscribe({
      error: (err) => console.error('[SecurityLoggerService] No se pudo enviar el log al servidor:', err)
    });
  }

  private printToConsole(level: LogLevel, logEntry: string): void {
    switch (level) {
      case LogLevel.INFO:
        console.info(`%c${logEntry}`, 'color: #007bff');
        break;
      case LogLevel.WARN:
        console.warn(`%c${logEntry}`, 'color: #ffc107');
        break;
      case LogLevel.CRITICAL:
        console.error(`%c${logEntry}`, 'color: #dc3545; font-weight: bold');
        break;
    }
  }

  private saveToLocalStorage(entry: string): void {
    try {
      const current = localStorage.getItem(this.LOG_KEY);
      const logs = current ? JSON.parse(current) : [];
      logs.push(entry);

      // Mantener solo los últimos 500 registros locales
      if (logs.length > 500) logs.shift();

      localStorage.setItem(this.LOG_KEY, JSON.stringify(logs));
    } catch (e) {
      console.error('[SecurityLoggerService] Error al escribir en localStorage:', e);
    }
  }

  getLogs(): string[] {
    const logs = localStorage.getItem(this.LOG_KEY);
    return logs ? JSON.parse(logs) : [];
  }

  clearLogs(): void {
    localStorage.removeItem(this.LOG_KEY);
  }

  /**
   * Descarga el log local como archivo security_audit.log.
   * Útil para debug. El log completo y confiable está en el servidor.
   */
  exportToPhysicalFile(): void {
    const logs = this.getLogs().join('\n');
    const blob = new Blob([logs], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.download = 'security_audit.log';
    anchor.href = url;
    anchor.click();
    window.URL.revokeObjectURL(url);
  }
}
