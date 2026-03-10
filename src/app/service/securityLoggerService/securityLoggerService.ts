import { Injectable } from '@angular/core';

export enum LogLevel {
  INFO = 'INFO',
  WARN = 'WARN',
  CRITICAL = 'CRITICAL'
}

@Injectable({
  providedIn: 'root'
})
export class SecurityLoggerService {
  private readonly LOG_KEY = 'security_audit_log';

  constructor() {
    // Exponer el comando globalmente para auditoría manual fácil
    (window as any).downloadLogs = () => this.exportToPhysicalFile();
  }

  /**
   * Registra un evento de seguridad en el log persistente.
   * REGLA DE ORO: Nunca registrar contraseñas.
   */
  log(level: LogLevel, message: string, email: string, ip: string = 'unknown'): void {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${level}] [User: ${email}] [IP: ${ip}] - ${message}`;

    // Guardar en localStorage (simulando archivo físico en el navegador)
    this.saveToPersistentStorage(logEntry);

    // También mostrar en consola para depuración
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

  private saveToPersistentStorage(entry: string): void {
    try {
      const currentLogs = localStorage.getItem(this.LOG_KEY);
      const logsArray = currentLogs ? JSON.parse(currentLogs) : [];
      logsArray.push(entry);

      // Mantener solo los últimos 500 registros
      if (logsArray.length > 500) {
        logsArray.shift();
      }

      localStorage.setItem(this.LOG_KEY, JSON.stringify(logsArray));
    } catch (e) {
      console.error('Error al escribir en security_audit.log:', e);
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
   * Genera y descarga el archivo security_audit.log físicamente.
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
