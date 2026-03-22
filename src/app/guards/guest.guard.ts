import { Injectable } from '@angular/core';
import { CanActivate, Router, UrlTree } from '@angular/router';
import { AuthService } from '../service/authService/authService';

@Injectable({
  providedIn: 'root'
})
export class GuestGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  async canActivate(): Promise<boolean | UrlTree> {
    console.log('[GuestGuard] Verificando si es invitado...');
    const authenticated = await this.authService.isAuthenticated();
    console.log('[GuestGuard] Autenticado (no invitado):', authenticated);
    if (authenticated) {
      // Si ya está autenticado, redirigir al perfil
      console.warn('[GuestGuard] Ya autenticado, redirigiendo a /profile');
      return this.router.parseUrl('/profile');
    } else {
      // Si no está autenticado, permitir acceso a la ruta (login/register)
      return true;
    }
  }
}
