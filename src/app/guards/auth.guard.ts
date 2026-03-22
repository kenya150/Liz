import { Injectable } from '@angular/core';
import { CanActivate, Router, UrlTree } from '@angular/router';
import { AuthService } from '../service/authService/authService';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  async canActivate(): Promise<boolean | UrlTree> {
    console.log('[AuthGuard] Verificando autenticación...');
    const authenticated = await this.authService.isAuthenticated();
    console.log('[AuthGuard] Autenticado:', authenticated);
    if (authenticated) {
      return true;
    } else {
      console.warn('[AuthGuard] No autenticado, redirigiendo a /login');
      return this.router.parseUrl('/login');
    }
  }
}
