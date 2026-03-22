import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../service/authService/authService';
import { Router } from '@angular/router';
import { NotificationService } from '../../service/notificationService/notificationService';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="min-h-screen bg-gray-100 p-8">
      <div class="max-w-2xl mx-auto bg-white rounded-xl shadow-md overflow-hidden p-6">
        <div class="flex justify-between items-center mb-6">
          <h1 class="text-2xl font-bold text-gray-800">Perfil de Usuario</h1>
          <button 
            (click)="onLogout()" 
            class="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg transition duration-200">
            Cerrar Sesión
          </button>
        </div>

        <div *ngIf="loading" class="text-center py-8">
          <p class="text-gray-600">Cargando datos del perfil...</p>
        </div>

        <div *ngIf="!loading && profile" class="space-y-4">
          <div class="border-b pb-4">
            <p class="text-sm text-gray-500 uppercase tracking-wider">Nombre Completo</p>
            <p class="text-lg font-medium text-gray-900">{{ profile.name }}</p>
          </div>

          <div class="border-b pb-4">
            <p class="text-sm text-gray-500 uppercase tracking-wider">Correo Electrónico</p>
            <p class="text-lg font-medium text-gray-900">{{ userEmail }}</p>
          </div>

          <div class="border-b pb-4">
            <p class="text-sm text-gray-500 uppercase tracking-wider">Teléfono (Cifrado en repositorio)</p>
            <div class="flex items-center gap-2">
              <p class="text-lg font-medium text-gray-900">
                {{ showPhone ? profile.phone : maskPhone(profile.phone) }}
              </p>
              <button 
                (click)="togglePhone()" 
                class="text-blue-600 hover:text-blue-800 text-sm font-semibold">
                {{ showPhone ? 'Ocultar' : 'Ver' }}
              </button>
            </div>
          </div>

          <div class="mt-8 p-4 bg-blue-50 rounded-lg">
            <p class="text-sm text-blue-800">
              <strong>Cumplimiento Normativo:</strong> Al visualizar estos datos, confirmas que tienes consentimiento explícito para manejar esta información personal sensible.
            </p>
            <p class="text-xs text-blue-600 mt-2">
              Último acceso: {{ lastAccess | date:'medium' }}
            </p>
          </div>
        </div>

        <div *ngIf="!loading && !profile" class="text-center py-8">
          <p class="text-red-600">No se pudo cargar la información del perfil.</p>
        </div>
      </div>
    </div>
  `
})
export class ProfileComponent implements OnInit, OnDestroy {
  profile: any = null;
  userEmail: string = '';
  loading: boolean = true;
  showPhone: boolean = false;
  lastAccess: Date = new Date();
  private inactivityTimeout: any;
  private readonly INACTIVITY_LIMIT = 5 * 60 * 1000; // 5 minutos

  constructor(
    private authService: AuthService,
    private router: Router,
    private notificationService: NotificationService
  ) {}

  async ngOnInit() {
    this.resetInactivityTimer();
    this.setupInactivityListeners();
    
    try {
      const user = await this.authService.getCurrentUser();
      if (!user) {
        this.router.navigate(['/login']);
        return;
      }
      this.userEmail = user.email || '';
      
      const resp = await this.authService.getProfile(user.id);
      if (resp.success) {
        this.profile = resp.data;
      } else {
        this.notificationService.error('Error al procesar datos del perfil');
      }
    } catch (e) {
      this.notificationService.error('Error al procesar datos');
    } finally {
      this.loading = false;
    }
  }

  ngOnDestroy() {
    this.clearInactivityTimer();
    this.removeInactivityListeners();
  }

  togglePhone() {
    this.showPhone = !this.showPhone;
  }

  maskPhone(phone: string): string {
    if (!phone) return '';
    return phone.substring(0, 3) + '****' + phone.substring(phone.length - 3);
  }

  async onLogout() {
    const success = await this.authService.logout();
    if (success) {
      this.notificationService.success('Sesión cerrada exitosamente');
      this.router.navigate(['/login']);
    }
  }

  private resetInactivityTimer() {
    this.clearInactivityTimer();
    this.inactivityTimeout = setTimeout(() => {
      this.notificationService.warning('Sesión expirada por inactividad');
      this.onLogout();
    }, this.INACTIVITY_LIMIT);
  }

  private clearInactivityTimer() {
    if (this.inactivityTimeout) {
      clearTimeout(this.inactivityTimeout);
    }
  }

  private setupInactivityListeners() {
    window.addEventListener('mousemove', () => this.resetInactivityTimer());
    window.addEventListener('keydown', () => this.resetInactivityTimer());
    window.addEventListener('click', () => this.resetInactivityTimer());
  }

  private removeInactivityListeners() {
    window.removeEventListener('mousemove', () => this.resetInactivityTimer());
    window.removeEventListener('keydown', () => this.resetInactivityTimer());
    window.removeEventListener('click', () => this.resetInactivityTimer());
  }
}
