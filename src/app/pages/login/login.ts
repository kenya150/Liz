import { Component, OnDestroy, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { AuthService, LoginResult } from '../../service/authService/authService';
import { NotificationService } from '../../service/notificationService/notificationService';
import { Router, RouterLink } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: 'login.html',
  styleUrl: 'login.css',
  standalone: true,
  imports: [ReactiveFormsModule, RouterLink]
})
export class LoginComponent implements OnInit, OnDestroy {
  loginForm!: FormGroup;
  message = '';
  isLocked = false;
  countdownText = '';
  isSubmitting = false;
  private lockInterval: any = null;
  private readonly LOCK_STORAGE_KEY = 'loginLockUntil';

  constructor(
    private authService: AuthService,
    private fb: FormBuilder,
    private notificationService: NotificationService,
    private router: Router
  ) {}

  ngOnInit() {
    this.loginForm = this.fb.group({
      correo: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]]
    });

    // Verificar si hay bloqueo persistido
    this.checkPersistentLock();
  }

  ngOnDestroy() {
    if (this.lockInterval) {
      clearInterval(this.lockInterval);
    }
  }

  private checkPersistentLock() {
    const lockedUntilStr = localStorage.getItem(this.LOCK_STORAGE_KEY);
    if (lockedUntilStr) {
      const lockedUntil = parseInt(lockedUntilStr, 10);
      if (lockedUntil > Date.now()) {
        this.startLockCountdown(lockedUntil);
      } else {
        localStorage.removeItem(this.LOCK_STORAGE_KEY);
      }
    }
  }

  private saveLockToStorage(lockedUntil: number) {
    localStorage.setItem(this.LOCK_STORAGE_KEY, lockedUntil.toString());
  }

  private clearLockFromStorage() {
    localStorage.removeItem(this.LOCK_STORAGE_KEY);
  }

  private startLockCountdown(lockedUntil: number) {
    this.isLocked = true;
    const update = () => {
      const now = Date.now();
      const remain = lockedUntil - now;
      if (remain <= 0) {
        this.isLocked = false;
        this.countdownText = '';
        this.isSubmitting = false;
        this.clearLockFromStorage();
        if (this.lockInterval) {
          clearInterval(this.lockInterval);
          this.lockInterval = null;
        }
        return;
      }
      const mins = Math.floor(remain / 60000);
      const secs = Math.floor((remain % 60000) / 1000);
      this.countdownText = `${mins}m ${secs}s`;
    };

    update();
    if (this.lockInterval) {
      clearInterval(this.lockInterval);
    }
    this.lockInterval = setInterval(update, 1000);
  }

  getEmailError(): string {
    const control = this.loginForm.get('correo');
    if (control?.hasError('required')) {
      return 'El correo es requerido';
    }
    if (control?.hasError('email')) {
      return 'Ingresa un correo válido';
    }
    return '';
  }

  getPasswordError(): string {
    const control = this.loginForm.get('password');
    if (control?.hasError('required')) {
      return 'La contraseña es requerida';
    }
    if (control?.hasError('minlength')) {
      return 'La contraseña debe tener al menos 6 caracteres';
    }
    return '';
  }

  async onLoginClick() {
    if (this.isLocked) {
      this.notificationService.warning(`Acceso bloqueado. Tiempo restante: ${this.countdownText}`);
      return;
    }

    if (this.loginForm.invalid) {
      this.notificationService.warning('Por favor completa los campos correctamente.');
      return;
    }

    this.isSubmitting = true;
    const { correo, password } = this.loginForm.value;

    const result = await this.authService.login(correo, password);
    this.isSubmitting = false;

    if (result.success) {
      this.notificationService.success('Inicio de sesion exitoso.');
      const navSuccess = await this.router.navigate(['/profile']);
      if (!navSuccess) {
        console.warn('[LoginComponent] La navegacion al perfil no pudo completarse.');
      }
      return;
    }

    // Manejo de errores de inicio de sesion
    const errorMsg = result.message || 'Credenciales incorrectas.';
    this.notificationService.error(errorMsg);

    // Activacion de bloqueo temporal si el servicio lo indica
    if (result.lockedUntil && result.lockedUntil > Date.now()) {
      this.saveLockToStorage(result.lockedUntil);
      this.startLockCountdown(result.lockedUntil);
      this.notificationService.error('Demasiados intentos fallidos. El acceso ha sido bloqueado temporalmente por seguridad.');
    }
  }
}
