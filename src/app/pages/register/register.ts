import { Component, OnDestroy, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { AuthService } from '../../service/authService/authService';
import { NotificationService } from '../../service/notificationService/notificationService';
import { CommonModule } from '@angular/common';
import { Router, RouterLink } from '@angular/router';

@Component({
  selector: 'app-register',
  templateUrl: 'register.html',
  styleUrl: 'register.css',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink]
})
export class RegisterComponent implements OnInit, OnDestroy {
  registerForm!: FormGroup;
  isSubmitting = false;

  constructor(
    private authService: AuthService,
    private fb: FormBuilder,
    private notificationService: NotificationService,
    private router: Router
  ) {}

  ngOnInit() {
    this.registerForm = this.fb.group({
      nombre: ['', [Validators.required, Validators.minLength(3)]],
      correo: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]],
      confirmPassword: ['', [Validators.required]]
    }, { validators: this.passwordMatchValidator });
  }

  ngOnDestroy() {
    // Cleanup if needed
  }

  passwordMatchValidator(group: FormGroup): any {
    const password = group.get('password');
    const confirmPassword = group.get('confirmPassword');

    if (!password || !confirmPassword) return null;
    
    return password.value === confirmPassword.value ? null : { passwordMismatch: true };
  }

  getNameError(): string {
    const control = this.registerForm.get('nombre');
    if (control?.hasError('required')) {
      return 'El nombre es requerido';
    }
    if (control?.hasError('minlength')) {
      return 'El nombre debe tener al menos 3 caracteres';
    }
    return '';
  }

  getEmailError(): string {
    const control = this.registerForm.get('correo');
    if (control?.hasError('required')) {
      return 'El correo es requerido';
    }
    if (control?.hasError('email')) {
      return 'Ingresa un correo válido';
    }
    return '';
  }

  getPasswordError(): string {
    const control = this.registerForm.get('password');
    if (control?.hasError('required')) {
      return 'La contraseña es requerida';
    }
    if (control?.hasError('minlength')) {
      return 'La contraseña debe tener al menos 6 caracteres';
    }
    return '';
  }

  getConfirmPasswordError(): string {
    const control = this.registerForm.get('confirmPassword');
    if (control?.hasError('required')) {
      return 'Confirma tu contraseña';
    }
    if (this.registerForm.hasError('passwordMismatch')) {
      return 'Las contraseñas no coinciden';
    }
    return '';
  }

  async onRegisterClick() {
    if (this.registerForm.invalid) {
      this.notificationService.warning('Por favor completa los campos correctamente');
      return;
    }

    this.isSubmitting = true;
    const { nombre, correo, password } = this.registerForm.value;
    
    console.log('[RegisterComponent] Enviando registro al authService');
    const result = await this.authService.signup(correo, password, nombre);
    console.log('[RegisterComponent] Resultado del registro:', result);
    this.isSubmitting = false;

    if (result.success) {
      console.log('[RegisterComponent] Registro exitoso');
      this.notificationService.success('✓ Cuenta registrada correctamente. Redirigiendo al login...');
      this.registerForm.reset();
      
      // Redirigir al login en 2 segundos
      setTimeout(() => {
        this.router.navigate(['/login']);
      }, 2000);
      return;
    }

    // Manejo de fallo
    console.log('[RegisterComponent] Registro fallido:', result.message);
    this.notificationService.error(result.message || '❌ Error al registrar');
  }
}
