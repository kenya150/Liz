import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { NotificationsComponent } from './components/notifications/notifications.component';
import { SecurityLoggerService } from './service/securityLoggerService/securityLoggerService';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, NotificationsComponent],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'Healt_Thech';
  // Solo inyectarlo es suficiente — el constructor del servicio
  // registra window.downloadLogs automáticamente al instanciarse
  constructor(private securityLogger: SecurityLoggerService) {}
}
