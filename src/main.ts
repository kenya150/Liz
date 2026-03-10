import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';

// Frame busting - Capa adicional de seguridad para prevenir Clickjacking
if (window.top !== window.self) {
  window.top.location = window.self.location;
}

bootstrapApplication(AppComponent, appConfig)
  .catch((err: any) => console.error(err));
