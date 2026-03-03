import { ApplicationConfig, provideZoneChangeDetection, APP_INITIALIZER } from '@angular/core';
import { provideRouter } from '@angular/router';

import { routes } from './app.routes';
import { SupabaseService } from './service/supabaseService/supabaseService';
import { environment } from '../environments/environment';

// Factory para inicializar Supabase al arrancar la aplicación
export function initSupabase(supabase: SupabaseService) {
  return () => {
    supabase.init(environment.supabaseUrl, environment.supabaseAnonKey);
  };
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    SupabaseService,
    {
      provide: APP_INITIALIZER,
      useFactory: initSupabase,
      deps: [SupabaseService],
      multi: true
    }
  ]
};
