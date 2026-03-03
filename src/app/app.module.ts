import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppComponent } from './app.component';
import { environment } from '../environments/environment';
import { SupabaseService } from './service/supabaseService/supabaseService';

@NgModule({
  declarations: [],
  imports: [BrowserModule],
  providers: [],
  
})
export class AppModule {
  constructor(private supabase: SupabaseService) {
    // Inicializar Supabase con credenciales desde archivo de entorno
    this.supabase.init(environment.supabaseUrl, environment.supabaseAnonKey);
  }
}
