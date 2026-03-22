import { Routes } from '@angular/router';
import { LoginComponent } from './pages/login/login';
import { RegisterComponent } from './pages/register/register';
import { ProfileComponent } from './pages/profile/profile';
import { AuthGuard } from './guards/auth.guard';
import { GuestGuard } from './guards/guest.guard';

export const routes: Routes = [
  {
    path:'login',
    component:LoginComponent,
    canActivate: [GuestGuard]
  },
  {
    path:'register',
    component:RegisterComponent,
    canActivate: [GuestGuard]
  },
  {
    path: 'profile',
    component: ProfileComponent,
    canActivate: [AuthGuard]
  },
  {
    path: '',
    redirectTo: 'login',
    pathMatch: 'full'
  },
  {
    path: "**",
    pathMatch: 'full',
    redirectTo: 'login'
  }
];
