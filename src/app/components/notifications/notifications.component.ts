import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NgStyle } from '@angular/common';
import { NotificationService, Notification } from '../../service/notificationService/notificationService';

@Component({
  selector: 'app-notifications',
  standalone: true,
  imports: [CommonModule, NgStyle],
  template: `
    <div class="fixed top-4 right-4 space-y-2 z-50" style="pointer-events: auto;">
      @for (notification of notifications; track notification.id) {
        <div 
          [ngStyle]="getNotificationStyles(notification.type)"
          class="px-4 py-3 rounded-lg shadow-lg flex items-center gap-3 min-w-96"
          style="animation: slideIn 0.3s ease-out;">
          <span style="font-size: 1.25rem; flex-shrink: 0;">{{ getIcon(notification.type) }}</span>
          <span class="flex-1" style="word-wrap: break-word;">{{ notification.message }}</span>
          <button 
            (click)="notificationService.remove(notification.id)"
            class="leading-none opacity-70 hover:opacity-100"
            style="font-size: 1.125rem; flex-shrink: 0; cursor: pointer; border: none; background: none; color: inherit; padding: 0;">
            ✕
          </button>
        </div>
      }
    </div>
  `,
  styles: [`
    :host {
      pointer-events: none;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(-10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
  `]
})
export class NotificationsComponent implements OnInit {
  notifications: Notification[] = [];

  constructor(public notificationService: NotificationService) {}

  ngOnInit() {
    this.notificationService.notifications$.subscribe(
      notifications => this.notifications = notifications
    );
  }

  getIcon(type: string): string {
    switch (type) {
      case 'success':
        return '✓';
      case 'error':
        return '❌';
      case 'warning':
        return '⚠️';
      case 'info':
        return 'ℹ️';
      default:
        return 'ℹ️';
    }
  }

  getNotificationStyles(type: string): any {
    const baseStyles = {
      'font-weight': '500',
      'border-radius': '0.5rem',
      'box-shadow': '0 10px 15px -3px rgba(0, 0, 0, 0.2)',
      'display': 'flex',
      'align-items': 'center',
      'gap': '0.75rem',
      'padding': '0.75rem 1rem',
      'pointer-events': 'auto'
    };

    switch (type) {
      case 'success':
        return {
          ...baseStyles,
          'background-color': '#dcfce7',
          'border-left': '4px solid #22c55e',
          'color': '#166534'
        };
      case 'error':
        return {
          ...baseStyles,
          'background-color': '#fee2e2',
          'border-left': '4px solid #ef4444',
          'color': '#7f1d1d'
        };
      case 'warning':
        return {
          ...baseStyles,
          'background-color': '#fef3c7',
          'border-left': '4px solid #f59e0b',
          'color': '#78350f'
        };
      case 'info':
      default:
        return {
          ...baseStyles,
          'background-color': '#dbeafe',
          'border-left': '4px solid #3b82f6',
          'color': '#1e3a8a'
        };
    }
  }
}
