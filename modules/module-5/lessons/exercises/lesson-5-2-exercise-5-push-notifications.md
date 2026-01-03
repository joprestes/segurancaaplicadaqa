---
layout: exercise
title: "Exercício 5.2.5: Push Notifications"
slug: "push-notifications"
lesson_id: "lesson-5-2"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **push notifications** através da **implementação de push notifications em PWA**.

Ao completar este exercício, você será capaz de:

- Entender Web Push API
- Solicitar permissão de notificação
- Enviar push notifications
- Receber push notifications
- Gerenciar subscriptions
- Tratar notificações no Service Worker

---

## Descrição

Você precisa implementar push notifications para uma aplicação PWA.

### Contexto

Uma aplicação precisa enviar notificações push para usuários.

### Tarefa

Crie:

1. **Subscription**: Solicitar subscription
2. **Backend**: Criar endpoint para enviar notificações
3. **Service Worker**: Tratar notificações
4. **UI**: Gerenciar permissões
5. **Teste**: Enviar e receber notificações

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Subscription solicitada
- [ ] Endpoint backend criado
- [ ] Service Worker trata notificações
- [ ] UI gerencia permissões
- [ ] Notificações funcionam

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Push notifications estão implementadas corretamente
- [ ] Notificações funcionam

---

## Solução Esperada

### Abordagem Recomendada

**push-notification.service.ts**
```typescript
import { Injectable, signal } from '@angular/core';
import { SwPush } from '@angular/service-worker';

const VAPID_PUBLIC_KEY = 'YOUR_VAPID_PUBLIC_KEY';

@Injectable({
  providedIn: 'root'
})
export class PushNotificationService {
  subscription = signal<PushSubscription | null>(null);
  isSupported = signal('serviceWorker' in navigator && 'PushManager' in window);

  constructor(private swPush: SwPush) {
    this.checkSubscription();
  }

  async requestPermission(): Promise<boolean> {
    if (!this.isSupported()) {
      return false;
    }

    try {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    } catch (error) {
      console.error('Permission request failed:', error);
      return false;
    }
  }

  async subscribe(): Promise<PushSubscription | null> {
    if (!this.isSupported()) {
      return null;
    }

    try {
      const sub = await this.swPush.requestSubscription({
        serverPublicKey: VAPID_PUBLIC_KEY
      });
      
      this.subscription.set(sub);
      await this.sendSubscriptionToServer(sub);
      return sub;
    } catch (error) {
      console.error('Subscription failed:', error);
      return null;
    }
  }

  async unsubscribe(): Promise<void> {
    const sub = this.subscription();
    if (sub) {
      await sub.unsubscribe();
      this.subscription.set(null);
      await this.removeSubscriptionFromServer(sub);
    }
  }

  private async checkSubscription(): Promise<void> {
    if (!this.isSupported()) {
      return;
    }

    try {
      const registration = await navigator.serviceWorker.ready;
      const sub = await registration.pushManager.getSubscription();
      this.subscription.set(sub);
    } catch (error) {
      console.error('Check subscription failed:', error);
    }
  }

  private async sendSubscriptionToServer(sub: PushSubscription): Promise<void> {
    await fetch('/api/push/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(sub)
    });
  }

  private async removeSubscriptionFromServer(sub: PushSubscription): Promise<void> {
    await fetch('/api/push/unsubscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(sub)
    });
  }
}
```

**notification-settings.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { PushNotificationService } from './push-notification.service';

@Component({
  selector: 'app-notification-settings',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Notificações Push</h2>
      
      @if (!isSupported()) {
        <p>Push notifications não são suportadas neste navegador.</p>
      } @else {
        @if (subscription()) {
          <p>Você está inscrito para receber notificações.</p>
          <button (click)="unsubscribe()">Cancelar Inscrição</button>
        } @else {
          <button (click)="subscribe()">Ativar Notificações</button>
        }
      }
    </div>
  `
})
export class NotificationSettingsComponent {
  isSupported = this.pushService.isSupported;
  subscription = this.pushService.subscription;

  constructor(private pushService: PushNotificationService) {}

  async subscribe(): Promise<void> {
    const granted = await this.pushService.requestPermission();
    if (granted) {
      await this.pushService.subscribe();
    }
  }

  async unsubscribe(): Promise<void> {
    await this.pushService.unsubscribe();
  }
}
```

**ngsw-worker.js** (customizado)
```javascript
self.addEventListener('push', (event) => {
  const options = {
    body: event.data ? event.data.text() : 'Nova notificação',
    icon: '/assets/icons/icon-192x192.png',
    badge: '/assets/icons/icon-72x72.png',
    vibrate: [200, 100, 200],
    tag: 'notification',
    requireInteraction: true
  };

  event.waitUntil(
    self.registration.showNotification('Task Manager', options)
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  event.waitUntil(
    clients.openWindow('/')
  );
});
```

**backend-endpoint.ts** (exemplo)
```typescript
import { webpush } from 'web-push';

const VAPID_PUBLIC_KEY = 'YOUR_VAPID_PUBLIC_KEY';
const VAPID_PRIVATE_KEY = 'YOUR_VAPID_PRIVATE_KEY';

webpush.setVapidDetails(
  'mailto:your-email@example.com',
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY
);

export async function sendPushNotification(subscription: PushSubscription, payload: any) {
  try {
    await webpush.sendNotification(subscription, JSON.stringify(payload));
  } catch (error) {
    console.error('Push notification failed:', error);
  }
}
```

**Explicação da Solução**:

1. PushNotificationService gerencia subscriptions
2. SwPush usado para subscription
3. VAPID keys necessárias para push
4. Service Worker trata eventos push
5. Backend envia notificações
6. UI gerencia permissões e subscriptions

---

## Testes

### Casos de Teste

**Teste 1**: Permissão solicitada
- **Input**: Solicitar permissão
- **Output Esperado**: Permissão concedida

**Teste 2**: Subscription funciona
- **Input**: Subscrever
- **Output Esperado**: Subscription criada

**Teste 3**: Notificação recebida
- **Input**: Enviar notificação
- **Output Esperado**: Notificação exibida

---

## Extensões (Opcional)

1. **Rich Notifications**: Adicione imagens e ações
2. **Notification Actions**: Adicione botões de ação
3. **Badge Updates**: Atualize badge do app

---

## Referências Úteis

- **[Web Push API](https://developer.mozilla.org/en-US/docs/Web/API/Push_API)**: MDN Push API
- **[Notification API](https://developer.mozilla.org/en-US/docs/Web/API/Notifications_API)**: MDN Notification API
- **[VAPID](https://tools.ietf.org/html/rfc8292)**: RFC VAPID

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

