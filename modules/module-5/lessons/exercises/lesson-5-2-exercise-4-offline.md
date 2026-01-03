---
layout: exercise
title: "Exercício 5.2.4: Funcionalidades Offline"
slug: "offline"
lesson_id: "lesson-5-2"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **funcionalidades offline** através da **implementação de funcionalidades offline usando Service Worker**.

Ao completar este exercício, você será capaz de:

- Implementar cache offline
- Criar estratégias de cache
- Implementar background sync
- Gerenciar dados offline
- Sincronizar quando online

---

## Descrição

Você precisa implementar funcionalidades offline completas para uma aplicação de tarefas.

### Contexto

Uma aplicação precisa funcionar completamente offline e sincronizar quando voltar online.

### Tarefa

Crie:

1. **Cache Strategy**: Implementar estratégia de cache
2. **Offline Storage**: Armazenar dados offline
3. **Background Sync**: Sincronizar quando online
4. **Offline UI**: Indicar status offline
5. **Sync**: Sincronizar dados

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Cache strategy implementada
- [ ] Dados armazenados offline
- [ ] Background sync funciona
- [ ] UI indica status offline
- [ ] Sincronização funciona

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Funcionalidades offline estão completas
- [ ] Sincronização funciona corretamente

---

## Solução Esperada

### Abordagem Recomendada

**ngsw-config.json**
```json
{
  "$schema": "./node_modules/@angular/service-worker/config/schema.json",
  "index": "/index.html",
  "assetGroups": [
    {
      "name": "app",
      "installMode": "prefetch",
      "updateMode": "prefetch",
      "resources": {
        "files": [
          "/favicon.ico",
          "/index.html",
          "/*.css",
          "/*.js"
        ]
      }
    }
  ],
  "dataGroups": [
    {
      "name": "api-cache",
      "urls": ["/api/tasks"],
      "cacheConfig": {
        "strategy": "freshness",
        "maxAge": "1h",
        "timeout": "5s",
        "maxEntries": 100
      }
    },
    {
      "name": "api-offline",
      "urls": ["/api/tasks"],
      "cacheConfig": {
        "strategy": "performance",
        "maxAge": "7d",
        "maxEntries": 50
      }
    }
  ]
}
```

**offline.service.ts**
```typescript
import { Injectable, signal } from '@angular/core';
import { SwUpdate } from '@angular/service-worker';
import { NetworkStatus } from '@capacitor/network';

@Injectable({
  providedIn: 'root'
})
export class OfflineService {
  isOnline = signal(navigator.onLine);
  pendingSync = signal<any[]>([]);

  constructor(private swUpdate: SwUpdate) {
    this.setupNetworkListeners();
  }

  private setupNetworkListeners(): void {
    window.addEventListener('online', () => {
      this.isOnline.set(true);
      this.syncPending();
    });

    window.addEventListener('offline', () => {
      this.isOnline.set(false);
    });
  }

  addToPending(data: any): void {
    const pending = this.pendingSync();
    this.pendingSync.set([...pending, data]);
    this.storePending();
  }

  private storePending(): void {
    localStorage.setItem('pendingSync', JSON.stringify(this.pendingSync()));
  }

  private loadPending(): void {
    const stored = localStorage.getItem('pendingSync');
    if (stored) {
      this.pendingSync.set(JSON.parse(stored));
    }
  }

  async syncPending(): Promise<void> {
    if (!this.isOnline()) {
      return;
    }

    const pending = this.pendingSync();
    if (pending.length === 0) {
      return;
    }

    try {
      for (const item of pending) {
        await this.syncItem(item);
      }
      this.pendingSync.set([]);
      localStorage.removeItem('pendingSync');
    } catch (error) {
      console.error('Sync failed:', error);
    }
  }

  private async syncItem(item: any): Promise<void> {
    const response = await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(item)
    });
    
    if (!response.ok) {
      throw new Error('Sync failed');
    }
  }
}
```

**task.service.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { OfflineService } from './offline.service';

@Injectable({
  providedIn: 'root'
})
export class TaskService {
  private http = inject(HttpClient);
  private offlineService = inject(OfflineService);

  createTask(task: any): Observable<any> {
    if (!this.offlineService.isOnline()) {
      this.offlineService.addToPending(task);
      return of({ ...task, id: Date.now(), synced: false });
    }

    return this.http.post('/api/tasks', task).pipe(
      catchError(error => {
        this.offlineService.addToPending(task);
        return of({ ...task, id: Date.now(), synced: false });
      })
    );
  }
}
```

**offline-indicator.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { OfflineService } from './offline.service';

@Component({
  selector: 'app-offline-indicator',
  standalone: true,
  imports: [CommonModule],
  template: `
    @if (!isOnline()) {
      <div class="offline-banner">
        <span>Você está offline. Mudanças serão sincronizadas quando voltar online.</span>
      </div>
    }
  `,
  styles: [`
    .offline-banner {
      background: #f44336;
      color: white;
      padding: 1rem;
      text-align: center;
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 1000;
    }
  `]
})
export class OfflineIndicatorComponent {
  isOnline = this.offlineService.isOnline;

  constructor(private offlineService: OfflineService) {}
}
```

**Explicação da Solução**:

1. ngsw-config.json configura cache strategies
2. OfflineService gerencia estado offline
3. TaskService adapta para offline
4. Dados pendentes armazenados em localStorage
5. Background sync quando volta online
6. UI indica status offline

---

## Testes

### Casos de Teste

**Teste 1**: Offline funciona
- **Input**: Desconectar internet
- **Output Esperado**: Aplicação funciona offline

**Teste 2**: Sync funciona
- **Input**: Voltar online
- **Output Esperado**: Dados sincronizados

**Teste 3**: UI indica offline
- **Input**: Verificar interface
- **Output Esperado**: Banner offline visível

---

## Extensões (Opcional)

1. **IndexedDB**: Use IndexedDB para storage
2. **Conflict Resolution**: Resolva conflitos de sync
3. **Optimistic Updates**: Implemente updates otimistas

---

## Referências Úteis

- **[Service Worker Cache](https://developer.mozilla.org/en-US/docs/Web/API/Cache)**: MDN Cache API
- **[Background Sync](https://developer.mozilla.org/en-US/docs/Web/API/Background_Sync_API)**: MDN Background Sync

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

