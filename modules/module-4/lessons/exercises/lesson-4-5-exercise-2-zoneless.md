---
layout: exercise
title: "Exercício 4.5.2: Aplicação Zoneless"
slug: "zoneless"
lesson_id: "lesson-4-5"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **aplicação zoneless** através da **criação de aplicação completa usando zoneless change detection**.

Ao completar este exercício, você será capaz de:

- Configurar aplicação zoneless
- Usar Signals para reatividade
- Entender diferenças de aplicações zoneless
- Criar aplicação sem Zone.js
- Aplicar padrões zoneless

---

## Descrição

Você precisa criar uma aplicação completa usando zoneless change detection.

### Contexto

Uma aplicação precisa ser criada usando zoneless change detection para melhor performance.

### Tarefa

Crie:

1. **Configuração**: Configurar zoneless change detection
2. **Componentes**: Criar componentes usando Signals
3. **Aplicação**: Aplicação completa funcional
4. **Verificação**: Verificar que funciona sem Zone.js

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Zoneless configurado
- [ ] Signals usados para reatividade
- [ ] Aplicação completa e funcional
- [ ] Sem dependências de Zone.js
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Zoneless está configurado corretamente
- [ ] Aplicação é funcional

---

## Solução Esperada

### Abordagem Recomendada

**main.ts**
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';

bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection(),
    provideRouter(routes),
    provideHttpClient()
  ]
});
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';

bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection(),
    provideRouter(routes),
    provideHttpClient()
  ]
});
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';

bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection(),
    provideRouter(routes),
    provideHttpClient()
  ]
});
```

**app.component.ts**
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './header/header.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, HeaderComponent],
  template: `
    <div class="app">
      <app-header [title]="appTitle()"></app-header>
      <main>
        <router-outlet></router-outlet>
      </main>
      <footer>
{% raw %}

        <p>Versão: {{ version() }}</p>
{% endraw %}

      </footer>
    </div>
  `
})
export class AppComponent {
  appTitle = signal('Zoneless App');
  version = signal('1.0.0');
}
{% raw %}
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './header/header.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, HeaderComponent],
  template: `
    <div class="app">
      <app-header [title]="appTitle()"></app-header>
      <main>
        <router-outlet></router-outlet>
      </main>
      <footer>
        <p>Versão: {{ version() }}</p>
      </footer>
    </div>
  `
})
export class AppComponent {
  appTitle = signal('Zoneless App');
  version = signal('1.0.0');
}
```typescript
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './header/header.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, HeaderComponent],
  template: `
    <div class="app">
      <app-header [title]="appTitle()"></app-header>
      <main>
        <router-outlet></router-outlet>
      </main>
      <footer>
        <p>Versão: {{ version() }}</p>
      </footer>
    </div>
  `
})
export class AppComponent {
  appTitle = signal('Zoneless App');
  version = signal('1.0.0');
}
```
{% endraw %}

**counter.component.ts**
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="counter">
      <h2>Contador (Zoneless)</h2>
{% raw %}

      <p>Valor: {{ count() }}</p>
{% endraw %}

      <p>Dobro: {{ doubleCount() }}</p>

      <div class="buttons">
        <button (click)="increment()">+</button>
        <button (click)="decrement()">-</button>
        <button (click)="reset()">Reset</button>
      </div>
    </div>
  `,
  styles: [`
    .counter {
      padding: 2rem;
      border: 1px solid #ccc;
      border-radius: 8px;
      max-width: 400px;
      margin: 2rem auto;
    }
    
    .buttons {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
    }
    
    button {
      flex: 1;
      padding: 0.75rem;
      background: #3498db;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
  `]
})
export class CounterComponent {
  count = signal(0);
  doubleCount = computed(() => this.count() * 2);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
  
  decrement(): void {
    this.count.update(v => v - 1);
  }
  
  reset(): void {
    this.count.set(0);
  }
}
{% raw %}
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="counter">
      <h2>Contador (Zoneless)</h2>
      <p>Valor: {{ count() }}</p>
      <p>Dobro: {{ doubleCount() }}</p>
      <div class="buttons">
        <button (click)="increment()">+</button>
        <button (click)="decrement()">-</button>
        <button (click)="reset()">Reset</button>
      </div>
    </div>
  `,
  styles: [`
    .counter {
      padding: 2rem;
      border: 1px solid #ccc;
      border-radius: 8px;
      max-width: 400px;
      margin: 2rem auto;
    }
    
    .buttons {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
    }
    
    button {
      flex: 1;
      padding: 0.75rem;
      background: #3498db;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
  `]
})
export class CounterComponent {
  count = signal(0);
  doubleCount = computed(() => this.count() * 2);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
  
  decrement(): void {
    this.count.update(v => v - 1);
  }
  
  reset(): void {
    this.count.set(0);
  }
}
```typescript
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="counter">
      <h2>Contador (Zoneless)</h2>
      <p>Valor: {{ count() }}</p>
      <p>Dobro: {{ doubleCount() }}</p>
      <div class="buttons">
        <button (click)="increment()">+</button>
        <button (click)="decrement()">-</button>
        <button (click)="reset()">Reset</button>
      </div>
    </div>
  `,
  styles: [`
    .counter {
      padding: 2rem;
      border: 1px solid #ccc;
      border-radius: 8px;
      max-width: 400px;
      margin: 2rem auto;
    }
    
    .buttons {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
    }
    
    button {
      flex: 1;
      padding: 0.75rem;
      background: #3498db;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
  `]
})
export class CounterComponent {
  count = signal(0);
  doubleCount = computed(() => this.count() * 2);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
  
  decrement(): void {
    this.count.update(v => v - 1);
  }
  
  reset(): void {
    this.count.set(0);
  }
}
```
{% endraw %}

**user-list.component.ts**
import { Component, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Usuários (Zoneless)</h2>
      <button (click)="loadUsers()">Carregar Usuários</button>
      
      @if (loading()) {
        <p>Carregando...</p>
      }
      
      <ul>
        @for (user of users(); track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
      
{% raw %}

      <p>Total: {{ userCount() }}</p>
{% endraw %}

    </div>
  `
})
export class UserListComponent {
  private http = inject(HttpClient);
  
  loading = signal(false);
  users = signal<User[]>([]);
  
  userCount = computed(() => this.users().length);
  
  loadUsers(): void {
    this.loading.set(true);
    this.http.get<User[]>('/api/users').subscribe({
      next: (users) => {
        this.users.set(users);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      }
    });
  }
}
{% raw %}
import { Component, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Usuários (Zoneless)</h2>
      <button (click)="loadUsers()">Carregar Usuários</button>
      
      @if (loading()) {
        <p>Carregando...</p>
      }
      
      <ul>
        @for (user of users(); track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
      
      <p>Total: {{ userCount() }}</p>
    </div>
  `
})
export class UserListComponent {
  private http = inject(HttpClient);
  
  loading = signal(false);
  users = signal<User[]>([]);
  
  userCount = computed(() => this.users().length);
  
  loadUsers(): void {
    this.loading.set(true);
    this.http.get<User[]>('/api/users').subscribe({
      next: (users) => {
        this.users.set(users);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      }
    });
  }
}
```typescript
import { Component, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Usuários (Zoneless)</h2>
      <button (click)="loadUsers()">Carregar Usuários</button>
      
      @if (loading()) {
        <p>Carregando...</p>
      }
      
      <ul>
        @for (user of users(); track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
      
      <p>Total: {{ userCount() }}</p>
    </div>
  `
})
export class UserListComponent {
  private http = inject(HttpClient);
  
  loading = signal(false);
  users = signal<User[]>([]);
  
  userCount = computed(() => this.users().length);
  
  loadUsers(): void {
    this.loading.set(true);
    this.http.get<User[]>('/api/users').subscribe({
      next: (users) => {
        this.users.set(users);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      }
    });
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. provideExperimentalZonelessChangeDetection() configurado
2. Todos componentes usam Signals
3. Computed signals para valores derivados
4. toSignal() usado para HTTP
5. Aplicação funciona sem Zone.js
6. Performance melhorada

---

## Testes

### Casos de Teste

**Teste 1**: Zoneless funciona
- **Input**: Usar aplicação
- **Output Esperado**: Tudo funciona corretamente

**Teste 2**: Signals funcionam
- **Input**: Interagir com componentes
- **Output Esperado**: Reatividade funciona

**Teste 3**: Performance melhorada
- **Input**: Comparar com Zone.js
- **Output Esperado**: Melhor performance

---

## Extensões (Opcional)

1. **Router**: Integre router em zoneless
2. **Forms**: Use forms em zoneless
3. **NgRx**: Integre NgRx em zoneless

---

## Referências Úteis

- **[Zoneless Change Detection](https://angular.io/guide/zoneless-change-detection)**: Guia zoneless
- **[provideExperimentalZonelessChangeDetection](https://angular.io/api/core/provideExperimentalZonelessChangeDetection)**: Documentação

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

