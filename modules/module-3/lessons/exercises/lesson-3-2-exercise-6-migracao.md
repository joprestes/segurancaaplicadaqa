---
layout: exercise
title: "Exercício 3.2.6: Migração Observables para Signals"
slug: "migracao"
lesson_id: "lesson-3-2"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **migração de Observables para Signals** através da **conversão de componente existente**.

Ao completar este exercício, você será capaz de:

- Identificar quando migrar para Signals
- Converter Observables para Signals
- Usar toSignal() para integração
- Manter compatibilidade durante migração
- Aplicar estratégias de migração

---

## Descrição

Você precisa migrar um componente que usa Observables para usar Signals, mantendo funcionalidade.

### Contexto

Uma aplicação existente precisa ser migrada para Signal-First Architecture.

### Tarefa

Crie:

1. **Componente Original**: Componente usando Observables
2. **Componente Migrado**: Versão usando Signals
3. **Comparação**: Demonstre diferenças
4. **Integração**: Use toSignal() onde necessário

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente original criado
- [ ] Componente migrado criado
- [ ] Funcionalidade mantida
- [ ] toSignal() usado onde apropriado
- [ ] Comparação demonstrada
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Migração está completa
- [ ] Código é melhorado

---

## Solução Esperada

### Abordagem Recomendada

**user-list-observable.component.ts** (Original)
{% raw %}
```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject, Subscription } from 'rxjs';
import { map } from 'rxjs/operators';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-user-list-observable',
  standalone: true,
  imports: [CommonModule],
{% raw %}
  template: `
    <div>
      <h2>User List (Observable)</h2>
      <input 
        #searchInput
        (input)="searchTerm$.next(searchInput.value)"
        placeholder="Buscar...">
      <ul>
        @for (user of users$ | async; track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class UserListObservableComponent implements OnInit, OnDestroy {
  users$: Observable<User[]>;
  searchTerm$ = new BehaviorSubject<string>('');
  private subscription?: Subscription;
  
  constructor(private http: HttpClient) {
    this.users$ = this.searchTerm$.pipe(
      map(term => this.filterUsers(term))
    );
  }
  
  ngOnInit(): void {
    this.subscription = this.http.get<User[]>('/api/users').subscribe(
      users => {
        this.allUsers = users;
        this.searchTerm$.next('');
      }
    );
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }
  
  private allUsers: User[] = [];
  
  private filterUsers(term: string): User[] {
    if (!term) return this.allUsers;
    return this.allUsers.filter(u => 
      u.name.toLowerCase().includes(term.toLowerCase())
    );
  }
}
```
{% endraw %}

**user-list-signal.component.ts** (Migrado)
```typescript
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-user-list-signal',
  standalone: true,
  imports: [CommonModule],
{% raw %}
  template: `
    <div>
      <h2>User List (Signal)</h2>
      <input 
        #searchInput
        (input)="searchTerm.set(searchInput.value)"
        placeholder="Buscar...">
      <ul>
        @for (user of filteredUsers(); track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class UserListSignalComponent {
  private http = inject(HttpClient);
  
  users = toSignal(
    this.http.get<User[]>('/api/users'),
    { initialValue: [] }
  );
  
  searchTerm = signal<string>('');
  
  filteredUsers = computed(() => {
    const users = this.users();
    const term = this.searchTerm().toLowerCase();
    
    if (!term) return users;
    
    return users.filter(u => 
      u.name.toLowerCase().includes(term)
    );
  });
}
```

**Explicação da Solução**:

1. Observable HTTP convertido para Signal com toSignal()
2. BehaviorSubject substituído por signal()
3. Observable pipe substituído por computed()
4. async pipe substituído por computed()
5. Subscription management removido (não necessário)
6. Código mais simples e performático

---

## Testes

### Casos de Teste

**Teste 1**: Funcionalidade mantida
- **Input**: Buscar usuários
- **Output Esperado**: Funciona igual ao original

**Teste 2**: Performance melhorada
- **Input**: Comparar performance
- **Output Esperado**: Signal version mais rápida

**Teste 3**: Código mais simples
- **Input**: Comparar código
- **Output Esperado**: Menos código, mais legível

---

## Extensões (Opcional)

1. **Migração Gradual**: Migre gradualmente mantendo compatibilidade
2. **Híbrido**: Mantenha Observables onde faz sentido
3. **Benchmark**: Compare performance real

---

## Referências Úteis

- **[Migration Guide](https://angular.io/guide/signals#migrating-from-observables)**: Guia migração
- **[toSignal()](https://angular.io/api/core/rxjs-interop/toSignal)**: Documentação toSignal()

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

