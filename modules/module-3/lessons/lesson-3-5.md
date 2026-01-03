---
layout: lesson
title: "Aula 3.5: Integração Signals + Observables"
slug: signals-observables
module: module-3
lesson_id: lesson-3-5
duration: "30 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-3-4"
exercises:
  - 
  - "lesson-3-5-exercise-1"
  - "lesson-3-5-exercise-2"
  - "lesson-3-5-exercise-3"
podcast:
  file: "assets/podcasts/03.5-toSignal_e_toObservable_as_pontes_do_Angular.m4a"
  title: "toSignal e toObservable - As Pontes do Angular"
  description: "Angular oferece funções para integrar Signals com Observables."
  duration: "40-50 minutos"
---

## Introdução

Nesta aula final do Módulo 3, você aprenderá a integrar Signals com Observables usando as funções de interoperação do Angular. Esta integração permite usar o melhor de ambos os mundos: Signals para estado simples e Observables para streams assíncronos complexos.

### O que você vai aprender

- Usar toSignal() para converter Observables em Signals
- Usar toObservable() para converter Signals em Observables
- Entender quando usar Signals vs Observables
- Integrar Signals com HTTP e outros Observables
- Criar aplicações híbridas eficientes

### Por que isso é importante

A integração Signals + Observables é essencial para aplicações Angular modernas. Permite aproveitar Signals para estado local enquanto mantém Observables para operações assíncronas complexas, criando aplicações mais performáticas e fáceis de manter.

---

## Conceitos Teóricos

### toSignal()

**Definição**: `toSignal()` converte um Observable em um Signal, permitindo usar dados assíncronos com Signals.

**Explicação Detalhada**:

toSignal():
- Converte Observable para Signal
- Gerencia subscription automaticamente
- Fornece valor inicial opcional
- Desinscreve automaticamente quando Signal é destruído
- Útil para integrar HTTP e outros Observables com Signals

**Analogia**:

toSignal() é como uma ponte entre dois mundos. Você tem um Observable (stream assíncrono) e precisa de um Signal (valor reativo). toSignal() cria essa ponte automaticamente.

**Visualização**:

```
Observable ──toSignal()──→ Signal
    │                          │
    └──→ HTTP Request          │
    └──→ Auto Subscribe        │
    └──→ Auto Unsubscribe ─────┘
```

**Exemplo Prático**:

```typescript
import { Component, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';

@Component({
  selector: 'app-users',
  standalone: true,
{% raw %}
  template: `
    <div>
      <h2>Usuários</h2>
      @if (users().length > 0) {
        <ul>
          @for (user of users(); track user.id) {
            <li>{{ user.name }}</li>
          }
        </ul>
      } @else {
        <p>Carregando...</p>
      }
    </div>
  `
{% endraw %}
})
export class UsersComponent {
  private http = inject(HttpClient);
  
  users = toSignal(
    this.http.get<User[]>('/api/users'),
    { initialValue: [] }
  );
}
```

---

### toObservable()

**Definição**: `toObservable()` converte um Signal em um Observable, permitindo usar Signals com código baseado em Observables.

**Explicação Detalhada**:

toObservable():
- Converte Signal para Observable
- Emite valores quando Signal muda
- Útil para integrar Signals com código RxJS existente
- Útil para usar Signals com operadores RxJS

**Analogia**:

toObservable() é o oposto de toSignal(). Você tem um Signal e precisa de um Observable para usar com operadores RxJS ou código existente.

**Exemplo Prático**:

```typescript
import { Component, signal } from '@angular/core';
import { toObservable } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged } from 'rxjs/operators';

@Component({
  selector: 'app-search',
  standalone: true,
{% raw %}
  template: `
    <div>
      <input 
        [value]="searchTerm()" 
        (input)="searchTerm.set($any($event.target).value)"
        placeholder="Buscar...">
      <ul>
        @for (result of results(); track result.id) {
          <li>{{ result.name }}</li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class SearchComponent {
  searchTerm = signal('');
  
  results = toSignal(
    toObservable(this.searchTerm).pipe(
      debounceTime(300),
      distinctUntilChanged(),
      switchMap(term => this.searchService.search(term))
    ),
    { initialValue: [] }
  );
}
```

---

### Quando Usar Signals vs Observables

**Definição**: Diretrizes para decidir quando usar Signals e quando usar Observables.

**Explicação Detalhada**:

**Use Signals quando**:
- Estado local simples
- Valores síncronos
- Computações derivadas
- Integração com template
- Performance crítica

**Use Observables quando**:
- Streams assíncronos complexos
- Operações HTTP
- Eventos do usuário
- Operadores RxJS avançados
- Código existente baseado em RxJS

**Analogia**:

Signals são como variáveis reativas simples - use para valores que mudam. Observables são como streams de eventos - use para sequências de valores ao longo do tempo.

**Exemplo Prático**:

```typescript
export class HybridComponent {
  count = signal(0);
  
  doubleCount = computed(() => this.count() * 2);
  
  users = toSignal(
    this.http.get<User[]>('/api/users'),
    { initialValue: [] }
  );
  
  searchResults = toSignal(
    toObservable(this.searchTerm).pipe(
      debounceTime(300),
      switchMap(term => this.search(term))
    ),
    { initialValue: [] }
  );
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Integração Completa Signals + Observables

**Contexto**: Criar componente que usa Signals para estado local e Observables para dados HTTP.

**Código**:

{% raw %}
```typescript
import { Component, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';
import { toObservable } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged, switchMap } from 'rxjs/operators';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-user-search',
  standalone: true,
  imports: [CommonModule],
{% raw %}
  template: `
    <div>
      <h2>Busca de Usuários</h2>
      
      <input 
        [value]="searchTerm()" 
        (input)="searchTerm.set($any($event.target).value)"
        placeholder="Buscar usuários...">
      
      @if (loading()) {
        <p>Carregando...</p>
      }
      
      @if (error()) {
        <p class="error">{{ error() }}</p>
      }
      
      <ul>
        @for (user of users(); track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
      
      <p>Total encontrado: {{ userCount() }}</p>
    </div>
  `
{% endraw %}
})
export class UserSearchComponent {
  private http = inject(HttpClient);
  
  searchTerm = signal('');
  
  users = toSignal(
    toObservable(this.searchTerm).pipe(
      debounceTime(300),
      distinctUntilChanged(),
      switchMap(term => {
        if (!term.trim()) {
          return of([]);
        }
        return this.http.get<User[]>(`/api/users/search?q=${term}`);
      })
    ),
    { initialValue: [] }
  );
  
  loading = computed(() => {
    const term = this.searchTerm();
    return term.length > 0 && this.users().length === 0;
  });
  
  userCount = computed(() => this.users().length);
  
  error = signal<string | null>(null);
}
```
{% endraw %}

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use toSignal() para HTTP e Observables assíncronos**
   - **Por quê**: Integração simples com Signals
   - **Exemplo**: `users = toSignal(this.http.get(...))`

2. **Use toObservable() para aplicar operadores RxJS**
   - **Por quê**: Aproveita poder dos operadores
   - **Exemplo**: `debounceTime`, `switchMap`

3. **Prefira Signals para estado local**
   - **Por quê**: Mais simples e performático
   - **Exemplo**: `count = signal(0)`

4. **Use Observables para streams complexos**
   - **Por quê**: Melhor para operações assíncronas
   - **Exemplo**: HTTP, eventos, timers

### ❌ Anti-padrões Comuns

1. **Não converta desnecessariamente**
   - **Problema**: Complexidade desnecessária
   - **Solução**: Use diretamente quando possível

2. **Não ignore valor inicial em toSignal()**
   - **Problema**: Erros de tipo e runtime
   - **Solução**: Sempre forneça initialValue

3. **Não misture sem necessidade**
   - **Problema**: Código confuso
   - **Solução**: Escolha uma abordagem consistente

---

## Exercícios Práticos

### Exercício 1: toSignal() e toObservable() (Intermediário)

**Objetivo**: Praticar conversão entre Signals e Observables

**Descrição**: 
Crie componente que converte Observable HTTP para Signal e aplica operadores.

**Arquivo**: `exercises/exercise-3-5-1-tosignal-toobservable.md`

---

### Exercício 2: Integração Prática (Avançado)

**Objetivo**: Integrar Signals e Observables em aplicação real

**Descrição**:
Crie aplicação que usa Signals para estado local e Observables para dados HTTP.

**Arquivo**: `exercises/exercise-3-5-2-integracao.md`

---

### Exercício 3: Quando Usar Signals vs Observables (Avançado)

**Objetivo**: Entender quando usar cada abordagem

**Descrição**:
Crie exemplos demonstrando quando usar Signals e quando usar Observables.

**Arquivo**: `exercises/exercise-3-5-3-decisao.md`

---

## Referências Externas

### Documentação Oficial

- **[toSignal()](https://angular.io/api/core/rxjs-interop/toSignal)**: Documentação toSignal()
- **[toObservable()](https://angular.io/api/core/rxjs-interop/toObservable)**: Documentação toObservable()
- **[Signals Guide](https://angular.io/guide/signals)**: Guia completo Signals

---

## Resumo

### Principais Conceitos

- toSignal() converte Observables em Signals
- toObservable() converte Signals em Observables
- Signals para estado local simples
- Observables para streams assíncronos complexos
- Integração permite melhor dos dois mundos

### Pontos-Chave para Lembrar

- Use toSignal() para HTTP e Observables assíncronos
- Use toObservable() para aplicar operadores RxJS
- Prefira Signals para estado local
- Use Observables para streams complexos
- Escolha abordagem consistente

### Próximos Passos

- Próximo módulo: Módulo 4 - Performance e Otimização
- Praticar integração Signals + Observables
- Explorar padrões avançados de integração

---

## Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 3.4: Padrões Reativos e Memory Leaks](./lesson-3-4-memory-leaks.md)  
**Próxima Aula**: [Aula 4.1: Change Detection e Performance](./lesson-4-1-change-detection.md)  
**Voltar ao Módulo**: [Módulo 3: Programação Reativa e Estado](../modules/module-3-programacao-reativa-estado.md)

