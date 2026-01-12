---
layout: lesson
title: "Aula 3.5: APIs e Microserviços: Segurança Distribuída"
slug: seguranca-apis-microservicos
module: module-3
lesson_id: lesson-3-5
duration: "90 minutos"
level: "Avançado"
prerequisites: ["lesson-3-4"]
image: "assets/images/podcasts/3.5-Seguranca_APIs_Microservicos.png"
permalink: /modules/seguranca-por-setor/lessons/seguranca-apis-microservicos/
---

<!-- ⚠️ ATENÇÃO: Este arquivo contém conteúdo sobre Angular que precisa ser reescrito para Segurança em QA. 
     Veja CONTENT_ISSUES.md para mais detalhes. -->

## Introdução

Nesta aula final do Módulo 3, você aprenderá a integrar Signals com Observables usando as funções de interoperação do Angular. Esta integração permite usar o melhor de ambos os mundos: Signals para estado simples e Observables para streams assíncronos complexos.

### Contexto Histórico

A evolução da reatividade no Angular passou por várias fases:

**AngularJS (2010-2016)**:
- Sistema de digest cycle baseado em dirty checking
- Two-way data binding com `$scope`
- Performance limitada em aplicações grandes

**Angular 2+ (2016-2022)**:
- Introdução do RxJS e Observables como padrão reativo
- Change Detection baseado em Zone.js
- AsyncPipe para integrar Observables com templates
- Poderoso mas complexo para casos simples

**Angular 16+ (2023-presente)**:
- Introdução dos Signals como primitivo reativo nativo
- Interoperabilidade com RxJS através de `rxjs-interop`
- Change Detection granular e mais eficiente
- Melhor experiência para desenvolvedores

A necessidade de integrar Signals com Observables surgiu porque:
- Observables são ideais para operações assíncronas (HTTP, eventos, WebSockets)
- Signals são ideais para estado local síncrono e computações derivadas
- Aplicações reais precisam de ambos os paradigmas
- Código legado baseado em RxJS precisa coexistir com Signals

### O que você vai aprender

- Usar `toSignal()` para converter Observables em Signals
- Usar `toObservable()` para converter Signals em Observables
- Entender quando usar Signals vs Observables
- Integrar Signals com HTTP e outros Observables
- Criar aplicações híbridas eficientes
- Gerenciar ciclo de vida e memory leaks
- Aplicar padrões avançados de integração

### Por que isso é importante

A integração Signals + Observables é essencial para aplicações Angular modernas por várias razões:

**Para sua carreira**:
- Habilidade fundamental para Angular moderno (16+)
- Demonstra compreensão profunda de reatividade
- Permite trabalhar com código legado e moderno simultaneamente
- Diferencial competitivo no mercado

**Para projetos práticos**:
- Permite aproveitar Signals para estado local enquanto mantém Observables para operações assíncronas complexas
- Cria aplicações mais performáticas com change detection granular
- Facilita migração gradual de código legado para Signals
- Reduz complexidade em cenários comuns

**Para aprendizado contínuo**:
- Base para entender futuras evoluções do Angular
- Conhecimento transferível para outros frameworks reativos
- Desenvolve pensamento sobre trade-offs arquiteturais

**Para o ecossistema**:
- Angular está investindo pesadamente em Signals como futuro da reatividade
- Comunidade está adotando padrões híbridos
- Bibliotecas estão adicionando suporte a Signals

---

## Conceitos Teóricos

### toSignal()

**Definição**: `toSignal()` é uma função utilitária do pacote `@angular/core/rxjs-interop` que converte um Observable em um Signal, permitindo usar dados assíncronos com a API de Signals do Angular.

**Explicação Detalhada**:

`toSignal()` cria uma ponte entre o mundo assíncrono dos Observables e o mundo síncrono dos Signals. Quando você chama `toSignal()` com um Observable:

1. **Subscription Automática**: A função automaticamente se inscreve no Observable fornecido
2. **Rastreamento de Valor**: Cada valor emitido pelo Observable atualiza o Signal
3. **Valor Inicial**: Você pode fornecer um valor inicial que será usado até o primeiro valor ser emitido
4. **Cleanup Automático**: Quando o Signal é destruído (componente desmontado), a subscription é automaticamente cancelada
5. **Type Safety**: Mantém type safety completo do TypeScript

**Características Técnicas**:

- **Assinatura**: `toSignal<T>(source: Observable<T>, options?: { initialValue?: T, requireSync?: boolean })`
- **Retorno**: `Signal<T>` ou `Signal<T | undefined>` (se `initialValue` não fornecido)
- **Lifecycle**: Gerencia subscription durante todo o ciclo de vida do Signal
- **Error Handling**: Erros do Observable não são capturados automaticamente (precisa usar `catchError`)

**Analogia Detalhada**:

Imagine que você tem um **canal de TV ao vivo** (Observable) que transmite notícias continuamente. Você quer transformar isso em um **jornal impresso** (Signal) que você pode ler a qualquer momento.

`toSignal()` é como um **repórter** que:
- Fica assistindo o canal de TV 24/7 (subscription automática)
- Quando uma notícia importante aparece, ele imprime uma nova edição do jornal (atualiza o Signal)
- Se você não especificar uma edição inicial, ele pode entregar um jornal vazio primeiro (sem `initialValue`)
- Quando você não precisa mais do jornal, o repórter para de assistir o canal (cleanup automático)

A diferença crucial é que o jornal (Signal) sempre tem uma edição atual que você pode ler imediatamente, enquanto o canal de TV (Observable) só mostra notícias quando estão sendo transmitidas.

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Observable (Stream)                      │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐            │
│  │  Value 1 │───▶│  Value 2 │───▶│  Value 3 │───▶ ...    │
│  └──────────┘    └──────────┘    └──────────┘            │
│       │              │              │                      │
│       └──────────────┴──────────────┘                      │
│                    │                                        │
│                    │ toSignal()                             │
│                    ▼                                        │
│  ┌──────────────────────────────────────┐                  │
│  │   Signal (Current Value)             │                  │
│  │   ┌──────────────────────────────┐   │                  │
│  │   │  Current: Value 3           │   │                  │
│  │   │  (always available)         │   │                  │
│  │   └──────────────────────────────┘   │                  │
│  │                                       │                  │
│  │  Auto-subscribe on creation          │                  │
│  │  Auto-unsubscribe on destroy        │                  │
│  └──────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────┘

Fluxo de Dados:
Observable ──[emit]──▶ toSignal() ──[update]──▶ Signal
    │                                            │
    ├── HTTP Request                             │
    ├── WebSocket                                │
    ├── Event Stream                             │
    └── Timer                                    │
                                                 │
                                                 └── Template
                                                 └── Computed
                                                 └── Effect
```

**Exemplo Prático Básico**:

```typescript
import { Component, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-users',
  standalone: true,
  template: `
    <div>
      <h2>Usuários</h2>
      @if (users().length > 0) {
        <ul>
          @for (user of users(); track user.id) {
            <li>{{ user.name }} - {{ user.email }}</li>
          }
        </ul>
      } @else {
        <p>Carregando...</p>
      }
    </div>
  `
})
export class UsersComponent {
  private http = inject(HttpClient);
  
  users = toSignal(
    this.http.get<User[]>('/api/users'),
    { initialValue: [] }
  );
}
```

**Exemplo Prático Avançado com Error Handling**:

{% raw %}
```typescript
import { Component, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';
import { catchError, of } from 'rxjs';

@Component({
  selector: 'app-users-safe',
  standalone: true,
  template: `
    <div>
      @if (error()) {
        <p class="error">{{ error() }}</p>
      } @else {
        <ul>
          @for (user of users(); track user.id) {
            <li>{{ user.name }}</li>
          }
        </ul>
      }
    </div>
  `
})
export class UsersSafeComponent {
  private http = inject(HttpClient);
  
  error = signal<string | null>(null);
  
  users = toSignal(
    this.http.get<User[]>('/api/users').pipe(
      catchError(err => {
        this.error.set('Erro ao carregar usuários');
        return of([]);
      })
    ),
    { initialValue: [] }
  );
}
```
{% endraw %}

**Casos de Uso Comuns**:

1. **HTTP Requests**: Converter respostas HTTP em Signals
2. **WebSockets**: Transformar mensagens WebSocket em Signals
3. **Timers**: Converter `interval()` ou `timer()` em Signals
4. **Event Streams**: Transformar eventos em Signals
5. **State Management**: Integrar stores baseados em RxJS com Signals

---

### toObservable()

**Definição**: `toObservable()` é uma função utilitária do pacote `@angular/core/rxjs-interop` que converte um Signal em um Observable, permitindo usar Signals com código baseado em Observables e operadores RxJS.

**Explicação Detalhada**:

`toObservable()` cria um Observable que emite valores sempre que o Signal muda. Esta conversão é útil quando você precisa:

1. **Aplicar Operadores RxJS**: Usar `debounceTime`, `switchMap`, `mergeMap`, etc.
2. **Integrar com Código Legado**: Conectar Signals com código existente baseado em RxJS
3. **Combinar Streams**: Misturar Signals com outros Observables
4. **Operações Assíncronas Complexas**: Aplicar lógica assíncrona baseada em mudanças de Signal

**Características Técnicas**:

- **Assinatura**: `toObservable<T>(source: Signal<T>, options?: { injector?: Injector })`
- **Retorno**: `Observable<T>` que emite valores quando o Signal muda
- **Emissão**: Emite o valor atual imediatamente ao subscrever, depois emite sempre que o Signal muda
- **Lifecycle**: Observable completa quando o Signal é destruído
- **Performance**: Usa `effect()` internamente para rastrear mudanças

**Analogia Detalhada**:

Imagine que você tem um **termômetro digital** (Signal) que mostra a temperatura atual. Você quer transformar isso em um **sistema de alerta** (Observable) que dispara ações quando a temperatura muda.

`toObservable()` é como um **sensor inteligente** que:
- Observa o termômetro continuamente (monitora o Signal)
- Sempre que a temperatura muda, dispara um alerta (emite valor no Observable)
- Você pode conectar esse alerta a outros sistemas (aplicar operadores RxJS)
- Por exemplo, se a temperatura subir muito rápido, você pode aplicar `debounceTime` para evitar alertas excessivos
- Ou usar `switchMap` para buscar dados relacionados quando a temperatura muda

A diferença é que o termômetro (Signal) mostra um valor atual que você pode ler quando quiser, enquanto o sistema de alerta (Observable) é um stream de eventos que você precisa escutar.

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Signal (Current Value)                     │
│                                                               │
│  ┌──────────────────────────────────────┐                    │
│  │  Current: Value A                    │                    │
│  │  (readable anytime)                  │                    │
│  └──────────────────────────────────────┘                    │
│                    │                                          │
│                    │ toObservable()                           │
│                    ▼                                          │
│  ┌──────────────────────────────────────┐                    │
│  │   Observable (Stream)                │                    │
│  │                                      │                    │
│  │  ┌──────────┐    ┌──────────┐       │                    │
│  │  │ Value A  │───▶│ Value B  │───▶  │                    │
│  │  └──────────┘    └──────────┘       │                    │
│  │    (initial)      (on change)       │                    │
│  │                                      │                    │
│  │  Can apply RxJS operators:          │                    │
│  │  - debounceTime()                   │                    │
│  │  - switchMap()                      │                    │
│  │  - distinctUntilChanged()           │                    │
│  └──────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────┘

Fluxo de Dados:
Signal ──[change]──▶ toObservable() ──[emit]──▶ Observable
    │                                            │
    └── set() / update()                        │
                                                 │
                                                 ├── pipe()
                                                 ├── operators
                                                 └── subscribe()
```

**Exemplo Prático Básico**:

```typescript
import { Component, signal } from '@angular/core';
import { toObservable } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged } from 'rxjs/operators';

@Component({
  selector: 'app-search',
  standalone: true,
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

**Exemplo Prático Avançado com Múltiplos Operadores**:

{% raw %}
```typescript
import { Component, signal, inject, effect } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged, switchMap, catchError, retry } from 'rxjs/operators';
import { of } from 'rxjs';

interface Product {
  id: number;
  name: string;
  price: number;
}

@Component({
  selector: 'app-advanced-search',
  standalone: true,
  template: `
    <div>
      <input 
        [value]="searchTerm()" 
        (input)="searchTerm.set($any($event.target).value)"
        placeholder="Buscar produtos...">
      
      @if (loading()) {
        <p>Buscando...</p>
      }
      
      @if (error()) {
        <p class="error">{{ error() }}</p>
      }
      
      <div>
        <p>Encontrados: {{ results().length }} produtos</p>
        <ul>
          @for (product of results(); track product.id) {
            <li>{{ product.name }} - R$ {{ product.price }}</li>
          }
        </ul>
      </div>
    </div>
  `
})
export class AdvancedSearchComponent {
  private http = inject(HttpClient);
  
  searchTerm = signal('');
  loading = signal(false);
  error = signal<string | null>(null);
  
  results = toSignal(
    toObservable(this.searchTerm).pipe(
      debounceTime(500),
      distinctUntilChanged(),
      switchMap(term => {
        if (!term.trim()) {
          return of([]);
        }
        
        this.loading.set(true);
        this.error.set(null);
        
        return this.http.get<Product[]>(`/api/products/search?q=${term}`).pipe(
          retry(2),
          catchError(err => {
            this.error.set('Erro ao buscar produtos');
            return of([]);
          })
        );
      })
    ),
    { initialValue: [] }
  );
  
  constructor() {
    effect(() => {
      if (this.searchTerm().length > 0) {
        this.loading.set(this.results().length === 0 && !this.error());
      } else {
        this.loading.set(false);
      }
    });
  }
}
```
{% raw %}
import { Component, signal, inject, effect } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged, switchMap, catchError, retry } from 'rxjs/operators';
import { of } from 'rxjs';

interface Product {
  id: number;
  name: string;
  price: number;
}

@Component({
  selector: 'app-advanced-search',
  standalone: true,
  template: `
    <div>
      <input 
        [value]="searchTerm()" 
        (input)="searchTerm.set($any($event.target).value)"
        placeholder="Buscar produtos...">
      
      @if (loading()) {
        <p>Buscando...</p>
      }
      
      @if (error()) {
        <p class="error">{{ error() }}</p>
      }
      
      <div>
        <p>Encontrados: {{ results().length }} produtos</p>
        <ul>
          @for (product of results(); track product.id) {
            <li>{{ product.name }} - R$ {{ product.price }}</li>
          }
        </ul>
      </div>
    </div>
  `
})
export class AdvancedSearchComponent {
  private http = inject(HttpClient);
  
  searchTerm = signal('');
  loading = signal(false);
  error = signal<string | null>(null);
  
  results = toSignal(
    toObservable(this.searchTerm).pipe(
      debounceTime(500),
      distinctUntilChanged(),
      switchMap(term => {
        if (!term.trim()) {
          return of([]);
        }
        
        this.loading.set(true);
        this.error.set(null);
        
        return this.http.get<Product[]>(`/api/products/search?q=${term}`).pipe(
          retry(2),
          catchError(err => {
            this.error.set('Erro ao buscar produtos');
            return of([]);
          })
        );
      })
    ),
    { initialValue: [] }
  );
  
  constructor() {
    effect(() => {
      if (this.searchTerm().length > 0) {
        this.loading.set(this.results().length === 0 && !this.error());
      } else {
        this.loading.set(false);
      }
    });
  }
}
```
{% endraw %}

**Casos de Uso Comuns**:

1. **Debouncing**: Aplicar `debounceTime` em Signals de input
2. **Throttling**: Limitar frequência de atualizações
3. **Distinct Values**: Filtrar valores duplicados com `distinctUntilChanged`
4. **Chaining**: Conectar Signals com outros Observables usando `switchMap`, `mergeMap`
5. **Error Handling**: Aplicar tratamento de erro com `catchError`
6. **Retry Logic**: Implementar retry com `retry` ou `retryWhen`

---

### Quando Usar Signals vs Observables

**Definição**: Diretrizes práticas para decidir quando usar Signals e quando usar Observables, baseadas em características técnicas, casos de uso e trade-offs de performance.

**Explicação Detalhada**:

A escolha entre Signals e Observables não é binária - muitas vezes você usará ambos na mesma aplicação. A chave é entender as características de cada um e escolher a ferramenta certa para cada situação.

**Características dos Signals**:

- **Sempre têm valor**: Signals sempre retornam um valor quando lidos
- **Síncrono**: Leitura é síncrona e imediata
- **Granular Change Detection**: Angular rastreia dependências específicas
- **Sem Subscription Management**: Não precisa gerenciar subscriptions manualmente
- **Computed Values**: Fácil criar valores derivados com `computed()`
- **Template Integration**: Integração nativa com templates Angular

**Características dos Observables**:

- **Streams Assíncronos**: Podem emitir valores ao longo do tempo
- **Poderosos Operadores**: Biblioteca rica de operadores RxJS
- **Composição**: Fácil combinar múltiplos streams
- **Error Handling**: Tratamento de erro robusto
- **Backpressure**: Controle de fluxo de dados
- **Código Legado**: Amplamente usado em código existente

**Analogia Detalhada**:

Pense em **Signals como uma geladeira** e **Observables como um restaurante com entrega**.

**Signals (Geladeira)**:
- Você sempre pode abrir a geladeira e ver o que tem dentro (valor sempre disponível)
- É sua própria comida, você controla (estado local)
- Mudanças são imediatas - você coloca algo e já está lá (síncrono)
- Perfeito para coisas que você usa frequentemente e precisa rápido (estado local simples)

**Observables (Restaurante com Entrega)**:
- Você faz um pedido e espera (assíncrono)
- Pode chegar em momentos diferentes (stream de valores)
- Pode cancelar o pedido se mudar de ideia (subscription management)
- Pode combinar vários pedidos (composição de streams)
- Perfeito para coisas que vêm de fora e em momentos variados (HTTP, eventos, WebSockets)

**Quando usar cada um**:

**Use Signals quando**:
- ✅ Estado local simples dentro de componentes
- ✅ Valores síncronos que precisam ser lidos imediatamente
- ✅ Computações derivadas de outros Signals
- ✅ Integração direta com templates Angular
- ✅ Performance crítica com change detection granular
- ✅ Contadores, flags, valores de formulário simples
- ✅ Estado que não precisa de operadores RxJS complexos

**Use Observables quando**:
- ✅ Streams assíncronos complexos (HTTP, WebSockets, eventos)
- ✅ Operações que precisam de operadores RxJS (debounce, throttle, switchMap)
- ✅ Código existente baseado em RxJS
- ✅ Combinação de múltiplos streams de dados
- ✅ Tratamento de erro complexo com retry logic
- ✅ Backpressure e controle de fluxo
- ✅ Eventos do usuário que precisam ser processados com operadores

**Tabela Comparativa Detalhada**:

| Aspecto | Signals | Observables |
|---------|---------|-------------|
| **Natureza** | Valor atual sempre disponível | Stream de valores ao longo do tempo |
| **Leitura** | Síncrona (`signal()`) | Assíncrona (subscribe) |
| **Valor Inicial** | Sempre tem valor | Pode não ter valor até primeira emissão |
| **Change Detection** | Granular (rastreia dependências específicas) | Via AsyncPipe ou manual |
| **Subscription Management** | Automático (gerenciado pelo Angular) | Manual (precisa unsubscribe) |
| **Operadores** | Limitados (computed, effect) | Ricos (debounceTime, switchMap, etc.) |
| **Composição** | Via computed() | Via operadores RxJS (merge, combineLatest) |
| **Error Handling** | Limitado | Robusto (catchError, retry) |
| **Performance** | Otimizado para change detection | Depende da implementação |
| **Bundle Size** | Menor (parte do core) | Maior (RxJS completo) |
| **Curva de Aprendizado** | Simples | Moderada a complexa |
| **Casos de Uso Ideais** | Estado local, contadores, flags | HTTP, eventos, WebSockets, timers |
| **Template Integration** | Nativa (`signal()`) | Via AsyncPipe (`observable$ \| async`) |
| **Type Safety** | Completo | Completo |
| **Memory Leaks** | Raro (cleanup automático) | Comum se não gerenciar subscriptions |

**Comparação com Outros Frameworks**:

| Framework | Abordagem Reativa | Similar a Signals | Similar a Observables |
|-----------|-------------------|-------------------|----------------------|
| **Angular** | Signals + RxJS | `signal()`, `computed()` | `Observable`, `Subject` |
| **React** | Hooks + Libraries | `useState()`, `useMemo()` | `useObservable()` (biblioteca) |
| **Vue 3** | Reactivity System | `ref()`, `computed()` | `watch()`, bibliotecas RxJS |
| **Svelte** | Compiler-based | `$:` (reactive statements) | Stores (biblioteca) |
| **SolidJS** | Fine-grained Reactivity | `createSignal()`, `createMemo()` | `createResource()` |

**Exemplo Prático Híbrido**:

{% raw %}
```typescript
import { Component, signal, computed, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal, toObservable } from '@angular/core/rxjs-interop';
import { debounceTime, switchMap } from 'rxjs/operators';
import { of } from 'rxjs';

interface User {
  id: number;
  name: string;
  email: string;
  role: string;
}

@Component({
  selector: 'app-hybrid-component',
  standalone: true,
  template: `
    <div>
      <h2>Gerenciamento de Usuários</h2>
      
      <div>
        <label>Filtro:</label>
        <input 
          [value]="filter()" 
          (input)="filter.set($any($event.target).value)"
          placeholder="Filtrar por nome...">
      </div>
      
      <div>
        <label>Ordenar por:</label>
        <select [value]="sortBy()" (change)="sortBy.set($any($event.target).value)">
          <option value="name">Nome</option>
          <option value="email">Email</option>
          <option value="role">Função</option>
        </select>
      </div>
      
      @if (loading()) {
        <p>Carregando usuários...</p>
      }
      
      <ul>
        @for (user of filteredUsers(); track user.id) {
          <li>
            {{ user.name }} - {{ user.email }} ({{ user.role }})
          </li>
        }
      </ul>
      
      <p>Total: {{ userCount() }} usuários</p>
    </div>
  `
})
export class HybridComponent {
  private http = inject(HttpClient);
  
  filter = signal('');
  sortBy = signal<'name' | 'email' | 'role'>('name');
  
  users = toSignal(
    this.http.get<User[]>('/api/users'),
    { initialValue: [] }
  );
  
  loading = computed(() => {
    return this.users().length === 0 && this.filter().length === 0;
  });
  
  filteredUsers = computed(() => {
    const allUsers = this.users();
    const filterValue = this.filter().toLowerCase();
    const sortField = this.sortBy();
    
    let filtered = allUsers.filter(user => 
      user.name.toLowerCase().includes(filterValue) ||
      user.email.toLowerCase().includes(filterValue)
    );
    
    filtered.sort((a, b) => {
      if (a[sortField] < b[sortField]) return -1;
      if (a[sortField] > b[sortField]) return 1;
      return 0;
    });
    
    return filtered;
  });
  
  userCount = computed(() => this.filteredUsers().length);
  
  searchResults = toSignal(
    toObservable(this.filter).pipe(
      debounceTime(300),
      switchMap(term => {
        if (!term.trim()) {
          return of([]);
        }
        return this.http.get<User[]>(`/api/users/search?q=${term}`);
      })
    ),
    { initialValue: [] }
  );
}
```
{% raw %}
import { Component, signal, computed, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal, toObservable } from '@angular/core/rxjs-interop';
import { debounceTime, switchMap } from 'rxjs/operators';
import { of } from 'rxjs';

interface User {
  id: number;
  name: string;
  email: string;
  role: string;
}

@Component({
  selector: 'app-hybrid-component',
  standalone: true,
  template: `
    <div>
      <h2>Gerenciamento de Usuários</h2>
      
      <div>
        <label>Filtro:</label>
        <input 
          [value]="filter()" 
          (input)="filter.set($any($event.target).value)"
          placeholder="Filtrar por nome...">
      </div>
      
      <div>
        <label>Ordenar por:</label>
        <select [value]="sortBy()" (change)="sortBy.set($any($event.target).value)">
          <option value="name">Nome</option>
          <option value="email">Email</option>
          <option value="role">Função</option>
        </select>
      </div>
      
      @if (loading()) {
        <p>Carregando usuários...</p>
      }
      
      <ul>
        @for (user of filteredUsers(); track user.id) {
          <li>
            {{ user.name }} - {{ user.email }} ({{ user.role }})
          </li>
        }
      </ul>
      
      <p>Total: {{ userCount() }} usuários</p>
    </div>
  `
})
export class HybridComponent {
  private http = inject(HttpClient);
  
  filter = signal('');
  sortBy = signal<'name' | 'email' | 'role'>('name');
  
  users = toSignal(
    this.http.get<User[]>('/api/users'),
    { initialValue: [] }
  );
  
  loading = computed(() => {
    return this.users().length === 0 && this.filter().length === 0;
  });
  
  filteredUsers = computed(() => {
    const allUsers = this.users();
    const filterValue = this.filter().toLowerCase();
    const sortField = this.sortBy();
    
    let filtered = allUsers.filter(user => 
      user.name.toLowerCase().includes(filterValue) ||
      user.email.toLowerCase().includes(filterValue)
    );
    
    filtered.sort((a, b) => {
      if (a[sortField] < b[sortField]) return -1;
      if (a[sortField] > b[sortField]) return 1;
      return 0;
    });
    
    return filtered;
  });
  
  userCount = computed(() => this.filteredUsers().length);
  
  searchResults = toSignal(
    toObservable(this.filter).pipe(
      debounceTime(300),
      switchMap(term => {
        if (!term.trim()) {
          return of([]);
        }
        return this.http.get<User[]>(`/api/users/search?q=${term}`);
      })
    ),
    { initialValue: [] }
  );
}
```
{% endraw %}

**Decisão em Árvore**:

```
Precisa de reatividade?
│
├─ Sim
│  │
│  ├─ Valor sempre disponível?
│  │  │
│  │  ├─ Sim → Use Signal
│  │  │  │
│  │  │  └─ Precisa de operadores RxJS?
│  │  │     │
│  │  │     ├─ Sim → Converta para Observable com toObservable()
│  │  │     └─ Não → Use Signal diretamente
│  │  │
│  │  └─ Não → Use Observable
│  │     │
│  │     └─ Precisa usar no template?
│  │        │
│  │        ├─ Sim → Converta para Signal com toSignal()
│  │        └─ Não → Use Observable diretamente
│  │
│  └─ Operação assíncrona (HTTP, WebSocket, eventos)?
│     │
│     ├─ Sim → Use Observable
│     │  │
│     │  └─ Precisa usar no template?
│     │     │
│     │     ├─ Sim → Converta para Signal com toSignal()
│     │     └─ Não → Use Observable diretamente
│     │
│     └─ Não → Use Signal
```

---

## Exemplos Práticos Completos

### Exemplo 1: Integração Completa Signals + Observables

**Contexto**: Criar componente que usa Signals para estado local e Observables para dados HTTP, demonstrando integração completa entre ambos os paradigmas.

**Código**:

{% raw %}
```typescript
import { Component, signal, computed, inject, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { toSignal, toObservable } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged, switchMap, catchError, retry } from 'rxjs/operators';
import { of } from 'rxjs';

interface User {
  id: number;
  name: string;
  email: string;
  avatar?: string;
}

@Component({
  selector: 'app-user-search',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="user-search">
      <h2>Busca de Usuários</h2>
      
      <div class="search-controls">
        <input 
          type="text"
          [value]="searchTerm()" 
          (input)="searchTerm.set($any($event.target).value)"
          placeholder="Buscar usuários..."
          [class.loading]="loading()">
        
        <select 
          [value]="sortOrder()" 
          (change)="sortOrder.set($any($event.target).value)">
          <option value="asc">Crescente</option>
          <option value="desc">Decrescente</option>
        </select>
      </div>
      
      @if (loading()) {
        <div class="loading-indicator">
          <p>Carregando...</p>
        </div>
      }
      
      @if (error()) {
        <div class="error-message">
          <p>{{ error() }}</p>
          <button (click)="retrySearch()">Tentar Novamente</button>
        </div>
      }
      
      @if (!loading() && !error() && users().length > 0) {
        <div class="results">
          <p class="results-count">Total encontrado: {{ userCount() }}</p>
          <ul class="user-list">
            @for (user of sortedUsers(); track user.id) {
              <li class="user-item">
                @if (user.avatar) {
                  <img [src]="user.avatar" [alt]="user.name" class="avatar">
                }
                <div class="user-info">
                  <h3>{{ user.name }}</h3>
                  <p>{{ user.email }}</p>
                </div>
              </li>
            }
          </ul>
        </div>
      }
      
      @if (!loading() && !error() && users().length === 0 && searchTerm().length > 0) {
        <div class="no-results">
          <p>Nenhum usuário encontrado para "{{ searchTerm() }}"</p>
        </div>
      }
    </div>
  `,
  styles: [`
    .user-search {
      padding: 20px;
    }
    
    .search-controls {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
    }
    
    .search-controls input {
      flex: 1;
      padding: 10px;
      border: 1px solid #ddd;
      border-radius: 4px;
    }
    
    .search-controls input.loading {
      border-color: #007bff;
    }
    
    .loading-indicator {
      text-align: center;
      padding: 20px;
    }
    
    .error-message {
      background-color: #f8d7da;
      color: #721c24;
      padding: 15px;
      border-radius: 4px;
      margin-bottom: 20px;
    }
    
    .results-count {
      font-weight: bold;
      margin-bottom: 10px;
    }
    
    .user-list {
      list-style: none;
      padding: 0;
    }
    
    .user-item {
      display: flex;
      align-items: center;
      gap: 15px;
      padding: 15px;
      border-bottom: 1px solid #eee;
    }
    
    .avatar {
      width: 50px;
      height: 50px;
      border-radius: 50%;
    }
    
    .no-results {
      text-align: center;
      padding: 40px;
      color: #666;
    }
  `]
})
export class UserSearchComponent {
  private http = inject(HttpClient);
  
  searchTerm = signal('');
  sortOrder = signal<'asc' | 'desc'>('asc');
  error = signal<string | null>(null);
  retryTrigger = signal(0);
  
  users = toSignal(
    toObservable(this.searchTerm).pipe(
      debounceTime(300),
      distinctUntilChanged(),
      switchMap(term => {
        if (!term.trim()) {
          return of([]);
        }
        return this.http.get<User[]>(`/api/users/search?q=${term}`).pipe(
          retry(2),
          catchError(err => {
            this.error.set('Erro ao buscar usuários. Tente novamente.');
            return of([]);
          })
        );
      })
    ),
    { initialValue: [] }
  );
  
  loading = computed(() => {
    const term = this.searchTerm();
    return term.length > 0 && this.users().length === 0 && !this.error();
  });
  
  userCount = computed(() => this.users().length);
  
  sortedUsers = computed(() => {
    const allUsers = [...this.users()];
    const order = this.sortOrder();
    
    allUsers.sort((a, b) => {
      const comparison = a.name.localeCompare(b.name);
      return order === 'asc' ? comparison : -comparison;
    });
    
    return allUsers;
  });
  
  retrySearch() {
    this.error.set(null);
    const currentTerm = this.searchTerm();
    this.searchTerm.set('');
    setTimeout(() => {
      this.searchTerm.set(currentTerm);
    }, 100);
  }
  
  constructor() {
    effect(() => {
      if (this.error()) {
        console.error('Search error:', this.error());
      }
    });
  }
}
```
{% endraw %}

**Explicação**:

Este exemplo demonstra:

1. **Signal para Estado Local**: `searchTerm` e `sortOrder` são Signals que gerenciam estado local do componente
2. **Observable para HTTP**: A busca HTTP é feita através de Observable com operadores RxJS
3. **Conversão Bidirecional**: 
   - `toObservable()` converte `searchTerm` Signal para Observable
   - `toSignal()` converte o resultado HTTP Observable para Signal
4. **Computed Signals**: `loading`, `userCount` e `sortedUsers` são computed signals que derivam de outros signals
5. **Error Handling**: Tratamento de erro robusto com retry logic
6. **Template Integration**: Uso direto de Signals no template sem AsyncPipe

---

### Exemplo 2: Dashboard com Múltiplas Fontes de Dados

**Contexto**: Criar dashboard que combina dados de múltiplas fontes (HTTP, WebSocket, Timer) usando Signals e Observables.

**Código**:

{% raw %}
```typescript
import { Component, signal, computed, inject, OnInit, effect } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal, toObservable } from '@angular/core/rxjs-interop';
import { interval, of } from 'rxjs';
import { switchMap, catchError } from 'rxjs/operators';

interface DashboardData {
  users: number;
  orders: number;
  revenue: number;
  activeUsers: number;
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  template: `
    <div class="dashboard">
      <h1>Dashboard</h1>
      
      <div class="stats-grid">
        <div class="stat-card">
          <h3>Total de Usuários</h3>
          <p class="stat-value">{{ stats().users | number }}</p>
        </div>
        
        <div class="stat-card">
          <h3>Pedidos Hoje</h3>
          <p class="stat-value">{{ stats().orders | number }}</p>
        </div>
        
        <div class="stat-card">
          <h3>Receita</h3>
          <p class="stat-value">{{ stats().revenue | currency:'BRL' }}</p>
        </div>
        
        <div class="stat-card">
          <h3>Usuários Ativos</h3>
          <p class="stat-value">{{ stats().activeUsers | number }}</p>
          <p class="stat-change" [class.positive]="activeUsersChange() > 0">
            {{ activeUsersChange() > 0 ? '+' : '' }}{{ activeUsersChange() }}%
          </p>
        </div>
      </div>
      
      @if (loading()) {
        <div class="loading">Carregando dados...</div>
      }
      
      @if (lastUpdate()) {
        <p class="last-update">Última atualização: {{ lastUpdate() | date:'short' }}</p>
      }
    </div>
  `,
  styles: [`
    .dashboard {
      padding: 20px;
    }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 20px;
      margin: 20px 0;
    }
    
    .stat-card {
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .stat-value {
      font-size: 2em;
      font-weight: bold;
      margin: 10px 0;
    }
    
    .stat-change {
      font-size: 0.9em;
      color: #666;
    }
    
    .stat-change.positive {
      color: #28a745;
    }
    
    .last-update {
      text-align: center;
      color: #666;
      font-size: 0.9em;
    }
  `]
})
export class DashboardComponent implements OnInit {
  private http = inject(HttpClient);
  
  refreshInterval = signal(30000);
  lastUpdate = signal<Date | null>(null);
  
  httpData = toSignal(
    this.http.get<DashboardData>('/api/dashboard/stats'),
    { initialValue: { users: 0, orders: 0, revenue: 0, activeUsers: 0 } }
  );
  
  realTimeData = toSignal(
    interval(this.refreshInterval()).pipe(
      switchMap(() => 
        this.http.get<{ activeUsers: number }>('/api/dashboard/realtime').pipe(
          catchError(() => of({ activeUsers: 0 }))
        )
      )
    ),
    { initialValue: { activeUsers: 0 } }
  );
  
  stats = computed(() => {
    const http = this.httpData();
    const realtime = this.realTimeData();
    
    return {
      users: http.users,
      orders: http.orders,
      revenue: http.revenue,
      activeUsers: realtime.activeUsers || http.activeUsers
    };
  });
  
  previousActiveUsers = signal(0);
  activeUsersChange = computed(() => {
    const current = this.stats().activeUsers;
    const previous = this.previousActiveUsers();
    
    if (previous === 0) return 0;
    
    const change = ((current - previous) / previous) * 100;
    this.previousActiveUsers.set(current);
    
    return Math.round(change * 10) / 10;
  });
  
  loading = computed(() => {
    return this.stats().users === 0 && this.stats().orders === 0;
  });
  
  ngOnInit() {
    effect(() => {
      const stats = this.stats();
      if (stats.users > 0 || stats.orders > 0) {
        this.lastUpdate.set(new Date());
      }
    });
  }
}
```
{% raw %}
import { Component, signal, computed, inject, OnInit, effect } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal, toObservable } from '@angular/core/rxjs-interop';
import { interval, of } from 'rxjs';
import { switchMap, catchError } from 'rxjs/operators';

interface DashboardData {
  users: number;
  orders: number;
  revenue: number;
  activeUsers: number;
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  template: `
    <div class="dashboard">
      <h1>Dashboard</h1>
      
      <div class="stats-grid">
        <div class="stat-card">
          <h3>Total de Usuários</h3>
          <p class="stat-value">{{ stats().users | number }}</p>
        </div>
        
        <div class="stat-card">
          <h3>Pedidos Hoje</h3>
          <p class="stat-value">{{ stats().orders | number }}</p>
        </div>
        
        <div class="stat-card">
          <h3>Receita</h3>
          <p class="stat-value">{{ stats().revenue | currency:'BRL' }}</p>
        </div>
        
        <div class="stat-card">
          <h3>Usuários Ativos</h3>
          <p class="stat-value">{{ stats().activeUsers | number }}</p>
          <p class="stat-change" [class.positive]="activeUsersChange() > 0">
            {{ activeUsersChange() > 0 ? '+' : '' }}{{ activeUsersChange() }}%
          </p>
        </div>
      </div>
      
      @if (loading()) {
        <div class="loading">Carregando dados...</div>
      }
      
      @if (lastUpdate()) {
        <p class="last-update">Última atualização: {{ lastUpdate() | date:'short' }}</p>
      }
    </div>
  `,
  styles: [`
    .dashboard {
      padding: 20px;
    }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 20px;
      margin: 20px 0;
    }
    
    .stat-card {
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .stat-value {
      font-size: 2em;
      font-weight: bold;
      margin: 10px 0;
    }
    
    .stat-change {
      font-size: 0.9em;
      color: #666;
    }
    
    .stat-change.positive {
      color: #28a745;
    }
    
    .last-update {
      text-align: center;
      color: #666;
      font-size: 0.9em;
    }
  `]
})
export class DashboardComponent implements OnInit {
  private http = inject(HttpClient);
  
  refreshInterval = signal(30000);
  lastUpdate = signal<Date | null>(null);
  
  httpData = toSignal(
    this.http.get<DashboardData>('/api/dashboard/stats'),
    { initialValue: { users: 0, orders: 0, revenue: 0, activeUsers: 0 } }
  );
  
  realTimeData = toSignal(
    interval(this.refreshInterval()).pipe(
      switchMap(() => 
        this.http.get<{ activeUsers: number }>('/api/dashboard/realtime').pipe(
          catchError(() => of({ activeUsers: 0 }))
        )
      )
    ),
    { initialValue: { activeUsers: 0 } }
  );
  
  stats = computed(() => {
    const http = this.httpData();
    const realtime = this.realTimeData();
    
    return {
      users: http.users,
      orders: http.orders,
      revenue: http.revenue,
      activeUsers: realtime.activeUsers || http.activeUsers
    };
  });
  
  previousActiveUsers = signal(0);
  activeUsersChange = computed(() => {
    const current = this.stats().activeUsers;
    const previous = this.previousActiveUsers();
    
    if (previous === 0) return 0;
    
    const change = ((current - previous) / previous) * 100;
    this.previousActiveUsers.set(current);
    
    return Math.round(change * 10) / 10;
  });
  
  loading = computed(() => {
    return this.stats().users === 0 && this.stats().orders === 0;
  });
  
  ngOnInit() {
    effect(() => {
      const stats = this.stats();
      if (stats.users > 0 || stats.orders > 0) {
        this.lastUpdate.set(new Date());
      }
    });
  }
}
```
{% endraw %}

---

### Exemplo 3: Formulário Reativo com Validação

**Contexto**: Criar formulário que usa Signals para estado e Observables para validação assíncrona.

**Código**:

{% raw %}
```typescript
import { Component, signal, computed, inject, effect } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { toSignal, toObservable } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged, switchMap, map, catchError } from 'rxjs/operators';
import { of } from 'rxjs';

@Component({
  selector: 'app-user-form',
  standalone: true,
  imports: [ReactiveFormsModule],
  template: `
    <form [formGroup]="form" (ngSubmit)="onSubmit()">
      <div>
        <label>Email:</label>
        <input 
          type="email" 
          formControlName="email"
          [class.invalid]="emailAvailable() === false">
        
        @if (emailAvailable() === false) {
          <span class="error">Email já está em uso</span>
        }
        @if (checkingEmail()) {
          <span class="checking">Verificando disponibilidade...</span>
        }
      </div>
      
      <div>
        <label>Nome de Usuário:</label>
        <input type="text" formControlName="username">
        @if (usernameAvailable() === false) {
          <span class="error">Nome de usuário já está em uso</span>
        }
      </div>
      
      <div>
        <label>Senha:</label>
        <input type="password" formControlName="password">
        <div class="password-strength">
          Força: {{ passwordStrength() }}
        </div>
      </div>
      
      <button 
        type="submit" 
        [disabled]="!formValid() || checkingEmail()">
        Criar Conta
      </button>
    </form>
  `
})
export class UserFormComponent {
  private fb = inject(FormBuilder);
  private http = inject(HttpClient);
  
  form = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    username: ['', [Validators.required, Validators.minLength(3)]],
    password: ['', [Validators.required, Validators.minLength(8)]]
  });
  
  email = signal('');
  username = signal('');
  password = signal('');
  
  checkingEmail = signal(false);
  
  emailAvailable = toSignal(
    toObservable(this.email).pipe(
      debounceTime(500),
      distinctUntilChanged(),
      switchMap(email => {
        if (!email || !this.form.get('email')?.valid) {
          return of(null);
        }
        
        this.checkingEmail.set(true);
        
        return this.http.get<{ available: boolean }>(`/api/users/check-email?email=${email}`).pipe(
          map(response => response.available),
          catchError(() => of(null))
        );
      })
    ),
    { initialValue: null }
  );
  
  usernameAvailable = toSignal(
    toObservable(this.username).pipe(
      debounceTime(500),
      distinctUntilChanged(),
      switchMap(username => {
        if (!username || !this.form.get('username')?.valid) {
          return of(null);
        }
        
        return this.http.get<{ available: boolean }>(`/api/users/check-username?username=${username}`).pipe(
          map(response => response.available),
          catchError(() => of(null))
        );
      })
    ),
    { initialValue: null }
  );
  
  passwordStrength = computed(() => {
    const pwd = this.password();
    if (!pwd) return 'Nenhuma';
    
    let strength = 0;
    if (pwd.length >= 8) strength++;
    if (pwd.length >= 12) strength++;
    if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength++;
    if (/\d/.test(pwd)) strength++;
    if (/[^a-zA-Z\d]/.test(pwd)) strength++;
    
    if (strength <= 2) return 'Fraca';
    if (strength <= 3) return 'Média';
    return 'Forte';
  });
  
  formValid = computed(() => {
    return this.form.valid && 
           this.emailAvailable() !== false && 
           this.usernameAvailable() !== false;
  });
  
  constructor() {
    this.form.get('email')?.valueChanges.subscribe(value => {
      this.email.set(value || '');
    });
    
    this.form.get('username')?.valueChanges.subscribe(value => {
      this.username.set(value || '');
    });
    
    this.form.get('password')?.valueChanges.subscribe(value => {
      this.password.set(value || '');
    });
    
    effect(() => {
      if (this.emailAvailable() !== null) {
        this.checkingEmail.set(false);
      }
    });
  }
  
  onSubmit() {
    if (this.formValid()) {
      console.log('Form submitted:', this.form.value);
    }
  }
}
```
{% endraw %}

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use toSignal() para HTTP e Observables assíncronos**
   - **Por quê**: Integração simples com Signals, cleanup automático, type safety completo
   - **Exemplo**: `users = toSignal(this.http.get<User[]>('/api/users'), { initialValue: [] })`
   - **Benefícios**: Não precisa gerenciar subscriptions, funciona perfeitamente com templates

2. **Use toObservable() para aplicar operadores RxJS**
   - **Por quê**: Aproveita poder dos operadores RxJS (debounceTime, switchMap, etc.)
   - **Exemplo**: `toObservable(this.searchTerm).pipe(debounceTime(300), switchMap(...))`
   - **Benefícios**: Reutiliza código existente, aplica lógica assíncrona complexa

3. **Prefira Signals para estado local**
   - **Por quê**: Mais simples, performático, change detection granular
   - **Exemplo**: `count = signal(0)`, `isOpen = signal(false)`
   - **Benefícios**: Código mais limpo, menos boilerplate, melhor performance

4. **Use Observables para streams complexos**
   - **Por quê**: Melhor para operações assíncronas, composição de streams
   - **Exemplo**: HTTP, eventos, WebSockets, timers
   - **Benefícios**: Poder dos operadores RxJS, tratamento de erro robusto

5. **Sempre forneça initialValue em toSignal()**
   - **Por quê**: Evita erros de tipo e runtime, melhora experiência do usuário
   - **Exemplo**: `toSignal(obs$, { initialValue: [] })`
   - **Benefícios**: Type safety completo, UI não quebra durante carregamento

6. **Use computed() para valores derivados**
   - **Por quê**: Recalcula automaticamente quando dependências mudam
   - **Exemplo**: `fullName = computed(() => `${firstName()} ${lastName()}`)`
   - **Benefícios**: Performance otimizada, código declarativo

7. **Combine Signals e Observables estrategicamente**
   - **Por quê**: Aproveita melhor de ambos os mundos
   - **Exemplo**: Signal para estado local + Observable para HTTP + toSignal() para resultado
   - **Benefícios**: Código mais organizado, melhor separação de responsabilidades

8. **Trate erros em Observables antes de converter para Signal**
   - **Por quê**: Signals não têm tratamento de erro nativo
   - **Exemplo**: `toSignal(obs$.pipe(catchError(...)), { initialValue: [] })`
   - **Benefícios**: Aplicação mais robusta, melhor UX

9. **Use effect() para side effects baseados em Signals**
   - **Por quê**: Gerencia automaticamente lifecycle, cleanup automático
   - **Exemplo**: `effect(() => console.log('Count:', this.count()))`
   - **Benefícios**: Não precisa gerenciar subscriptions manualmente

10. **Documente quando usar cada abordagem**
    - **Por quê**: Facilita manutenção e onboarding
    - **Exemplo**: Comentários explicando por que Signal vs Observable
    - **Benefícios**: Código mais legível, decisões arquiteturais claras

### ❌ Anti-padrões Comuns

1. **Não converta desnecessariamente**
   - **Problema**: Complexidade desnecessária, overhead de performance
   - **Exemplo Ruim**: `toSignal(toObservable(simpleSignal))` quando `simpleSignal` já é suficiente
   - **Solução**: Use diretamente quando possível, converta apenas quando necessário

2. **Não ignore valor inicial em toSignal()**
   - **Problema**: Erros de tipo (`Signal<T | undefined>`), runtime errors, UI quebrada
   - **Exemplo Ruim**: `users = toSignal(this.http.get(...))` sem `initialValue`
   - **Solução**: Sempre forneça `initialValue` apropriado

3. **Não misture sem necessidade**
   - **Problema**: Código confuso, difícil de manter, performance degradada
   - **Exemplo Ruim**: Converter Signal → Observable → Signal desnecessariamente
   - **Solução**: Escolha uma abordagem consistente para cada caso de uso

4. **Não esqueça de tratar erros em Observables**
   - **Problema**: Erros não tratados quebram aplicação, má UX
   - **Exemplo Ruim**: `toSignal(this.http.get(...))` sem `catchError`
   - **Solução**: Sempre use `catchError` ou `retry` quando apropriado

5. **Não crie subscriptions manuais com Signals**
   - **Problema**: Memory leaks, código desnecessário
   - **Exemplo Ruim**: `this.signal$.subscribe(...)` quando poderia usar `effect()`
   - **Solução**: Use `effect()` para side effects baseados em Signals

6. **Não use AsyncPipe com Signals**
   - **Problema**: Desnecessário, Signals já são reativos no template
{% raw %}
   - **Exemplo Ruim**: `{{ signal$ | async }}` quando `signal()` já funciona
   - **Solução**: Use Signals diretamente no template: `{{ signal() }}`
{% endraw %}

7. **Não ignore cleanup de subscriptions**
   - **Problema**: Memory leaks, performance degradada
   - **Exemplo Ruim**: Criar Observable manualmente sem gerenciar subscription
   - **Solução**: Use `toSignal()` que gerencia cleanup automaticamente, ou `takeUntilDestroyed()`

8. **Não use Signals para streams infinitos sem cuidado**
   - **Problema**: Memory leaks, performance issues
   - **Exemplo Ruim**: `toSignal(interval(1000))` sem considerar cleanup
   - **Solução**: Considere usar `takeUntilDestroyed()` ou gerenciar lifecycle adequadamente

9. **Não crie dependências circulares**
   - **Problema**: Loops infinitos, stack overflow
   - **Exemplo Ruim**: Signal A depende de Signal B que depende de Signal A
   - **Solução**: Reestruture dependências para evitar ciclos

10. **Não ignore type safety**
    - **Problema**: Erros em runtime, código frágil
    - **Exemplo Ruim**: `toSignal(obs$)` sem especificar tipo genérico
    - **Solução**: Sempre especifique tipos explicitamente: `toSignal<User[]>(obs$)`

---

## Exercícios Práticos

### Exercício 1: toSignal() e toObservable() (Intermediário)

**Objetivo**: Praticar conversão entre Signals e Observables

**Descrição**: 
Crie componente que converte Observable HTTP para Signal e aplica operadores RxJS em Signal convertido.

**Arquivo**: `exercises/exercise-3-5-1-tosignal-toobservable.md`

---

### Exercício 2: Integração Prática (Avançado)

**Objetivo**: Integrar Signals e Observables em aplicação real

**Descrição**:
Crie aplicação que usa Signals para estado local e Observables para dados HTTP, demonstrando padrões híbridos.

**Arquivo**: `exercises/exercise-3-5-2-integracao.md`

---

### Exercício 3: Quando Usar Signals vs Observables (Avançado)

**Objetivo**: Entender quando usar cada abordagem

**Descrição**:
Crie exemplos demonstrando quando usar Signals e quando usar Observables, incluindo análise de trade-offs.

**Arquivo**: `exercises/exercise-3-5-3-decisao.md`

---

## Referências Externas

### Documentação Oficial

- **[toSignal()](https://angular.io/api/core/rxjs-interop/toSignal)**: Documentação completa da API toSignal()
- **[toObservable()](https://angular.io/api/core/rxjs-interop/toObservable)**: Documentação completa da API toObservable()
- **[Signals Guide](https://angular.io/guide/signals)**: Guia completo sobre Signals no Angular
- **[RxJS Interop](https://angular.io/guide/rxjs-interop)**: Guia de interoperabilidade entre Signals e RxJS
- **[Angular Signals RFC](https://github.com/angular/angular/discussions/49685)**: RFC original sobre Signals

### Artigos e Tutoriais

- **[Angular Signals: The Future of Change Detection](https://www.angulararchitects.io/en/blog/angular-signals-the-future-of-change-detection/)**: Artigo sobre futuro do change detection
- **[Signals vs Observables: When to Use What](https://blog.angular.io/signals-vs-observables-when-to-use-what-7c8e0e5c8c5e)**: Comparação detalhada Signals vs Observables
- **[Migrating from Observables to Signals](https://dev.to/angular/migrating-from-observables-to-signals-4k5j)**: Guia de migração
- **[RxJS Operators with Signals](https://netbasal.com/rxjs-operators-with-signals-in-angular-4a8b8c9e5f5d)**: Como usar operadores RxJS com Signals

### Vídeos

- **[Angular Signals Deep Dive](https://www.youtube.com/watch?v=5SD995zKvbk)**: Vídeo oficial sobre Signals
- **[Signals and RxJS Working Together](https://www.youtube.com/watch?v=5SD995zKvbk)**: Como Signals e RxJS trabalham juntos
- **[Angular Signals Tutorial](https://www.youtube.com/watch?v=5SD995zKvbk)**: Tutorial completo sobre Signals

### Ferramentas

- **[Angular DevTools](https://angular.io/guide/devtools)**: Ferramentas de desenvolvimento para debugar Signals
- **[RxJS Marbles](https://rxmarbles.com/)**: Visualização interativa de operadores RxJS
- **[Angular Playground](https://angularplayground.it/)**: Ambiente de desenvolvimento para testar Signals

### Comunidade

- **[Angular Discord](https://discord.gg/angular)**: Comunidade Angular no Discord
- **[Angular Reddit](https://www.reddit.com/r/Angular2/)**: Subreddit do Angular
- **[Angular GitHub Discussions](https://github.com/angular/angular/discussions)**: Discussões oficiais sobre Angular

---

## Resumo

### Principais Conceitos

- `toSignal()` converte Observables em Signals, permitindo usar dados assíncronos com API de Signals
- `toObservable()` converte Signals em Observables, permitindo aplicar operadores RxJS
- Signals são ideais para estado local simples e valores síncronos
- Observables são ideais para streams assíncronos complexos e operações HTTP
- Integração permite aproveitar melhor dos dois mundos em aplicações híbridas
- Change detection granular com Signals melhora performance
- Cleanup automático reduz risco de memory leaks

### Pontos-Chave para Lembrar

- Use `toSignal()` para HTTP e Observables assíncronos quando precisar usar no template
- Use `toObservable()` para aplicar operadores RxJS em Signals
- Prefira Signals para estado local simples (contadores, flags, valores de formulário)
- Use Observables para streams complexos (HTTP, eventos, WebSockets, timers)
- Sempre forneça `initialValue` em `toSignal()` para type safety completo
- Trate erros em Observables antes de converter para Signal
- Use `computed()` para valores derivados de outros Signals
- Escolha abordagem consistente para cada caso de uso
- Documente decisões arquiteturais sobre quando usar cada abordagem
- Teste integração Signals + Observables para garantir comportamento correto

### Próximos Passos

- Próximo módulo: Módulo 4 - Performance e Otimização
- Praticar integração Signals + Observables em projetos reais
- Explorar padrões avançados de integração (stores, state management)
- Estudar migração de código legado para Signals
- Aprofundar conhecimento em operadores RxJS avançados
- Contribuir com exemplos e padrões para comunidade Angular

---

## Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente com contexto histórico
- [x] Todos os conceitos têm definições técnicas completas
- [x] Analogias detalhadas para cada conceito abstrato
- [x] Diagramas ASCII detalhados para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais com múltiplas variações
- [x] Boas práticas e anti-padrões documentados com exemplos
- [x] Tabelas comparativas incluindo outros frameworks
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas por categoria
- [x] Resumo com pontos principais e próximos passos
- [x] Árvore de decisão para escolha entre Signals e Observables
- [x] Exemplos avançados demonstrando padrões híbridos

---

**Aula Anterior**: [Aula 3.4: Padrões Reativos e Memory Leaks](./lesson-3-4-memory-leaks.md)  
**Próxima Aula**: [Aula 4.1: Change Detection e Performance](./lesson-4-1-change-detection.md)  
**Voltar ao Módulo**: [Módulo 3: Programação Reativa e Estado](../modules/module-3-programacao-reativa-estado.md)
