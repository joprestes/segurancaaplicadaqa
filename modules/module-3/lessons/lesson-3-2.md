---
layout: lesson
title: "Aula 3.2: Signals e Signal-First Architecture"
slug: signals
module: module-3
lesson_id: lesson-3-2
duration: "120 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-3-1"
exercises:
  - 
  - "lesson-3-2-exercise-1"
  - "lesson-3-2-exercise-2"
  - "lesson-3-2-exercise-3"
  - "lesson-3-2-exercise-4"
  - "lesson-3-2-exercise-5"
  - "lesson-3-2-exercise-6"
podcast:
  file: "assets/podcasts/03.2-Angular_Signals__O_Guia_Completo_e_Prático.m4a"
  title: "Angular Signals - O Guia Completo e Prático"
  description: "Signals são a nova forma reativa do Angular."
  duration: "60-75 minutos"
---

## Introdução

Nesta aula, você dominará Signals, a nova primitiva reativa do Angular introduzida no Angular 16+. Signals representam uma evolução na forma como Angular gerencia reatividade, oferecendo melhor performance, type safety e uma API mais simples que Observables em muitos casos.

### O que você vai aprender

- Criar e usar signal() e computed()
- Trabalhar com effect() para side effects
- Usar Model Inputs para inputs reativos
- Criar formulários baseados em Signals
- Implementar Signal-First Architecture
- Migrar de Observables para Signals
- Integrar Signals com Observables

### Por que isso é importante

Signals são o futuro do Angular. Eles oferecem melhor performance, código mais simples e melhor integração com o sistema de change detection. Signal-First Architecture é a direção recomendada para novas aplicações Angular.

---

## Conceitos Teóricos

### signal()

**Definição**: `signal()` cria um signal reativo que mantém um valor e notifica dependentes quando o valor muda.

**Explicação Detalhada**:

signal():
- Cria valor reativo primitivo
- Type-safe por padrão
- Notifica automaticamente dependentes
- Pode ser atualizado com set(), update() ou mutate()
- Melhor performance que Observables para valores simples

**Analogia**:

signal() é como uma variável especial que "grita" quando muda. Qualquer coisa que está "ouvindo" (computed, effect, template) é notificada automaticamente.

**Visualização**:

```
signal(value)
    │
    ├─→ computed() ──→ Novo valor calculado
    ├─→ effect() ────→ Side effect executado
    └─→ Template ────→ View atualizada
```

**Exemplo Prático**:

```typescript
import { signal, computed } from '@angular/core';

export class CounterComponent {
  count = signal(0);
  doubleCount = computed(() => this.count() * 2);
  
  increment(): void {
    this.count.update(value => value + 1);
  }
  
  setValue(value: number): void {
    this.count.set(value);
  }
  
  mutateArray(): void {
    const items = signal([1, 2, 3]);
    items.mutate(arr => arr.push(4));
  }
}
```

---

### computed()

**Definição**: `computed()` cria um signal derivado que calcula seu valor baseado em outros signals.

**Explicação Detalhada**:

computed():
- Calcula valor baseado em outros signals
- Recalcula automaticamente quando dependências mudam
- Lazy: só calcula quando acessado
- Memoizado: cacheia resultado até dependências mudarem
- Read-only: não pode ser modificado diretamente

**Analogia**:

computed() é como uma fórmula em uma planilha. Quando os valores de entrada mudam, a fórmula recalcula automaticamente.

**Exemplo Prático**:

```typescript
import { signal, computed } from '@angular/core';

export class ShoppingCartComponent {
  items = signal<Item[]>([]);
  
  totalPrice = computed(() => 
    this.items().reduce((sum, item) => sum + item.price, 0)
  );
  
  itemCount = computed(() => this.items().length);
  
  hasItems = computed(() => this.items().length > 0);
  
  discount = signal(0);
  
  finalPrice = computed(() => 
    this.totalPrice() * (1 - this.discount())
  );
}
```

---

### effect()

**Definição**: `effect()` executa side effects quando signals mudam, similar a watch em outros frameworks.

**Explicação Detalhada**:

effect():
- Executa código quando signals mudam
- Útil para logging, sincronização, side effects
- Executa após mudanças serem aplicadas
- Pode ser destruído automaticamente
- Deve ser usado com cuidado para evitar loops infinitos

**Analogia**:

effect() é como um observador que reage a mudanças. Quando algo muda, ele executa uma ação.

**Exemplo Prático**:

```typescript
import { signal, effect } from '@angular/core';

export class UserPreferencesComponent {
  theme = signal<'light' | 'dark'>('light');
  fontSize = signal(16);
  
  constructor() {
    effect(() => {
      const theme = this.theme();
      document.body.className = theme;
      localStorage.setItem('theme', theme);
    });
    
    effect(() => {
      const size = this.fontSize();
      document.documentElement.style.fontSize = `${size}px`;
    });
  }
}
```

---

### Model Inputs

**Definição**: Model Inputs (Angular 17+) permitem two-way binding usando signals, substituindo ngModel em muitos casos.

**Explicação Detalhada**:

Model Inputs:
- Usam `model()` para criar two-way binding
- Type-safe e reativo
- Mais simples que ngModel
- Integrado com Signals
- Suporta validação

**Analogia**:

Model Inputs são como uma ponte bidirecional. Mudanças no componente pai e filho são sincronizadas automaticamente.

**Exemplo Prático**:

```typescript
import { Component, model } from '@angular/core';

@Component({
  selector: 'app-child',
  standalone: true,
{% raw %}
  template: `
    <input [value]="value()" (input)="value.set($any($event.target).value)">
  `
{% endraw %}
})
export class ChildComponent {
  value = model<string>('');
}

@Component({
  selector: 'app-parent',
  standalone: true,
  imports: [ChildComponent],
{% raw %}
  template: `
    <app-child [(value)]="parentValue" />
    <p>Valor do pai: {{ parentValue }}</p>
  `
{% endraw %}
})
export class ParentComponent {
  parentValue = signal('Valor inicial');
}
```

---

### Signal-Based Forms

**Definição**: Formulários baseados em Signals usando Signal Forms API (Angular 19+).

**Explicação Detalhada**:

Signal Forms:
- Usam signals para valores e estado
- Mais simples que Reactive Forms
- Melhor performance
- Type-safe
- Integrado com Signals

**Analogia**:

Signal Forms são como formulários tradicionais, mas com superpoderes reativos. Cada campo é um signal que reage automaticamente.

**Exemplo Prático**:

```typescript
import { Component, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-signal-form',
  standalone: true,
  imports: [FormsModule],
{% raw %}
  template: `
    <form>
      <input [(ngModel)]="name" name="name">
      <input [(ngModel)]="email" name="email" type="email">
      <p>Nome: {{ name() }}</p>
      <p>Email: {{ email() }}</p>
    </form>
  `
{% endraw %}
})
export class SignalFormComponent {
  name = signal('');
  email = signal('');
  
  get name() {
    return this.name;
  }
  
  get email() {
    return this.email;
  }
}
```

---

### Signal-First Architecture

**Definição**: Arquitetura onde Signals são a primitiva reativa primária, com Observables usados apenas quando necessário.

**Explicação Detalhada**:

Signal-First:
- Signals para estado local e derivado
- Signals para comunicação entre componentes
- Observables apenas para streams assíncronos (HTTP, eventos)
- Integração via toSignal() e toObservable()
- Melhor performance e simplicidade

**Analogia**:

Signal-First é como usar a ferramenta certa para cada trabalho. Signals para valores simples, Observables para streams complexos.

**Exemplo Prático**:

```typescript
import { Component, signal, computed, effect } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';

@Component({
  selector: 'app-signal-first',
  standalone: true,
{% raw %}
  template: `
    <div>
      <h2>{{ title() }}</h2>
      @if (loading()) {
        <p>Carregando...</p>
      } @else {
        <ul>
          @for (item of items(); track item.id) {
            <li>{{ item.name }}</li>
          }
        </ul>
      }
    </div>
  `
{% endraw %}
})
export class SignalFirstComponent {
  title = signal('Signal-First App');
  loading = signal(false);
  
  private http = inject(HttpClient);
  
  items = toSignal(
    this.http.get<Item[]>('/api/items'),
    { initialValue: [] }
  );
  
  itemCount = computed(() => this.items().length);
  
  constructor() {
    effect(() => {
      console.log('Items changed:', this.items().length);
    });
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Componente Signal-First Completo

**Contexto**: Criar componente completo usando Signals para todo estado.

**Código**:

{% raw %}
```typescript
import { Component, signal, computed, effect } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Todo {
  id: number;
  text: string;
  completed: boolean;
}

@Component({
  selector: 'app-todo-signal',
  standalone: true,
  imports: [CommonModule],
{% raw %}
  template: `
    <div>
      <h2>Todo List (Signals)</h2>
      
      <input 
        #input
        (keyup.enter)="addTodo(input.value); input.value = ''"
        placeholder="Nova tarefa">
      
      <div>
        <button (click)="filter.set('all')">Todas</button>
        <button (click)="filter.set('active')">Ativas</button>
        <button (click)="filter.set('completed')">Completas</button>
      </div>
      
      <p>Total: {{ totalTodos() }} | Ativas: {{ activeTodos() }} | Completas: {{ completedTodos() }}</p>
      
      <ul>
        @for (todo of filteredTodos(); track todo.id) {
          <li>
            <input 
              type="checkbox" 
              [checked]="todo.completed"
              (change)="toggleTodo(todo.id)">
            <span [class.completed]="todo.completed">{{ todo.text }}</span>
            <button (click)="removeTodo(todo.id)">Remover</button>
          </li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class TodoSignalComponent {
  todos = signal<Todo[]>([]);
  filter = signal<'all' | 'active' | 'completed'>('all');
  
  totalTodos = computed(() => this.todos().length);
  activeTodos = computed(() => 
    this.todos().filter(t => !t.completed).length
  );
  completedTodos = computed(() => 
    this.todos().filter(t => t.completed).length
  );
  
  filteredTodos = computed(() => {
    const todos = this.todos();
    const filter = this.filter();
    
    switch (filter) {
      case 'active':
        return todos.filter(t => !t.completed);
      case 'completed':
        return todos.filter(t => t.completed);
      default:
        return todos;
    }
  });
  
  private nextId = 0;
  
  constructor() {
    effect(() => {
      const todos = this.todos();
      localStorage.setItem('todos', JSON.stringify(todos));
    });
    
    const saved = localStorage.getItem('todos');
    if (saved) {
      this.todos.set(JSON.parse(saved));
    }
  }
  
  addTodo(text: string): void {
    if (text.trim()) {
      this.todos.update(todos => [
        ...todos,
        { id: this.nextId++, text: text.trim(), completed: false }
      ]);
    }
  }
  
  toggleTodo(id: number): void {
    this.todos.update(todos =>
      todos.map(t => t.id === id ? { ...t, completed: !t.completed } : t)
    );
  }
  
  removeTodo(id: number): void {
    this.todos.update(todos => todos.filter(t => t.id !== id));
  }
}
```
{% endraw %}

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use Signals para estado local**
   - **Por quê**: Mais simples e performático
   - **Exemplo**: `count = signal(0)`

2. **Use computed() para valores derivados**
   - **Por quê**: Reatividade automática e memoização
   - **Exemplo**: `total = computed(() => items().reduce(...))`

3. **Use effect() com cuidado**
   - **Por quê**: Pode causar loops infinitos
   - **Exemplo**: Apenas para side effects necessários

4. **Prefira Signal-First quando possível**
   - **Por quê**: Melhor performance e simplicidade
   - **Exemplo**: Signals para estado, Observables para HTTP

### ❌ Anti-padrões Comuns

1. **Não use effect() para atualizar signals**
   - **Problema**: Pode causar loops infinitos
   - **Solução**: Use computed() ou atualize diretamente

2. **Não misture Signals e Observables desnecessariamente**
   - **Problema**: Complexidade desnecessária
   - **Solução**: Use Signals quando possível

3. **Não ignore toSignal() para HTTP**
   - **Problema**: Perde benefícios de Signals
   - **Solução**: Converta Observables HTTP para Signals

---

## Exercícios Práticos

### Exercício 1: signal() e computed() Básicos (Básico)

**Objetivo**: Criar primeiros signals

**Descrição**: 
Crie componente que usa signal() e computed() para gerenciar estado simples.

**Arquivo**: `exercises/exercise-3-2-1-signal-computed.md`

---

### Exercício 2: effect() e Reatividade (Intermediário)

**Objetivo**: Trabalhar com effects

**Descrição**:
Crie componente que usa effect() para sincronizar estado com localStorage.

**Arquivo**: `exercises/exercise-3-2-2-effect.md`

---

### Exercício 3: Model Inputs (Intermediário)

**Objetivo**: Usar Model Inputs

**Descrição**:
Crie componente que usa model() para two-way binding com signals.

**Arquivo**: `exercises/exercise-3-2-3-model-inputs.md`

---

### Exercício 4: Signal-Based Forms (Avançado)

**Objetivo**: Criar formulário baseado em Signals

**Descrição**:
Crie formulário completo usando Signal Forms API.

**Arquivo**: `exercises/exercise-3-2-4-signal-forms.md`

---

### Exercício 5: Signal-First Architecture (Avançado)

**Objetivo**: Implementar arquitetura Signal-First

**Descrição**:
Crie aplicação completa usando Signal-First Architecture.

**Arquivo**: `exercises/exercise-3-2-5-signal-first.md`

---

### Exercício 6: Migração Observables para Signals (Avançado)

**Objetivo**: Migrar código existente

**Descrição**:
Migre componente que usa Observables para usar Signals.

**Arquivo**: `exercises/exercise-3-2-6-migracao.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular Signals](https://angular.io/guide/signals)**: Guia oficial de Signals
- **[Signal API](https://angular.io/api/core/signal)**: Documentação signal()
- **[computed API](https://angular.io/api/core/computed)**: Documentação computed()
- **[effect API](https://angular.io/api/core/effect)**: Documentação effect()

---

## Resumo

### Principais Conceitos

- signal() cria valores reativos primitivos
- computed() cria valores derivados automaticamente
- effect() executa side effects quando signals mudam
- Model Inputs permitem two-way binding com signals
- Signal Forms oferecem formulários baseados em signals
- Signal-First Architecture é recomendada para novas apps

### Pontos-Chave para Lembrar

- Use Signals para estado local
- Use computed() para valores derivados
- Use effect() com cuidado
- Prefira Signal-First quando possível
- Converta Observables HTTP para Signals

### Próximos Passos

- Próxima aula: NgRx - Gerenciamento de Estado
- Praticar criando componentes Signal-First
- Explorar integração Signals + Observables

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

**Aula Anterior**: [Aula 3.1: RxJS Operators Avançados](./lesson-3-1-rxjs-operators.md)  
**Próxima Aula**: [Aula 3.3: NgRx - Gerenciamento de Estado](./lesson-3-3-ngrx.md)  
**Voltar ao Módulo**: [Módulo 3: Programação Reativa e Estado](../modules/module-3-programacao-reativa-estado.md)

