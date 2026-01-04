---
layout: lesson
title: "Aula 3.4: Padrões Reativos e Memory Leaks"
slug: memory-leaks
module: module-3
lesson_id: lesson-3-4
duration: "60 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-3-3"
exercises:
  - 
  - "lesson-3-4-exercise-1"
  - "lesson-3-4-exercise-2"
  - "lesson-3-4-exercise-3"
  - "lesson-3-4-exercise-4"
podcast:
  file: "assets/podcasts/03.4-Combatendo_Memory_Leaks_com_Async_Pipe.m4a"
  image: "assets/images/podcasts/03.4-Combatendo_Memory_Leaks_com_Async_Pipe.png"
  title: "Combatendo Memory Leaks com Async Pipe"
  description: "Memory leaks são um problema comum em aplicações Angular reativas."
  duration: "50-65 minutos"
permalink: /modules/programacao-reativa-estado/lessons/memory-leaks/
---

## Introdução

Nesta aula, você aprenderá a prevenir e debugar memory leaks em aplicações Angular reativas. Memory leaks são um problema comum e crítico que pode degradar performance e causar crashes em aplicações Angular.

### O que você vai aprender

- Usar async pipe para gerenciamento automático de subscriptions
- Implementar padrão takeUntil para cleanup
- Prevenir memory leaks em diferentes cenários
- Identificar e debugar memory leaks
- Usar ferramentas para detectar leaks
- Aplicar boas práticas para evitar leaks

### Por que isso é importante

Memory leaks são um dos problemas mais comuns e difíceis de debugar em aplicações Angular. Eles podem causar degradação gradual de performance, crashes e experiência ruim do usuário. Entender como prevenir e debugar leaks é essencial para aplicações profissionais.

---

## Conceitos Teóricos

### async pipe

**Definição**: `async` pipe é um pipe do Angular que automaticamente subscreve e desinscreve de Observables, prevenindo memory leaks.

**Explicação Detalhada**:

async pipe:
- Subscreve automaticamente ao Observable
- Desinscreve automaticamente quando componente é destruído
- Marca componente para change detection quando valor muda
- Não requer gerenciamento manual de subscriptions
- Previne memory leaks automaticamente

**Analogia**:

async pipe é como um assistente que cuida da limpeza automaticamente. Você fornece o Observable e ele cuida de tudo, limpando quando você não precisa mais.

**Visualização**:

```
Observable ──async pipe──→ Template
    │                          │
    └──→ Auto Subscribe        │
    └──→ Auto Unsubscribe ────┘
```

**Exemplo Prático**:

{% raw %}
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Usuários</h2>
      @if (users$ | async; as users) {
        <ul>
          @for (user of users; track user.id) {
            <li>{{ user.name }}</li>
          }
        </ul>
      }
    </div>
  `
{% endraw %}
})
export class UserListComponent {
  users$: Observable<User[]>;
  
  constructor(private http: HttpClient) {
    this.users$ = this.http.get<User[]>('/api/users');
  }
}
```

---

### takeUntil Pattern

**Definição**: Padrão que usa `takeUntil` operator para desinscrever de múltiplos Observables quando componente é destruído.

**Explicação Detalhada**:

takeUntil Pattern:
- Cria Subject no componente
- Usa takeUntil com Subject em todos Observables
- Completa Subject no ngOnDestroy
- Desinscreve todos Observables automaticamente
- Útil quando async pipe não pode ser usado

**Analogia**:

takeUntil é como um interruptor mestre. Quando você desliga o interruptor (completa o Subject), todas as luzes (subscriptions) se apagam automaticamente.

**Exemplo Prático**:

```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

@Component({
  selector: 'app-data',
  standalone: true,
{% raw %}
  template: `...`
})
export class DataComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();
  
  constructor(
    private userService: UserService,
    private productService: ProductService
  ) {}
  
  ngOnInit(): void {
    this.userService.getUsers()
      .pipe(takeUntil(this.destroy$))
      .subscribe(users => {
        this.users = users;
      });
    
    this.productService.getProducts()
      .pipe(takeUntil(this.destroy$))
      .subscribe(products => {
        this.products = products;
      });
  }
  
  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }
}
{% endraw %}
```

---

### Memory Leaks Comuns

**Definição**: Memory leaks ocorrem quando subscriptions não são desinscritas, mantendo referências a objetos que deveriam ser coletados pelo garbage collector.

**Explicação Detalhada**:

Memory Leaks:
- Subscriptions não desinscritas
- Event listeners não removidos
- Timers não cancelados
- Referências circulares
- Closures mantendo referências

**Analogia**:

Memory leaks são como deixar torneiras abertas. A água (memória) continua fluindo mesmo quando você não precisa mais, eventualmente causando problemas.

**Exemplo Prático**:

```typescript
export class LeakyComponent implements OnInit {
  constructor(private service: DataService) {}
  
  ngOnInit(): void {
    this.service.getData().subscribe(data => {
      this.data = data;
    });
  }
}
```

**Problema**: Subscription nunca é desinscrita, causando memory leak.

**Solução**:

```typescript
export class FixedComponent implements OnInit, OnDestroy {
  private subscription?: Subscription;
  
  constructor(private service: DataService) {}
  
  ngOnInit(): void {
    this.subscription = this.service.getData().subscribe(data => {
      this.data = data;
    });
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }
}
```

---

### Prevenção de Memory Leaks

**Definição**: Técnicas e padrões para prevenir memory leaks em aplicações Angular.

**Explicação Detalhada**:

Prevenção:
- Sempre usar async pipe quando possível
- Usar takeUntil pattern para múltiplas subscriptions
- Desinscrever manualmente quando necessário
- Evitar closures que mantêm referências
- Limpar event listeners e timers
- Usar OnPush change detection quando possível

**Analogia**:

Prevenção é como manter uma casa limpa. É mais fácil prevenir sujeira do que limpar depois. Aplicar boas práticas desde o início evita problemas futuros.

**Exemplo Prático**:

```typescript
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy } from '@angular/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

@Component({
  selector: 'app-safe',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
{% raw %}
  template: `...`
})
export class SafeComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();
  
  constructor(private service: DataService) {}
  
  ngOnInit(): void {
    this.service.getData()
      .pipe(takeUntil(this.destroy$))
      .subscribe(data => {
        this.data = data;
        this.cdr.markForCheck();
      });
  }
  
  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }
}
{% endraw %}
```

---

### Debugging Memory Leaks

**Definição**: Técnicas e ferramentas para identificar e debugar memory leaks.

**Explicação Detalhada**:

Debugging:
- Chrome DevTools Memory Profiler
- Angular DevTools
- RxJS Spy
- Verificar subscriptions ativas
- Monitorar uso de memória
- Identificar objetos não coletados

**Analogia**:

Debugging memory leaks é como investigar um vazamento de água. Você precisa encontrar de onde está vindo e por que não está sendo coletado.

**Exemplo Prático**:

```typescript
import { Subscription } from 'rxjs';

export class DebugComponent implements OnInit, OnDestroy {
  private subscriptions: Subscription[] = [];
  
  constructor(private service: DataService) {}
  
  ngOnInit(): void {
    const sub = this.service.getData().subscribe(data => {
      this.data = data;
    });
    
    this.subscriptions.push(sub);
    console.log('Active subscriptions:', this.subscriptions.length);
  }
  
  ngOnDestroy(): void {
    this.subscriptions.forEach(sub => sub.unsubscribe());
    console.log('All subscriptions cleaned up');
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Componente Seguro com Múltiplas Subscriptions

**Contexto**: Criar componente que gerencia múltiplas subscriptions de forma segura.

**Código**:

```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subject } from 'rxjs';
import { takeUntil, finalize } from 'rxjs/operators';
import { UserService } from './user.service';
import { ProductService } from './product.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
{% raw %}
  template: `
    <div>
      <h2>Dashboard</h2>
      <div>
        <h3>Usuários: {{ userCount }}</h3>
        <h3>Produtos: {{ productCount }}</h3>
      </div>
    </div>
  `
{% endraw %}
})
export class DashboardComponent implements OnInit, OnDestroy {
  userCount = 0;
  productCount = 0;
  private destroy$ = new Subject<void>();
  
  constructor(
    private userService: UserService,
    private productService: ProductService
  ) {}
  
  ngOnInit(): void {
    this.userService.getUsers()
      .pipe(
        takeUntil(this.destroy$),
        finalize(() => console.log('User subscription completed'))
      )
      .subscribe(users => {
        this.userCount = users.length;
      });
    
    this.productService.getProducts()
      .pipe(
        takeUntil(this.destroy$),
        finalize(() => console.log('Product subscription completed'))
      )
      .subscribe(products => {
        this.productCount = products.length;
      });
  }
  
  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
    console.log('Component destroyed, all subscriptions cleaned');
  }
}
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Sempre use async pipe quando possível**
   - **Por quê**: Gerenciamento automático de subscriptions
   - **Exemplo**: `users$ | async`

2. **Use takeUntil pattern para múltiplas subscriptions**
   - **Por quê**: Cleanup centralizado e simples
   - **Exemplo**: `takeUntil(this.destroy$)`

3. **Implemente ngOnDestroy sempre que necessário**
   - **Por quê**: Garante cleanup adequado
   - **Exemplo**: Completar destroy$ Subject

4. **Monitore subscriptions em desenvolvimento**
   - **Por quê**: Detecta leaks cedo
   - **Exemplo**: Logging de subscriptions

### ❌ Anti-padrões Comuns

1. **Não esquecer de desinscrever**
   - **Problema**: Memory leaks inevitáveis
   - **Solução**: Sempre usar async pipe ou takeUntil

2. **Não criar subscriptions em loops**
   - **Problema**: Múltiplas subscriptions desnecessárias
   - **Solução**: Usar operators apropriados

3. **Não ignorar ngOnDestroy**
   - **Problema**: Recursos não liberados
   - **Solução**: Sempre implementar quando necessário

---

## Exercícios Práticos

### Exercício 1: async pipe (Básico)

**Objetivo**: Usar async pipe para prevenir memory leaks

**Descrição**: 
Crie componente que usa async pipe para exibir dados de Observable.

**Arquivo**: `exercises/exercise-3-4-1-async-pipe.md`

---

### Exercício 2: takeUntil Pattern (Intermediário)

**Objetivo**: Implementar padrão takeUntil

**Descrição**:
Crie componente que usa takeUntil pattern para gerenciar múltiplas subscriptions.

**Arquivo**: `exercises/exercise-3-4-2-takeuntil.md`

---

### Exercício 3: Prevenção de Memory Leaks (Avançado)

**Objetivo**: Prevenir memory leaks em cenários complexos

**Descrição**:
Crie componente que previne memory leaks em múltiplos cenários.

**Arquivo**: `exercises/exercise-3-4-3-prevencao.md`

---

### Exercício 4: Debugging Memory Leaks (Avançado)

**Objetivo**: Identificar e debugar memory leaks

**Descrição**:
Crie componente com memory leak e use ferramentas para identificá-lo.

**Arquivo**: `exercises/exercise-3-4-4-debugging.md`

---

## Referências Externas

### Documentação Oficial

- **[async pipe](https://angular.io/api/common/AsyncPipe)**: Documentação async pipe
- **[RxJS takeUntil](https://rxjs.dev/api/operators/takeUntil)**: Documentação takeUntil

---

## Resumo

### Principais Conceitos

- async pipe gerencia subscriptions automaticamente
- takeUntil pattern desinscreve múltiplas subscriptions
- Memory leaks são causados por subscriptions não desinscritas
- Prevenção é melhor que correção
- Ferramentas ajudam a identificar leaks

### Pontos-Chave para Lembrar

- Sempre use async pipe quando possível
- Use takeUntil pattern para múltiplas subscriptions
- Implemente ngOnDestroy quando necessário
- Monitore subscriptions em desenvolvimento

### Próximos Passos

- Próxima aula: Integração Signals + Observables
- Praticar prevenção de memory leaks
- Explorar ferramentas de debugging

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

**Aula Anterior**: [Aula 3.3: NgRx - Gerenciamento de Estado](./lesson-3-3-ngrx.md)  
**Próxima Aula**: [Aula 3.5: Integração Signals + Observables](./lesson-3-5-signals-observables.md)  
**Voltar ao Módulo**: [Módulo 3: Programação Reativa e Estado](../modules/module-3-programacao-reativa-estado.md)

