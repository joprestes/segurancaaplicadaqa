---
layout: exercise
title: "Exercício 5.4.3: Design Patterns"
slug: "design-patterns"
lesson_id: "lesson-5-4"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Design Patterns** através da **implementação de Factory, Strategy e Facade patterns em aplicação Angular**.

Ao completar este exercício, você será capaz de:

- Implementar Factory Pattern
- Implementar Strategy Pattern
- Implementar Facade Pattern
- Aplicar Design Patterns adequadamente
- Entender quando usar cada pattern

---

## Descrição

Você precisa implementar Factory, Strategy e Facade patterns em uma aplicação Angular.

### Contexto

Uma aplicação precisa usar Design Patterns para resolver problemas comuns de forma elegante.

### Tarefa

Crie:

1. **Factory Pattern**: Implementar factory para criação de objetos
2. **Strategy Pattern**: Implementar strategy para algoritmos intercambiáveis
3. **Facade Pattern**: Implementar facade para interface simplificada
4. **Integração**: Integrar patterns na aplicação
5. **Testes**: Testar patterns

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Factory Pattern implementado
- [ ] Strategy Pattern implementado
- [ ] Facade Pattern implementado
- [ ] Patterns integrados
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue padrões corretamente
- [ ] Patterns estão bem implementados
- [ ] Código é extensível

---

## Solução Esperada

### Abordagem Recomendada

**Factory Pattern - Payment Processor**

**payment-processor.interface.ts**
```typescript
export interface PaymentProcessor {
  process(amount: number): Observable<PaymentResult>;
}

export interface PaymentResult {
  success: boolean;
  transactionId?: string;
  error?: string;
}
```

**credit-card.processor.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { PaymentProcessor, PaymentResult } from './payment-processor.interface';

@Injectable()
export class CreditCardProcessor implements PaymentProcessor {
  private http = inject(HttpClient);
  
  process(amount: number): Observable<PaymentResult> {
    return this.http.post<PaymentResult>('/api/payments/credit', { amount });
  }
}
```

**paypal.processor.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { PaymentProcessor, PaymentResult } from './payment-processor.interface';

@Injectable()
export class PayPalProcessor implements PaymentProcessor {
  private http = inject(HttpClient);
  
  process(amount: number): Observable<PaymentResult> {
    return this.http.post<PaymentResult>('/api/payments/paypal', { amount });
  }
}
```

**payment-processor.factory.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { PaymentProcessor } from './payment-processor.interface';
import { CreditCardProcessor } from './credit-card.processor';
import { PayPalProcessor } from './paypal.processor';

export type PaymentType = 'credit' | 'paypal' | 'bank';

@Injectable({
  providedIn: 'root'
})
export class PaymentProcessorFactory {
  private creditCardProcessor = inject(CreditCardProcessor);
  private paypalProcessor = inject(PayPalProcessor);
  
  create(type: PaymentType): PaymentProcessor {
    switch (type) {
      case 'credit':
        return this.creditCardProcessor;
      case 'paypal':
        return this.paypalProcessor;
      default:
        throw new Error(`Unknown payment type: ${type}`);
    }
  }
}
```

**Strategy Pattern - Sorting**

**sort-strategy.interface.ts**
```typescript
export interface SortStrategy<T> {
  sort(items: T[]): T[];
}
```

**name-sort.strategy.ts**
```typescript
import { SortStrategy } from './sort-strategy.interface';

export class NameSortStrategy<T extends { name: string }> implements SortStrategy<T> {
  sort(items: T[]): T[] {
    return [...items].sort((a, b) => a.name.localeCompare(b.name));
  }
}
```

**date-sort.strategy.ts**
```typescript
import { SortStrategy } from './sort-strategy.interface';

export class DateSortStrategy<T extends { createdAt: Date }> implements SortStrategy<T> {
  sort(items: T[]): T[] {
    return [...items].sort((a, b) => 
      b.createdAt.getTime() - a.createdAt.getTime()
    );
  }
}
```

**sort-context.ts**
```typescript
import { Injectable } from '@angular/core';
import { SortStrategy } from './sort-strategy.interface';

@Injectable({
  providedIn: 'root'
})
export class SortContext<T> {
  private strategy: SortStrategy<T> | null = null;
  
  setStrategy(strategy: SortStrategy<T>): void {
    this.strategy = strategy;
  }
  
  executeSort(items: T[]): T[] {
    if (!this.strategy) {
      throw new Error('Sort strategy not set');
    }
    return this.strategy.sort(items);
  }
}
```

**Facade Pattern - Task Management**

**task-management.facade.ts**
```typescript
import { Injectable, inject, signal } from '@angular/core';
import { Observable } from 'rxjs';
import { TaskService } from './task.service';
import { TaskNotificationService } from './task-notification.service';
import { TaskAnalyticsService } from './task-analytics.service';
import { Task } from './task.model';

@Injectable({
  providedIn: 'root'
})
export class TaskManagementFacade {
  private taskService = inject(TaskService);
  private notificationService = inject(TaskNotificationService);
  private analyticsService = inject(TaskAnalyticsService);
  
  tasks = signal<Task[]>([]);
  
  createTask(task: Omit<Task, 'id'>): Observable<Task> {
    return this.taskService.create(task).pipe(
      tap(newTask => {
        this.tasks.update(tasks => [...tasks, newTask]);
        this.notificationService.notifyTaskCreated(newTask);
        this.analyticsService.trackTaskCreation(newTask);
      })
    );
  }
  
  completeTask(id: number): Observable<void> {
    return this.taskService.complete(id).pipe(
      tap(() => {
        this.tasks.update(tasks => 
          tasks.map(t => t.id === id ? { ...t, completed: true } : t)
        );
        this.notificationService.notifyTaskCompleted(id);
        this.analyticsService.trackTaskCompletion(id);
      })
    );
  }
  
  deleteTask(id: number): Observable<void> {
    return this.taskService.delete(id).pipe(
      tap(() => {
        this.tasks.update(tasks => tasks.filter(t => t.id !== id));
        this.notificationService.notifyTaskDeleted(id);
        this.analyticsService.trackTaskDeletion(id);
      })
    );
  }
  
  loadTasks(): Observable<Task[]> {
    return this.taskService.getAll().pipe(
      tap(tasks => {
        this.tasks.set(tasks);
        this.analyticsService.trackTasksLoaded(tasks.length);
      })
    );
  }
}
```

**Uso dos Patterns**:

**payment.component.ts**
```typescript
import { Component } from '@angular/core';
import { PaymentProcessorFactory } from './payment-processor.factory';

@Component({
  selector: 'app-payment',
  template: `
    <button (click)="payWithCredit()">Pay with Credit Card</button>
    <button (click)="payWithPayPal()">Pay with PayPal</button>
  `
})
export class PaymentComponent {
  constructor(private factory: PaymentProcessorFactory) {}
  
  payWithCredit(): void {
    const processor = this.factory.create('credit');
    processor.process(100).subscribe(result => {
      console.log('Payment result:', result);
    });
  }
  
  payWithPayPal(): void {
    const processor = this.factory.create('paypal');
    processor.process(100).subscribe(result => {
      console.log('Payment result:', result);
    });
  }
}
```

**task-list.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { TaskManagementFacade } from './task-management.facade';

@Component({
  selector: 'app-task-list',
  template: `
    <div>
      @for (task of facade.tasks(); track task.id) {
        <div>{{ task.title }}</div>
      }
    </div>
  `
})
export class TaskListComponent implements OnInit {
  constructor(public facade: TaskManagementFacade) {}
  
  ngOnInit(): void {
    this.facade.loadTasks().subscribe();
  }
}
```

**Explicação da Solução**:

1. Factory Pattern cria objetos sem especificar classe exata
2. Strategy Pattern permite algoritmos intercambiáveis
3. Facade Pattern simplifica interface complexa
4. Patterns tornam código mais flexível
5. Fácil adicionar novos tipos/estratégias
6. Código mais testável e manutenível

---

## Testes

### Casos de Teste

**Teste 1**: Factory funciona
- **Input**: Criar processor via factory
- **Output Esperado**: Processor correto criado

**Teste 2**: Strategy funciona
- **Input**: Mudar estratégia de ordenação
- **Output Esperado**: Ordenação muda

**Teste 3**: Facade funciona
- **Input**: Usar facade
- **Output Esperado**: Operações completas executadas

---

## Extensões (Opcional)

1. **More Patterns**: Implemente mais patterns
2. **Pattern Combinations**: Combine patterns
3. **Angular-Specific Patterns**: Use patterns específicos do Angular

---

## Referências Úteis

- **[Design Patterns](https://refactoring.guru/design-patterns)**: Refactoring Guru
- **[Angular Patterns](https://angular.io/guide/architecture)**: Arquitetura Angular

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

