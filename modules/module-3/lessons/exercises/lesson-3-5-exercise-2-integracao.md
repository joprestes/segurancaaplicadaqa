---
layout: exercise
title: "Exercício 3.5.2: Integração Prática"
slug: "integracao"
lesson_id: "lesson-3-5"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **integração prática** através da **criação de aplicação real que usa Signals e Observables**.

Ao completar este exercício, você será capaz de:

- Criar aplicação híbrida Signals + Observables
- Usar Signals para estado local
- Usar Observables para dados HTTP
- Integrar ambos de forma eficiente
- Aplicar padrões de integração

---

## Descrição

Você precisa criar uma aplicação de gerenciamento de tarefas que usa Signals para estado local e Observables para operações HTTP.

### Contexto

Uma aplicação precisa ser criada usando melhor abordagem para cada caso: Signals para estado local e Observables para HTTP.

### Tarefa

Crie:

1. **Estado Local**: Usar Signals para estado local
2. **HTTP**: Usar Observables para operações HTTP
3. **Integração**: Integrar ambos usando toSignal()
4. **Aplicação**: Aplicação completa e funcional

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Signals usados para estado local
- [ ] Observables usados para HTTP
- [ ] toSignal() usado para integração
- [ ] Aplicação completa e funcional
- [ ] Código bem organizado

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Integração está correta
- [ ] Código é escalável

---

## Solução Esperada

### Abordagem Recomendada

**task.service.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Task {
  id: number;
  title: string;
  completed: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class TaskService {
  private http = inject(HttpClient);
  
  getTasks(): Observable<Task[]> {
    return this.http.get<Task[]>('/api/tasks');
  }
  
  createTask(task: Omit<Task, 'id'>): Observable<Task> {
    return this.http.post<Task>('/api/tasks', task);
  }
  
  updateTask(id: number, changes: Partial<Task>): Observable<Task> {
    return this.http.patch<Task>(`/api/tasks/${id}`, changes);
  }
  
  deleteTask(id: number): Observable<void> {
    return this.http.delete<void>(`/api/tasks/${id}`);
  }
}
```

**task-list.component.ts**
{% raw %}
```typescript
import { Component, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { toObservable } from '@angular/core/rxjs-interop';
import { switchMap } from 'rxjs/operators';
import { TaskService, Task } from './task.service';

@Component({
  selector: 'app-task-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Tarefas (Signals + Observables)</h2>
      
      <div class="filters">
        <button (click)="filter.set('all')" [class.active]="filter() === 'all'">Todas</button>
        <button (click)="filter.set('active')" [class.active]="filter() === 'active'">Ativas</button>
        <button (click)="filter.set('completed')" [class.active]="filter() === 'completed'">Completas</button>
      </div>
      
      <div class="stats">
        <p>Total: {{ totalCount() }}</p>
        <p>Ativas: {{ activeCount() }}</p>
        <p>Completas: {{ completedCount() }}</p>
      </div>
      
      <app-task-form (taskAdded)="addTask($event)"></app-task-form>
      
      <ul>
        @for (task of filteredTasks(); track task.id) {
          <li>
            <input 
              type="checkbox" 
              [checked]="task.completed"
              (change)="toggleTask(task.id)">
            <span [class.completed]="task.completed">{{ task.title }}</span>
            <button (click)="deleteTask(task.id)">Deletar</button>
          </li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class TaskListComponent {
  private taskService = inject(TaskService);
  
  filter = signal<'all' | 'active' | 'completed'>('all');
  
  tasks = toSignal(
    this.taskService.getTasks(),
    { initialValue: [] }
  );
  
  totalCount = computed(() => this.tasks().length);
  activeCount = computed(() => 
    this.tasks().filter(t => !t.completed).length
  );
  completedCount = computed(() => 
    this.tasks().filter(t => t.completed).length
  );
  
  filteredTasks = computed(() => {
    const tasks = this.tasks();
    const filter = this.filter();
    
    switch (filter) {
      case 'active':
        return tasks.filter(t => !t.completed);
      case 'completed':
        return tasks.filter(t => t.completed);
      default:
        return tasks;
    }
  });
  
  addTask(title: string): void {
    this.taskService.createTask({ title, completed: false })
      .subscribe(newTask => {
        this.tasks = toSignal(
          this.taskService.getTasks(),
          { initialValue: [] }
        );
      });
  }
  
  toggleTask(id: number): void {
    const task = this.tasks().find(t => t.id === id);
    if (task) {
      this.taskService.updateTask(id, { completed: !task.completed })
        .subscribe(() => {
          this.tasks = toSignal(
            this.taskService.getTasks(),
            { initialValue: [] }
          );
        });
    }
  }
  
  deleteTask(id: number): void {
    this.taskService.deleteTask(id)
      .subscribe(() => {
        this.tasks = toSignal(
          this.taskService.getTasks(),
          { initialValue: [] }
        );
      });
  }
}
```

**Explicação da Solução**:

1. Signals usados para estado local (filter)
2. Observables usados para operações HTTP
3. toSignal() converte Observable HTTP para Signal
4. Computed signals derivam valores
5. Operações HTTP atualizam Signal via toSignal()
6. Integração completa e funcional

---

## Testes

### Casos de Teste

**Teste 1**: Estado local funciona
- **Input**: Mudar filtro
- **Output Esperado**: Lista filtrada corretamente

**Teste 2**: HTTP funciona
- **Input**: Criar/atualizar/deletar tarefa
- **Output Esperado**: Operações HTTP funcionam

**Teste 3**: Integração funciona
- **Input**: Usar ambos Signals e Observables
- **Output Esperado**: Tudo funciona corretamente

---

## Extensões (Opcional)

1. **Optimistic Updates**: Adicione atualizações otimistas
2. **Error Handling**: Adicione tratamento de erros
3. **Loading States**: Adicione estados de loading

---

## Referências Úteis

- **[Signals Guide](https://angular.io/guide/signals)**: Guia Signals
- **[RxJS Guide](https://rxjs.dev/guide/overview)**: Guia RxJS

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

