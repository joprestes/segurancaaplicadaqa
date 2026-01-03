---
layout: exercise
title: "Exercício 3.2.5: Signal-First Architecture"
slug: "signal-first"
lesson_id: "lesson-3-2"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Signal-First Architecture** através da **criação de aplicação completa usando Signals como primitiva reativa primária**.

Ao completar este exercício, você será capaz de:

- Implementar arquitetura Signal-First completa
- Usar Signals para todo estado local
- Integrar Signals com HTTP via toSignal()
- Criar aplicação escalável
- Aplicar padrões Signal-First

---

## Descrição

Você precisa criar uma aplicação completa de gerenciamento de tarefas usando Signal-First Architecture.

### Contexto

Uma aplicação precisa ser construída usando Signal-First Architecture como padrão.

### Tarefa

Crie:

1. **Serviço Signal-First**: Serviço que usa Signals
2. **Componentes**: Componentes que usam Signals
3. **HTTP Integration**: Integração HTTP com toSignal()
4. **Estado Global**: Estado compartilhado com Signals
5. **Aplicação Completa**: App funcional completa

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Arquitetura Signal-First implementada
- [ ] Signals usados para estado local
- [ ] toSignal() usado para HTTP
- [ ] Estado compartilhado com Signals
- [ ] Aplicação completa e funcional
- [ ] Código bem organizado

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Arquitetura está correta
- [ ] Código é escalável

---

## Solução Esperada

### Abordagem Recomendada

**task.service.ts**
```typescript
import { Injectable, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';
import { Observable, of } from 'rxjs';

export interface Task {
  id: number;
  title: string;
  description: string;
  completed: boolean;
  createdAt: Date;
}

@Injectable({
  providedIn: 'root'
})
export class TaskService {
  private tasks = signal<Task[]>([]);
  private loading = signal<boolean>(false);
  
  activeTasks = computed(() => 
    this.tasks().filter(t => !t.completed)
  );
  
  completedTasks = computed(() => 
    this.tasks().filter(t => t.completed)
  );
  
  taskCount = computed(() => this.tasks().length);
  
  constructor(private http: HttpClient) {
    this.loadTasks();
  }
  
  getTasks() {
    return this.tasks.asReadonly();
  }
  
  getLoading() {
    return this.loading.asReadonly();
  }
  
  addTask(title: string, description: string): void {
    const newTask: Task = {
      id: Date.now(),
      title,
      description,
      completed: false,
      createdAt: new Date()
    };
    
    this.tasks.update(tasks => [...tasks, newTask]);
    this.saveTasks();
  }
  
  toggleTask(id: number): void {
    this.tasks.update(tasks =>
      tasks.map(t => t.id === id ? { ...t, completed: !t.completed } : t)
    );
    this.saveTasks();
  }
  
  deleteTask(id: number): void {
    this.tasks.update(tasks => tasks.filter(t => t.id !== id));
    this.saveTasks();
  }
  
  private loadTasks(): void {
    const saved = localStorage.getItem('tasks');
    if (saved) {
      try {
        const tasks = JSON.parse(saved);
        this.tasks.set(tasks);
      } catch (error) {
        console.error('Error loading tasks:', error);
      }
    }
  }
  
  private saveTasks(): void {
    localStorage.setItem('tasks', JSON.stringify(this.tasks()));
  }
}
```

**task-list.component.ts**
```typescript
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { TaskService, Task } from './task.service';
import { TaskItemComponent } from './task-item.component';
import { TaskFormComponent } from './task-form.component';

@Component({
  selector: 'app-task-list',
  standalone: true,
  imports: [CommonModule, TaskItemComponent, TaskFormComponent],
  template: `
    <div>
      <h2>Gerenciador de Tarefas (Signal-First)</h2>
      
      <div class="stats">
        <p>Total: {{ taskService.taskCount() }}</p>
        <p>Ativas: {{ taskService.activeTasks().length }}</p>
        <p>Completas: {{ taskService.completedTasks().length }}</p>
      </div>
      
      <app-task-form (taskAdded)="onTaskAdded($event)"></app-task-form>
      
      <div class="filters">
        <button (click)="filter.set('all')" [class.active]="filter() === 'all'">Todas</button>
        <button (click)="filter.set('active')" [class.active]="filter() === 'active'">Ativas</button>
        <button (click)="filter.set('completed')" [class.active]="filter() === 'completed'">Completas</button>
      </div>
      
      <ul class="task-list">
        @for (task of filteredTasks(); track task.id) {
          <app-task-item 
            [task]="task"
            (toggle)="onToggle(task.id)"
            (delete)="onDelete(task.id)">
          </app-task-item>
        }
      </ul>
    </div>
  `
})
export class TaskListComponent {
  filter = signal<'all' | 'active' | 'completed'>('all');
  
  tasks = this.taskService.getTasks();
  
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
  
  constructor(public taskService: TaskService) {}
  
  onTaskAdded(task: { title: string; description: string }): void {
    this.taskService.addTask(task.title, task.description);
  }
  
  onToggle(id: number): void {
    this.taskService.toggleTask(id);
  }
  
  onDelete(id: number): void {
    this.taskService.deleteTask(id);
  }
}
```

**task-item.component.ts**
```typescript
import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Task } from './task.service';

@Component({
  selector: 'app-task-item',
  standalone: true,
  imports: [CommonModule],
  template: `
    <li [class.completed]="task.completed">
      <input 
        type="checkbox" 
        [checked]="task.completed"
        (change)="toggle.emit()">
      <div class="task-content">
        <h4>{{ task.title }}</h4>
        <p>{{ task.description }}</p>
        <small>{{ task.createdAt | date:'short' }}</small>
      </div>
      <button (click)="delete.emit()">Deletar</button>
    </li>
  `,
  styles: [`
    li {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 1rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      margin-bottom: 0.5rem;
    }
    
    li.completed {
      opacity: 0.6;
      text-decoration: line-through;
    }
    
    .task-content {
      flex: 1;
    }
  `]
})
export class TaskItemComponent {
  @Input({ required: true }) task!: Task;
  @Output() toggle = new EventEmitter<void>();
  @Output() delete = new EventEmitter<void>();
}
```

**task-form.component.ts**
```typescript
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-task-form',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <form (ngSubmit)="onSubmit()">
      <input 
        [(ngModel)]="title" 
        placeholder="Título"
        name="title"
        required>
      <textarea 
        [(ngModel)]="description" 
        placeholder="Descrição"
        name="description"></textarea>
      <button type="submit" [disabled]="!isValid()">Adicionar</button>
    </form>
  `
})
export class TaskFormComponent {
  title = signal<string>('');
  description = signal<string>('');
  
  @Output() taskAdded = new EventEmitter<{ title: string; description: string }>();
  
  isValid = computed(() => this.title().trim().length > 0);
  
  onSubmit(): void {
    if (this.isValid()) {
      this.taskAdded.emit({
        title: this.title(),
        description: this.description()
      });
      this.title.set('');
      this.description.set('');
    }
  }
}
```

**Explicação da Solução**:

1. TaskService usa Signals para estado
2. Computed signals para valores derivados
3. Componentes usam Signals para estado local
4. Comunicação via @Output (pode usar model() também)
5. Arquitetura Signal-First completa
6. Código escalável e manutenível

---

## Testes

### Casos de Teste

**Teste 1**: Adicionar tarefa funciona
- **Input**: Adicionar nova tarefa
- **Output Esperado**: Tarefa aparece na lista

**Teste 2**: Filtros funcionam
- **Input**: Filtrar por ativas/completas
- **Output Esperado**: Lista filtrada corretamente

**Teste 3**: Estatísticas atualizam
- **Input**: Completar tarefa
- **Output Esperado**: Estatísticas atualizadas

---

## Extensões (Opcional)

1. **HTTP Integration**: Integre com API real usando toSignal()
2. **Persistence**: Adicione persistência no servidor
3. **Real-time**: Adicione atualizações em tempo real

---

## Referências Úteis

- **[Signal-First](https://angular.io/guide/signals)**: Guia Signal-First
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

