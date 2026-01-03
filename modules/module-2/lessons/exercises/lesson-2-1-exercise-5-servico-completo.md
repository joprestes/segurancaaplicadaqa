---
layout: exercise
title: "Exercício 2.1.5: Serviço Completo com DI"
slug: "servico-completo"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **todas as técnicas de DI** através da **criação de um serviço completo de gerenciamento de tarefas**.

Ao completar este exercício, você será capaz de:

- Combinar todas as técnicas de DI aprendidas
- Criar serviço real e funcional
- Usar inject(), InjectionTokens, factory providers
- Implementar serviço com múltiplas dependências

---

## Descrição

Você precisa criar um serviço completo `TaskService` que gerencia tarefas usando todas as técnicas de DI aprendidas: inject(), InjectionTokens, factory providers e múltiplas dependências.

### Contexto

Um sistema de gerenciamento de tarefas precisa de um serviço robusto que pode ser configurado e usado em diferentes contextos.

### Tarefa

Crie um serviço `TaskService` completo com:

1. **InjectionToken**: Para configuração de storage
2. **Factory Provider**: Para criar serviço configurado
3. **inject()**: Para dependências modernas
4. **Múltiplas Dependências**: Logger, Storage, Config
5. **Funcionalidades**: CRUD completo de tarefas
6. **Uso**: Componente que usa o serviço

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Serviço completo e funcional
- [ ] InjectionToken usado
- [ ] Factory provider implementado
- [ ] inject() usado
- [ ] Múltiplas dependências injetadas
- [ ] CRUD completo implementado
- [ ] Componente funcional usando serviço

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todas as técnicas são aplicadas
- [ ] Serviço é útil e realista
- [ ] Código é bem organizado

---

## Solução Esperada

### Abordagem Recomendada

**task-config.ts**
```typescript
import { InjectionToken } from '@angular/core';

export interface TaskStorageConfig {
  storageKey: string;
  autoSave: boolean;
  maxTasks: number;
}

export const TASK_STORAGE_CONFIG = new InjectionToken<TaskStorageConfig>('TASK_STORAGE_CONFIG');

export const DEFAULT_TASK_CONFIG: TaskStorageConfig = {
  storageKey: 'tasks',
  autoSave: true,
  maxTasks: 100
};
```

**logger.service.ts**
```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class LoggerService {
  log(message: string, data?: any): void {
    console.log(`[LOG] ${message}`, data || '');
  }
  
  error(message: string, error?: any): void {
    console.error(`[ERROR] ${message}`, error || '');
  }
}
```

**storage.service.ts**
```typescript
import { Injectable, Inject, inject } from '@angular/core';
import { TASK_STORAGE_CONFIG, TaskStorageConfig } from './task-config';

@Injectable({
  providedIn: 'root'
})
export class StorageService {
  private config = inject(TASK_STORAGE_CONFIG);
  
  save(key: string, data: any): void {
    try {
      localStorage.setItem(`${this.config.storageKey}_${key}`, JSON.stringify(data));
    } catch (error) {
      console.error('Erro ao salvar:', error);
    }
  }
  
  load<T>(key: string): T | null {
    try {
      const data = localStorage.getItem(`${this.config.storageKey}_${key}`);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error('Erro ao carregar:', error);
      return null;
    }
  }
  
  remove(key: string): void {
    localStorage.removeItem(`${this.config.storageKey}_${key}`);
  }
}
```

**task.service.ts**
```typescript
import { Injectable, Inject, inject } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { LoggerService } from './logger.service';
import { StorageService } from './storage.service';
import { TASK_STORAGE_CONFIG, TaskStorageConfig } from './task-config';

export interface Task {
  id: number;
  title: string;
  description: string;
  completed: boolean;
  createdAt: Date;
  updatedAt: Date;
}

@Injectable({
  providedIn: 'root',
  useFactory: (
    logger: LoggerService,
    storage: StorageService,
    config: TaskStorageConfig
  ) => {
    return new TaskService(logger, storage, config);
  },
  deps: [LoggerService, StorageService, TASK_STORAGE_CONFIG]
})
export class TaskService {
  private logger = inject(LoggerService);
  private storage = inject(StorageService);
  private config = inject(TASK_STORAGE_CONFIG);
  
  private tasks$ = new BehaviorSubject<Task[]>([]);
  private nextId = 1;
  
  constructor(
    logger: LoggerService,
    storage: StorageService,
    config: TaskStorageConfig
  ) {
    this.logger = logger;
    this.storage = storage;
    this.config = config;
    this.loadTasks();
  }
  
  getTasks(): Observable<Task[]> {
    return this.tasks$.asObservable();
  }
  
  addTask(title: string, description: string): Task {
    if (this.tasks$.value.length >= this.config.maxTasks) {
      throw new Error(`Máximo de ${this.config.maxTasks} tarefas atingido`);
    }
    
    const task: Task = {
      id: this.nextId++,
      title,
      description,
      completed: false,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    const tasks = [...this.tasks$.value, task];
    this.tasks$.next(tasks);
    this.saveTasks();
    this.logger.log('Tarefa adicionada', task);
    
    return task;
  }
  
  updateTask(id: number, updates: Partial<Task>): Task | null {
    const tasks = this.tasks$.value.map(task => {
      if (task.id === id) {
        const updated = { ...task, ...updates, updatedAt: new Date() };
        this.logger.log('Tarefa atualizada', updated);
        return updated;
      }
      return task;
    });
    
    this.tasks$.next(tasks);
    this.saveTasks();
    
    return tasks.find(t => t.id === id) || null;
  }
  
  deleteTask(id: number): boolean {
    const tasks = this.tasks$.value.filter(t => t.id !== id);
    const deleted = tasks.length < this.tasks$.value.length;
    
    if (deleted) {
      this.tasks$.next(tasks);
      this.saveTasks();
      this.logger.log('Tarefa deletada', { id });
    }
    
    return deleted;
  }
  
  toggleTask(id: number): void {
    const task = this.tasks$.value.find(t => t.id === id);
    if (task) {
      this.updateTask(id, { completed: !task.completed });
    }
  }
  
  private saveTasks(): void {
    if (this.config.autoSave) {
      this.storage.save('tasks', this.tasks$.value);
      this.storage.save('nextId', this.nextId);
    }
  }
  
  private loadTasks(): void {
    const tasks = this.storage.load<Task[]>('tasks') || [];
    const savedNextId = this.storage.load<number>('nextId');
    
    if (savedNextId) {
      this.nextId = savedNextId;
    } else if (tasks.length > 0) {
      this.nextId = Math.max(...tasks.map(t => t.id)) + 1;
    }
    
    this.tasks$.next(tasks);
    this.logger.log('Tarefas carregadas', { count: tasks.length });
  }
}
```

**task-list.component.ts**
{% raw %}
```typescript
import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { TaskService, Task } from './task.service';

@Component({
  selector: 'app-task-list',
  standalone: true,
  imports: [CommonModule, FormsModule],
{% raw %}
  template: `
    <div class="task-list">
      <h2>Gerenciador de Tarefas</h2>
      
      <form (ngSubmit)="addTask()" class="task-form">
        <input 
          [(ngModel)]="newTaskTitle" 
          placeholder="Título da tarefa"
          name="title"
          required>
        <textarea 
          [(ngModel)]="newTaskDescription" 
          placeholder="Descrição"
          name="description"></textarea>
        <button type="submit">Adicionar Tarefa</button>
      </form>
      
      <div class="tasks">
        @for (task of tasks; track task.id) {
          <div class="task-card" [class.completed]="task.completed">
            <div class="task-header">
              <h3>{{ task.title }}</h3>
              <button (click)="toggleTask(task.id)">
                {{ task.completed ? 'Desmarcar' : 'Concluir' }}
              </button>
              <button (click)="deleteTask(task.id)" class="delete">Deletar</button>
            </div>
            <p>{{ task.description }}</p>
            <small>Criada em: {{ task.createdAt | date:'dd/MM/yyyy HH:mm' }}</small>
          </div>
        } @empty {
          <p class="empty">Nenhuma tarefa cadastrada</p>
        }
      </div>
    </div>
  `
{% endraw %}
})
export class TaskListComponent implements OnInit {
  private taskService = inject(TaskService);
  
  tasks: Task[] = [];
  newTaskTitle: string = '';
  newTaskDescription: string = '';
  
  ngOnInit(): void {
    this.taskService.getTasks().subscribe(tasks => {
      this.tasks = tasks;
    });
  }
  
  addTask(): void {
    if (this.newTaskTitle.trim()) {
      this.taskService.addTask(this.newTaskTitle, this.newTaskDescription);
      this.newTaskTitle = '';
      this.newTaskDescription = '';
    }
  }
  
  toggleTask(id: number): void {
    this.taskService.toggleTask(id);
  }
  
  deleteTask(id: number): void {
    this.taskService.deleteTask(id);
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. InjectionToken para configuração type-safe
2. Factory provider cria serviço com dependências
3. inject() usado para dependências modernas
4. Múltiplas dependências (Logger, Storage, Config)
5. CRUD completo implementado
6. Auto-save configurável
7. Componente funcional usando serviço

---

## Testes

### Casos de Teste

**Teste 1**: Adicionar tarefa funciona
- **Input**: Adicionar nova tarefa
- **Output Esperado**: Tarefa aparece na lista

**Teste 2**: Persistência funciona
- **Input**: Adicionar tarefa e recarregar
- **Output Esperado**: Tarefa persiste

**Teste 3**: Limite de tarefas funciona
- **Input**: Adicionar mais que maxTasks
- **Output Esperado**: Erro lançado

---

## Extensões (Opcional)

1. **Filtros**: Adicione filtros por status
2. **Busca**: Implemente busca de tarefas
3. **Categorias**: Adicione categorias
4. **Prioridades**: Adicione sistema de prioridades

---

## Referências Úteis

- **[Dependency Injection Guide](https://angular.io/guide/dependency-injection)**: Guia completo
- **[All DI Techniques](https://angular.io/guide/dependency-injection-in-action)**: Todas as técnicas

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

