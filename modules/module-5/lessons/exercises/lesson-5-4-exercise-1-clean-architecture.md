---
layout: exercise
title: "Exercício 5.4.1: Clean Architecture"
slug: "clean-architecture"
lesson_id: "lesson-5-4"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Clean Architecture** através da **implementação de estrutura seguindo Clean Architecture para feature de tarefas**.

Ao completar este exercício, você será capaz de:

- Entender Clean Architecture
- Separar camadas adequadamente
- Implementar Domain Layer
- Criar Application Layer
- Estruturar Presentation Layer
- Aplicar Dependency Inversion

---

## Descrição

Você precisa implementar estrutura completa de feature de tarefas seguindo Clean Architecture.

### Contexto

Uma aplicação precisa ser estruturada seguindo Clean Architecture para facilitar manutenção e escalabilidade.

### Tarefa

Crie:

1. **Domain Layer**: Criar entidades e interfaces
2. **Application Layer**: Criar use cases e serviços
3. **Infrastructure Layer**: Criar repositórios
4. **Presentation Layer**: Criar componentes
5. **Estrutura**: Organizar todas camadas

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Domain Layer criado
- [ ] Application Layer criado
- [ ] Infrastructure Layer criado
- [ ] Presentation Layer criado
- [ ] Dependências apontam para dentro
- [ ] Estrutura completa

### Critérios de Qualidade

- [ ] Código segue Clean Architecture
- [ ] Camadas estão bem separadas
- [ ] Dependências estão corretas

---

## Solução Esperada

### Abordagem Recomendada

**domain/entities/task.entity.ts**
```typescript
export class Task {
  constructor(
    public id: number,
    public title: string,
    public description: string,
    public completed: boolean,
    public createdAt: Date,
    public updatedAt: Date
  ) {}
  
  markAsCompleted(): void {
    this.completed = true;
    this.updatedAt = new Date();
  }
  
  markAsIncomplete(): void {
    this.completed = false;
    this.updatedAt = new Date();
  }
  
  updateTitle(title: string): void {
    if (!title || title.trim().length === 0) {
      throw new Error('Title cannot be empty');
    }
    this.title = title.trim();
    this.updatedAt = new Date();
  }
}
```

**domain/interfaces/task.repository.interface.ts**
```typescript
import { Observable } from 'rxjs';
import { Task } from '../entities/task.entity';

export interface ITaskRepository {
  findAll(): Observable<Task[]>;
  findById(id: number): Observable<Task | null>;
  create(task: Omit<Task, 'id' | 'createdAt' | 'updatedAt'>): Observable<Task>;
  update(id: number, task: Partial<Task>): Observable<Task>;
  delete(id: number): Observable<void>;
}
```

**application/use-cases/create-task.use-case.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ITaskRepository } from '../../domain/interfaces/task.repository.interface';
import { Task } from '../../domain/entities/task.entity';

export interface CreateTaskRequest {
  title: string;
  description: string;
}

@Injectable({
  providedIn: 'root'
})
export class CreateTaskUseCase {
  private repository = inject(ITaskRepository);
  
  execute(request: CreateTaskRequest): Observable<Task> {
    const task = {
      title: request.title,
      description: request.description,
      completed: false
    };
    
    return this.repository.create(task);
  }
}
```

**application/use-cases/get-tasks.use-case.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ITaskRepository } from '../../domain/interfaces/task.repository.interface';
import { Task } from '../../domain/entities/task.entity';

@Injectable({
  providedIn: 'root'
})
export class GetTasksUseCase {
  private repository = inject(ITaskRepository);
  
  execute(): Observable<Task[]> {
    return this.repository.findAll();
  }
}
```

**infrastructure/repositories/task.repository.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map } from 'rxjs';
import { ITaskRepository } from '../../domain/interfaces/task.repository.interface';
import { Task } from '../../domain/entities/task.entity';

@Injectable({
  providedIn: 'root'
})
export class TaskRepository implements ITaskRepository {
  private http = inject(HttpClient);
  private apiUrl = '/api/tasks';
  
  findAll(): Observable<Task[]> {
    return this.http.get<any[]>(this.apiUrl).pipe(
      map(tasks => tasks.map(task => this.mapToEntity(task)))
    );
  }
  
  findById(id: number): Observable<Task | null> {
    return this.http.get<any>(`${this.apiUrl}/${id}`).pipe(
      map(task => task ? this.mapToEntity(task) : null)
    );
  }
  
  create(task: Omit<Task, 'id' | 'createdAt' | 'updatedAt'>): Observable<Task> {
    return this.http.post<any>(this.apiUrl, task).pipe(
      map(task => this.mapToEntity(task))
    );
  }
  
  update(id: number, task: Partial<Task>): Observable<Task> {
    return this.http.patch<any>(`${this.apiUrl}/${id}`, task).pipe(
      map(task => this.mapToEntity(task))
    );
  }
  
  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }
  
  private mapToEntity(data: any): Task {
    return new Task(
      data.id,
      data.title,
      data.description,
      data.completed,
      new Date(data.createdAt),
      new Date(data.updatedAt)
    );
  }
}
```

**presentation/components/task-list/task-list.component.ts**
```typescript
import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { GetTasksUseCase } from '../../../application/use-cases/get-tasks.use-case';
import { Task } from '../../../domain/entities/task.entity';

@Component({
  selector: 'app-task-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Tarefas</h2>
      <ul>
        @for (task of tasks(); track task.id) {
          <li>
            <h3>{{ task.title }}</h3>
            <p>{{ task.description }}</p>
            <span [class.completed]="task.completed">
              {{ task.completed ? 'Concluída' : 'Pendente' }}
            </span>
          </li>
        }
      </ul>
    </div>
  `
})
export class TaskListComponent implements OnInit {
  tasks = signal<Task[]>([]);
  
  constructor(private getTasksUseCase: GetTasksUseCase) {}
  
  ngOnInit(): void {
    this.loadTasks();
  }
  
  loadTasks(): void {
    this.getTasksUseCase.execute().subscribe({
      next: (tasks) => this.tasks.set(tasks),
      error: (error) => console.error('Error loading tasks:', error)
    });
  }
}
```

**app.config.ts**
```typescript
import { ApplicationConfig } from '@angular/core';
import { provideHttpClient } from '@angular/common/http';
import { ITaskRepository } from './features/tasks/domain/interfaces/task.repository.interface';
import { TaskRepository } from './features/tasks/infrastructure/repositories/task.repository';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(),
    { provide: ITaskRepository, useClass: TaskRepository }
  ]
};
```

**Estrutura de Pastas**:
```
src/app/features/tasks/
├── domain/
│   ├── entities/
│   │   └── task.entity.ts
│   └── interfaces/
│       └── task.repository.interface.ts
├── application/
│   └── use-cases/
│       ├── create-task.use-case.ts
│       └── get-tasks.use-case.ts
├── infrastructure/
│   └── repositories/
│       └── task.repository.ts
└── presentation/
    └── components/
        └── task-list/
            └── task-list.component.ts
```

**Explicação da Solução**:

1. Domain Layer contém entidades e interfaces
2. Application Layer contém use cases
3. Infrastructure Layer implementa interfaces do Domain
4. Presentation Layer usa use cases
5. Dependências apontam para dentro
6. Dependency Inversion aplicado

---

## Testes

### Casos de Teste

**Teste 1**: Camadas separadas
- **Input**: Verificar estrutura
- **Output Esperado**: Camadas bem definidas

**Teste 2**: Dependências corretas
- **Input**: Verificar imports
- **Output Esperado**: Dependências apontam para dentro

**Teste 3**: Funcionalidade funciona
- **Input**: Usar aplicação
- **Output Esperado**: Tudo funciona corretamente

---

## Extensões (Opcional)

1. **More Use Cases**: Adicione mais use cases
2. **Error Handling**: Implemente tratamento de erros
3. **Validation**: Adicione validação no Domain

---

## Referências Úteis

- **[Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)**: Artigo original
- **[Domain-Driven Design](https://martinfowler.com/bliki/DomainDrivenDesign.html)**: DDD

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

