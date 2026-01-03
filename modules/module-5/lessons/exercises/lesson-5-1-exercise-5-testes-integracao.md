---
layout: exercise
title: "Exercício 5.1.5: Testes de Integração"
slug: "testes-integracao"
lesson_id: "lesson-5-1"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **testes de integração** através da **criação de testes que testam múltiplos componentes juntos**.

Ao completar este exercício, você será capaz de:

- Criar testes de integração
- Testar fluxos completos
- Verificar interação entre componentes
- Testar integração com serviços
- Garantir comportamento end-to-end

---

## Descrição

Você precisa criar testes de integração para um fluxo completo de criação e listagem de tarefas.

### Contexto

Uma aplicação precisa testar fluxos completos que envolvem múltiplos componentes.

### Tarefa

Crie:

1. **Componentes**: Criar componentes relacionados
2. **Fluxo**: Identificar fluxo a ser testado
3. **Testes**: Escrever testes de integração
4. **Verificação**: Verificar comportamento completo

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componentes criados
- [ ] Fluxo identificado
- [ ] Testes de integração escritos
- [ ] Fluxo completo testado
- [ ] Todos testes passam

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Testes estão completos
- [ ] Fluxo está bem testado

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
  
  updateTask(id: number, task: Partial<Task>): Observable<Task> {
    return this.http.patch<Task>(`/api/tasks/${id}`, task);
  }
  
  deleteTask(id: number): Observable<void> {
    return this.http.delete<void>(`/api/tasks/${id}`);
  }
}
```

**task-form.component.ts**
```typescript
import { Component, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';

@Component({
  selector: 'app-task-form',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  template: `
    <form [formGroup]="taskForm" (ngSubmit)="onSubmit()">
      <input 
        formControlName="title"
        placeholder="Título da tarefa">
      @if (taskForm.get('title')?.hasError('required') && taskForm.get('title')?.touched) {
        <span class="error">Título é obrigatório</span>
      }
      <button type="submit" [disabled]="taskForm.invalid">Adicionar</button>
    </form>
  `
})
export class TaskFormComponent {
  @Output() taskAdded = new EventEmitter<string>();
  
  taskForm = this.fb.group({
    title: ['', Validators.required]
  });
  
  constructor(private fb: FormBuilder) {}
  
  onSubmit(): void {
    if (this.taskForm.valid) {
      this.taskAdded.emit(this.taskForm.value.title!);
      this.taskForm.reset();
    }
  }
}
```

**task-list.component.ts**
```typescript
import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { TaskFormComponent } from './task-form.component';
import { TaskItemComponent } from './task-item.component';
import { TaskService, Task } from './task.service';

@Component({
  selector: 'app-task-list',
  standalone: true,
  imports: [CommonModule, TaskFormComponent, TaskItemComponent],
  template: `
    <div>
      <h2>Tarefas</h2>
      <app-task-form (taskAdded)="addTask($event)"></app-task-form>
      <ul>
        @for (task of tasks(); track task.id) {
          <app-task-item 
            [task]="task"
            (toggle)="toggleTask($event)"
            (delete)="deleteTask($event)">
          </app-task-item>
        }
      </ul>
    </div>
  `
})
export class TaskListComponent implements OnInit {
  tasks = signal<Task[]>([]);
  
  constructor(private taskService: TaskService) {}
  
  ngOnInit(): void {
    this.loadTasks();
  }
  
  loadTasks(): void {
    this.taskService.getTasks().subscribe(tasks => {
      this.tasks.set(tasks);
    });
  }
  
  addTask(title: string): void {
    this.taskService.createTask({ title, completed: false }).subscribe(newTask => {
      this.tasks.update(tasks => [...tasks, newTask]);
    });
  }
  
  toggleTask(id: number): void {
    const task = this.tasks().find(t => t.id === id);
    if (task) {
      this.taskService.updateTask(id, { completed: !task.completed }).subscribe(updatedTask => {
        this.tasks.update(tasks => tasks.map(t => t.id === id ? updatedTask : t));
      });
    }
  }
  
  deleteTask(id: number): void {
    this.taskService.deleteTask(id).subscribe(() => {
      this.tasks.update(tasks => tasks.filter(t => t.id !== id));
    });
  }
}
```

**task-list.integration.spec.ts**
```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { TaskListComponent } from './task-list.component';
import { TaskFormComponent } from './task-form.component';
import { TaskItemComponent } from './task-item.component';
import { TaskService, Task } from './task.service';
import { By } from '@angular/platform-browser';

describe('TaskListComponent Integration', () => {
  let component: TaskListComponent;
  let fixture: ComponentFixture<TaskListComponent>;
  let httpMock: HttpTestingController;
  let taskService: TaskService;

  const mockTasks: Task[] = [
    { id: 1, title: 'Task 1', completed: false },
    { id: 2, title: 'Task 2', completed: true }
  ];

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [
        TaskListComponent,
        TaskFormComponent,
        TaskItemComponent,
        HttpClientTestingModule,
        ReactiveFormsModule
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(TaskListComponent);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    taskService = TestBed.inject(TaskService);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should load tasks on init', () => {
    fixture.detectChanges();
    
    const req = httpMock.expectOne('/api/tasks');
    req.flush(mockTasks);
    
    fixture.detectChanges();
    
    expect(component.tasks().length).toBe(2);
    const taskItems = fixture.debugElement.queryAll(By.css('app-task-item'));
    expect(taskItems.length).toBe(2);
  });

  it('should create task through form', () => {
    fixture.detectChanges();
    
    const initialReq = httpMock.expectOne('/api/tasks');
    initialReq.flush(mockTasks);
    fixture.detectChanges();
    
    const form = fixture.debugElement.query(By.css('app-task-form'));
    const input = form.query(By.css('input'));
    const button = form.query(By.css('button'));
    
    input.nativeElement.value = 'New Task';
    input.nativeElement.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    
    button.nativeElement.click();
    fixture.detectChanges();
    
    const createReq = httpMock.expectOne('/api/tasks');
    expect(createReq.request.method).toBe('POST');
    expect(createReq.request.body).toEqual({ title: 'New Task', completed: false });
    
    const newTask: Task = { id: 3, title: 'New Task', completed: false };
    createReq.flush(newTask);
    fixture.detectChanges();
    
    expect(component.tasks().length).toBe(3);
    expect(component.tasks()[2].title).toBe('New Task');
  });

  it('should toggle task completion', () => {
    fixture.detectChanges();
    
    const req = httpMock.expectOne('/api/tasks');
    req.flush(mockTasks);
    fixture.detectChanges();
    
    const taskItem = fixture.debugElement.query(By.css('app-task-item'));
    const checkbox = taskItem.query(By.css('input[type="checkbox"]'));
    
    checkbox.nativeElement.click();
    fixture.detectChanges();
    
    const updateReq = httpMock.expectOne('/api/tasks/1');
    expect(updateReq.request.method).toBe('PATCH');
    expect(updateReq.request.body).toEqual({ completed: true });
    
    const updatedTask = { ...mockTasks[0], completed: true };
    updateReq.flush(updatedTask);
    fixture.detectChanges();
    
    expect(component.tasks()[0].completed).toBe(true);
  });

  it('should delete task', () => {
    fixture.detectChanges();
    
    const req = httpMock.expectOne('/api/tasks');
    req.flush(mockTasks);
    fixture.detectChanges();
    
    const taskItem = fixture.debugElement.query(By.css('app-task-item'));
    const deleteButton = taskItem.query(By.css('button'));
    
    deleteButton.nativeElement.click();
    fixture.detectChanges();
    
    const deleteReq = httpMock.expectOne('/api/tasks/1');
    expect(deleteReq.request.method).toBe('DELETE');
    deleteReq.flush(null);
    fixture.detectChanges();
    
    expect(component.tasks().length).toBe(1);
    expect(component.tasks()[0].id).toBe(2);
  });
});
```

**Explicação da Solução**:

1. Múltiplos componentes testados juntos
2. Serviço integrado com componentes
3. Fluxo completo testado
4. HTTP mockado mas integração real
5. Comportamento end-to-end verificado
6. Testes mais próximos do comportamento real

---

## Testes

### Casos de Teste

**Teste 1**: Fluxo completo funciona
- **Input**: Criar tarefa através do form
- **Output Esperado**: Tarefa criada e exibida

**Teste 2**: Integração funciona
- **Input**: Interagir com múltiplos componentes
- **Output Esperado**: Comportamento correto

**Teste 3**: HTTP integrado
- **Input**: Operações HTTP através de componentes
- **Output Esperado**: Requisições feitas corretamente

---

## Extensões (Opcional)

1. **Router Integration**: Teste integração com router
2. **State Management**: Teste integração com NgRx
3. **Forms Integration**: Teste formulários complexos

---

## Referências Úteis

- **[Integration Testing](https://angular.io/guide/testing#testing-components)**: Guia testes integração
- **[Testing Best Practices](https://angular.io/guide/testing-best-practices)**: Boas práticas

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

