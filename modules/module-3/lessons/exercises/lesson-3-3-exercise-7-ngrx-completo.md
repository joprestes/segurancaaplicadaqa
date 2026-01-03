---
layout: exercise
title: "Exercício 3.3.7: NgRx Completo"
slug: "ngrx-completo"
lesson_id: "lesson-3-3"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **todas as técnicas NgRx** através da **criação de aplicação completa usando todas as funcionalidades aprendidas**.

Ao completar este exercício, você será capaz de:

- Criar aplicação NgRx completa
- Usar Store, Actions, Reducers, Effects, Selectors
- Implementar Entities
- Usar Facade Pattern
- Configurar DevTools
- Aplicar todas as boas práticas

---

## Descrição

Você precisa criar uma aplicação completa de gerenciamento de tarefas usando todas as técnicas NgRx aprendidas.

### Contexto

Uma aplicação precisa demonstrar uso completo e correto do NgRx em aplicação real.

### Tarefa

Crie:

1. **Store Configuration**: Configuração completa do Store
2. **Actions**: Actions completas para todas operações
3. **Reducers**: Reducers usando Entities
4. **Effects**: Effects para operações assíncronas
5. **Selectors**: Selectors básicos e compostos
6. **Facade**: Facade Pattern implementado
7. **DevTools**: DevTools configurado
8. **Application**: Aplicação completa e funcional

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Store configurado completamente
- [ ] Actions para todas operações
- [ ] Reducers usando Entities
- [ ] Effects implementados
- [ ] Selectors criados
- [ ] Facade implementado
- [ ] DevTools configurado
- [ ] Aplicação completa e funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todas as técnicas são aplicadas
- [ ] Código é bem organizado

---

## Solução Esperada

### Abordagem Recomendada

**task.actions.ts**
```typescript
import { createAction, props } from '@ngrx/store';
import { Task } from './task.model';

export const loadTasks = createAction('[Task] Load Tasks');
export const loadTasksSuccess = createAction(
  '[Task] Load Tasks Success',
  props<{ tasks: Task[] }>()
);
export const loadTasksFailure = createAction(
  '[Task] Load Tasks Failure',
  props<{ error: string }>()
);

export const addTask = createAction(
  '[Task] Add Task',
  props<{ task: Omit<Task, 'id'> }>()
);
export const addTaskSuccess = createAction(
  '[Task] Add Task Success',
  props<{ task: Task }>()
);

export const updateTask = createAction(
  '[Task] Update Task',
  props<{ id: number; changes: Partial<Task> }>()
);

export const deleteTask = createAction(
  '[Task] Delete Task',
  props<{ id: number }>()
);

export const toggleTask = createAction(
  '[Task] Toggle Task',
  props<{ id: number }>()
);
```

**task.effects.ts**
```typescript
import { Injectable } from '@angular/core';
import { Actions, createEffect, ofType } from '@ngrx/effects';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { map, catchError, switchMap } from 'rxjs/operators';
import { TaskActions } from './task.actions';
import { Task } from './task.model';

@Injectable()
export class TaskEffects {
  loadTasks$ = createEffect(() =>
    this.actions$.pipe(
      ofType(TaskActions.loadTasks),
      switchMap(() =>
        this.http.get<Task[]>('/api/tasks').pipe(
          map(tasks => TaskActions.loadTasksSuccess({ tasks })),
          catchError(error => of(TaskActions.loadTasksFailure({ error: error.message })))
        )
      )
    )
  );
  
  addTask$ = createEffect(() =>
    this.actions$.pipe(
      ofType(TaskActions.addTask),
      switchMap(({ task }) =>
        this.http.post<Task>('/api/tasks', task).pipe(
          map(newTask => TaskActions.addTaskSuccess({ task: newTask })),
          catchError(error => of(TaskActions.addTaskFailure({ error: error.message })))
        )
      )
    )
  );
  
  constructor(
    private actions$: Actions,
    private http: HttpClient
  ) {}
}
```

**task.reducer.ts**
```typescript
import { createEntityAdapter, EntityState, EntityAdapter } from '@ngrx/entity';
import { createReducer, on } from '@ngrx/store';
import { Task } from './task.model';
import { TaskActions } from './task.actions';

export interface TaskState extends EntityState<Task> {
  loading: boolean;
  error: string | null;
}

export const taskAdapter: EntityAdapter<Task> = createEntityAdapter<Task>({
  selectId: (task: Task) => task.id
});

export const initialState: TaskState = taskAdapter.getInitialState({
  loading: false,
  error: null
});

export const taskReducer = createReducer(
  initialState,
  on(TaskActions.loadTasks, state => ({
    ...state,
    loading: true,
    error: null
  })),
  on(TaskActions.loadTasksSuccess, (state, { tasks }) =>
    taskAdapter.setAll(tasks, { ...state, loading: false })
  ),
  on(TaskActions.loadTasksFailure, (state, { error }) => ({
    ...state,
    error,
    loading: false
  })),
  on(TaskActions.addTaskSuccess, (state, { task }) =>
    taskAdapter.addOne(task, state)
  ),
  on(TaskActions.updateTask, (state, { id, changes }) =>
    taskAdapter.updateOne({ id, changes }, state)
  ),
  on(TaskActions.deleteTask, (state, { id }) =>
    taskAdapter.removeOne(id, state)
  ),
  on(TaskActions.toggleTask, (state, { id }) => {
    const task = state.entities[id];
    if (task) {
      return taskAdapter.updateOne(
        { id, changes: { completed: !task.completed } },
        state
      );
    }
    return state;
  })
);
```

**task.selectors.ts**
```typescript
import { createFeatureSelector, createSelector } from '@ngrx/store';
import { TaskState, taskAdapter } from './task.reducer';

export const selectTaskState = createFeatureSelector<TaskState>('tasks');

export const {
  selectAll: selectAllTasks,
  selectIds: selectTaskIds,
  selectEntities: selectTaskEntities
} = taskAdapter.getSelectors(selectTaskState);

export const selectLoading = createSelector(
  selectTaskState,
  (state) => state.loading
);

export const selectError = createSelector(
  selectTaskState,
  (state) => state.error
);

export const selectCompletedTasks = createSelector(
  selectAllTasks,
  (tasks) => tasks.filter(t => t.completed)
);

export const selectActiveTasks = createSelector(
  selectAllTasks,
  (tasks) => tasks.filter(t => !t.completed)
);

export const selectTaskById = (id: number) => createSelector(
  selectTaskEntities,
  (entities) => entities[id]
);
```

**task.facade.ts**
```typescript
import { Injectable } from '@angular/core';
import { Store } from '@ngrx/store';
import { Observable } from 'rxjs';
import { Task } from './task.model';
import { TaskActions } from './task.actions';
import {
  selectAllTasks,
  selectLoading,
  selectError,
  selectCompletedTasks,
  selectActiveTasks
} from './task.selectors';

@Injectable({
  providedIn: 'root'
})
export class TaskFacade {
  tasks$: Observable<Task[]> = this.store.select(selectAllTasks);
  loading$: Observable<boolean> = this.store.select(selectLoading);
  error$: Observable<string | null> = this.store.select(selectError);
  completedTasks$: Observable<Task[]> = this.store.select(selectCompletedTasks);
  activeTasks$: Observable<Task[]> = this.store.select(selectActiveTasks);
  
  constructor(private store: Store) {}
  
  loadTasks(): void {
    this.store.dispatch(TaskActions.loadTasks());
  }
  
  addTask(task: Omit<Task, 'id'>): void {
    this.store.dispatch(TaskActions.addTask({ task }));
  }
  
  updateTask(id: number, changes: Partial<Task>): void {
    this.store.dispatch(TaskActions.updateTask({ id, changes }));
  }
  
  deleteTask(id: number): void {
    this.store.dispatch(TaskActions.deleteTask({ id }));
  }
  
  toggleTask(id: number): void {
    this.store.dispatch(TaskActions.toggleTask({ id }));
  }
}
```

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { isDevMode } from '@angular/core';
import { provideStore } from '@ngrx/store';
import { provideEffects } from '@ngrx/effects';
import { provideStoreDevtools } from '@ngrx/store-devtools';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app/app.component';
import { taskReducer } from './app/store/task.reducer';
import { TaskEffects } from './app/store/task.effects';

bootstrapApplication(AppComponent, {
  providers: [
    provideStore({
      tasks: taskReducer
    }),
    provideEffects([TaskEffects]),
    provideStoreDevtools({
      maxAge: 25,
      logOnly: !isDevMode()
    }),
    provideHttpClient()
  ]
});
```

**task-list.component.ts**
{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { TaskFacade } from './store/task.facade';
import { Task } from './task.model';
import { TaskFormComponent } from './task-form.component';

@Component({
  selector: 'app-task-list',
  standalone: true,
  imports: [CommonModule, TaskFormComponent],
  template: `
    <div>
      <h2>Tarefas (NgRx Completo)</h2>
      <button (click)="load()">Carregar</button>
      
      @if (facade.loading$ | async) {
        <p>Carregando...</p>
      }
      
      @if (facade.error$ | async) {
        <p class="error">{{ facade.error$ | async }}</p>
      }
      
      <app-task-form (taskAdded)="add($event)"></app-task-form>
      
      <h3>Ativas ({{ (facade.activeTasks$ | async)?.length }})</h3>
      <ul>
        @for (task of facade.activeTasks$ | async; track task.id) {
          <li>
            <input 
              type="checkbox" 
              [checked]="task.completed"
              (change)="toggle(task.id)">
            {{ task.title }}
            <button (click)="delete(task.id)">Deletar</button>
          </li>
        }
      </ul>
      
      <h3>Completas ({{ (facade.completedTasks$ | async)?.length }})</h3>
      <ul>
        @for (task of facade.completedTasks$ | async; track task.id) {
          <li>
            <input 
              type="checkbox" 
              [checked]="task.completed"
              (change)="toggle(task.id)">
            {{ task.title }}
            <button (click)="delete(task.id)">Deletar</button>
          </li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class TaskListComponent implements OnInit {
  constructor(public facade: TaskFacade) {}
  
  ngOnInit(): void {
    this.load();
  }
  
  load(): void {
    this.facade.loadTasks();
  }
  
  add(task: Omit<Task, 'id'>): void {
    this.facade.addTask(task);
  }
  
  toggle(id: number): void {
    this.facade.toggleTask(id);
  }
  
  delete(id: number): void {
    this.facade.deleteTask(id);
  }
}
```

**Explicação da Solução**:

1. Store configurado com reducer
2. Effects configurados para side effects
3. DevTools configurado para debugging
4. Entities usado para normalização
5. Selectors criados para acesso eficiente
6. Facade encapsula toda complexidade
7. Component usa apenas Facade
8. Aplicação completa e funcional

---

## Testes

### Casos de Teste

**Teste 1**: CRUD completo funciona
- **Input**: Criar, ler, atualizar, deletar tarefas
- **Output Esperado**: Todas operações funcionam

**Teste 2**: DevTools funciona
- **Input**: Abrir DevTools
- **Output Esperado**: Estado e actions visíveis

**Teste 3**: Facade simplifica uso
- **Input**: Comparar com uso direto do Store
- **Output Esperado**: Código mais simples

---

## Extensões (Opcional)

1. **Múltiplas Features**: Adicione mais features ao Store
2. **Meta Reducers**: Implemente meta reducers
3. **Router Store**: Integre com Router Store

---

## Referências Úteis

- **[NgRx Complete Guide](https://ngrx.io/)**: Guia completo NgRx
- **[Best Practices](https://ngrx.io/guide/store/selectors#best-practices)**: Boas práticas

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

