---
layout: exercise
title: "Exercício 3.3.2: Effects"
slug: "effects"
lesson_id: "lesson-3-3"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Effects** através da **implementação de Effects que fazem chamadas HTTP**.

Ao completar este exercício, você será capaz de:

- Criar Effects com createEffect()
- Escutar Actions
- Fazer chamadas HTTP em Effects
- Dispatch Actions de sucesso/erro
- Tratar erros em Effects
- Configurar Effects no bootstrap

---

## Descrição

Você precisa criar Effects que carregam usuários de uma API e atualizam o Store.

### Contexto

Uma aplicação precisa carregar dados de API e atualizar Store através de Effects.

### Tarefa

Crie:

1. **Actions**: Actions para load, success, failure
2. **Effects**: Effect que faz chamada HTTP
3. **Reducer**: Reducer que processa success/failure
4. **Component**: Componente que dispatch load action
5. **Configuration**: Configurar Effects no bootstrap

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Actions criadas para load/success/failure
- [ ] Effect criado com createEffect()
- [ ] HTTP chamada implementada
- [ ] Tratamento de erros implementado
- [ ] Effects configurados no bootstrap
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Effects estão bem estruturados
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**user.actions.ts**
```typescript
import { createAction, props } from '@ngrx/store';
import { User } from './user.model';

export const loadUsers = createAction('[User] Load Users');
export const loadUsersSuccess = createAction(
  '[User] Load Users Success',
  props<{ users: User[] }>()
);
export const loadUsersFailure = createAction(
  '[User] Load Users Failure',
  props<{ error: string }>()
);
```

**user.effects.ts**
```typescript
import { Injectable } from '@angular/core';
import { Actions, createEffect, ofType } from '@ngrx/effects';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { map, catchError, switchMap } from 'rxjs/operators';
import { loadUsers, loadUsersSuccess, loadUsersFailure } from './user.actions';

@Injectable()
export class UserEffects {
  loadUsers$ = createEffect(() =>
    this.actions$.pipe(
      ofType(loadUsers),
      switchMap(() =>
        this.http.get<User[]>('/api/users').pipe(
          map(users => loadUsersSuccess({ users })),
          catchError(error => of(loadUsersFailure({ error: error.message })))
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

**user.reducer.ts**
```typescript
import { createReducer, on } from '@ngrx/store';
import { loadUsers, loadUsersSuccess, loadUsersFailure } from './user.actions';
import { User } from './user.model';

export interface UserState {
  users: User[];
  loading: boolean;
  error: string | null;
}

export const initialState: UserState = {
  users: [],
  loading: false,
  error: null
};

export const userReducer = createReducer(
  initialState,
  on(loadUsers, state => ({
    ...state,
    loading: true,
    error: null
  })),
  on(loadUsersSuccess, (state, { users }) => ({
    ...state,
    users,
    loading: false
  })),
  on(loadUsersFailure, (state, { error }) => ({
    ...state,
    error,
    loading: false
  }))
);
```

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideStore } from '@ngrx/store';
import { provideEffects } from '@ngrx/effects';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app/app.component';
import { userReducer } from './app/store/user.reducer';
import { UserEffects } from './app/store/user.effects';

bootstrapApplication(AppComponent, {
  providers: [
    provideStore({
      users: userReducer
    }),
    provideEffects([UserEffects]),
    provideHttpClient()
  ]
});
```

**user-list.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Store } from '@ngrx/store';
import { Observable } from 'rxjs';
import { loadUsers } from './store/user.actions';
import { selectAllUsers, selectLoading, selectError } from './store/user.selectors';
import { User } from './user.model';

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Usuários</h2>
      <button (click)="load()">Carregar Usuários</button>
      
      @if (loading$ | async) {
        <p>Carregando...</p>
      }
      
      @if (error$ | async) {
        <p class="error">{{ error$ | async }}</p>
      }
      
      <ul>
        @for (user of users$ | async; track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
    </div>
  `
})
export class UserListComponent implements OnInit {
  users$: Observable<User[]>;
  loading$: Observable<boolean>;
  error$: Observable<string | null>;
  
  constructor(private store: Store) {
    this.users$ = this.store.select(selectAllUsers);
    this.loading$ = this.store.select(selectLoading);
    this.error$ = this.store.select(selectError);
  }
  
  ngOnInit(): void {
    this.load();
  }
  
  load(): void {
    this.store.dispatch(loadUsers());
  }
}
```

**Explicação da Solução**:

1. Actions criadas para load/success/failure
2. Effect escuta loadUsers action
3. Effect faz chamada HTTP
4. Effect dispatch success ou failure
5. Reducer atualiza estado baseado em actions
6. Component dispatch action e seleciona estado

---

## Testes

### Casos de Teste

**Teste 1**: Load funciona
- **Input**: Clicar em "Carregar Usuários"
- **Output Esperado**: Usuários carregados e exibidos

**Teste 2**: Loading state funciona
- **Input**: Durante carregamento
- **Output Esperado**: "Carregando..." aparece

**Teste 3**: Error handling funciona
- **Input**: Simular erro na API
- **Output Esperado**: Mensagem de erro exibida

---

## Extensões (Opcional)

1. **Retry Logic**: Adicione retry em caso de erro
2. **Cache**: Implemente cache de dados
3. **Pagination**: Adicione paginação

---

## Referências Úteis

- **[Effects](https://ngrx.io/guide/effects)**: Guia Effects
- **[createEffect](https://ngrx.io/api/effects/createEffect)**: Documentação createEffect

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

