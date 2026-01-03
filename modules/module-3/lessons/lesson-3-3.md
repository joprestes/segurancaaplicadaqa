---
layout: lesson
title: "Aula 3.3: NgRx - Gerenciamento de Estado"
slug: ngrx
module: module-3
lesson_id: lesson-3-3
duration: "150 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-3-2"
exercises:
  - 
  - "lesson-3-3-exercise-1"
  - "lesson-3-3-exercise-2"
  - "lesson-3-3-exercise-3"
  - "lesson-3-3-exercise-4"
  - "lesson-3-3-exercise-5"
  - "lesson-3-3-exercise-6"
  - "lesson-3-3-exercise-7"
podcast:
  file: "assets/podcasts/03.3-NgRx_quando_vale_a_pena_usar.m4a"
  title: "NgRx - Quando Vale a Pena Usar"
  description: "NgRx é poderoso, mas nem sempre necessário."
  duration: "70-85 minutos"
---

## Introdução

Nesta aula, você dominará NgRx, a biblioteca oficial do Angular para gerenciamento de estado global baseada em Redux. NgRx oferece uma arquitetura previsível e escalável para gerenciar estado complexo em aplicações Angular grandes.

### O que você vai aprender

- Configurar Store do NgRx
- Criar Actions, Reducers e Effects
- Usar Selectors para acessar estado
- Trabalhar com Entities para dados normalizados
- Implementar Facade Pattern
- Usar NgRx DevTools para debugging
- Criar aplicação completa com NgRx

### Por que isso é importante

NgRx é essencial para aplicações Angular grandes e complexas. Oferece previsibilidade, testabilidade e ferramentas poderosas para debugging. É a solução padrão para gerenciamento de estado global em Angular.

---

## Conceitos Teóricos

### Store

**Definição**: Store é o container centralizado que mantém o estado da aplicação como uma única fonte de verdade.

**Explicação Detalhada**:

Store:
- Mantém estado imutável
- Única fonte de verdade
- Acessível em toda aplicação
- Previsível através de Actions e Reducers
- Time-travel debugging com DevTools

**Analogia**:

Store é como um cofre central. Todas as mudanças passam por ele de forma controlada (Actions), são processadas de forma previsível (Reducers) e o estado resultante é acessível por todos.

**Visualização**:

```
Component ──Action──→ Store ──Reducer──→ New State
    ↑                                        │
    └───────────Selector─────────────────────┘
```

**Exemplo Prático**:

```typescript
import { Store } from '@ngrx/store';
import { createAction, createReducer, on } from '@ngrx/store';
import { createFeatureSelector, createSelector } from '@ngrx/store';

export const increment = createAction('[Counter] Increment');
export const decrement = createAction('[Counter] Decrement');
export const reset = createAction('[Counter] Reset');

export interface CounterState {
  count: number;
}

export const initialState: CounterState = {
  count: 0
};

export const counterReducer = createReducer(
  initialState,
  on(increment, state => ({ ...state, count: state.count + 1 })),
  on(decrement, state => ({ ...state, count: state.count - 1 })),
  on(reset, state => ({ ...state, count: 0 }))
);
```

---

### Actions

**Definição**: Actions são eventos que descrevem algo que aconteceu na aplicação.

**Explicação Detalhada**:

Actions:
- Descrevem eventos, não comandos
- Têm type e payload opcional
- Criadas com createAction()
- Dispatched via Store.dispatch()
- Processadas por Reducers e Effects

**Analogia**:

Actions são como mensagens enviadas ao Store. "Alguém clicou no botão" (Action) → Store processa → Estado atualizado.

**Exemplo Prático**:

```typescript
import { createAction, props } from '@ngrx/store';

export const loadUsers = createAction('[User] Load Users');
export const loadUsersSuccess = createAction(
  '[User] Load Users Success',
  props<{ users: User[] }>()
);
export const loadUsersFailure = createAction(
  '[User] Load Users Failure',
  props<{ error: string }>()
);

export const addUser = createAction(
  '[User] Add User',
  props<{ user: User }>()
);

export const updateUser = createAction(
  '[User] Update User',
  props<{ id: number; changes: Partial<User> }>()
);

export const deleteUser = createAction(
  '[User] Delete User',
  props<{ id: number }>()
);
```

---

### Reducers

**Definição**: Reducers são funções puras que especificam como o estado muda em resposta a Actions.

**Explicação Detalhada**:

Reducers:
- Funções puras (sem side effects)
- Recebem estado atual e action
- Retornam novo estado (imutável)
- Criados com createReducer()
- Combinados com combineReducers()

**Analogia**:

Reducers são como processadores de eventos. Recebem um evento (Action) e o estado atual, e retornam o novo estado baseado nas regras definidas.

**Exemplo Prático**:

```typescript
import { createReducer, on } from '@ngrx/store';
import { UserActions } from './user.actions';

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
  on(UserActions.loadUsers, state => ({
    ...state,
    loading: true,
    error: null
  })),
  on(UserActions.loadUsersSuccess, (state, { users }) => ({
    ...state,
    users,
    loading: false
  })),
  on(UserActions.loadUsersFailure, (state, { error }) => ({
    ...state,
    error,
    loading: false
  })),
  on(UserActions.addUser, (state, { user }) => ({
    ...state,
    users: [...state.users, user]
  })),
  on(UserActions.updateUser, (state, { id, changes }) => ({
    ...state,
    users: state.users.map(u => u.id === id ? { ...u, ...changes } : u)
  })),
  on(UserActions.deleteUser, (state, { id }) => ({
    ...state,
    users: state.users.filter(u => u.id !== id)
  }))
);
```

---

### Effects

**Definição**: Effects são usados para lidar com side effects (como chamadas HTTP) de forma isolada dos componentes.

**Explicação Detalhada**:

Effects:
- Lidam com side effects assíncronos
- Escutam Actions
- Podem dispatch novas Actions
- Retornam Observables
- Criados com createEffect()

**Analogia**:

Effects são como assistentes que fazem trabalho pesado (HTTP, timers, etc.) enquanto Reducers apenas atualizam estado. Effects ouvem Actions e fazem trabalho assíncrono.

**Exemplo Prático**:

```typescript
import { Injectable } from '@angular/core';
import { Actions, createEffect, ofType } from '@ngrx/effects';
import { Store } from '@ngrx/store';
import { of } from 'rxjs';
import { map, catchError, switchMap } from 'rxjs/operators';
import { UserService } from './user.service';
import { UserActions } from './user.actions';

@Injectable()
export class UserEffects {
  loadUsers$ = createEffect(() =>
    this.actions$.pipe(
      ofType(UserActions.loadUsers),
      switchMap(() =>
        this.userService.getUsers().pipe(
          map(users => UserActions.loadUsersSuccess({ users })),
          catchError(error => of(UserActions.loadUsersFailure({ error: error.message })))
        )
      )
    )
  );
  
  addUser$ = createEffect(() =>
    this.actions$.pipe(
      ofType(UserActions.addUser),
      switchMap(({ user }) =>
        this.userService.createUser(user).pipe(
          map(newUser => UserActions.addUserSuccess({ user: newUser })),
          catchError(error => of(UserActions.addUserFailure({ error: error.message })))
        )
      )
    )
  );
  
  constructor(
    private actions$: Actions,
    private userService: UserService
  ) {}
}
```

---

### Selectors

**Definição**: Selectors são funções que extraem e derivam dados do estado do Store.

**Explicação Detalhada**:

Selectors:
- Extraem dados do estado
- Podem derivar dados computados
- Memoizados automaticamente
- Criados com createSelector()
- Podem ser compostos

**Analogia**:

Selectors são como consultas SQL. Você especifica o que quer do estado e recebe apenas esses dados, otimizados e memoizados.

**Exemplo Prático**:

```typescript
import { createFeatureSelector, createSelector } from '@ngrx/store';
import { UserState } from './user.reducer';

export const selectUserState = createFeatureSelector<UserState>('users');

export const selectAllUsers = createSelector(
  selectUserState,
  (state) => state.users
);

export const selectLoading = createSelector(
  selectUserState,
  (state) => state.loading
);

export const selectError = createSelector(
  selectUserState,
  (state) => state.error
);

export const selectActiveUsers = createSelector(
  selectAllUsers,
  (users) => users.filter(u => u.active)
);

export const selectUserById = (id: number) => createSelector(
  selectAllUsers,
  (users) => users.find(u => u.id === id)
);
```

---

### Entities

**Definição**: Entities é uma biblioteca NgRx que fornece padrões para gerenciar coleções de entidades de forma normalizada.

**Explicação Detalhada**:

Entities:
- Normaliza dados em formato { ids: [], entities: {} }
- Facilita operações CRUD
- Melhora performance
- Reduz boilerplate
- Fornece adapters e selectors

**Analogia**:

Entities é como um índice de livro. Ao invés de procurar em uma lista linear, você tem um índice (ids) que aponta para entradas (entities), tornando busca e atualização muito mais rápidas.

**Exemplo Prático**:

```typescript
import { createEntityAdapter, EntityState, EntityAdapter } from '@ngrx/entity';
import { createReducer, on } from '@ngrx/store';
import { UserActions } from './user.actions';

export interface User {
  id: number;
  name: string;
  email: string;
}

export interface UserState extends EntityState<User> {
  loading: boolean;
  error: string | null;
}

export const userAdapter: EntityAdapter<User> = createEntityAdapter<User>({
  selectId: (user: User) => user.id
});

export const initialState: UserState = userAdapter.getInitialState({
  loading: false,
  error: null
});

export const userReducer = createReducer(
  initialState,
  on(UserActions.loadUsersSuccess, (state, { users }) =>
    userAdapter.setAll(users, { ...state, loading: false })
  ),
  on(UserActions.addUser, (state, { user }) =>
    userAdapter.addOne(user, state)
  ),
  on(UserActions.updateUser, (state, { id, changes }) =>
    userAdapter.updateOne({ id, changes }, state)
  ),
  on(UserActions.deleteUser, (state, { id }) =>
    userAdapter.removeOne(id, state)
  )
);

export const { selectAll, selectIds, selectEntities } = userAdapter.getSelectors();
```

---

### Facade Pattern

**Definição**: Facade Pattern encapsula complexidade do NgRx, fornecendo API simples para componentes.

**Explicação Detalhada**:

Facade:
- Encapsula Store, Actions e Selectors
- Fornece API simples para componentes
- Esconde detalhes de implementação
- Facilita testes e manutenção
- Melhora separação de responsabilidades

**Analogia**:

Facade é como uma recepção de hotel. Você não precisa saber como funciona o sistema interno, apenas pede o que precisa através de uma interface simples.

**Exemplo Prático**:

```typescript
import { Injectable } from '@angular/core';
import { Store } from '@ngrx/store';
import { Observable } from 'rxjs';
import { UserActions } from './user.actions';
import { selectAllUsers, selectLoading, selectError } from './user.selectors';
import { User } from './user.model';

@Injectable({
  providedIn: 'root'
})
export class UserFacade {
  users$: Observable<User[]> = this.store.select(selectAllUsers);
  loading$: Observable<boolean> = this.store.select(selectLoading);
  error$: Observable<string | null> = this.store.select(selectError);
  
  constructor(private store: Store) {}
  
  loadUsers(): void {
    this.store.dispatch(UserActions.loadUsers());
  }
  
  addUser(user: User): void {
    this.store.dispatch(UserActions.addUser({ user }));
  }
  
  updateUser(id: number, changes: Partial<User>): void {
    this.store.dispatch(UserActions.updateUser({ id, changes }));
  }
  
  deleteUser(id: number): void {
    this.store.dispatch(UserActions.deleteUser({ id }));
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Configuração Completa do NgRx

**Contexto**: Configurar NgRx completo em aplicação standalone.

**Código**:

```typescript
import { provideStore } from '@ngrx/store';
import { provideEffects } from '@ngrx/effects';
import { provideStoreDevtools } from '@ngrx/store-devtools';
import { counterReducer } from './store/counter.reducer';
import { UserEffects } from './store/user.effects';
import { userReducer } from './store/user.reducer';

bootstrapApplication(AppComponent, {
  providers: [
    provideStore({
      counter: counterReducer,
      users: userReducer
    }),
    provideEffects([UserEffects]),
    provideStoreDevtools({
      maxAge: 25,
      logOnly: !isDevMode()
    })
  ]
});
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use Facade Pattern para abstrair NgRx**
   - **Por quê**: Simplifica uso em componentes
   - **Exemplo**: UserFacade encapsula Store

2. **Use Entities para coleções grandes**
   - **Por quê**: Melhor performance e menos boilerplate
   - **Exemplo**: EntityAdapter para users

3. **Mantenha Reducers puros**
   - **Por quê**: Previsibilidade e testabilidade
   - **Exemplo**: Sem side effects em reducers

4. **Use Selectors para derivar dados**
   - **Por quê**: Memoização e performance
   - **Exemplo**: selectActiveUsers

### ❌ Anti-padrões Comuns

1. **Não faça side effects em Reducers**
   - **Problema**: Quebra previsibilidade
   - **Solução**: Use Effects

2. **Não acesse Store diretamente em componentes**
   - **Problema**: Acoplamento forte
   - **Solução**: Use Facade

3. **Não ignore DevTools**
   - **Problema**: Debugging difícil
   - **Solução**: Sempre configure DevTools

---

## Exercícios Práticos

### Exercício 1: Store, Actions e Reducers Básicos (Básico)

**Objetivo**: Criar primeira configuração NgRx

**Descrição**: 
Configure Store básico com Actions e Reducers para contador.

**Arquivo**: `exercises/exercise-3-3-1-store-actions-reducers.md`

---

### Exercício 2: Effects (Intermediário)

**Objetivo**: Implementar Effects para side effects

**Descrição**:
Crie Effects que fazem chamadas HTTP e atualizam Store.

**Arquivo**: `exercises/exercise-3-3-2-effects.md`

---

### Exercício 3: Selectors (Intermediário)

**Objetivo**: Criar Selectors para acessar estado

**Descrição**:
Crie Selectors básicos e compostos para extrair dados do Store.

**Arquivo**: `exercises/exercise-3-3-3-selectors.md`

---

### Exercício 4: Entities (Avançado)

**Objetivo**: Trabalhar com Entities

**Descrição**:
Implemente gerenciamento de usuários usando EntityAdapter.

**Arquivo**: `exercises/exercise-3-3-4-entities.md`

---

### Exercício 5: Facade Pattern (Avançado)

**Objetivo**: Implementar Facade Pattern

**Descrição**:
Crie Facade que encapsula Store, Actions e Selectors.

**Arquivo**: `exercises/exercise-3-3-5-facade.md`

---

### Exercício 6: NgRx DevTools (Avançado)

**Objetivo**: Configurar e usar DevTools

**Descrição**:
Configure NgRx DevTools e demonstre debugging.

**Arquivo**: `exercises/exercise-3-3-6-devtools.md`

---

### Exercício 7: NgRx Completo (Avançado)

**Objetivo**: Criar aplicação completa com NgRx

**Descrição**:
Crie aplicação completa usando todas as técnicas NgRx aprendidas.

**Arquivo**: `exercises/exercise-3-3-7-ngrx-completo.md`

---

## Referências Externas

### Documentação Oficial

- **[NgRx Documentation](https://ngrx.io/)**: Documentação completa
- **[Store](https://ngrx.io/guide/store)**: Guia Store
- **[Effects](https://ngrx.io/guide/effects)**: Guia Effects
- **[Selectors](https://ngrx.io/guide/store/selectors)**: Guia Selectors

---

## Resumo

### Principais Conceitos

- Store mantém estado global centralizado
- Actions descrevem eventos
- Reducers atualizam estado de forma previsível
- Effects lidam com side effects
- Selectors extraem e derivam dados
- Entities normalizam coleções
- Facade Pattern simplifica uso

### Pontos-Chave para Lembrar

- Use Facade Pattern para abstrair NgRx
- Use Entities para coleções grandes
- Mantenha Reducers puros
- Use Selectors para derivar dados
- Configure DevTools sempre

### Próximos Passos

- Próxima aula: Padrões Reativos e Memory Leaks
- Praticar criando aplicações NgRx
- Explorar padrões avançados

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

**Aula Anterior**: [Aula 3.2: Signals e Signal-First Architecture](./lesson-3-2-signals.md)  
**Próxima Aula**: [Aula 3.4: Padrões Reativos e Memory Leaks](./lesson-3-4-memory-leaks.md)  
**Voltar ao Módulo**: [Módulo 3: Programação Reativa e Estado](../modules/module-3-programacao-reativa-estado.md)

