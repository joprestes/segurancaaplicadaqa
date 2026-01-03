---
layout: exercise
title: "Exercício 3.3.4: Entities"
slug: "entities"
lesson_id: "lesson-3-3"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Entities** através da **implementação de gerenciamento de usuários usando EntityAdapter**.

Ao completar este exercício, você será capaz de:

- Usar EntityAdapter para normalizar dados
- Trabalhar com EntityState
- Implementar operações CRUD eficientes
- Usar selectors de EntityAdapter
- Entender benefícios de normalização

---

## Descrição

Você precisa criar gerenciamento completo de usuários usando EntityAdapter do NgRx.

### Contexto

Uma aplicação precisa gerenciar coleção grande de usuários de forma eficiente.

### Tarefa

Crie:

1. **EntityAdapter**: Criar adapter para User
2. **EntityState**: Definir estado com EntityState
3. **Reducer**: Reducer usando métodos do adapter
4. **Selectors**: Selectors usando adapter selectors
5. **Component**: Componente com CRUD completo

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] EntityAdapter criado
- [ ] EntityState definido
- [ ] Reducer usa métodos do adapter
- [ ] Selectors do adapter usados
- [ ] CRUD completo implementado
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Entities estão bem implementadas
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**user.model.ts**
```typescript
export interface User {
  id: number;
  name: string;
  email: string;
  active: boolean;
}
```

**user.reducer.ts**
```typescript
import { createEntityAdapter, EntityState, EntityAdapter } from '@ngrx/entity';
import { createReducer, on } from '@ngrx/store';
import { User } from './user.model';
import { UserActions } from './user.actions';

export interface UserState extends EntityState<User> {
  loading: boolean;
  error: string | null;
}

export const userAdapter: EntityAdapter<User> = createEntityAdapter<User>({
  selectId: (user: User) => user.id,
  sortComparer: (a, b) => a.name.localeCompare(b.name)
});

export const initialState: UserState = userAdapter.getInitialState({
  loading: false,
  error: null
});

export const userReducer = createReducer(
  initialState,
  on(UserActions.loadUsers, state => ({
    ...state,
    loading: true,
    error: null
  })),
  on(UserActions.loadUsersSuccess, (state, { users }) =>
    userAdapter.setAll(users, { ...state, loading: false })
  ),
  on(UserActions.loadUsersFailure, (state, { error }) => ({
    ...state,
    error,
    loading: false
  })),
  on(UserActions.addUser, (state, { user }) =>
    userAdapter.addOne(user, state)
  ),
  on(UserActions.updateUser, (state, { id, changes }) =>
    userAdapter.updateOne({ id, changes }, state)
  ),
  on(UserActions.deleteUser, (state, { id }) =>
    userAdapter.removeOne(id, state)
  ),
  on(UserActions.upsertUser, (state, { user }) =>
    userAdapter.upsertOne(user, state)
  )
);
```

**user.selectors.ts**
```typescript
import { createFeatureSelector, createSelector } from '@ngrx/store';
import { UserState, userAdapter } from './user.reducer';

export const selectUserState = createFeatureSelector<UserState>('users');

export const {
  selectAll: selectAllUsers,
  selectIds: selectUserIds,
  selectEntities: selectUserEntities
} = userAdapter.getSelectors(selectUserState);

export const selectLoading = createSelector(
  selectUserState,
  (state) => state.loading
);

export const selectUserById = (id: number) => createSelector(
  selectUserEntities,
  (entities) => entities[id]
);

export const selectActiveUsers = createSelector(
  selectAllUsers,
  (users) => users.filter(u => u.active)
);
```

**user-list.component.ts**
{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Store } from '@ngrx/store';
import { Observable } from 'rxjs';
import { UserActions } from './store/user.actions';
import { selectAllUsers, selectLoading } from './store/user.selectors';
import { User } from './user.model';

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Usuários (Entities)</h2>
      <button (click)="load()">Carregar</button>
      
      @if (loading$ | async) {
        <p>Carregando...</p>
      }
      
      <ul>
        @for (user of users$ | async; track user.id) {
          <li>
            {{ user.name }} - {{ user.email }}
            <button (click)="toggleActive(user)">Toggle</button>
            <button (click)="delete(user.id)">Deletar</button>
          </li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class UserListComponent implements OnInit {
  users$: Observable<User[]>;
  loading$: Observable<boolean>;
  
  constructor(private store: Store) {
    this.users$ = this.store.select(selectAllUsers);
    this.loading$ = this.store.select(selectLoading);
  }
  
  ngOnInit(): void {
    this.load();
  }
  
  load(): void {
    this.store.dispatch(UserActions.loadUsers());
  }
  
  toggleActive(user: User): void {
    this.store.dispatch(UserActions.updateUser({
      id: user.id,
      changes: { active: !user.active }
    }));
  }
  
  delete(id: number): void {
    this.store.dispatch(UserActions.deleteUser({ id }));
  }
}
```

**Explicação da Solução**:

1. EntityAdapter criado com selectId e sortComparer
2. EntityState estende EntityState<User>
3. Reducer usa métodos do adapter (setAll, addOne, updateOne, etc.)
4. Selectors do adapter exportados
5. Operações CRUD simplificadas
6. Performance melhorada com normalização

---

## Testes

### Casos de Teste

**Teste 1**: Load funciona
- **Input**: Carregar usuários
- **Output Esperado**: Usuários carregados e normalizados

**Teste 2**: Update funciona
- **Input**: Atualizar usuário
- **Output Esperado**: Usuário atualizado eficientemente

**Teste 3**: Delete funciona
- **Input**: Deletar usuário
- **Output Esperado**: Usuário removido

---

## Extensões (Opcional)

1. **Upsert**: Implemente upsert para criar ou atualizar
2. **Batch Operations**: Adicione operações em lote
3. **Sorting**: Implemente sorting dinâmico

---

## Referências Úteis

- **[Entities](https://ngrx.io/guide/entity)**: Guia Entities
- **[EntityAdapter](https://ngrx.io/api/entity/EntityAdapter)**: Documentação EntityAdapter

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

