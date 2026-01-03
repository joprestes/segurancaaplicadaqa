---
layout: exercise
title: "Exercício 3.3.1: Store, Actions e Reducers Básicos"
slug: "store-actions-reducers"
lesson_id: "lesson-3-3"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Store, Actions e Reducers básicos** através da **criação de primeira configuração NgRx**.

Ao completar este exercício, você será capaz de:

- Configurar Store do NgRx
- Criar Actions
- Criar Reducers
- Dispatch Actions
- Selecionar estado do Store
- Entender fluxo básico do NgRx

---

## Descrição

Você precisa criar um contador simples usando NgRx Store, Actions e Reducers.

### Contexto

Uma aplicação precisa entender fundamentos do NgRx antes de usar recursos avançados.

### Tarefa

Crie:

1. **Actions**: Criar actions para increment, decrement, reset
2. **Reducer**: Criar reducer que processa actions
3. **Store Configuration**: Configurar Store no bootstrap
4. **Component**: Componente que usa Store

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Actions criadas
- [ ] Reducer criado
- [ ] Store configurado
- [ ] Component dispatch actions
- [ ] Component seleciona estado
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] NgRx está configurado corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**counter.actions.ts**
```typescript
import { createAction } from '@ngrx/store';

export const increment = createAction('[Counter] Increment');
export const decrement = createAction('[Counter] Decrement');
export const reset = createAction('[Counter] Reset');
export const setValue = createAction(
  '[Counter] Set Value',
  (value: number) => ({ value })
);
```

**counter.reducer.ts**
```typescript
import { createReducer, on } from '@ngrx/store';
import { increment, decrement, reset, setValue } from './counter.actions';

export interface CounterState {
  count: number;
}

export const initialState: CounterState = {
  count: 0
};

export const counterReducer = createReducer(
  initialState,
  on(increment, state => ({
    ...state,
    count: state.count + 1
  })),
  on(decrement, state => ({
    ...state,
    count: state.count - 1
  })),
  on(reset, state => ({
    ...state,
    count: 0
  })),
  on(setValue, (state, { value }) => ({
    ...state,
    count: value
  }))
);
```

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideStore } from '@ngrx/store';
import { AppComponent } from './app/app.component';
import { counterReducer } from './app/store/counter.reducer';

bootstrapApplication(AppComponent, {
  providers: [
    provideStore({
      counter: counterReducer
    })
  ]
});
```

**counter.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Store } from '@ngrx/store';
import { Observable } from 'rxjs';
import { increment, decrement, reset, setValue } from './store/counter.actions';
import { selectCounter } from './store/counter.selectors';

@Component({
  selector: 'app-counter',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="counter">
      <h2>Contador com NgRx</h2>
      <p>Valor: {{ count$ | async }}</p>
      
      <div class="buttons">
        <button (click)="increment()">+</button>
        <button (click)="decrement()">-</button>
        <button (click)="reset()">Reset</button>
        <button (click)="setValue(10)">Set to 10</button>
      </div>
    </div>
  `
})
export class CounterComponent {
  count$: Observable<number>;
  
  constructor(private store: Store) {
    this.count$ = this.store.select(selectCounter);
  }
  
  increment(): void {
    this.store.dispatch(increment());
  }
  
  decrement(): void {
    this.store.dispatch(decrement());
  }
  
  reset(): void {
    this.store.dispatch(reset());
  }
  
  setValue(value: number): void {
    this.store.dispatch(setValue(value));
  }
}
```

**counter.selectors.ts**
```typescript
import { createFeatureSelector, createSelector } from '@ngrx/store';
import { CounterState } from './counter.reducer';

export const selectCounterState = createFeatureSelector<CounterState>('counter');

export const selectCounter = createSelector(
  selectCounterState,
  (state) => state.count
);
```

**Explicação da Solução**:

1. Actions criadas com createAction()
2. Reducer criado com createReducer()
3. Store configurado com provideStore()
4. Component dispatch actions via store.dispatch()
5. Component seleciona estado via store.select()
6. Selector criado para acesso type-safe

---

## Testes

### Casos de Teste

**Teste 1**: Increment funciona
- **Input**: Clicar em "+"
- **Output Esperado**: Contador incrementa

**Teste 2**: Decrement funciona
- **Input**: Clicar em "-"
- **Output Esperado**: Contador decrementa

**Teste 3**: Reset funciona
- **Input**: Clicar em "Reset"
- **Output Esperado**: Contador volta para 0

---

## Extensões (Opcional)

1. **Múltiplos Contadores**: Adicione múltiplos contadores
2. **Histórico**: Mantenha histórico de mudanças
3. **Undo/Redo**: Implemente undo/redo

---

## Referências Úteis

- **[NgRx Store](https://ngrx.io/guide/store)**: Guia Store
- **[Actions](https://ngrx.io/guide/store/actions)**: Guia Actions
- **[Reducers](https://ngrx.io/guide/store/reducers)**: Guia Reducers

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

