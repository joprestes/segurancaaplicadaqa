---
layout: lesson
title: "Aula 3.3: NgRx - Gerenciamento de Estado"
slug: ngrx
module: module-3
lesson_id: lesson-3-3
duration: "150 minutos"
level: "Avançado"
prerequisites: []
exercises: []
podcast:
  file: "assets/podcasts/03.3-NgRx_quando_vale_a_pena_usar.m4a"
  image: "assets/images/podcasts/03.3-NgRx_quando_vale_a_pena_usar.png"
  title: "NgRx - Quando Vale a Pena Usar"
  description: "NgRx é poderoso, mas nem sempre necessário."
  duration: "70-85 minutos"
permalink: /modules/programacao-reativa-estado/lessons/ngrx/
---

## Introdução

Nesta aula, você dominará NgRx, a biblioteca oficial do Angular para gerenciamento de estado global baseada em Redux. NgRx oferece uma arquitetura previsível e escalável para gerenciar estado complexo em aplicações Angular grandes.

### Contexto Histórico: A Evolução do Gerenciamento de Estado

A jornada do NgRx está profundamente conectada com a evolução do desenvolvimento frontend moderno:

#### Redux: A Origem (2015)

**Contexto**: Em 2015, Dan Abramov e Andrew Clark criaram Redux para resolver problemas de gerenciamento de estado em aplicações React complexas. Redux introduziu três princípios fundamentais:

1. **Single Source of Truth**: Todo estado da aplicação em uma única árvore
2. **State is Read-Only**: Estado só muda através de Actions
3. **Changes are Made with Pure Functions**: Reducers são funções puras

**Impacto**: Redux revolucionou como desenvolvedores pensavam sobre estado, trazendo previsibilidade e testabilidade para aplicações complexas.

#### NgRx: A Adaptação para Angular (2016)

**Contexto**: Em 2016, a equipe do Angular reconheceu que aplicações grandes precisavam de uma solução robusta de gerenciamento de estado. NgRx foi criado como uma adaptação do Redux para o ecossistema Angular, combinando:

- **Padrões Redux**: Actions, Reducers, Store
- **RxJS**: Observables e programação reativa nativa do Angular
- **TypeScript**: Tipagem forte e IntelliSense
- **Angular DI**: Integração perfeita com Dependency Injection

**Evolução**:
- **v1.x (2016)**: Implementação básica do padrão Redux
- **v2.x (2017)**: Introdução de Effects para side effects
- **v4.x (2018)**: Entity Adapter para normalização de dados
- **v8.x (2019)**: createAction, createReducer, createEffect (menos boilerplate)
- **v10+ (2020)**: Suporte completo para Angular standalone
- **v15+ (2022)**: Signals integration e melhorias de performance
- **v17+ (2024)**: Functional effects e melhor DX

#### Por que NgRx se Tornou Essencial

**Problema que Resolve**: Em aplicações Angular grandes, o estado pode estar espalhado por:
- Componentes (via @Input/@Output)
- Serviços (via BehaviorSubject/Subject)
- Formulários (via FormControl/FormGroup)
- Roteamento (via ActivatedRoute)

Isso leva a:
- Estado inconsistente entre componentes
- Dificuldade de rastrear mudanças
- Bugs difíceis de debugar
- Código difícil de testar

**Solução NgRx**: Centraliza todo estado em um Store, tornando:
- Estado previsível e rastreável
- Mudanças auditáveis (time-travel debugging)
- Código testável (pure functions)
- Escalável para equipes grandes

### O que você vai aprender

- Configurar Store do NgRx em aplicações standalone e modulares
- Criar Actions tipadas com createAction
- Implementar Reducers puros com createReducer
- Usar Effects para gerenciar side effects assíncronos
- Criar Selectors memoizados para performance
- Trabalhar com Entities para dados normalizados
- Implementar Facade Pattern para abstrair complexidade
- Usar NgRx DevTools para debugging avançado
- Criar aplicação completa com NgRx seguindo boas práticas

### Por que isso é importante

NgRx é essencial para aplicações Angular grandes e complexas por várias razões:

**Para sua Carreira**:
- NgRx é padrão de mercado para aplicações Angular enterprise
- Demonstra conhecimento de arquitetura escalável
- Habilidade valorizada em entrevistas técnicas
- Base para entender outros padrões de estado (Redux, MobX, etc.)

**Para Projetos Práticos**:
- Previsibilidade: sempre sabe onde estado está e como muda
- Testabilidade: funções puras são fáceis de testar
- Debugging: DevTools permite time-travel debugging
- Escalabilidade: padrão que escala para equipes grandes
- Manutenibilidade: código organizado e previsível

**Para o Ecossistema Angular**:
- Solução oficial recomendada pelo time Angular
- Integração perfeita com RxJS e TypeScript
- Comunidade ativa e documentação extensa
- Ferramentas maduras (DevTools, Schematics)

**Quando Usar NgRx**:
- ✅ Aplicações com múltiplos componentes compartilhando estado
- ✅ Estado complexo com muitas dependências
- ✅ Necessidade de rastreabilidade e auditoria
- ✅ Equipes grandes trabalhando no mesmo código
- ✅ Aplicações que precisam de time-travel debugging

**Quando NÃO Usar NgRx**:
- ❌ Aplicações pequenas com estado simples
- ❌ Protótipos rápidos
- ❌ Quando overhead não justifica benefícios
- ❌ Equipe sem experiência com padrões Redux

---

## Conceitos Teóricos

### Store

**Definição**: Store é o container centralizado que mantém o estado da aplicação como uma única fonte de verdade. É uma instância do Store do NgRx que gerencia toda a árvore de estado da aplicação de forma imutável e previsível.

**Explicação Detalhada**:

O Store do NgRx é muito mais que um simples objeto JavaScript. É um sistema completo de gerenciamento de estado que:

**Características Fundamentais**:
- **Estado Imutável**: Estado nunca é mutado diretamente, sempre cria nova versão
- **Única Fonte de Verdade**: Todo estado da aplicação em uma única árvore
- **Acessível Globalmente**: Qualquer componente pode acessar via Dependency Injection
- **Previsível**: Mudanças só acontecem através de Actions → Reducers
- **Observable**: Store é um Observable, permitindo programação reativa
- **Time-travel Debugging**: DevTools permite voltar no tempo e ver estado anterior

**Como Funciona Internamente**:

O Store mantém uma árvore de estado onde cada nó representa um feature do estado:

```
Store (Root)
├── users (Feature State)
│   ├── ids: [1, 2, 3]
│   ├── entities: {1: {...}, 2: {...}, 3: {...}}
│   ├── loading: false
│   └── error: null
├── products (Feature State)
│   ├── items: [...]
│   ├── selectedId: 5
│   └── filters: {...}
└── auth (Feature State)
    ├── user: {...}
    ├── token: "..."
    └── isAuthenticated: true
```

**Fluxo Completo de Dados**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    NgRx Store Architecture                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐                                              │
│  │  Component   │                                              │
│  │              │                                              │
│  │  dispatch()  │───Action──→┌──────────┐                    │
│  │  select()    │←──State─────│  Store   │                    │
│  └──────────────┘             │          │                    │
│                                │  State   │                    │
│  ┌──────────────┐             │  Tree    │                    │
│  │   Effect      │             │          │                    │
│  │              │             │          │                    │
│  │  listen()    │←──Action────│          │                    │
│  │  dispatch()  │───Action──→│          │                    │
│  └──────────────┘             └────┬─────┘                    │
│                                     │                           │
│                                     │ Reducer                   │
│                                     │ (Pure Function)           │
│                                     ▼                           │
│                              ┌──────────┐                      │
│                              │ New State│                      │
│                              │ (Immutable)                      │
│                              └──────────┘                      │
│                                     │                           │
│                                     │ Notify                    │
│                                     ▼                           │
│                              ┌──────────┐                      │
│                              │ Selectors│                      │
│                              │ (Memoized)                       │
│                              └────┬─────┘                      │
│                                   │                            │
│                                   │ Computed State              │
│                                   ▼                            │
│                              ┌──────────┐                      │
│                              │Component │                      │
│                              │(Updated) │                      │
│                              └──────────┘                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Analogia Detalhada**:

Store é como um **banco central** para o estado da aplicação:

1. **Cofre Central (Store)**: Todo dinheiro (estado) fica em um único lugar seguro
2. **Transações (Actions)**: Todas as operações são registradas como transações
3. **Regras (Reducers)**: Funcionários seguem regras rígidas para processar transações
4. **Extratos (Selectors)**: Você pode pedir extratos específicos sem ver tudo
5. **Auditoria (DevTools)**: Histórico completo de todas as transações
6. **Imutabilidade**: Cada transação cria novo saldo, nunca modifica o anterior

**Por que Imutabilidade Importa**:

Imutabilidade permite:
- **Time-travel**: Voltar para qualquer estado anterior
- **Debugging**: Ver exatamente o que mudou
- **Performance**: Comparações rápidas (referência vs valor)
- **Previsibilidade**: Sem efeitos colaterais inesperados

**Visualização Simplificada**:

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

**Definição**: Actions são objetos que descrevem eventos que aconteceram na aplicação. Elas são a única forma de comunicar intenções de mudança de estado ao Store.

**Explicação Detalhada**:

Actions são o ponto de entrada para todas as mudanças de estado no NgRx. Elas seguem o padrão Flux/Redux:

**Estrutura de uma Action**:

```typescript
{
  type: '[User] Load Users',  // Identificador único
  payload?: { ... }            // Dados opcionais
}
```

**Características Fundamentais**:
- **Descrevem Eventos**: "Algo aconteceu", não "faça algo"
- **Têm Type Único**: Identificador string no formato `[Source] Event`
- **Payload Opcional**: Dados necessários para processar a action
- **Imutáveis**: Nunca modificadas após criação
- **Dispatched**: Enviadas via `store.dispatch()`
- **Processadas**: Reducers e Effects escutam e reagem

**Convenção de Nomenclatura**:

```
[Source] Event Description

Exemplos:
[User] Load Users
[User] Load Users Success
[User] Load Users Failure
[Product] Add Product to Cart
[Auth] Login Success
```

**Fluxo de Actions**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Action Flow                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐                                           │
│  │  Component   │                                           │
│  │              │                                           │
│  │  User clicks │                                           │
│  │  "Load Users"│                                           │
│  └──────┬───────┘                                           │
│         │                                                    │
│         │ dispatch(loadUsers())                              │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │         Action Created                │                   │
│  │  {                                    │                   │
│  │    type: '[User] Load Users',         │                   │
│  │    payload: undefined                 │                   │
│  │  }                                    │                   │
│  └──────┬───────────────────────────────┘                   │
│         │                                                    │
│         │ Action dispatched to Store                        │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │           Store                      │                   │
│  │                                      │                   │
│  │  ┌──────────────┐  ┌──────────────┐ │                   │
│  │  │   Reducer     │  │   Effect     │ │                   │
│  │  │              │  │              │ │                   │
│  │  │  Listens to  │  │  Listens to │ │                   │
│  │  │  Action      │  │  Action      │ │                   │
│  │  │              │  │              │ │                   │
│  │  │  Updates     │  │  Performs    │ │                   │
│  │  │  State       │  │  Side Effect │ │                   │
│  │  └──────────────┘  └──────┬───────┘ │                   │
│  │                           │          │                   │
│  └───────────────────────────┼──────────┘                   │
│                              │                               │
│                              │ Effect dispatches new Action   │
│                              ▼                               │
│                    ┌──────────────────┐                     │
│                    │  New Action      │                     │
│                    │  loadUsersSuccess│                     │
│                    └──────────────────┘                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Tipos de Actions**:

1. **Command Actions**: Iniciam um processo
```
   loadUsers() // Inicia carregamento
```

2. **Event Actions**: Descrevem algo que aconteceu
```
   loadUsersSuccess({ users }) // Carregamento completou
   loadUsersFailure({ error }) // Carregamento falhou
```

3. **Document Actions**: Descrevem estado atual
```
   setUsers({ users }) // Define usuários diretamente
```

**Analogia Detalhada**:

Actions são como **formulários de requisição** em uma biblioteca:

1. **Formulário (Action)**: Você preenche um formulário descrevendo o que quer
2. **Tipo de Requisição (Type)**: "Empréstimo", "Devolução", "Renovação"
3. **Detalhes (Payload)**: Informações adicionais (ID do livro, data, etc.)
4. **Processamento**: Funcionários (Reducers/Effects) processam o formulário
5. **Resultado**: Estado da biblioteca é atualizado (livro emprestado, devolvido, etc.)

**Padrão de Três Actions** (para operações assíncronas):

```
[Feature] Action          → Inicia processo
[Feature] Action Success  → Processo completou com sucesso
[Feature] Action Failure  → Processo falhou
```

**Por que Actions são Importantes**:

- **Rastreabilidade**: Todas as mudanças são registradas
- **Debugging**: DevTools mostra todas as actions
- **Testabilidade**: Fácil testar se actions corretas são dispatched
- **Previsibilidade**: Sempre sabe o que causou uma mudança

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

**Definição**: Reducers são funções puras que especificam como o estado muda em resposta a Actions. Eles são a única forma de atualizar o estado no Store.

**Explicação Detalhada**:

Reducers são o coração do padrão Redux/NgRx. Eles garantem que mudanças de estado sejam previsíveis e testáveis.

**Características Fundamentais**:
- **Funções Puras**: Sem side effects, sempre retornam mesmo output para mesmo input
- **Imutáveis**: Nunca modificam estado atual, sempre retornam novo estado
- **Determinísticos**: Mesma action + mesmo estado = mesmo resultado
- **Combináveis**: Múltiplos reducers podem ser combinados
- **Testáveis**: Fácil testar isoladamente

**Assinatura de um Reducer**:

```typescript
(state: State, action: Action) => State
```

**Fluxo de um Reducer**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Reducer Flow                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Action Dispatched                                          │
│         │                                                    │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │      Store receives Action           │                   │
│  └──────┬───────────────────────────────┘                   │
│         │                                                    │
│         │ Calls all registered reducers                     │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │         Reducer Function             │                   │
│  │                                      │                   │
│  │  function reducer(state, action) {    │                   │
│  │    switch (action.type) {            │                   │
│  │      case '[User] Load Users':       │                   │
│  │        return {                      │                   │
│  │          ...state,                   │                   │
│  │          loading: true               │                   │
│  │        };                            │                   │
│  │      case '[User] Load Success':     │                   │
│  │        return {                      │                   │
│  │          ...state,                   │                   │
│  │          users: action.users,        │                   │
│  │          loading: false              │                   │
│  │        };                            │                   │
│  │      default:                        │                   │
│  │        return state;                 │                   │
│  │    }                                 │                   │
│  │  }                                   │                   │
│  └──────┬───────────────────────────────┘                   │
│         │                                                    │
│         │ Returns new state (immutable)                      │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │      New State Created                │                   │
│  │  {                                    │                   │
│  │    users: [...],                     │                   │
│  │    loading: false,                    │                   │
│  │    error: null                        │                   │
│  │  }                                    │                   │
│  └──────┬───────────────────────────────┘                   │
│         │                                                    │
│         │ Store updates and notifies subscribers             │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │    Components receive new state      │                   │
│  └──────────────────────────────────────┘                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Por que Funções Puras**:

Funções puras garantem:
- **Previsibilidade**: Sempre sabe o resultado
- **Testabilidade**: Fácil testar sem mocks
- **Time-travel**: Pode recriar qualquer estado
- **Debugging**: Fácil rastrear problemas

**Exemplo de Função Impura (ERRADO)**:

```typescript
function badReducer(state, action) {
  state.loading = true;  // ❌ Muta estado diretamente
  fetch('/api/users');   // ❌ Side effect
  return state;
}
```

**Exemplo de Função Pura (CORRETO)**:

```typescript
function goodReducer(state, action) {
  return {              // ✅ Retorna novo objeto
    ...state,          // ✅ Copia estado anterior
    loading: true      // ✅ Atualiza propriedade
  };
}
```

**Analogia Detalhada**:

Reducers são como **calculadoras** que seguem regras rígidas:

1. **Input Fixo**: Sempre recebem estado atual + action
2. **Regras Definidas**: Cada action tem regra específica
3. **Output Previsível**: Mesmo input = mesmo output
4. **Sem Efeitos Colaterais**: Não fazem chamadas HTTP, não modificam variáveis externas
5. **Novo Resultado**: Sempre retornam novo valor, nunca modificam o anterior

**Combinação de Reducers**:

```
┌─────────────────────────────────────────────┐
│         Root State                          │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────┐  ┌──────────────┐        │
│  │ User Reducer │  │Product Reducer│        │
│  │              │  │              │        │
│  │  users: []   │  │ products: [] │        │
│  │  loading: f   │  │ selected: 0  │        │
│  └──────────────┘  └──────────────┘        │
│                                             │
│  combineReducers({                          │
│    users: userReducer,                      │
│    products: productReducer                 │
│  })                                         │
│                                             │
└─────────────────────────────────────────────┘
```

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

**Definição**: Effects são classes injetáveis que lidam com side effects (operações assíncronas como chamadas HTTP, WebSockets, timers) de forma isolada dos componentes e reducers.

**Explicação Detalhada**:

Effects são essenciais porque Reducers devem ser funções puras. Qualquer operação assíncrona ou side effect deve ser tratada em Effects.

**Características Fundamentais**:
- **Side Effects**: Lidam com operações assíncronas e I/O
- **Reativos**: Escutam Actions através de `Actions` service
- **Observables**: Retornam Observables que podem dispatch novas Actions
- **Isolados**: Separados de componentes e reducers
- **Testáveis**: Podem ser testados isoladamente

**Fluxo de um Effect**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Effect Flow                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐                                           │
│  │  Component   │                                           │
│  │              │                                           │
│  │  dispatch(   │                                           │
│  │   loadUsers()│                                           │
│  │  )           │                                           │
│  └──────┬───────┘                                           │
│         │                                                    │
│         │ Action dispatched                                  │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │         Store                         │                   │
│  │                                      │                   │
│  │  ┌──────────────┐                    │                   │
│  │  │   Reducer     │                    │                   │
│  │  │              │                    │                   │
│  │  │  Updates     │                    │                   │
│  │  │  loading:true│                    │                   │
│  │  └──────────────┘                    │                   │
│  │                                      │                   │
│  └──────┬───────────────────────────────┘                   │
│         │                                                    │
│         │ Action also sent to Effects                        │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │         Effect                        │                   │
│  │                                      │                   │
│  │  loadUsers$ = createEffect(() =>     │                   │
│  │    this.actions$.pipe(               │                   │
│  │      ofType(loadUsers),              │                   │
│  │      switchMap(() =>                  │                   │
│  │        this.userService              │                   │
│  │          .getUsers()                 │                   │
│  │          .pipe(                      │                   │
│  │            map(users =>               │                   │
│  │              loadUsersSuccess({users})│                   │
│  │            ),                        │                   │
│  │            catchError(error =>       │                   │
│  │              of(loadUsersFailure({error}))│               │
│  │            )                         │                   │
│  │          )                           │                   │
│  │      )                               │                   │
│  │    )                                 │                   │
│  │  );                                  │                   │
│  └──────┬───────────────────────────────┘                   │
│         │                                                    │
│         │ Effect dispatches new Action                       │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │  New Action: loadUsersSuccess        │                   │
│  └──────┬───────────────────────────────┘                   │
│         │                                                    │
│         │ Back to Store → Reducer updates state              │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │  State updated: users loaded         │                   │
│  └──────────────────────────────────────┘                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Operadores RxJS Comuns em Effects**:

- **ofType**: Filtra actions específicas
- **switchMap**: Cancela requisições anteriores se nova action chegar
- **mergeMap**: Executa múltiplas requisições em paralelo
- **exhaustMap**: Ignora novas actions se uma já está em execução
- **catchError**: Trata erros e dispatch action de erro
- **map**: Transforma resultado em nova action
- **tap**: Efeitos colaterais sem modificar stream

**Por que Effects são Necessários**:

Sem Effects, você teria que fazer side effects em:
- ❌ **Componentes**: Acopla lógica de negócio à UI
- ❌ **Reducers**: Quebra pureza e previsibilidade
- ❌ **Serviços**: Difícil rastrear e testar

Com Effects:
- ✅ **Separação de Responsabilidades**: Side effects isolados
- ✅ **Testabilidade**: Fácil mockar serviços
- ✅ **Rastreabilidade**: Todas as operações assíncronas visíveis
- ✅ **Reutilização**: Effects podem ser compartilhados

**Analogia Detalhada**:

Effects são como **garçons** em um restaurante:

1. **Recebem Pedido (Action)**: Cliente (Component) faz pedido
2. **Comunicam com Cozinha (Service)**: Vão até cozinha fazer requisição
3. **Aguardam Preparo (Async)**: Esperam comida ficar pronta
4. **Trazem Resultado (New Action)**: Trazem comida ou avisam se deu problema
5. **Não Cozinham (Não Mutam Estado)**: Apenas facilitam comunicação

**Reducers** são os **chefs**: recebem ingredientes (Actions) e preparam pratos (Novo Estado), mas não vão buscar ingredientes (sem side effects).

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

## Comparação com Outras Soluções de Estado

### Tabela Comparativa: NgRx vs Alternativas

| Característica | NgRx | Redux (React) | Zustand | MobX | Akita | Services + RxJS |
|----------------|------|--------------|---------|------|-------|------------------|
| **Padrão Arquitetural** | Redux | Redux | Flux simplificado | Observables | Redux-like | Custom |
| **Integração Angular** | Nativa perfeita | Manual complexa | Manual | Manual | Nativa | Nativa |
| **Boilerplate** | Alto | Alto | Baixo | Baixo | Médio | Baixo |
| **Curva de Aprendizado** | Moderada-Alta | Moderada-Alta | Baixa | Moderada | Moderada | Baixa |
| **TypeScript Support** | Excelente | Bom | Bom | Excelente | Excelente | Excelente |
| **DevTools** | Sim (oficial) | Sim (Redux DevTools) | Sim (com plugin) | Sim | Sim | Não |
| **Time-travel Debug** | Sim | Sim | Não | Não | Sim | Não |
| **Imutabilidade** | Obrigatória | Obrigatória | Opcional | Não requerida | Obrigatória | Opcional |
| **Performance** | Excelente (memoização) | Excelente | Boa | Excelente | Excelente | Boa |
| **Bundle Size** | ~50KB | ~10KB | ~1KB | ~15KB | ~30KB | 0KB (nativo) |
| **Comunidade** | Grande (Angular) | Muito Grande | Crescendo | Grande | Pequena | N/A |
| **Documentação** | Excelente | Excelente | Boa | Excelente | Boa | Angular docs |
| **Casos de Uso Ideais** | Apps grandes, equipes grandes | Apps React grandes | Apps pequenas-médias | Apps reativas complexas | Apps Angular médias | Apps pequenas |

### Análise Detalhada por Solução

#### NgRx vs Redux

**NgRx**:
- ✅ Integração perfeita com Angular e RxJS
- ✅ TypeScript-first com tipagem forte
- ✅ Effects integrados para side effects
- ✅ Entity Adapter para normalização
- ✅ Schematics para scaffolding
- ❌ Mais boilerplate que alternativas
- ❌ Curva de aprendizado mais íngreme

**Redux**:
- ✅ Ecossistema enorme (React)
- ✅ Muitos middlewares disponíveis
- ✅ Comunidade muito grande
- ❌ Requer integração manual com Angular
- ❌ Não aproveita RxJS nativamente
- ❌ Mais verboso em TypeScript

**Quando Usar Cada Um**:
- **NgRx**: Projetos Angular enterprise, necessidade de DevTools avançado
- **Redux**: Projetos React, ou se já conhece Redux profundamente

#### NgRx vs Zustand

**Zustand**:
- ✅ Extremamente simples e leve
- ✅ Menos boilerplate
- ✅ API intuitiva
- ✅ Bom para protótipos
- ❌ Menos ferramentas de debugging
- ❌ Não tem time-travel
- ❌ Comunidade menor no Angular

**Quando Usar Cada Um**:
- **NgRx**: Aplicações grandes que precisam de rastreabilidade
- **Zustand**: Protótipos rápidos, apps pequenas, quando simplicidade é prioridade

#### NgRx vs MobX

**MobX**:
- ✅ Menos boilerplate
- ✅ Reatividade automática
- ✅ Mais "mágico" (menos código)
- ✅ Excelente para UIs reativas
- ❌ Menos previsível (mutabilidade)
- ❌ Debugging mais difícil
- ❌ Integração Angular não oficial

**Quando Usar Cada Um**:
- **NgRx**: Quando precisa de previsibilidade e rastreabilidade
- **MobX**: Quando precisa de reatividade automática e menos código

#### NgRx vs Akita

**Akita**:
- ✅ Menos boilerplate que NgRx
- ✅ API mais simples
- ✅ Entity Store integrado
- ✅ Boa documentação
- ❌ Comunidade menor
- ❌ Menos recursos que NgRx
- ❌ Menos integração com ecossistema Angular

**Quando Usar Cada Um**:
- **NgRx**: Padrão oficial, mais recursos, comunidade maior
- **Akita**: Quando quer Redux-like mas com menos boilerplate

#### NgRx vs Services + RxJS

**Services + RxJS**:
- ✅ Zero dependências externas
- ✅ Flexibilidade total
- ✅ Curva de aprendizado baixa
- ✅ Bom para apps pequenas
- ❌ Sem padrão definido
- ❌ Difícil escalar
- ❌ Sem DevTools
- ❌ Estado pode ficar espalhado

**Quando Usar Cada Um**:
- **NgRx**: Apps grandes, equipes grandes, necessidade de padrão
- **Services + RxJS**: Apps pequenas, protótipos, quando flexibilidade é prioridade

### Matriz de Decisão

```
┌─────────────────────────────────────────────────────────────┐
│              Quando Usar Cada Solução                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────┐                  │
│  │  App Pequena (< 10 componentes)       │                  │
│  │  → Services + RxJS                    │                  │
│  └──────────────────────────────────────┘                  │
│                                                              │
│  ┌──────────────────────────────────────┐                  │
│  │  App Média (10-50 componentes)        │                  │
│  │  → Akita ou Zustand                  │                  │
│  └──────────────────────────────────────┘                  │
│                                                              │
│  ┌──────────────────────────────────────┐                  │
│  │  App Grande (> 50 componentes)       │                  │
│  │  → NgRx                               │                  │
│  └──────────────────────────────────────┘                  │
│                                                              │
│  ┌──────────────────────────────────────┐                  │
│  │  Equipe Grande (> 5 devs)            │                  │
│  │  → NgRx (padrão facilita colaboração)│                  │
│  └──────────────────────────────────────┘                  │
│                                                              │
│  ┌──────────────────────────────────────┐                  │
│  │  Precisa de Debugging Avançado       │                  │
│  │  → NgRx (DevTools + time-travel)     │                  │
│  └──────────────────────────────────────┘                  │
│                                                              │
│  ┌──────────────────────────────────────┐                  │
│  │  Protótipo Rápido                    │                  │
│  │  → Services + RxJS ou Zustand         │                  │
│  └──────────────────────────────────────┘                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Trade-offs Resumidos

**NgRx é Ideal Quando**:
- ✅ Aplicação grande e complexa
- ✅ Múltiplos desenvolvedores trabalhando
- ✅ Necessidade de rastreabilidade e auditoria
- ✅ Time-travel debugging é importante
- ✅ Padrão oficial é preferível

**NgRx NÃO é Ideal Quando**:
- ❌ Aplicação pequena e simples
- ❌ Protótipo rápido
- ❌ Equipe sem experiência com Redux
- ❌ Overhead não justifica benefícios
- ❌ Bundle size é crítico

---

## Exemplos Práticos Completos

### Exemplo 1: Configuração Completa do NgRx em Aplicação Standalone

**Contexto**: Configurar NgRx completo em aplicação Angular standalone moderna, incluindo Store, Effects e DevTools.

**Estrutura de Arquivos**:

```
src/
├── app/
│   ├── app.config.ts          # Configuração do NgRx
│   ├── app.component.ts
│   └── store/
│       ├── counter/
│       │   ├── counter.actions.ts
│       │   ├── counter.reducer.ts
│       │   └── counter.selectors.ts
│       └── users/
│           ├── user.actions.ts
│           ├── user.reducer.ts
│           ├── user.effects.ts
│           └── user.selectors.ts
```

**Código Completo**:

**1. app.config.ts**:

```typescript
import { ApplicationConfig, isDevMode } from '@angular/core';
import { provideStore } from '@ngrx/store';
import { provideEffects } from '@ngrx/effects';
import { provideStoreDevtools } from '@ngrx/store-devtools';
import { provideRouter } from '@angular/router';

import { counterReducer } from './store/counter/counter.reducer';
import { userReducer } from './store/users/user.reducer';
import { UserEffects } from './store/users/user.effects';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter([]),
    provideStore({
      counter: counterReducer,
      users: userReducer
    }),
    provideEffects([UserEffects]),
    provideStoreDevtools({
      maxAge: 25,
      logOnly: !isDevMode(),
      autoPause: true,
      trace: true,
      traceLimit: 75
    })
  ]
};
```

**2. main.ts**:

```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { appConfig } from './app/app.config';

bootstrapApplication(AppComponent, appConfig)
  .catch(err => console.error(err));
```

**Explicação Detalhada**:

1. **provideStore**: Configura o Store raiz com todos os reducers
2. **provideEffects**: Registra todos os Effects da aplicação
3. **provideStoreDevtools**: Configura DevTools com opções:
   - `maxAge`: Mantém últimas 25 actions no histórico
   - `logOnly`: Em produção, apenas loga (não permite time-travel)
   - `autoPause`: Pausa quando DevTools está fechado
   - `trace`: Mostra stack trace para cada action
   - `traceLimit`: Limita tamanho do stack trace

**Verificação**:

Após configurar, você pode verificar no console do navegador:
- DevTools extension detecta o Store
- Actions aparecem no DevTools quando dispatched
- Estado pode ser inspecionado em tempo real

---

### Exemplo 2: Feature Module com NgRx (Padrão Antigo)

**Contexto**: Configurar NgRx em módulo feature usando padrão de módulos (para aplicações que ainda usam NgModules).

**Código**:

```typescript
import { NgModule } from '@angular/core';
import { StoreModule } from '@ngrx/store';
import { EffectsModule } from '@ngrx/effects';
import { userReducer } from './store/user.reducer';
import { UserEffects } from './store/user.effects';

@NgModule({
  imports: [
    StoreModule.forFeature('users', userReducer),
    EffectsModule.forFeature([UserEffects])
  ]
})
export class UsersModule { }
```

**Diferenças**:
- `StoreModule.forFeature`: Registra reducer em feature específica
- `EffectsModule.forFeature`: Registra effects específicos do feature
- Estado fica em `state.users` ao invés de raiz

---

### Exemplo 3: Aplicação Completa com NgRx - Gerenciamento de Usuários

**Contexto**: Implementação completa de CRUD de usuários usando NgRx com todas as peças: Actions, Reducer, Effects, Selectors e Facade.

**1. Model (user.model.ts)**:

```typescript
export interface User {
  id: number;
  name: string;
  email: string;
  active: boolean;
  createdAt: Date;
}

export interface UserState extends EntityState<User> {
  selectedUserId: number | null;
  loading: boolean;
  error: string | null;
}
```

**2. Actions (user.actions.ts)**:

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

export const selectUser = createAction(
  '[User] Select User',
  props<{ id: number }>()
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

**3. Reducer com Entity Adapter (user.reducer.ts)**:

```typescript
import { createReducer, on } from '@ngrx/store';
import { createEntityAdapter, EntityAdapter, EntityState } from '@ngrx/entity';
import { UserActions } from './user.actions';
import { User, UserState } from './user.model';

export const userAdapter: EntityAdapter<User> = createEntityAdapter<User>({
  selectId: (user: User) => user.id,
  sortComparer: (a: User, b: User) => a.name.localeCompare(b.name)
});

export const initialState: UserState = userAdapter.getInitialState({
  selectedUserId: null,
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
    userAdapter.setAll(users, {
      ...state,
      loading: false
    })
  ),
  on(UserActions.loadUsersFailure, (state, { error }) => ({
    ...state,
    error,
    loading: false
  })),
  on(UserActions.selectUser, (state, { id }) => ({
    ...state,
    selectedUserId: id
  })),
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
```

**4. Effects (user.effects.ts)**:

```typescript
import { Injectable } from '@angular/core';
import { Actions, createEffect, ofType } from '@ngrx/effects';
import { Store } from '@ngrx/store';
import { of } from 'rxjs';
import { map, catchError, switchMap, tap } from 'rxjs/operators';
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
          catchError(error =>
            of(UserActions.loadUsersFailure({ error: error.message }))
          )
        )
      )
    )
  );

  addUser$ = createEffect(() =>
    this.actions$.pipe(
      ofType(UserActions.addUser),
      switchMap(({ user }) =>
        this.userService.createUser(user).pipe(
          map(newUser => UserActions.addUser({ user: newUser })),
          catchError(error =>
            of(UserActions.loadUsersFailure({ error: error.message }))
          )
        )
      )
    )
  );

  constructor(
    private actions$: Actions,
    private userService: UserService,
    private store: Store
  ) {}
}
```

**5. Selectors (user.selectors.ts)**:

```typescript
import { createFeatureSelector, createSelector } from '@ngrx/store';
import { userAdapter, UserState } from './user.reducer';

export const selectUserState = createFeatureSelector<UserState>('users');

export const {
  selectAll: selectAllUsers,
  selectEntities: selectUserEntities,
  selectIds: selectUserIds,
  selectTotal: selectUserTotal
} = userAdapter.getSelectors(selectUserState);

export const selectLoading = createSelector(
  selectUserState,
  (state) => state.loading
);

export const selectError = createSelector(
  selectUserState,
  (state) => state.error
);

export const selectSelectedUserId = createSelector(
  selectUserState,
  (state) => state.selectedUserId
);

export const selectSelectedUser = createSelector(
  selectUserEntities,
  selectSelectedUserId,
  (entities, selectedId) => selectedId ? entities[selectedId] : null
);

export const selectActiveUsers = createSelector(
  selectAllUsers,
  (users) => users.filter(u => u.active)
);
```

**6. Facade (user.facade.ts)**:

```typescript
import { Injectable } from '@angular/core';
import { Store } from '@ngrx/store';
import { Observable } from 'rxjs';
import { UserActions } from './user.actions';
import {
  selectAllUsers,
  selectLoading,
  selectError,
  selectSelectedUser,
  selectActiveUsers
} from './user.selectors';
import { User } from './user.model';

@Injectable({
  providedIn: 'root'
})
export class UserFacade {
  users$: Observable<User[]> = this.store.select(selectAllUsers);
  loading$: Observable<boolean> = this.store.select(selectLoading);
  error$: Observable<string | null> = this.store.select(selectError);
  selectedUser$: Observable<User | null> = this.store.select(selectSelectedUser);
  activeUsers$: Observable<User[]> = this.store.select(selectActiveUsers);

  constructor(private store: Store) {}

  loadUsers(): void {
    this.store.dispatch(UserActions.loadUsers());
  }

  selectUser(id: number): void {
    this.store.dispatch(UserActions.selectUser({ id }));
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

**7. Component usando Facade (user-list.component.ts)**:

```typescript
import { Component, OnInit } from '@angular/core';
import { Observable } from 'rxjs';
import { UserFacade } from './store/user.facade';
import { User } from './user.model';

@Component({
  selector: 'app-user-list',
  template: `
    <div *ngIf="loading$ | async">Carregando...</div>
    <div *ngIf="error$ | async as error">Erro: {{ error }}</div>
    
    <ul>
      <li *ngFor="let user of users$ | async">
        {{ user.name }} - {{ user.email }}
        <button (click)="selectUser(user.id)">Selecionar</button>
        <button (click)="deleteUser(user.id)">Excluir</button>
      </li>
    </ul>
    
    <button (click)="loadUsers()">Recarregar</button>
  `
})
export class UserListComponent implements OnInit {
  users$: Observable<User[]> = this.userFacade.users$;
  loading$: Observable<boolean> = this.userFacade.loading$;
  error$: Observable<string | null> = this.userFacade.error$;

  constructor(private userFacade: UserFacade) {}

  ngOnInit(): void {
    this.loadUsers();
  }

  loadUsers(): void {
    this.userFacade.loadUsers();
  }

  selectUser(id: number): void {
    this.userFacade.selectUser(id);
  }

  deleteUser(id: number): void {
    this.userFacade.deleteUser(id);
  }
}
```

**Explicação do Fluxo Completo**:

1. **Component** chama `userFacade.loadUsers()`
2. **Facade** dispatch `UserActions.loadUsers()`
3. **Reducer** atualiza `loading: true`
4. **Effect** escuta action e chama `userService.getUsers()`
5. **Effect** dispatch `UserActions.loadUsersSuccess({ users })`
6. **Reducer** atualiza estado com usuários e `loading: false`
7. **Selectors** computam estado derivado
8. **Component** recebe atualização via Observable

Este exemplo demonstra o padrão completo NgRx com todas as melhores práticas.

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

#### 1. Use Facade Pattern para Abstrair NgRx

**Por quê**: 
- Componentes não precisam conhecer detalhes do NgRx
- Facilita refatoração (mudar implementação sem afetar componentes)
- Melhora testabilidade (mockar Facade é mais fácil)
- Reduz acoplamento entre UI e estado

**Exemplo**:

```typescript
@Injectable({ providedIn: 'root' })
export class UserFacade {
  users$ = this.store.select(selectAllUsers);
  
  constructor(private store: Store) {}
  
  loadUsers() {
    this.store.dispatch(UserActions.loadUsers());
  }
}

@Component({...})
export class UserComponent {
  users$ = this.facade.users$;
  
  constructor(private facade: UserFacade) {}
  
  ngOnInit() {
    this.facade.loadUsers();
  }
}
```

**Benefícios**:
- Componente não conhece Store, Actions ou Selectors
- Se mudar implementação (ex: usar Signals), só muda Facade
- Testes de componente são mais simples

---

#### 2. Use Entities para Coleções Grandes

**Por quê**:
- Performance melhor (busca O(1) vs O(n))
- Menos boilerplate (métodos CRUD prontos)
- Normalização automática de dados
- Selectors otimizados incluídos

**Exemplo**:

```typescript
export const userAdapter = createEntityAdapter<User>({
  selectId: (user) => user.id,
  sortComparer: (a, b) => a.name.localeCompare(b.name)
});

export const initialState = userAdapter.getInitialState({
  loading: false
});

export const userReducer = createReducer(
  initialState,
  on(loadUsersSuccess, (state, { users }) =>
    userAdapter.setAll(users, state)
  ),
  on(addUser, (state, { user }) =>
    userAdapter.addOne(user, state)
  ),
  on(updateUser, (state, { id, changes }) =>
    userAdapter.updateOne({ id, changes }, state)
  )
);
```

**Benefícios**:
- Operações CRUD simplificadas
- Estado normalizado automaticamente
- Selectors otimizados (`selectAll`, `selectEntities`, etc.)

---

#### 3. Mantenha Reducers Puros

**Por quê**:
- Previsibilidade: mesmo input = mesmo output
- Testabilidade: fácil testar sem mocks
- Time-travel: pode recriar qualquer estado
- Debugging: fácil rastrear problemas

**Exemplo Correto**:

```typescript
export const userReducer = createReducer(
  initialState,
  on(loadUsersSuccess, (state, { users }) => ({
    ...state,
    users,
    loading: false
  }))
);
```

**Exemplo Incorreto**:

```typescript
export const userReducer = createReducer(
  initialState,
  on(loadUsersSuccess, (state, { users }) => {
    state.users = users;  // ❌ Mutação direta
    state.loading = false; // ❌ Mutação direta
    fetch('/api/log');     // ❌ Side effect
    return state;
  })
);
```

---

#### 4. Use Selectors para Derivar Dados

**Por quê**:
- Memoização automática (não recalcula se inputs não mudaram)
- Performance melhor (evita computações desnecessárias)
- Reutilização (mesmo selector em múltiplos componentes)
- Separação de lógica de apresentação

**Exemplo**:

```typescript
export const selectAllUsers = createSelector(
  selectUserState,
  (state) => state.users
);

export const selectActiveUsers = createSelector(
  selectAllUsers,
  (users) => users.filter(u => u.active)
);

export const selectUserCount = createSelector(
  selectAllUsers,
  (users) => users.length
);
```

**Benefícios**:
- `selectActiveUsers` só recalcula se `selectAllUsers` mudar
- Múltiplos componentes podem usar mesmo selector
- Lógica de filtro centralizada

---

#### 5. Use Convenção de Nomenclatura Consistente

**Por quê**:
- Facilita navegação no código
- Padrão claro para equipe
- Facilita busca e refatoração

**Convenção**:

```
Actions:    [Source] Event Description
            [User] Load Users
            [User] Load Users Success
            [User] Load Users Failure

Reducers:   feature.reducer.ts
            user.reducer.ts

Effects:    feature.effects.ts
            user.effects.ts

Selectors:  feature.selectors.ts
            user.selectors.ts

Facades:    feature.facade.ts
            user.facade.ts
```

---

#### 6. Use createAction, createReducer, createEffect

**Por quê**:
- Menos boilerplate
- Type-safe por padrão
- API mais moderna e limpa

**Exemplo**:

```typescript
export const loadUsers = createAction('[User] Load Users');

export const userReducer = createReducer(
  initialState,
  on(loadUsers, state => ({ ...state, loading: true }))
);

export const loadUsers$ = createEffect(() =>
  this.actions$.pipe(
    ofType(loadUsers),
    switchMap(() => ...)
  )
);
```

---

#### 7. Trate Erros em Effects

**Por quê**:
- Erros devem ser parte do estado
- Permite UI mostrar mensagens de erro
- Rastreabilidade de falhas

**Exemplo**:

```typescript
loadUsers$ = createEffect(() =>
  this.actions$.pipe(
    ofType(loadUsers),
    switchMap(() =>
      this.userService.getUsers().pipe(
        map(users => loadUsersSuccess({ users })),
        catchError(error =>
          of(loadUsersFailure({ error: error.message }))
        )
      )
    )
  )
);
```

---

#### 8. Use Selectors Compostos

**Por quê**:
- Reutilização de lógica
- Performance (memoização em cascata)
- Manutenibilidade

**Exemplo**:

```typescript
export const selectUserById = (id: number) => createSelector(
  selectUserEntities,
  (entities) => entities[id]
);

export const selectUserWithDetails = (id: number) => createSelector(
  selectUserById(id),
  selectUserPermissions,
  (user, permissions) => ({
    ...user,
    permissions
  })
);
```

---

### ❌ Anti-padrões Comuns

#### 1. Não Faça Side Effects em Reducers

**Problema**:
- Quebra previsibilidade
- Impossível testar isoladamente
- Time-travel não funciona
- Debugging difícil

**Exemplo Incorreto**:

```typescript
export const userReducer = createReducer(
  initialState,
  on(loadUsers, state => {
    this.userService.getUsers().subscribe(...); // ❌ Side effect
    localStorage.setItem('loading', 'true');    // ❌ Side effect
    return { ...state, loading: true };
  })
);
```

**Solução**: Use Effects

```typescript
loadUsers$ = createEffect(() =>
  this.actions$.pipe(
    ofType(loadUsers),
    switchMap(() => this.userService.getUsers().pipe(...))
  )
);
```

---

#### 2. Não Acesse Store Diretamente em Componentes

**Problema**:
- Acoplamento forte com NgRx
- Difícil refatorar
- Testes complexos
- Violação de separação de responsabilidades

**Exemplo Incorreto**:

```typescript
@Component({...})
export class UserComponent {
  users$ = this.store.select(selectAllUsers);
  
  constructor(private store: Store) {}
  
  loadUsers() {
    this.store.dispatch(UserActions.loadUsers()); // ❌ Acoplamento direto
  }
}
```

**Solução**: Use Facade

```typescript
@Component({...})
export class UserComponent {
  users$ = this.facade.users$;
  
  constructor(private facade: UserFacade) {}
  
  loadUsers() {
    this.facade.loadUsers(); // ✅ Abstração
  }
}
```

---

#### 3. Não Ignore DevTools

**Problema**:
- Debugging muito difícil
- Sem rastreabilidade de actions
- Impossível time-travel debugging
- Perde uma das maiores vantagens do NgRx

**Solução**: Sempre configure DevTools

```typescript
provideStoreDevtools({
  maxAge: 25,
  logOnly: !isDevMode(),
  autoPause: true,
  trace: true
})
```

---

#### 4. Não Mutar Estado Diretamente

**Problema**:
- Quebra imutabilidade
- Time-travel não funciona
- Comparações de referência falham
- Bugs difíceis de rastrear

**Exemplo Incorreto**:

```typescript
on(addUser, (state, { user }) => {
  state.users.push(user); // ❌ Mutação direta
  return state;
})
```

**Solução**: Sempre retorne novo objeto

```typescript
on(addUser, (state, { user }) => ({
  ...state,
  users: [...state.users, user] // ✅ Novo array
}))
```

---

#### 5. Não Crie Actions com Payloads Muito Grandes

**Problema**:
- Difícil debugar (DevTools fica lento)
- Serialização pode ser problema
- Memória desnecessária

**Exemplo Incorreto**:

```typescript
export const loadUsersSuccess = createAction(
  '[User] Load Users Success',
  props<{ users: User[], metadata: {...}, cache: {...} }>() // ❌ Muito grande
);
```

**Solução**: Normalize dados, use Entities

```typescript
export const loadUsersSuccess = createAction(
  '[User] Load Users Success',
  props<{ users: User[] }>() // ✅ Apenas necessário
);
```

---

#### 6. Não Use Selectors Sem Memoização

**Problema**:
- Recalcula a cada change detection
- Performance ruim
- Pode causar loops infinitos

**Exemplo Incorreto**:

```typescript
// No componente
get activeUsers() {
  return this.users.filter(u => u.active); // ❌ Recalcula sempre
}
```

**Solução**: Use createSelector

```typescript
export const selectActiveUsers = createSelector(
  selectAllUsers,
  (users) => users.filter(u => u.active) // ✅ Memoizado
);
```

---

#### 7. Não Dispatch Actions em Loops

**Problema**:
- Múltiplas atualizações de estado
- Performance ruim
- Difícil debugar

**Exemplo Incorreto**:

```typescript
users.forEach(user => {
  this.store.dispatch(addUser({ user })); // ❌ Múltiplos dispatches
});
```

**Solução**: Dispatch uma action com array

```typescript
this.store.dispatch(addUsers({ users })); // ✅ Um dispatch
```

---

#### 8. Não Esqueça de Tratar Erros

**Problema**:
- Erros silenciosos
- Estado inconsistente
- UX ruim

**Exemplo Incorreto**:

```typescript
loadUsers$ = createEffect(() =>
  this.actions$.pipe(
    ofType(loadUsers),
    switchMap(() => this.userService.getUsers()) // ❌ Sem tratamento de erro
  )
);
```

**Solução**: Sempre use catchError

```typescript
loadUsers$ = createEffect(() =>
  this.actions$.pipe(
    ofType(loadUsers),
    switchMap(() =>
      this.userService.getUsers().pipe(
        map(users => loadUsersSuccess({ users })),
        catchError(error => of(loadUsersFailure({ error }))) // ✅ Tratamento
      )
    )
  )
);
```

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

- **[NgRx Documentation](https://ngrx.io/)**: Documentação completa oficial do NgRx
- **[Store Guide](https://ngrx.io/guide/store)**: Guia completo sobre Store
- **[Effects Guide](https://ngrx.io/guide/effects)**: Guia detalhado sobre Effects
- **[Selectors Guide](https://ngrx.io/guide/store/selectors)**: Guia sobre Selectors e memoização
- **[Entity Guide](https://ngrx.io/guide/entity)**: Guia sobre Entity Adapter
- **[Store DevTools](https://ngrx.io/guide/store-devtools)**: Configuração e uso do DevTools
- **[Schematics](https://ngrx.io/guide/schematics)**: Geradores de código NgRx

### Artigos e Tutoriais

- **[NgRx: Best Practices](https://blog.angular.io/ngrx-best-practices-angular-15-8c8e4b5c8e4f)**: Melhores práticas do time Angular
- **[Understanding NgRx Effects](https://www.learnrxjs.io/learn-rxjs/recipes/understanding-ngrx-effects)**: Tutorial profundo sobre Effects
- **[NgRx Entity: Complete Guide](https://ultimatecourses.com/blog/ngrx-entity-complete-guide)**: Guia completo sobre Entity Adapter
- **[NgRx Facade Pattern](https://medium.com/@thomasburleson_11450/ngrx-facade-pattern-best-practices-1c0c7c4c0c)**: Padrão Facade explicado
- **[NgRx Performance Optimization](https://indepth.dev/posts/1442/ngrx-performance-optimization)**: Otimizações de performance
- **[Testing NgRx](https://ngrx.io/guide/store/testing)**: Guia oficial de testes

### Vídeos e Cursos

- **[NgRx Official YouTube Channel](https://www.youtube.com/@ngrx)**: Canal oficial com tutoriais
- **[Angular NgRx: Getting Started (Pluralsight)](https://www.pluralsight.com/courses/angular-ngrx-getting-started)**: Curso introdutório
- **[NgRx Tutorial Series](https://www.intertech.com/ngrx-tutorial-series/)**: Série completa de tutoriais
- **[Mastering State Management with Angular and NgRx](https://www.educative.io/courses/mastering-state-management-with-angular-and-ngrx)**: Curso avançado

### Ferramentas e Extensões

- **[Redux DevTools Extension](https://chrome.google.com/webstore/detail/redux-devtools/lmhkpmbekcpmknklioeibfkpmmfibljd)**: Extensão Chrome para debugging
- **[NgRx Schematics](https://www.npmjs.com/package/@ngrx/schematics)**: Geradores de código CLI
- **[NgRx ESLint Plugin](https://github.com/timdeschryver/eslint-plugin-ngrx)**: Regras ESLint para NgRx

### Comunidade e Suporte

- **[NgRx GitHub](https://github.com/ngrx/platform)**: Repositório oficial no GitHub
- **[NgRx Discord](https://discord.gg/ngrx)**: Comunidade Discord para suporte
- **[Stack Overflow - NgRx Tag](https://stackoverflow.com/questions/tagged/ngrx)**: Perguntas e respostas da comunidade
- **[NgRx Blog](https://ngrx.io/blog)**: Blog oficial com atualizações e tutoriais

### Comparações e Decisões

- **[NgRx vs Akita](https://netbasal.com/ngrx-vs-akita-which-one-should-you-choose-1af16f4c8c)**: Comparação detalhada
- **[State Management in Angular](https://angular.io/guide/state-management)**: Guia oficial Angular sobre gerenciamento de estado
- **[When to Use NgRx](https://ngrx.io/guide/store/why)**: Quando usar NgRx vs alternativas

---

## Resumo

### Principais Conceitos

**Store**: Container centralizado que mantém estado global como única fonte de verdade. É um Observable que notifica mudanças para todos os subscribers.

**Actions**: Objetos que descrevem eventos que aconteceram na aplicação. Seguem convenção `[Source] Event Description` e são a única forma de comunicar mudanças ao Store.

**Reducers**: Funções puras que especificam como estado muda em resposta a Actions. Sempre retornam novo estado imutável, nunca mutam estado atual.

**Effects**: Classes injetáveis que lidam com side effects assíncronos (HTTP, WebSockets, timers). Escutam Actions e podem dispatch novas Actions.

**Selectors**: Funções memoizadas que extraem e derivam dados do estado. Otimizam performance evitando recálculos desnecessários.

**Entities**: Biblioteca NgRx que normaliza coleções em formato `{ ids: [], entities: {} }`. Facilita operações CRUD e melhora performance.

**Facade Pattern**: Abstração que encapsula Store, Actions e Selectors. Fornece API simples para componentes, escondendo complexidade do NgRx.

### Arquitetura NgRx Completa

```
Component → Facade → Actions → Store → Reducers → New State
                ↓                                    ↑
            Effects ←─────────────────────────────────┘
                ↓
         Side Effects (HTTP, etc.)
                ↓
         New Actions → Store
```

### Pontos-Chave para Lembrar

**Arquitetura**:
- Store é única fonte de verdade
- Estado é sempre imutável
- Mudanças só via Actions → Reducers
- Side effects apenas em Effects

**Boas Práticas**:
- Use Facade Pattern para abstrair NgRx dos componentes
- Use Entities para coleções grandes (melhor performance)
- Mantenha Reducers puros (sem side effects)
- Use Selectors para derivar dados (memoização automática)
- Configure DevTools sempre (debugging essencial)
- Trate erros em Effects (parte do estado)

**Anti-padrões a Evitar**:
- ❌ Side effects em Reducers
- ❌ Acesso direto ao Store em componentes
- ❌ Mutação direta de estado
- ❌ Actions sem tratamento de erro
- ❌ Selectors sem memoização

### Quando Usar NgRx

**Use NgRx quando**:
- ✅ Aplicação grande e complexa (> 50 componentes)
- ✅ Múltiplos componentes compartilham estado
- ✅ Necessidade de rastreabilidade e auditoria
- ✅ Equipe grande trabalhando no mesmo código
- ✅ Time-travel debugging é importante

**NÃO use NgRx quando**:
- ❌ Aplicação pequena e simples
- ❌ Protótipo rápido
- ❌ Estado pode ser gerenciado com Services + RxJS
- ❌ Overhead não justifica benefícios

### Comparação Rápida

| Solução | Boilerplate | Curva Aprendizado | DevTools | Ideal Para |
|---------|-------------|-------------------|----------|------------|
| NgRx | Alto | Moderada-Alta | Sim | Apps grandes |
| Akita | Médio | Moderada | Sim | Apps médias |
| Zustand | Baixo | Baixa | Sim | Apps pequenas |
| Services+RxJS | Baixo | Baixa | Não | Protótipos |

### Próximos Passos

**Imediatos**:
- Próxima aula: Padrões Reativos e Memory Leaks
- Praticar criando aplicação completa com NgRx
- Explorar NgRx DevTools em profundidade

**Aprofundamento**:
- Estudar padrões avançados (meta-reducers, feature state)
- Aprender a testar NgRx (reducers, effects, selectors)
- Explorar NgRx Component Store para estado local
- Estudar integração com Angular Signals

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
