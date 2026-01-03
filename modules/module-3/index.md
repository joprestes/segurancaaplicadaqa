---
layout: module
title: "Programação Reativa e Estado"
slug: programacao-reativa-estado
duration: "8 horas"
description: "Domine programação reativa e gerenciamento de estado"
lessons: 
  - "lesson-3-1"
  - "lesson-3-2"
  - "lesson-3-3"
  - "lesson-3-4"
  - "lesson-3-5"
module: module-3
---

## Objetivos do Módulo

Ao final deste módulo, o aluno será capaz de:

1. Dominar RxJS operators avançados e criar padrões reativos eficientes
2. Implementar Signals e Signal-First Architecture
3. Gerenciar estado global com NgRx (Store, Actions, Reducers, Effects, Selectors)
4. Criar padrões reativos que evitam memory leaks
5. Integrar Signals com Observables de forma eficiente

---

## Tópicos Cobertos

### 3.1 RxJS Operators Avançados (2h)
- Observables, Observers, Subscriptions
- Operators de transformação (map, switchMap, mergeMap, concatMap)
- Operators de combinação (combineLatest, forkJoin)
- Operators de filtragem (filter, debounceTime, throttleTime)
- Operators de erro (catchError, retry)
- Operators de compartilhamento (share, shareReplay)
- Subjects (Subject, BehaviorSubject, ReplaySubject, AsyncSubject)
- Hot vs Cold Observables
- Multicasting

### 3.2 Signals e Signal-First Architecture (2h)
- signal() e computed()
- effect()
- Model Inputs (Angular 17+)
- Signal-based forms
- Signal-based routing
- Signal-First Architecture
- Migração de Observables para Signals
- Interop Signals com Observables

### 3.3 NgRx - Gerenciamento de Estado (2.5h)
- Introdução ao NgRx
- Store, Actions, Reducers
- Effects
- Selectors
- Entities
- Facade Pattern
- NgRx DevTools
- Padrões avançados

### 3.4 Padrões Reativos e Memory Leaks (1h)
- Memory leaks com Observables
- takeUntil pattern
- async pipe
- Unsubscribe strategies
- Prevenção de memory leaks
- Debugging de memory leaks

### 3.5 Integração Signals + Observables (0.5h)
- toSignal() e toObservable()
- Integração prática
- Quando usar Signals vs Observables
- Padrões de integração

---

## Aulas Planejadas

1. **Aula 3.1**: RxJS Operators Avançados (2h)
   - Objetivo: Dominar RxJS operators essenciais
   - Exercícios: 8 exercícios práticos

2. **Aula 3.2**: Signals e Signal-First Architecture (2h)
   - Objetivo: Implementar Signals e Signal-First Architecture
   - Exercícios: 6 exercícios práticos

3. **Aula 3.3**: NgRx - Gerenciamento de Estado (2.5h)
   - Objetivo: Gerenciar estado global com NgRx
   - Exercícios: 7 exercícios práticos

4. **Aula 3.4**: Padrões Reativos e Memory Leaks (1h)
   - Objetivo: Evitar memory leaks e criar padrões seguros
   - Exercícios: 4 exercícios práticos

5. **Aula 3.5**: Integração Signals + Observables (0.5h)
   - Objetivo: Integrar Signals com Observables
   - Exercícios: 3 exercícios práticos

**Total de Aulas**: 5  
**Total de Exercícios**: 28

---

## Projeto Prático do Módulo

### Projeto: Gerenciador de Estado Completo

**Descrição**: Criar uma aplicação que demonstra diferentes estratégias de gerenciamento de estado.

**Requisitos**:
- Implementação com Signals puros
- Implementação com NgRx
- Comparação de performance
- Padrões reativos avançados
- Prevenção de memory leaks
- Integração Signals + Observables

**Duração Estimada**: 3 horas

---

## Dependências

**Pré-requisitos**:
- Módulo 1: Fundamentos Acelerados completo
- Módulo 2: Desenvolvimento Intermediário completo

**Dependências de Módulos**:
- Requer conhecimento de serviços, HTTP Client e componentes

**Prepara para**:
- Módulo 4: Performance e Otimização

---

## Recursos Adicionais

- [RxJS Documentation](https://rxjs.dev/)
- [Angular Signals Guide](https://angular.io/guide/signals)
- [NgRx Documentation](https://ngrx.io/)
- [RxJS Operators Guide](https://rxjs.dev/guide/operators)

---

## Checklist de Conclusão

- [ ] RxJS operators avançados dominados
- [ ] Signals implementados
- [ ] Signal-First Architecture aplicada
- [ ] NgRx configurado e funcionando
- [ ] Effects e Selectors criados
- [ ] Memory leaks prevenidos
- [ ] Padrões reativos seguros implementados
- [ ] Integração Signals + Observables funcionando
- [ ] Projeto prático concluído

---

**Módulo Anterior**: [Módulo 2: Desenvolvimento Intermediário](./module-2-desenvolvimento-intermediario.md)  
**Próximo Módulo**: [Módulo 4: Performance e Otimização](./module-4-performance-otimizacao.md)

