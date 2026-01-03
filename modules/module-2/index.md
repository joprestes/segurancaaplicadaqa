---
layout: module
title: "Desenvolvimento Intermediário"
slug: desenvolvimento-intermediario
duration: "8 horas"
description: "Construa funcionalidades completas de aplicações reais"
lessons: 
  - "lesson-2-1"
  - "lesson-2-2"
  - "lesson-2-3"
  - "lesson-2-4"
  - "lesson-2-5"
module: module-2
---

## Objetivos do Módulo

Ao final deste módulo, o aluno será capaz de:

1. Criar serviços e implementar injeção de dependência avançada
2. Configurar roteamento complexo com guards, resolvers e lazy loading
3. Desenvolver formulários reativos com validação customizada
4. Consumir APIs REST com HTTP Client e interceptors
5. Gerenciar comunicação entre componentes (Input/Output, ViewChild, serviços)

---

## Tópicos Cobertos

### 2.1 Serviços e Injeção de Dependência (1.5h)
- Criação de serviços
- @Injectable decorator
- Hierarquia de injectors
- Providers e escopos (root, platform, any)
- Função inject() (Angular 14+)
- InjectionTokens
- Factory providers
- Optional dependencies

### 2.2 Roteamento e Navegação Avançada (2h)
- Configuração de rotas
- RouterModule e Routes
- Parâmetros de rota e query parameters
- Rotas aninhadas
- Navegação programática
- Route Guards (CanActivate, CanDeactivate, CanLoad)
- Resolvers
- Lazy Loading de módulos
- Preloading strategies

### 2.3 Formulários Reativos e Validação (2h)
- FormControl, FormGroup, FormArray
- FormBuilder
- Validação síncrona e assíncrona
- Validators customizados
- Typed Forms (Angular 14+)
- Signal Forms (Angular 19+)
- Formulários dinâmicos
- Estados de formulário e feedback ao usuário

### 2.4 HTTP Client e Interceptors (1.5h)
- HttpClient básico
- Requisições GET, POST, PUT, DELETE
- Headers e configuração
- Tratamento de erros
- HTTP Interceptors
- Request/Response interceptors
- Auth interceptors
- Retry logic e timeout

### 2.5 Comunicação entre Componentes (1h)
- @Input() e @Output()
- EventEmitter
- ViewChild e ViewChildren
- ContentChild e ContentChildren
- Template Reference Variables
- Comunicação via serviços
- Smart e Dumb Components
- Padrão Master/Detail

---

## Aulas Planejadas

1. **Aula 2.1**: Serviços e Injeção de Dependência (1.5h)
   - Objetivo: Criar serviços e dominar DI
   - Exercícios: 5 exercícios práticos

2. **Aula 2.2**: Roteamento e Navegação Avançada (2h)
   - Objetivo: Implementar roteamento completo
   - Exercícios: 6 exercícios práticos

3. **Aula 2.3**: Formulários Reativos e Validação (2h)
   - Objetivo: Criar formulários reativos complexos
   - Exercícios: 7 exercícios práticos

4. **Aula 2.4**: HTTP Client e Interceptors (1.5h)
   - Objetivo: Consumir APIs e criar interceptors
   - Exercícios: 5 exercícios práticos

5. **Aula 2.5**: Comunicação entre Componentes (1h)
   - Objetivo: Gerenciar comunicação entre componentes
   - Exercícios: 4 exercícios práticos

**Total de Aulas**: 5  
**Total de Exercícios**: 27

---

## Projeto Prático do Módulo

### Projeto: CRUD de Produtos

**Descrição**: Criar uma aplicação completa de CRUD (Create, Read, Update, Delete) de produtos com autenticação básica.

**Requisitos**:
- Roteamento completo com lazy loading
- Formulário reativo para criar/editar produtos
- Validação customizada
- Serviço HTTP para comunicação com API
- Interceptor para autenticação
- Guards para proteger rotas
- Comunicação entre componentes
- Lista de produtos com filtros

**Duração Estimada**: 3 horas

---

## Dependências

**Pré-requisitos**:
- Módulo 1: Fundamentos Acelerados completo

**Dependências de Módulos**:
- Requer conhecimento de componentes, templates e data binding

**Prepara para**:
- Módulo 3: Programação Reativa e Estado

---

## Recursos Adicionais

- [Angular Services Guide](https://angular.io/guide/services)
- [Angular Routing Guide](https://angular.io/guide/router)
- [Angular Reactive Forms](https://angular.io/guide/reactive-forms)
- [Angular HTTP Client](https://angular.io/guide/http)

---

## Checklist de Conclusão

- [ ] Serviços criados e injetados corretamente
- [ ] Roteamento configurado com guards
- [ ] Lazy loading implementado
- [ ] Formulários reativos criados
- [ ] Validação customizada implementada
- [ ] HTTP Client configurado
- [ ] Interceptors criados
- [ ] Comunicação entre componentes funcionando
- [ ] Projeto prático concluído

---

**Módulo Anterior**: [Módulo 1: Fundamentos Acelerados](./module-1-fundamentos-acelerados.md)  
**Próximo Módulo**: [Módulo 3: Programação Reativa e Estado](./module-3-programacao-reativa-estado.md)

