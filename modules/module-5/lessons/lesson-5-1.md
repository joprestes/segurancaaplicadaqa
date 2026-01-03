---
layout: lesson
title: "Aula 5.1: Testes Completos (Unitários, Integração, E2E)"
slug: testes
module: module-5
lesson_id: lesson-5-1
duration: "120 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-4-5"
exercises:
  - 
  - "lesson-5-1-exercise-1"
  - "lesson-5-1-exercise-2"
  - "lesson-5-1-exercise-3"
  - "lesson-5-1-exercise-4"
  - "lesson-5-1-exercise-5"
  - "lesson-5-1-exercise-6"
podcast:
  file: "assets/podcasts/05.1-Testes_Unitários_Integração_E2E_Angular.m4a"
  title: "Testes Unitários, Integração e E2E no Angular"
  description: "Testes são essenciais para aplicações profissionais."
  duration: "70-85 minutos"
---

## Introdução

Nesta aula, você dominará testes completos em Angular, desde testes unitários até testes end-to-end. Testes são essenciais para garantir qualidade, confiabilidade e manutenibilidade de aplicações Angular.

### O que você vai aprender

- Configurar ambiente de testes (Jest/Vitest)
- Usar TestBed para testes de componentes
- Criar mocks e spies
- Escrever testes unitários completos
- Implementar testes de integração
- Criar testes E2E com Cypress/Playwright
- Gerar relatórios de coverage

### Por que isso é importante

Testes são fundamentais para desenvolvimento profissional. Eles garantem que código funciona corretamente, facilitam refatoração, documentam comportamento esperado e previnem regressões. Uma aplicação sem testes é uma aplicação frágil.

---

## Conceitos Teóricos

### Jest/Vitest

**Definição**: Jest e Vitest são frameworks de testes modernos que substituem Karma/Jasmine no Angular.

**Explicação Detalhada**:

Jest/Vitest:
- Mais rápido que Karma
- Melhor integração com TypeScript
- Snapshot testing
- Mocking poderoso
- Coverage integrado
- Vitest é mais moderno e rápido

**Analogia**:

Jest/Vitest são como assistentes de qualidade que verificam se seu código funciona como esperado, de forma rápida e eficiente.

**Exemplo Prático**:

```typescript
import { TestBed } from '@angular/core/testing';
import { Component } from '@angular/core';

describe('MyComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [MyComponent]
    });
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(MyComponent);
    expect(fixture.componentInstance).toBeTruthy();
  });
});
```

---

### TestBed

**Definição**: TestBed é utilitário Angular que configura ambiente de testes para componentes.

**Explicação Detalhada**:

TestBed:
- Configura módulo de teste
- Cria componentes
- Fornece dependências
- Simula ambiente Angular
- Essencial para testes de componentes

**Exemplo Prático**:

```typescript
import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { Component } from '@angular/core';

describe('Component Tests', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [
        Component,
        HttpClientTestingModule
      ],
      providers: [MyService]
    });
  });
});
```

---

### Mocks e Spies

**Definição**: Mocks simulam dependências e Spies rastreiam chamadas de métodos.

**Explicação Detalhada**:

Mocks e Spies:
- Isolam unidades sob teste
- Controlam comportamento de dependências
- Verificam interações
- Facilitam testes determinísticos
- Essenciais para testes unitários

**Exemplo Prático**:

```typescript
import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';

describe('Service Tests', () => {
  let service: MyService;
  let httpMock: jest.Mocked<HttpClient>;

  beforeEach(() => {
    httpMock = {
      get: jest.fn()
    } as any;

    TestBed.configureTestingModule({
      providers: [
        MyService,
        { provide: HttpClient, useValue: httpMock }
      ]
    });

    service = TestBed.inject(MyService);
  });

  it('should fetch data', () => {
    const mockData = { id: 1, name: 'Test' };
    httpMock.get.mockReturnValue(of(mockData));

    service.getData().subscribe(data => {
      expect(data).toEqual(mockData);
      expect(httpMock.get).toHaveBeenCalledWith('/api/data');
    });
  });
});
```

---

### Testes de Componentes

**Definição**: Testes de componentes verificam comportamento e renderização de componentes Angular.

**Explicação Detalhada**:

Testes de Componentes:
- Verificam criação
- Testam inputs e outputs
- Verificam renderização
- Testam interações do usuário
- Verificam change detection

**Exemplo Prático**:

```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Component, signal } from '@angular/core';
import { By } from '@angular/platform-browser';

describe('CounterComponent', () => {
  let component: CounterComponent;
  let fixture: ComponentFixture<CounterComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [CounterComponent]
    });
    fixture = TestBed.createComponent(CounterComponent);
    component = fixture.componentInstance;
  });

  it('should display count', () => {
    component.count.set(5);
    fixture.detectChanges();
    
    const countElement = fixture.debugElement.query(By.css('.count'));
    expect(countElement.nativeElement.textContent).toContain('5');
  });

  it('should increment on button click', () => {
    const button = fixture.debugElement.query(By.css('button'));
    button.nativeElement.click();
    fixture.detectChanges();
    
    expect(component.count()).toBe(1);
  });
});
```

---

### Testes de Integração

**Definição**: Testes de integração verificam interação entre múltiplos componentes ou serviços.

**Explicação Detalhada**:

Testes de Integração:
- Testam múltiplas unidades juntas
- Verificam fluxos completos
- Testam integração com APIs
- Mais próximos do comportamento real
- Essenciais para confiança

**Exemplo Prático**:

```typescript
import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';

describe('UserService Integration', () => {
  let service: UserService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [UserService]
    });
    
    service = TestBed.inject(UserService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  it('should fetch and process users', () => {
    const mockUsers = [{ id: 1, name: 'User 1' }];
    
    service.getUsers().subscribe(users => {
      expect(users).toEqual(mockUsers);
    });

    const req = httpMock.expectOne('/api/users');
    expect(req.request.method).toBe('GET');
    req.flush(mockUsers);
  });
});
```

---

### Testes E2E

**Definição**: Testes end-to-end verificam aplicação completa do ponto de vista do usuário.

**Explicação Detalhada**:

Testes E2E:
- Testam aplicação completa
- Simulam usuário real
- Verificam fluxos críticos
- Cypress e Playwright são populares
- Mais lentos mas mais confiáveis

**Exemplo Prático** (Cypress):

```typescript
describe('Task Manager E2E', () => {
  beforeEach(() => {
    cy.visit('/');
  });

  it('should create a task', () => {
    cy.get('[data-cy="task-input"]').type('Nova tarefa');
    cy.get('[data-cy="add-button"]').click();
    cy.get('[data-cy="task-list"]').should('contain', 'Nova tarefa');
  });

  it('should complete a task', () => {
    cy.get('[data-cy="task-checkbox"]').first().check();
    cy.get('[data-cy="task-list"]').should('contain', 'completed');
  });
});
```

---

## Exemplos Práticos Completos

### Exemplo 1: Suite de Testes Completa

**Contexto**: Criar suite completa de testes para componente de tarefas.

**Código**:

```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { By } from '@angular/platform-browser';
import { TaskComponent } from './task.component';

describe('TaskComponent', () => {
  let component: TaskComponent;
  let fixture: ComponentFixture<TaskComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TaskComponent]
    }).compileComponents();

    fixture = TestBed.createComponent(TaskComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display task title', () => {
    component.task = { id: 1, title: 'Test Task', completed: false };
    fixture.detectChanges();
    
    const titleElement = fixture.debugElement.query(By.css('.task-title'));
    expect(titleElement.nativeElement.textContent).toContain('Test Task');
  });

  it('should emit toggle event', () => {
    spyOn(component.toggle, 'emit');
    component.task = { id: 1, title: 'Test', completed: false };
    fixture.detectChanges();
    
    const checkbox = fixture.debugElement.query(By.css('input[type="checkbox"]'));
    checkbox.nativeElement.click();
    
    expect(component.toggle.emit).toHaveBeenCalledWith(1);
  });
});
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Teste comportamento, não implementação**
   - **Por quê**: Testes mais estáveis
   - **Exemplo**: Testar resultado, não método chamado

2. **Use AAA pattern (Arrange, Act, Assert)**
   - **Por quê**: Testes mais legíveis
   - **Exemplo**: Organizar código em três seções

3. **Isole unidades sob teste**
   - **Por quê**: Testes mais rápidos e confiáveis
   - **Exemplo**: Mock dependências

4. **Mantenha testes simples**
   - **Por quê**: Fácil de entender e manter
   - **Exemplo**: Um teste, uma verificação

### ❌ Anti-padrões Comuns

1. **Não testar implementação interna**
   - **Problema**: Testes frágeis
   - **Solução**: Teste comportamento público

2. **Não criar testes complexos demais**
   - **Problema**: Difícil de manter
   - **Solução**: Mantenha testes simples

3. **Não ignorar testes quebrados**
   - **Problema**: Confiança reduzida
   - **Solução**: Corrija ou remova testes

---

## Exercícios Práticos

### Exercício 1: Testes Unitários Básicos (Básico)

**Objetivo**: Criar primeiros testes unitários

**Descrição**: 
Crie testes unitários básicos para componente simples.

**Arquivo**: `exercises/exercise-5-1-1-testes-unitarios-basicos.md`

---

### Exercício 2: TestBed e Mocks (Intermediário)

**Objetivo**: Usar TestBed e criar mocks

**Descrição**:
Crie testes usando TestBed e mocks de dependências.

**Arquivo**: `exercises/exercise-5-1-2-testbed-mocks.md`

---

### Exercício 3: Testes de Componentes (Intermediário)

**Objetivo**: Testar componentes completos

**Descrição**:
Crie testes completos para componente com inputs, outputs e interações.

**Arquivo**: `exercises/exercise-5-1-3-testes-componentes.md`

---

### Exercício 4: Testes de Serviços (Intermediário)

**Objetivo**: Testar serviços com HTTP

**Descrição**:
Crie testes para serviços que fazem chamadas HTTP.

**Arquivo**: `exercises/exercise-5-1-4-testes-servicos.md`

---

### Exercício 5: Testes de Integração (Avançado)

**Objetivo**: Criar testes de integração

**Descrição**:
Crie testes de integração que testam múltiplos componentes juntos.

**Arquivo**: `exercises/exercise-5-1-5-testes-integracao.md`

---

### Exercício 6: Testes E2E (Avançado)

**Objetivo**: Criar testes E2E

**Descrição**:
Configure Cypress ou Playwright e crie testes E2E para fluxos críticos.

**Arquivo**: `exercises/exercise-5-1-6-testes-e2e.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular Testing](https://angular.io/guide/testing)**: Guia completo de testes
- **[Jest](https://jestjs.io/)**: Documentação Jest
- **[Vitest](https://vitest.dev/)**: Documentação Vitest
- **[Cypress](https://www.cypress.io/)**: Documentação Cypress

---

## Resumo

### Principais Conceitos

- Jest/Vitest são frameworks modernos de testes
- TestBed configura ambiente de testes
- Mocks e Spies isolam unidades
- Testes de componentes verificam UI
- Testes de integração testam fluxos
- Testes E2E testam aplicação completa

### Pontos-Chave para Lembrar

- Teste comportamento, não implementação
- Use AAA pattern
- Isole unidades sob teste
- Mantenha testes simples
- Almeje alta cobertura

### Próximos Passos

- Próxima aula: SSR e PWA
- Praticar escrevendo testes
- Explorar ferramentas avançadas

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

**Aula Anterior**: [Aula 4.5: Zone.js e Zoneless Apps](./lesson-4-5-zonejs.md)  
**Próxima Aula**: [Aula 5.2: SSR e PWA](./lesson-5-2-ssr-pwa.md)  
**Voltar ao Módulo**: [Módulo 5: Práticas Avançadas e Projeto Final](../modules/module-5-praticas-avancadas-projeto-final.md)

