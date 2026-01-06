---
layout: lesson
title: "Aula 5.1: Testes Completos (Unitários, Integração, E2E)"
slug: testes
module: module-5
lesson_id: lesson-5-1
duration: "120 minutos"
level: "Expert"
prerequisites: []
exercises: []
podcast:
  file: "assets/podcasts/05.1-Testes_Unitarios_Integracao_E2E_Angular.m4a"
  image: "assets/images/podcasts/05.1-Testes_Unitarios_Integracao_E2E_Angular.png"
  title: "Testes Unitários, Integração e E2E no Angular"
  description: "Testes são essenciais para aplicações profissionais."
  duration: "70-85 minutos"
permalink: /modules/praticas-avancadas-projeto-final/lessons/testes/
---

## Introdução

Nesta aula, você dominará testes completos em Angular, desde testes unitários até testes end-to-end. Testes são essenciais para garantir qualidade, confiabilidade e manutenibilidade de aplicações Angular.

### Contexto Histórico e Evolução dos Testes em Angular

A história dos testes em Angular reflete a evolução do próprio framework e das práticas de desenvolvimento web:

#### AngularJS (v1.x) - Karma e Jasmine (2010-2016)
- **Karma**: Executor de testes criado pelo time do AngularJS
- **Jasmine**: Framework de testes BDD (Behavior-Driven Development)
- **Problema**: Configuração complexa, execução lenta, dependência de navegadores reais
- **Limitação**: Testes E2E com Protractor eram lentos e frágeis

#### Angular 2+ (2016) - TestBed e Testing Utilities
- **TestBed**: Utilitário Angular para configurar ambiente de testes
- **HttpClientTestingModule**: Módulo para mockar requisições HTTP
- **Melhoria**: Testes mais isolados e determinísticos
- **Ainda**: Karma/Jasmine continuaram como padrão oficial

#### Angular 4-12 - Melhorias Incrementais
- **Schematics**: Geração automática de testes com Angular CLI
- **Test Coverage**: Relatórios de cobertura integrados
- **Async Testing**: Melhor suporte para testes assíncronos
- **Problema**: Karma ainda era lento e complexo de configurar

#### Angular 13+ - Migração para Jest/Vitest
- **Jest**: Framework moderno adotado por muitos projetos
- **Vitest**: Alternativa ainda mais rápida baseada em Vite
- **Vantagens**: Execução mais rápida, melhor TypeScript support, mocking poderoso
- **Tendência**: Comunidade migrando de Karma para Jest/Vitest

#### Angular 17+ - Testes Modernos e Signals
- **Signals Testing**: Suporte nativo para testar signals
- **Standalone Components**: Testes mais simples sem NgModules
- **Playwright**: Alternativa moderna ao Cypress para E2E
- **Futuro**: Testes mais rápidos e simples de escrever

### O que você vai aprender

- Configurar ambiente de testes moderno (Jest/Vitest)
- Usar TestBed para testes de componentes de forma avançada
- Criar mocks e spies eficazes e reutilizáveis
- Escrever testes unitários completos seguindo AAA pattern
- Implementar testes de integração que testam fluxos reais
- Criar testes E2E com Cypress/Playwright para fluxos críticos
- Gerar e interpretar relatórios de coverage
- Aplicar boas práticas e evitar anti-padrões comuns

### Por que isso é importante

Testes são fundamentais para desenvolvimento profissional. Eles garantem que código funciona corretamente, facilitam refatoração, documentam comportamento esperado e previnem regressões. Uma aplicação sem testes é uma aplicação frágil.

**Impacto Real**:
- **Confiança**: Você pode refatorar código sem medo de quebrar funcionalidades existentes
- **Documentação Viva**: Testes servem como documentação do comportamento esperado
- **Detecção Precoce**: Bugs são encontrados durante desenvolvimento, não em produção
- **Velocidade de Desenvolvimento**: Testes automatizados são mais rápidos que testes manuais
- **Qualidade**: Aplicações com boa cobertura de testes têm menos bugs

**Impacto na Carreira**: Desenvolvedores que dominam testes são capazes de:
- Criar aplicações mais confiáveis e manuteníveis
- Trabalhar em equipes que valorizam qualidade
- Reduzir tempo gasto em debugging e correção de bugs
- Aplicar TDD (Test-Driven Development) quando apropriado
- Entender profundamente como código funciona através de testes

---

## Conceitos Teóricos

### Jest/Vitest

**Definição**: Jest e Vitest são frameworks de testes modernos que substituem Karma/Jasmine no Angular, oferecendo execução mais rápida, melhor integração com TypeScript e ferramentas avançadas de mocking e coverage.

**Explicação Detalhada**:

Jest e Vitest representam uma evolução significativa em relação ao stack tradicional Karma/Jasmine:

**Jest**:
- Criado pelo Facebook, inicialmente para React
- Execução em Node.js (mais rápido que navegadores reais)
- Snapshot testing para detectar mudanças em UI
- Mocking automático de módulos
- Coverage integrado sem configuração adicional
- Watch mode inteligente que roda apenas testes afetados
- Matchers poderosos e extensíveis

**Vitest**:
- Criado pela equipe do Vite, baseado em Jest
- Ainda mais rápido que Jest (usa ESM nativo)
- Compatível com API do Jest (fácil migração)
- Integração perfeita com Vite
- Hot Module Replacement para testes
- Melhor suporte para TypeScript out-of-the-box
- Execução paralela otimizada

**Comparação de Performance**:

```
┌─────────────────────────────────────────────────────────────┐
│          Test Execution Speed Comparison                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Karma/Jasmine:  ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
│                  ~15-30s para 100 testes                     │
│                                                             │
│  Jest:           ████████████████░░░░░░░░░░░░░░░░░░░░░░░░  │
│                  ~5-10s para 100 testes                      │
│                                                             │
│  Vitest:         ████████████████████████░░░░░░░░░░░░░░░░  │
│                  ~2-5s para 100 testes                      │
│                                                             │
│  ⚡ Vitest é 3-6x mais rápido que Karma                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Analogia Detalhada**:

Imagine que você é um chef em um restaurante de alta qualidade. Você precisa garantir que cada prato está perfeito antes de servir:

**Karma/Jasmine** é como ter que cozinhar cada prato em uma cozinha diferente, uma de cada vez, verificando manualmente cada ingrediente. É confiável, mas lento e trabalhoso.

**Jest** é como ter uma cozinha moderna com equipamentos automatizados. Você pode preparar múltiplos pratos simultaneamente, tem termômetros digitais que verificam temperatura automaticamente, e um sistema que detecta problemas rapidamente. É muito mais rápido e eficiente.

**Vitest** é como ter a cozinha mais moderna possível - tudo é otimizado, os equipamentos são os mais rápidos, e você tem um assistente que já sabe o que você precisa antes mesmo de você pedir. É a experiência mais rápida e fluida possível.

**Fluxo de Execução de Testes**:

```
┌─────────────────────────────────────────────────────────────┐
│              Jest/Vitest Test Execution Flow                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Test Discovery                                          │
│     ┌─────────────────────────────────────┐                │
│     │  Scan *.spec.ts files               │                │
│     │  Identify test suites               │                │
│     └──────────────┬──────────────────────┘                │
│                    │                                         │
│                    ▼                                         │
│  2. Test Compilation                                        │
│     ┌─────────────────────────────────────┐                │
│     │  Transform TypeScript → JavaScript  │                │
│     │  Resolve imports                    │                │
│     │  Setup test environment             │                │
│     └──────────────┬──────────────────────┘                │
│                    │                                         │
│                    ▼                                         │
│  3. Parallel Execution                                      │
│     ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│     │ Worker 1 │  │ Worker 2 │  │ Worker 3 │               │
│     │ Test A   │  │ Test B   │  │ Test C   │               │
│     └──────────┘  └──────────┘  └──────────┘               │
│                    │                                         │
│                    ▼                                         │
│  4. Results Aggregation                                     │
│     ┌─────────────────────────────────────┐                │
│     │  Collect results                    │                │
│     │  Generate coverage report           │                │
│     │  Display summary                    │                │
│     └─────────────────────────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

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

**Configuração Jest** (`jest.config.js`):

```javascript
module.exports = {
  preset: 'jest-preset-angular',
  setupFilesAfterEnv: ['<rootDir>/setup-jest.ts'],
  testMatch: ['**/*.spec.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.spec.ts',
    '!src/**/*.module.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};
```

**Configuração Vitest** (`vitest.config.ts`):

```typescript
import { defineConfig } from 'vitest/config';
import angular from '@analogjs/vite-plugin-angular';

export default defineConfig({
  plugins: [angular()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['src/test-setup.ts'],
    include: ['**/*.spec.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      thresholds: {
        branches: 80,
        functions: 80,
        lines: 80,
        statements: 80
      }
    }
  }
});
```

---

### TestBed

**Definição**: TestBed é o utilitário central do Angular que configura e gerencia o ambiente de testes, criando uma instância isolada do Angular para cada teste, permitindo que componentes sejam testados de forma independente e determinística.

**Explicação Detalhada**:

TestBed é o coração do sistema de testes do Angular. Ele funciona como um "Angular em miniatura" que você configura especificamente para cada teste:

**Funcionalidades Principais**:
- **Configuração de Módulos**: Cria módulos de teste isolados sem afetar a aplicação real
- **Criação de Componentes**: Instancia componentes com todas as dependências necessárias
- **Injeção de Dependências**: Fornece serviços, pipes, diretivas e outros providers
- **Simulação de Ambiente**: Replica o ambiente Angular real (change detection, lifecycle hooks, etc.)
- **Isolamento**: Cada teste roda em ambiente completamente isolado

**Ciclo de Vida do TestBed**:

```
┌─────────────────────────────────────────────────────────────┐
│              TestBed Lifecycle in Tests                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. beforeEach() - Setup                                    │
│     ┌─────────────────────────────────────┐                │
│     │  TestBed.resetTestingModule()       │                │
│     │  Limpa estado anterior               │                │
│     └──────────────┬──────────────────────┘                │
│                    │                                         │
│                    ▼                                         │
│  2. configureTestingModule()                                │
│     ┌─────────────────────────────────────┐                │
│     │  Define imports                     │                │
│     │  Define providers                   │                │
│     │  Define declarations                │                │
│     │  Define schemas                     │                │
│     └──────────────┬──────────────────────┘                │
│                    │                                         │
│                    ▼                                         │
│  3. compileComponents() (async)                            │
│     ┌─────────────────────────────────────┐                │
│     │  Compila templates                  │                │
│     │  Resolve styles                     │                │
│     │  Processa decorators                │                │
│     └──────────────┬──────────────────────┘                │
│                    │                                         │
│                    ▼                                         │
│  4. createComponent()                                      │
│     ┌─────────────────────────────────────┐                │
│     │  Cria instância do componente       │                │
│     │  Injeta dependências                │                │
│     │  Inicializa lifecycle               │                │
│     └──────────────┬──────────────────────┘                │
│                    │                                         │
│                    ▼                                         │
│  5. Test Execution                                         │
│     ┌─────────────────────────────────────┐                │
│     │  Manipula componente                │                │
│     │  Verifica comportamento             │                │
│     │  Assertions                         │                │
│     └──────────────┬──────────────────────┘                │
│                    │                                         │
│                    ▼                                         │
│  6. afterEach() - Cleanup                                  │
│     ┌─────────────────────────────────────┐                │
│     │  TestBed.resetTestingModule()       │                │
│     │  Limpa para próximo teste           │                │
│     └─────────────────────────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Analogia Detalhada**:

TestBed é como um laboratório científico completamente equipado e isolado:

- **Antes de cada experimento (teste)**: Você limpa completamente o laboratório, remove todos os resíduos do experimento anterior, e prepara um ambiente completamente novo e controlado
- **Configuração**: Você escolhe exatamente quais equipamentos (módulos, serviços) precisa para este experimento específico, sem trazer nada desnecessário
- **Isolamento**: O laboratório está completamente isolado do mundo exterior - nada que acontece aqui afeta a aplicação real, e nada da aplicação real interfere aqui
- **Controle Total**: Você pode substituir qualquer equipamento por uma versão de teste (mock) que se comporta exatamente como você precisa
- **Reprodutibilidade**: Cada teste começa com um laboratório limpo e idêntico, garantindo resultados consistentes

**Estrutura de Configuração do TestBed**:

```
┌─────────────────────────────────────────────────────────────┐
│              TestBed Configuration Structure                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  TestBed.configureTestingModule({                          │
│    ┌─────────────────────────────────────────┐            │
│    │ imports: [                               │            │
│    │   Component,                            │            │
│    │   HttpClientTestingModule,              │            │
│    │   RouterTestingModule                   │            │
│    │ ]                                       │            │
│    └─────────────────────────────────────────┘            │
│                                                             │
│    ┌─────────────────────────────────────────┐            │
│    │ declarations: [                         │            │
│    │   ChildComponent,                       │            │
│    │   PipeComponent                        │            │
│    │ ]                                       │            │
│    └─────────────────────────────────────────┘            │
│                                                             │
│    ┌─────────────────────────────────────────┐            │
│    │ providers: [                            │            │
│    │   MyService,                            │            │
│    │   { provide: HttpClient,                │            │
│    │     useValue: mockHttpClient }          │            │
│    │ ]                                       │            │
│    └─────────────────────────────────────────┘            │
│                                                             │
│    ┌─────────────────────────────────────────┐            │
│    │ schemas: [                              │            │
│    │   NO_ERRORS_SCHEMA,                     │            │
│    │   CUSTOM_ELEMENTS_SCHEMA                │            │
│    │ ]                                       │            │
│    └─────────────────────────────────────────┘            │
│                                                             │
│  })                                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { Component } from '@angular/core';
import { MyService } from './my.service';

describe('Component Tests', () => {
  let component: MyComponent;
  let fixture: ComponentFixture<MyComponent>;
  let httpMock: HttpTestingController;
  let service: MyService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [
        MyComponent,
        HttpClientTestingModule,
        RouterTestingModule
      ],
      providers: [
        MyService,
        { provide: 'API_URL', useValue: 'http://test-api.com' }
      ],
      schemas: [NO_ERRORS_SCHEMA]
    }).compileComponents();

    fixture = TestBed.createComponent(MyComponent);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    service = TestBed.inject(MyService);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
```

**Métodos Importantes do TestBed**:

- `configureTestingModule()`: Configura o módulo de teste
- `createComponent()`: Cria instância do componente
- `inject()`: Injeta dependência do sistema de DI
- `overrideModule()`: Substitui módulo importado
- `overrideComponent()`: Substitui configuração de componente
- `overrideProvider()`: Substitui provider específico
- `resetTestingModule()`: Limpa configuração para próximo teste

---

### Mocks e Spies

**Definição**: Mocks são objetos simulados que substituem dependências reais durante testes, enquanto Spies são ferramentas que rastreiam e verificam chamadas de métodos, permitindo isolar unidades sob teste e controlar comportamento de dependências.

**Explicação Detalhada**:

Mocks e Spies são fundamentais para testes unitários eficazes:

**Mocks**:
- **Substituição Completa**: Substituem dependências reais por versões controladas
- **Comportamento Controlado**: Retornam valores específicos que você define
- **Isolamento**: Permitem testar componente/serviço sem dependências externas
- **Determinismo**: Garantem que testes são previsíveis e repetíveis
- **Velocidade**: Evitam chamadas reais a APIs, bancos de dados, etc.

**Spies**:
- **Rastreamento**: Monitoram quantas vezes métodos foram chamados
- **Verificação de Argumentos**: Confirmam que métodos foram chamados com argumentos corretos
- **Interceptação**: Podem interceptar chamadas e retornar valores customizados
- **Verificação de Ordem**: Podem verificar ordem de chamadas
- **Não Destrutivos**: Podem ser usados em objetos reais sem substituí-los completamente

**Tipos de Mocks e Spies**:

```
┌─────────────────────────────────────────────────────────────┐
│          Types of Mocks and Spies                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Manual Mocks                                            │
│     ┌─────────────────────────────────────┐                │
│     │  const mockService = {             │                │
│     │    getData: jest.fn(),             │                │
│     │    saveData: jest.fn()             │                │
│     │  }                                  │                │
│     └─────────────────────────────────────┘                │
│                                                             │
│  2. Spy Objects                                             │
│     ┌─────────────────────────────────────┐                │
│     │  const spy = jest.spyOn(            │                │
│     │    service, 'method'               │                │
│     │  )                                  │                │
│     └─────────────────────────────────────┘                │
│                                                             │
│  3. Mock Modules                                            │
│     ┌─────────────────────────────────────┐                │
│     │  jest.mock('./module', () => ({     │                │
│     │    default: mockImplementation     │                │
│     │  }))                                │                │
│     └─────────────────────────────────────┘                │
│                                                             │
│  4. Partial Mocks                                           │
│     ┌─────────────────────────────────────┐                │
│     │  jest.spyOn(obj, 'method')          │                │
│     │    .mockReturnValue(value)          │                │
│     └─────────────────────────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Analogia Detalhada**:

Imagine que você está testando um carro novo. Você precisa verificar se o motor funciona corretamente, mas não quer depender de:

- **Combustível real**: Muito caro e variável
- **Estrada real**: Condições imprevisíveis
- **Tráfego real**: Atrasos e variabilidade

**Mocks** são como um simulador de motor:
- Você conecta o motor a um simulador que fornece "combustível" controlado
- O simulador pode simular diferentes condições (subida, descida, velocidade)
- Você pode testar cenários específicos repetidamente
- É rápido, barato e previsível

**Spies** são como sensores conectados ao motor:
- Eles monitoram quantas vezes o motor foi ligado
- Verificam se foi ligado com os parâmetros corretos
- Podem interceptar sinais e modificá-los se necessário
- Não interferem no funcionamento real do motor

**Fluxo de Mocking em Testes**:

```
┌─────────────────────────────────────────────────────────────┐
│          Mocking Flow in Unit Tests                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Component Under Test                                       │
│         │                                                    │
│         │ depends on                                        │
│         ▼                                                    │
│  ┌──────────────┐                                           │
│  │ Real Service │  (HttpClient, Router, etc.)               │
│  └──────┬───────┘                                           │
│         │                                                    │
│         │ Replace with                                      │
│         ▼                                                    │
│  ┌──────────────┐                                           │
│  │ Mock Service │  (Controlled behavior)                   │
│  │              │                                           │
│  │ getData() ──► returns predefined data                    │
│  │ saveData() ─► tracks calls                              │
│  └──────────────┘                                           │
│         │                                                    │
│         │ Test verifies                                     │
│         ▼                                                    │
│  ┌──────────────┐                                           │
│  │ Assertions  │                                            │
│  │ - Called?   │                                            │
│  │ - How many? │                                            │
│  │ - With what?│                                            │
│  └──────────────┘                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { TestBed } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { of, throwError } from 'rxjs';
import { MyService } from './my.service';

describe('Service Tests', () => {
  let service: MyService;
  let httpMock: jest.Mocked<HttpClient>;

  beforeEach(() => {
    httpMock = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    } as any;

    TestBed.configureTestingModule({
      providers: [
        MyService,
        { provide: HttpClient, useValue: httpMock }
      ]
    });

    service = TestBed.inject(MyService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should fetch data successfully', () => {
    const mockData = { id: 1, name: 'Test' };
    httpMock.get.mockReturnValue(of(mockData));

    service.getData().subscribe(data => {
      expect(data).toEqual(mockData);
      expect(httpMock.get).toHaveBeenCalledTimes(1);
      expect(httpMock.get).toHaveBeenCalledWith('/api/data');
    });
  });

  it('should handle errors', () => {
    const error = new Error('Network error');
    httpMock.get.mockReturnValue(throwError(() => error));

    service.getData().subscribe({
      next: () => fail('should have failed'),
      error: (err) => {
        expect(err).toBe(error);
        expect(httpMock.get).toHaveBeenCalledTimes(1);
      }
    });
  });

  it('should call API with correct parameters', () => {
    httpMock.post.mockReturnValue(of({ success: true }));

    service.saveData({ name: 'Test' }).subscribe();

    expect(httpMock.post).toHaveBeenCalledWith(
      '/api/data',
      { name: 'Test' },
      expect.any(Object)
    );
  });
});
```

**Spy em Métodos de Componente**:

```typescript
describe('Component with Spies', () => {
  let component: MyComponent;
  let fixture: ComponentFixture<MyComponent>;

  beforeEach(() => {
    fixture = TestBed.createComponent(MyComponent);
    component = fixture.componentInstance;
  });

  it('should call method on button click', () => {
    const spy = jest.spyOn(component, 'handleClick');
    
    const button = fixture.debugElement.query(By.css('button'));
    button.nativeElement.click();
    
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(expect.any(Event));
  });

  it('should spy on method without calling original', () => {
    const spy = jest.spyOn(component, 'expensiveOperation')
      .mockImplementation(() => 'mocked result');
    
    const result = component.doSomething();
    
    expect(result).toBe('mocked result');
    expect(spy).toHaveBeenCalled();
  });
});
```

**Matchers Comuns para Spies**:

- `toHaveBeenCalled()`: Verifica se foi chamado
- `toHaveBeenCalledTimes(n)`: Verifica número de chamadas
- `toHaveBeenCalledWith(...args)`: Verifica argumentos
- `toHaveBeenLastCalledWith(...args)`: Verifica última chamada
- `toHaveReturnedWith(value)`: Verifica valor retornado

---

### Testes de Componentes

**Definição**: Testes de componentes verificam comportamento, renderização, interações do usuário e integração entre template e classe TypeScript de componentes Angular, garantindo que componentes funcionam corretamente em isolamento.

**Explicação Detalhada**:

Testes de componentes são a base dos testes em Angular. Eles verificam:

**Aspectos Testados**:
- **Criação**: Componente é instanciado corretamente
- **Inputs**: Propriedades @Input() recebem valores corretos
- **Outputs**: Eventos @Output() são emitidos corretamente
- **Renderização**: Template renderiza dados corretamente
- **Interações**: Cliques, inputs, mudanças são tratados
- **Change Detection**: Mudanças são detectadas e refletidas na view
- **Lifecycle Hooks**: Hooks são executados na ordem correta
- **Diretivas**: Diretivas estruturais e de atributo funcionam
- **Pipes**: Transformações de dados são aplicadas

**Estrutura de um Teste de Componente**:

```
┌─────────────────────────────────────────────────────────────┐
│          Component Test Structure                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Setup (beforeEach)                                     │
│     ┌─────────────────────────────────────┐                │
│     │  Configure TestBed                  │                │
│     │  Create ComponentFixture            │                │
│     │  Get Component Instance             │                │
│     └─────────────────────────────────────┘                │
│                                                             │
│  2. Arrange (Arrange-Act-Assert)                           │
│     ┌─────────────────────────────────────┐                │
│     │  Set component inputs               │                │
│     │  Setup initial state                │                │
│     │  Prepare test data                  │                │
│     └─────────────────────────────────────┘                │
│                                                             │
│  3. Act                                                    │
│     ┌─────────────────────────────────────┐                │
│     │  Trigger change detection           │                │
│     │  Simulate user interaction          │                │
│     │  Call component methods             │                │
│     └─────────────────────────────────────┘                │
│                                                             │
│  4. Assert                                                 │
│     ┌─────────────────────────────────────┐                │
│     │  Verify DOM content                 │                │
│     │  Verify component state             │                │
│     │  Verify emitted events              │                │
│     └─────────────────────────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Analogia Detalhada**:

Testar um componente é como testar um aparelho eletrônico completo:

- **Criação**: Verificar se o aparelho liga quando você aperta o botão de energia
- **Inputs**: Verificar se os botões respondem quando pressionados
- **Outputs**: Verificar se o aparelho produz a saída esperada (som, imagem, etc.)
- **Renderização**: Verificar se a tela/display mostra informações corretas
- **Interações**: Verificar se todas as funcionalidades respondem às ações do usuário
- **Change Detection**: Verificar se mudanças de estado são refletidas imediatamente na interface

**ComponentFixture e DebugElement**:

```
┌─────────────────────────────────────────────────────────────┐
│          ComponentFixture Structure                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ComponentFixture<MyComponent>                             │
│  ├─ componentInstance: MyComponent                         │
│  │    └─ Access to component class                         │
│  │                                                          │
│  ├─ debugElement: DebugElement                             │
│  │    ├─ query() - Find elements                          │
│  │    ├─ queryAll() - Find all elements                   │
│  │    └─ nativeElement - DOM element                       │
│  │                                                          │
│  ├─ nativeElement: HTMLElement                             │
│  │    └─ Direct DOM access                                │
│  │                                                          │
│  └─ detectChanges() - Trigger change detection            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

{% raw %}
```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Component, signal, input, output, EventEmitter } from '@angular/core';
import { By } from '@angular/platform-browser';
import { DebugElement } from '@angular/core';

@Component({
  selector: 'app-counter',
  standalone: true,
  template: `
    <div class="counter">
      <span class="count">{{ count() }}</span>
      <button (click)="increment()">+</button>
      <button (click)="decrement()">-</button>
      <button (click)="reset()">Reset</button>
    </div>
    <div *ngIf="showMessage()" class="message">
      {{ message() }}
    </div>
  `
})
class CounterComponent {
  count = signal(0);
  message = signal('');
  showMessage = signal(false);
  
  increment() {
    this.count.update(v => v + 1);
    if (this.count() > 10) {
      this.message.set('Count is high!');
      this.showMessage.set(true);
    }
  }
  
  decrement() {
    this.count.update(v => v - 1);
  }
  
  reset() {
    this.count.set(0);
    this.showMessage.set(false);
  }
}

describe('CounterComponent', () => {
  let component: CounterComponent;
  let fixture: ComponentFixture<CounterComponent>;
  let debugElement: DebugElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CounterComponent]
    }).compileComponents();

    fixture = TestBed.createComponent(CounterComponent);
    component = fixture.componentInstance;
    debugElement = fixture.debugElement;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display initial count', () => {
    const countElement = debugElement.query(By.css('.count'));
    expect(countElement.nativeElement.textContent).toContain('0');
  });

  it('should increment count on button click', () => {
    const incrementButton = debugElement.query(By.css('button'));
    incrementButton.nativeElement.click();
    fixture.detectChanges();
    
    expect(component.count()).toBe(1);
    const countElement = debugElement.query(By.css('.count'));
    expect(countElement.nativeElement.textContent).toContain('1');
  });

  it('should show message when count exceeds 10', () => {
    component.count.set(11);
    component.message.set('Count is high!');
    component.showMessage.set(true);
    fixture.detectChanges();
    
    const messageElement = debugElement.query(By.css('.message'));
    expect(messageElement).toBeTruthy();
    expect(messageElement.nativeElement.textContent).toContain('Count is high!');
  });

  it('should reset count and hide message', () => {
    component.count.set(15);
    component.showMessage.set(true);
    fixture.detectChanges();
    
    const resetButton = debugElement.queryAll(By.css('button'))[2];
    resetButton.nativeElement.click();
    fixture.detectChanges();
    
    expect(component.count()).toBe(0);
    expect(component.showMessage()).toBe(false);
    const messageElement = debugElement.query(By.css('.message'));
    expect(messageElement).toBeNull();
  });

  it('should handle multiple rapid clicks', () => {
    const incrementButton = debugElement.query(By.css('button'));
    
    for (let i = 0; i < 5; i++) {
      incrementButton.nativeElement.click();
    }
    fixture.detectChanges();
    
    expect(component.count()).toBe(5);
  });
});
```
{% endraw %}

**Seletores Úteis para Queries**:

- `By.css('.class-name')`: Seleciona por classe CSS
- `By.css('#id')`: Seleciona por ID
- `By.css('element')`: Seleciona por tag HTML
- `By.css('[attribute]')`: Seleciona por atributo
- `By.directive(DirectiveClass)`: Seleciona por diretiva
- `By.all()`: Seleciona todos os elementos

---

### Testes de Integração

**Definição**: Testes de integração verificam a interação entre múltiplos componentes, serviços, módulos e sistemas externos, testando fluxos completos e comportamentos que emergem da combinação de múltiplas unidades trabalhando juntas.

**Explicação Detalhada**:

Testes de integração preenchem a lacuna entre testes unitários (isolados) e testes E2E (completos):

**Características**:
- **Múltiplas Unidades**: Testam vários componentes/serviços trabalhando juntos
- **Fluxos Completos**: Verificam jornadas do usuário end-to-end dentro de módulos
- **Integração com APIs**: Testam comunicação HTTP real (com mock de servidor)
- **Comportamento Real**: Mais próximos do comportamento real que testes unitários
- **Confiança**: Garantem que partes do sistema funcionam juntas corretamente

**Pirâmide de Testes**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Testing Pyramid                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│                    ┌─────────┐                             │
│                    │   E2E   │  Poucos, lentos, caros       │
│                    │  Tests  │  Máxima confiança            │
│                    └─────────┘                             │
│                  ┌───────────────┐                          │
│                  │ Integration   │  Média quantidade         │
│                  │    Tests     │  Testam fluxos            │
│                  └───────────────┘                          │
│              ┌───────────────────────┐                      │
│              │   Unit Tests          │  Muitos, rápidos      │
│              │                       │  Testam unidades      │
│              └───────────────────────┘                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Analogia Detalhada**:

Imagine uma orquestra:

- **Testes Unitários**: São como testar cada instrumento individualmente - você verifica se o violino está afinado, se a flauta produz as notas corretas, se o piano funciona. Mas isso não garante que a música soará bem quando todos tocarem juntos.

- **Testes de Integração**: São como testar seções da orquestra - você verifica se todos os violinos tocam em harmonia, se a seção de metais está sincronizada, se cordas e sopros se complementam. Você testa como grupos de instrumentos trabalham juntos.

- **Testes E2E**: São como um ensaio completo da orquestra - você verifica se toda a sinfonia soa perfeita do início ao fim, com todos os instrumentos tocando juntos.

**Fluxo de Teste de Integração**:

```
┌─────────────────────────────────────────────────────────────┐
│          Integration Test Flow                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Setup Multiple Components                                │
│     ┌──────────────┐  ┌──────────────┐                     │
│     │  Component A │  │  Component B │                     │
│     └──────┬───────┘  └──────┬───────┘                     │
│            │                  │                             │
│            └────────┬─────────┘                             │
│                     │                                        │
│                     ▼                                        │
│  2. Setup Shared Service                                     │
│     ┌──────────────────────┐                                │
│     │   Shared Service     │                                │
│     │   (Real or Mock)     │                                │
│     └──────────┬───────────┘                                │
│                │                                             │
│                ▼                                             │
│  3. Setup HTTP Mock                                          │
│     ┌──────────────────────┐                                │
│     │ HttpTestingModule    │                                │
│     │ HttpTestingController│                                │
│     └──────────┬───────────┘                                │
│                │                                             │
│                ▼                                             │
│  4. Execute Integration Flow                                 │
│     ┌──────────────────────┐                                │
│     │  User Action         │                                │
│     │  → Component A       │                                │
│     │  → Service Call      │                                │
│     │  → HTTP Request      │                                │
│     │  → Component B Update│                                │
│     └──────────┬───────────┘                                │
│                │                                             │
│                ▼                                             │
│  5. Verify Complete Flow                                     │
│     ┌──────────────────────┐                                │
│     │  - HTTP called?      │                                │
│     │  - Data processed?   │                                │
│     │  - UI updated?      │                                │
│     │  - State correct?   │                                │
│     └──────────────────────┘                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { UserService } from './user.service';
import { UserListComponent } from './user-list.component';
import { UserDetailComponent } from './user-detail.component';

describe('User Module Integration', () => {
  let service: UserService;
  let httpMock: HttpTestingController;
  let listComponent: UserListComponent;
  let detailComponent: UserDetailComponent;
  let listFixture: ComponentFixture<UserListComponent>;
  let detailFixture: ComponentFixture<UserDetailComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [
        HttpClientTestingModule,
        RouterTestingModule,
        UserListComponent,
        UserDetailComponent
      ],
      providers: [UserService]
    });
    
    service = TestBed.inject(UserService);
    httpMock = TestBed.inject(HttpTestingController);
    
    listFixture = TestBed.createComponent(UserListComponent);
    listComponent = listFixture.componentInstance;
    
    detailFixture = TestBed.createComponent(UserDetailComponent);
    detailComponent = detailFixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should fetch users and display in list', () => {
    const mockUsers = [
      { id: 1, name: 'User 1', email: 'user1@test.com' },
      { id: 2, name: 'User 2', email: 'user2@test.com' }
    ];
    
    listComponent.loadUsers();
    listFixture.detectChanges();
    
    const req = httpMock.expectOne('/api/users');
    expect(req.request.method).toBe('GET');
    req.flush(mockUsers);
    
    listFixture.detectChanges();
    
    expect(listComponent.users()).toEqual(mockUsers);
    expect(listComponent.users().length).toBe(2);
  });

  it('should fetch user details when user selected', () => {
    const mockUser = { id: 1, name: 'User 1', email: 'user1@test.com' };
    
    listComponent.selectUser(1);
    listFixture.detectChanges();
    
    const listReq = httpMock.expectOne('/api/users');
    listReq.flush([mockUser]);
    
    const detailReq = httpMock.expectOne('/api/users/1');
    expect(detailReq.request.method).toBe('GET');
    detailReq.flush(mockUser);
    
    detailFixture.detectChanges();
    
    expect(detailComponent.user()).toEqual(mockUser);
  });

  it('should create user and update list', () => {
    const newUser = { name: 'New User', email: 'new@test.com' };
    const createdUser = { id: 3, ...newUser };
    
    service.createUser(newUser).subscribe(user => {
      expect(user).toEqual(createdUser);
      
      listComponent.loadUsers();
      listFixture.detectChanges();
      
      const req = httpMock.expectOne('/api/users');
      req.flush([createdUser]);
      
      expect(listComponent.users()).toContainEqual(createdUser);
    });
    
    const createReq = httpMock.expectOne('/api/users');
    expect(createReq.request.method).toBe('POST');
    expect(createReq.request.body).toEqual(newUser);
    createReq.flush(createdUser);
  });
});
```

---

### Testes E2E

**Definição**: Testes end-to-end (E2E) verificam a aplicação completa do ponto de vista do usuário final, simulando interações reais com navegador, testando fluxos críticos de negócio e garantindo que toda a stack (frontend, backend, banco de dados) funciona corretamente em conjunto.

**Explicação Detalhada**:

Testes E2E são a camada mais alta da pirâmide de testes:

**Características**:
- **Aplicação Completa**: Testam toda a aplicação rodando em navegador real
- **Simulação Real**: Simulam ações reais do usuário (cliques, digitação, navegação)
- **Fluxos Críticos**: Focam em jornadas importantes do usuário
- **Stack Completa**: Testam frontend, backend, banco de dados integrados
- **Confiança Máxima**: Maior nível de confiança, mas mais lentos e caros

**Ferramentas Populares**:

**Cypress**:
- Execução no navegador real
- Time-travel debugging
- Screenshots e vídeos automáticos
- API simples e intuitiva
- Boa integração com CI/CD

**Playwright**:
- Suporte multi-navegador (Chromium, Firefox, WebKit)
- Execução mais rápida que Cypress
- Auto-wait inteligente
- Network interception poderoso
- Melhor para testes complexos

**Comparação Cypress vs Playwright**:

```
┌─────────────────────────────────────────────────────────────┐
│          Cypress vs Playwright Comparison                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Aspecto              │  Cypress      │  Playwright         │
│  ─────────────────────┼───────────────┼───────────────────  │
│  Navegadores          │  Chrome only  │  Chrome, FF, Safari │
│  Velocidade           │  Médio        │  Rápido            │
│  API                  │  Simples      │  Poderosa          │
│  Debug                │  Excelente    │  Bom               │
│  CI/CD                │  Excelente    │  Excelente         │
│  Comunidade           │  Grande       │  Crescendo         │
│  TypeScript           │  Suportado    │  Nativo            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Analogia Detalhada**:

Testes E2E são como um teste de direção completo:

- **Testes Unitários**: São como verificar se cada peça do carro funciona isoladamente - motor, freios, pneus. Mas isso não garante que você consegue dirigir.

- **Testes de Integração**: São como testar se o motor funciona com a transmissão, se os freios respondem quando você pisa no pedal. Você testa sistemas trabalhando juntos.

- **Testes E2E**: São como um teste de direção completo na estrada real - você entra no carro, liga, dirige por diferentes tipos de estrada, enfrenta trânsito, para em semáforos, estaciona. Você testa TUDO funcionando junto, exatamente como um usuário real usaria.

**Fluxo de Teste E2E**:

```
┌─────────────────────────────────────────────────────────────┐
│          E2E Test Flow                                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Application Startup                                     │
│     ┌─────────────────────────────────────┐                │
│     │  Start Angular Dev Server            │                │
│     │  Open Browser                       │                │
│     │  Navigate to Application            │                │
│     └──────────┬──────────────────────────┘                │
│                │                                             │
│                ▼                                             │
│  2. User Interaction Simulation                            │
│     ┌─────────────────────────────────────┐                │
│     │  Click Button                       │                │
│     │  Type in Input                      │                │
│     │  Navigate Pages                     │                │
│     │  Submit Forms                       │                │
│     └──────────┬──────────────────────────┘                │
│                │                                             │
│                ▼                                             │
│  3. Backend Communication                                   │
│     ┌─────────────────────────────────────┐                │
│     │  HTTP Requests                      │                │
│     │  API Calls                          │                │
│     │  Database Operations                │                │
│     └──────────┬──────────────────────────┘                │
│                │                                             │
│                ▼                                             │
│  4. UI Verification                                         │
│     ┌─────────────────────────────────────┐                │
│     │  Check DOM Content                 │                │
│     │  Verify Visual State               │                │
│     │  Confirm User Feedback             │                │
│     └─────────────────────────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo - Cypress**:

```typescript
describe('Task Manager E2E', () => {
  beforeEach(() => {
    cy.visit('/');
    cy.intercept('GET', '/api/tasks', { fixture: 'tasks.json' }).as('getTasks');
    cy.intercept('POST', '/api/tasks', { statusCode: 201, body: { id: 3, title: 'Nova tarefa', completed: false } }).as('createTask');
  });

  it('should display task list on load', () => {
    cy.wait('@getTasks');
    cy.get('[data-cy="task-list"]').should('be.visible');
    cy.get('[data-cy="task-item"]').should('have.length', 2);
  });

  it('should create a new task', () => {
    cy.get('[data-cy="task-input"]').type('Nova tarefa');
    cy.get('[data-cy="add-button"]').click();
    
    cy.wait('@createTask');
    cy.get('[data-cy="task-list"]').should('contain', 'Nova tarefa');
    cy.get('[data-cy="task-item"]').should('have.length', 3);
  });

  it('should complete a task', () => {
    cy.intercept('PATCH', '/api/tasks/1', { statusCode: 200 }).as('completeTask');
    
    cy.get('[data-cy="task-checkbox"]').first().check();
    
    cy.wait('@completeTask');
    cy.get('[data-cy="task-item"]').first().should('have.class', 'completed');
  });

  it('should delete a task', () => {
    cy.intercept('DELETE', '/api/tasks/1', { statusCode: 200 }).as('deleteTask');
    
    cy.get('[data-cy="delete-button"]').first().click();
    
    cy.wait('@deleteTask');
    cy.get('[data-cy="task-item"]').should('have.length', 1);
  });

  it('should filter tasks', () => {
    cy.get('[data-cy="filter-active"]').click();
    cy.get('[data-cy="task-item"]').should('not.have.class', 'completed');
    
    cy.get('[data-cy="filter-completed"]').click();
    cy.get('[data-cy="task-item"]').should('have.class', 'completed');
  });
});
```

**Exemplo Prático Completo - Playwright**:

```typescript
import { test, expect } from '@playwright/test';

test.describe('Task Manager E2E', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.route('**/api/tasks', route => {
      route.fulfill({ json: [{ id: 1, title: 'Task 1', completed: false }] });
    });
  });

  test('should create a new task', async ({ page }) => {
    await page.fill('[data-cy="task-input"]', 'Nova tarefa');
    await page.click('[data-cy="add-button"]');
    
    await expect(page.locator('[data-cy="task-list"]')).toContainText('Nova tarefa');
  });

  test('should complete a task', async ({ page }) => {
    await page.check('[data-cy="task-checkbox"]');
    
    await expect(page.locator('[data-cy="task-item"]').first()).toHaveClass(/completed/);
  });

  test('should handle multiple browsers', async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    
    await page.goto('/');
    await expect(page.locator('[data-cy="task-list"]')).toBeVisible();
    
    await context.close();
  });
});
```

**Boas Práticas para E2E**:

1. **Usar data-cy attributes**: Evitar seletores frágeis baseados em CSS
2. **Testar fluxos críticos**: Focar em jornadas importantes do usuário
3. **Isolar testes**: Cada teste deve ser independente
4. **Mockar APIs lentas**: Usar fixtures para dados estáticos
5. **Limpar estado**: Garantir que testes não afetam uns aos outros
6. **Screenshots em falhas**: Configurar captura automática de screenshots

---

## Comparações e Análises

### Tabela Comparativa: Frameworks de Teste Unitário

| Aspecto | Karma/Jasmine | Jest | Vitest |
|---------|---------------|------|--------|
| **Velocidade** | Lento (15-30s) | Rápido (5-10s) | Muito Rápido (2-5s) |
| **Execução** | Navegador real | Node.js | Node.js (ESM) |
| **TypeScript** | Requer configuração | Nativo | Nativo (melhor) |
| **Mocking** | Manual | Automático | Automático |
| **Snapshot Testing** | Não | Sim | Sim |
| **Watch Mode** | Básico | Inteligente | Muito Inteligente |
| **Coverage** | Requer plugin | Integrado | Integrado |
| **Configuração** | Complexa | Simples | Muito Simples |
| **Comunidade** | Grande (legado) | Muito Grande | Crescendo |
| **Migração** | N/A | Fácil | Muito Fácil |
| **Bundle Size** | Grande | Médio | Pequeno |
| **Quando Usar** | Projetos legados | Projetos modernos | Projetos novos/Vite |

### Tabela Comparativa: Frameworks de Teste E2E

| Aspecto | Cypress | Playwright | Protractor (deprecated) |
|---------|---------|------------|-------------------------|
| **Navegadores** | Chrome/Edge | Chrome, Firefox, Safari | Chrome, Firefox |
| **Velocidade** | Médio | Rápido | Lento |
| **API** | Simples e intuitiva | Poderosa e flexível | Complexa |
| **Debug** | Excelente (time-travel) | Bom | Limitado |
| **Screenshots/Vídeo** | Automático | Automático | Manual |
| **Network Mocking** | Bom | Excelente | Limitado |
| **Multi-tab** | Limitado | Suportado | Suportado |
| **Mobile** | Limitado | Suportado | Não |
| **TypeScript** | Suportado | Nativo | Suportado |
| **Comunidade** | Muito Grande | Crescendo | Declinando |
| **Manutenção** | Ativa | Muito Ativa | Descontinuado |
| **Quando Usar** | Projetos web simples | Projetos complexos/multi-browser | Não usar (deprecated) |

### Tabela Comparativa: Estratégias de Teste

| Tipo | Velocidade | Confiança | Custo | Quando Usar |
|------|------------|-----------|-------|-------------|
| **Unitários** | ⚡⚡⚡ Muito Rápido | ⭐⭐ Média | 💰 Baixo | Testar lógica isolada, funções puras |
| **Integração** | ⚡⚡ Rápido | ⭐⭐⭐ Boa | 💰💰 Médio | Testar fluxos, componentes juntos |
| **E2E** | ⚡ Lento | ⭐⭐⭐⭐ Alta | 💰💰💰 Alto | Testar jornadas críticas do usuário |

### Evolução Histórica dos Testes em Angular

```
┌─────────────────────────────────────────────────────────────┐
│          Timeline: Testing in Angular                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  2010-2016: AngularJS                                      │
│  ┌─────────────────────────────────────┐                    │
│  │  Karma + Jasmine                    │                    │
│  │  Protractor (E2E)                   │                    │
│  │  Configuração complexa              │                    │
│  └─────────────────────────────────────┘                    │
│                                                             │
│  2016-2020: Angular 2-10                                   │
│  ┌─────────────────────────────────────┐                    │
│  │  Karma + Jasmine (padrão)          │                    │
│  │  TestBed melhorado                  │                    │
│  │  Jest ganha tração                  │                    │
│  └─────────────────────────────────────┘                    │
│                                                             │
│  2020-2023: Angular 11-16                                  │
│  ┌─────────────────────────────────────┐                    │
│  │  Migração para Jest                 │                    │
│  │  Cypress populariza                  │                    │
│  │  Protractor deprecated               │                    │
│  └─────────────────────────────────────┘                    │
│                                                             │
│  2023+: Angular 17+                                        │
│  ┌─────────────────────────────────────┐                    │
│  │  Vitest emerge                      │                    │
│  │  Playwright cresce                  │                    │
│  │  Signals testing                    │                    │
│  └─────────────────────────────────────┘                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
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

#### 1. Teste Comportamento, Não Implementação

**Por quê**: Testes que verificam implementação interna são frágeis e quebram quando você refatora código, mesmo que o comportamento permaneça correto.

**Exemplo Ruim**:
```typescript
it('should call calculateTotal method', () => {
  const spy = jest.spyOn(component, 'calculateTotal');
  component.processOrder();
  expect(spy).toHaveBeenCalled();
});
```

**Exemplo Bom**:
```typescript
it('should calculate order total correctly', () => {
  component.items = [{ price: 10 }, { price: 20 }];
  component.processOrder();
  expect(component.total).toBe(30);
});
```

#### 2. Use AAA Pattern (Arrange, Act, Assert)

**Por quê**: Organiza testes de forma clara e consistente, facilitando leitura e manutenção.

**Estrutura**:
```typescript
it('should do something', () => {
  // Arrange: Preparar dados e estado inicial
  const input = 'test data';
  component.value = '';
  
  // Act: Executar ação sendo testada
  component.process(input);
  
  // Assert: Verificar resultado esperado
  expect(component.value).toBe('processed test data');
});
```

#### 3. Isole Unidades Sob Teste

**Por quê**: Testes isolados são mais rápidos, determinísticos e fáceis de debugar.

**Exemplo**:
```typescript
beforeEach(() => {
  const mockHttp = {
    get: jest.fn().mockReturnValue(of({ data: 'test' }))
  };
  
  TestBed.configureTestingModule({
    providers: [
      MyService,
      { provide: HttpClient, useValue: mockHttp }
    ]
  });
});
```

#### 4. Mantenha Testes Simples e Focados

**Por quê**: Um teste deve verificar uma única coisa. Testes complexos são difíceis de entender e debugar.

**Exemplo Ruim**:
```typescript
it('should do everything', () => {
  // Testa criação, renderização, interação, validação...
});
```

**Exemplo Bom**:
```typescript
it('should create component', () => {
  expect(component).toBeTruthy();
});

it('should render title', () => {
  component.title = 'Test';
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('Test');
});

it('should handle click', () => {
  const button = fixture.debugElement.query(By.css('button'));
  button.nativeElement.click();
  expect(component.clicked).toBe(true);
});
```

#### 5. Use Nomes Descritivos para Testes

**Por quê**: Nomes claros servem como documentação e facilitam identificação de problemas.

**Exemplo Ruim**:
```typescript
it('test1', () => { });
it('works', () => { });
```

**Exemplo Bom**:
```typescript
it('should display error message when form is invalid', () => { });
it('should increment counter when increment button is clicked', () => { });
it('should call API with correct parameters when saving user', () => { });
```

#### 6. Limpe Estado Entre Testes

**Por quê**: Testes devem ser independentes e não depender de ordem de execução.

**Exemplo**:
```typescript
afterEach(() => {
  jest.clearAllMocks();
  TestBed.resetTestingModule();
});
```

#### 7. Use Helpers e Utilities

**Por quê**: Reduz duplicação de código e facilita manutenção.

**Exemplo**:
```typescript
function createComponent<T>(component: Type<T>): ComponentFixture<T> {
  TestBed.configureTestingModule({
    imports: [component]
  });
  return TestBed.createComponent(component);
}

function clickButton(fixture: ComponentFixture<any>, selector: string) {
  const button = fixture.debugElement.query(By.css(selector));
  button.nativeElement.click();
  fixture.detectChanges();
}
```

#### 8. Teste Casos Extremos e Erros

**Por quê**: Aplicações reais enfrentam erros. Testes devem verificar tratamento adequado.

**Exemplo**:
```typescript
it('should handle API errors gracefully', () => {
  httpMock.get.mockReturnValue(throwError(() => new Error('API Error')));
  
  component.loadData();
  
  expect(component.error).toBeTruthy();
  expect(component.errorMessage).toContain('API Error');
});
```

#### 9. Mantenha Cobertura Adequada (80%+)

**Por quê**: Alta cobertura reduz bugs, mas 100% pode ser excessivo. Foque em código crítico.

**Estratégia**:
- Código crítico: 90%+
- Código importante: 80%+
- Código auxiliar: 60%+

#### 10. Use data-cy Attributes para E2E

**Por quê**: Seletores baseados em CSS são frágeis. data-cy é estável e semântico.

**Exemplo**:
```html
<button data-cy="submit-button">Submit</button>
```

```typescript
cy.get('[data-cy="submit-button"]').click();
```

### ❌ Anti-padrões Comuns

#### 1. Testar Implementação Interna

**Problema**: Testes quebram quando você refatora, mesmo com comportamento correto.

**Exemplo Ruim**:
```typescript
it('should use internal method', () => {
  const spy = jest.spyOn(component, 'internalHelper');
  component.doSomething();
  expect(spy).toHaveBeenCalled();
});
```

**Solução**: Teste comportamento público
```typescript
it('should produce correct result', () => {
  const result = component.doSomething();
  expect(result).toBe(expectedValue);
});
```

#### 2. Testes Excessivamente Complexos

**Problema**: Difícil de entender, debugar e manter.

**Exemplo Ruim**:
```typescript
it('should do everything', () => {
  // 50 linhas testando múltiplas coisas
  component.init();
  component.load();
  component.process();
  component.validate();
  component.save();
  // ... muitas assertions
});
```

**Solução**: Divida em múltiplos testes focados
```typescript
it('should initialize correctly', () => { });
it('should load data', () => { });
it('should process data', () => { });
```

#### 3. Ignorar Testes Quebrados

**Problema**: Reduz confiança na suíte de testes.

**Solução**: Corrija ou remova testes quebrados imediatamente
```typescript
// ❌ NUNCA faça isso
it.skip('should work', () => { });

// ✅ Corrija ou remova
it('should work', () => {
  // Teste corrigido
});
```

#### 4. Dependências Entre Testes

**Problema**: Testes que dependem de ordem ou estado de outros testes são frágeis.

**Exemplo Ruim**:
```typescript
let sharedState = {};

it('test 1', () => {
  sharedState.value = 10;
});

it('test 2', () => {
  expect(sharedState.value).toBe(10); // Depende de test 1
});
```

**Solução**: Cada teste deve ser independente
```typescript
it('test 1', () => {
  const state = { value: 10 };
  // Teste independente
});

it('test 2', () => {
  const state = { value: 10 };
  // Teste independente
});
```

#### 5. Mocks Excessivos

**Problema**: Testes que mockam tudo não testam integração real.

**Solução**: Use mocks apenas quando necessário
```typescript
// ❌ Mockar tudo
const mockService = { get: jest.fn(), post: jest.fn(), ... };

// ✅ Mockar apenas dependências externas
const mockHttp = { get: jest.fn() };
// Usar serviços reais quando possível
```

#### 6. Assertions Fracas

**Problema**: Assertions genéricas não garantem comportamento correto.

**Exemplo Ruim**:
```typescript
expect(component.data).toBeTruthy();
```

**Solução**: Seja específico
```typescript
expect(component.data).toEqual({ id: 1, name: 'Test' });
expect(component.data.id).toBe(1);
expect(component.data.name).toBe('Test');
```

#### 7. Não Limpar Após Testes

**Problema**: Estado residual pode afetar outros testes.

**Solução**: Sempre limpe em afterEach
```typescript
afterEach(() => {
  jest.clearAllMocks();
  TestBed.resetTestingModule();
  fixture.destroy();
});
```

#### 8. Testes Lentos Desnecessariamente

**Problema**: Testes lentos desencorajam execução frequente.

**Solução**: 
- Use mocks para operações lentas
- Evite testes E2E quando unitários são suficientes
- Execute testes em paralelo quando possível

#### 9. Não Testar Casos de Erro

**Problema**: Aplicações reais têm erros. Testes devem verificar tratamento.

**Solução**: Sempre teste cenários de erro
```typescript
it('should handle network errors', () => { });
it('should validate input correctly', () => { });
it('should show error for invalid data', () => { });
```

#### 10. Cobertura Sem Significado

**Problema**: 100% de cobertura não garante qualidade se testes são fracos.

**Solução**: Foque em qualidade, não apenas quantidade
- Teste comportamento importante
- Teste casos extremos
- Teste tratamento de erros
- Não teste getters/setters simples sem lógica

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

#### Angular Testing
- **[Angular Testing Guide](https://angular.io/guide/testing)**: Guia oficial completo de testes em Angular
- **[Angular Testing Utilities](https://angular.io/api/core/testing)**: API reference do TestBed e utilitários
- **[Angular Testing Best Practices](https://angular.io/guide/testing-best-practices)**: Melhores práticas recomendadas pelo time Angular

#### Frameworks de Teste Unitário
- **[Jest Documentation](https://jestjs.io/)**: Documentação completa do Jest
- **[Jest Angular Preset](https://thymikee.github.io/jest-preset-angular/)**: Preset Jest para Angular
- **[Vitest Documentation](https://vitest.dev/)**: Documentação do Vitest
- **[Vitest Angular Guide](https://vitest.dev/guide/angular.html)**: Guia específico para Angular

#### Frameworks de Teste E2E
- **[Cypress Documentation](https://docs.cypress.io/)**: Documentação completa do Cypress
- **[Cypress Best Practices](https://docs.cypress.io/guides/references/best-practices)**: Melhores práticas Cypress
- **[Playwright Documentation](https://playwright.dev/)**: Documentação do Playwright
- **[Playwright Angular Guide](https://playwright.dev/docs/test-angular)**: Guia Playwright para Angular

### Artigos e Tutoriais

#### Testes Unitários
- **[Angular Unit Testing: Complete Guide](https://www.testim.io/blog/angular-unit-testing/)**: Guia completo de testes unitários
- **[Jest vs Karma: Migration Guide](https://dev.to/this-is-angular/migrating-from-karma-to-jest-in-angular-4k5h)**: Guia de migração Karma para Jest
- **[Vitest vs Jest Comparison](https://www.browserstack.com/guide/vitest-vs-jest)**: Comparação detalhada Vitest vs Jest
- **[Angular Testing Patterns](https://testingjavascript.com/)**: Padrões avançados de testes

#### Testes de Integração
- **[Integration Testing in Angular](https://angular.io/guide/testing-components-scenarios)**: Guia oficial de testes de integração
- **[Testing HTTP in Angular](https://angular.io/guide/http-test-requests)**: Como testar requisições HTTP

#### Testes E2E
- **[Cypress Best Practices](https://docs.cypress.io/guides/references/best-practices)**: Melhores práticas Cypress
- **[Playwright Best Practices](https://playwright.dev/docs/best-practices)**: Melhores práticas Playwright
- **[E2E Testing Strategy](https://kentcdodds.com/blog/common-mistakes-with-react-testing-library)**: Estratégias de testes E2E (conceitos aplicáveis)

### Vídeos e Cursos

#### Canais e Playlists
- **[Angular Testing Playlist](https://www.youtube.com/results?search_query=angular+testing+tutorial)**: Tutoriais em vídeo sobre testes Angular
- **[Jest Tutorial Series](https://www.youtube.com/results?search_query=jest+tutorial)**: Tutoriais Jest
- **[Cypress Tutorial](https://www.youtube.com/results?search_query=cypress+tutorial)**: Tutoriais Cypress

#### Vídeos Específicos Recomendados
- **Angular Unit Testing Best Practices**: Vídeos sobre boas práticas
- **Migrating from Karma to Jest**: Guias de migração
- **Cypress vs Playwright**: Comparações detalhadas

### Ferramentas e Extensões

#### VS Code Extensions
- **[Jest Extension](https://marketplace.visualstudio.com/items?itemName=Orta.vscode-jest)**: Suporte Jest no VS Code
- **[Vitest Extension](https://marketplace.visualstudio.com/items?itemName=ZixuanChen.vitest-explorer)**: Suporte Vitest no VS Code
- **[Cypress Extension](https://marketplace.visualstudio.com/items?itemName=Cypress.cypress)**: Suporte Cypress no VS Code

#### Ferramentas de Coverage
- **[Istanbul/nyc](https://istanbul.js.org/)**: Ferramenta de cobertura de código
- **[Coverage Badges](https://shields.io/)**: Badges de cobertura para README

#### Ferramentas de CI/CD
- **[GitHub Actions Testing](https://docs.github.com/en/actions/automating-builds-and-tests)**: Configurar testes no GitHub Actions
- **[CircleCI Angular Testing](https://circleci.com/docs/language-angular/)**: Testes Angular no CircleCI

### Comunidade e Recursos

#### Blogs e Artigos Técnicos
- **[Angular Testing Blog Posts](https://blog.angular.io/)**: Artigos sobre testes no blog oficial Angular
- **[Dev.to Angular Testing](https://dev.to/t/angular)**: Artigos da comunidade sobre testes Angular

#### Stack Overflow e Fóruns
- **[Angular Testing Tag](https://stackoverflow.com/questions/tagged/angular-testing)**: Perguntas e respostas sobre testes Angular
- **[Jest Tag](https://stackoverflow.com/questions/tagged/jestjs)**: Perguntas sobre Jest
- **[Cypress Tag](https://stackoverflow.com/questions/tagged/cypress)**: Perguntas sobre Cypress

### Livros Recomendados

- **"Testing Angular Applications"** - Jesse Palmer, Corinna Cohn, Mike Giambalvo, Craig Nishina
- **"The Art of Unit Testing"** - Roy Osherove (conceitos aplicáveis)
- **"Test-Driven Development"** - Kent Beck (TDD principles)

### Recursos Adicionais

#### Schematics e Templates
- **[Angular Testing Schematics](https://angular.io/cli/generate)**: Geradores de código para testes
- **[Jest Preset Angular](https://github.com/thymikee/jest-preset-angular)**: Configuração pré-definida Jest

#### Exemplos e Repositórios
- **[Angular Testing Examples](https://github.com/angular/angular/tree/main/packages/core/test)**: Exemplos oficiais Angular
- **[Jest Examples](https://github.com/facebook/jest/tree/main/examples)**: Exemplos Jest
- **[Cypress Examples](https://github.com/cypress-io/cypress-example-kitchensink)**: Exemplos Cypress

---

## Resumo

### Principais Conceitos

#### Frameworks de Teste
- **Jest/Vitest**: Frameworks modernos que substituem Karma/Jasmine, oferecendo execução mais rápida, melhor TypeScript support e ferramentas avançadas
- **Cypress/Playwright**: Ferramentas E2E modernas que substituem Protractor, oferecendo melhor experiência de desenvolvimento e debugging

#### Ferramentas Angular
- **TestBed**: Utilitário central que configura ambiente isolado de testes, criando instâncias de componentes com todas as dependências necessárias
- **ComponentFixture**: Wrapper que fornece acesso ao componente, DOM e métodos de change detection
- **HttpTestingController**: Controla requisições HTTP em testes, permitindo verificar chamadas e fornecer respostas mockadas

#### Estratégias de Teste
- **Testes Unitários**: Testam unidades isoladas (componentes, serviços) de forma rápida e determinística
- **Testes de Integração**: Testam múltiplas unidades trabalhando juntas, verificando fluxos completos
- **Testes E2E**: Testam aplicação completa do ponto de vista do usuário, garantindo máxima confiança

#### Técnicas de Teste
- **Mocks**: Objetos simulados que substituem dependências reais, permitindo controle total sobre comportamento
- **Spies**: Ferramentas que rastreiam chamadas de métodos, verificando interações sem substituir implementação
- **AAA Pattern**: Estrutura Arrange-Act-Assert que organiza testes de forma clara e consistente

### Pontos-Chave para Lembrar

#### Princípios Fundamentais
1. **Teste comportamento, não implementação**: Testes devem verificar resultados, não métodos internos
2. **Use AAA pattern**: Organize testes em três seções claras (Arrange, Act, Assert)
3. **Isole unidades sob teste**: Use mocks para dependências externas, garantindo testes determinísticos
4. **Mantenha testes simples**: Um teste deve verificar uma única coisa
5. **Use nomes descritivos**: Nomes claros servem como documentação

#### Estratégias de Cobertura
- **Código crítico**: Almeje 90%+ de cobertura
- **Código importante**: Almeje 80%+ de cobertura
- **Código auxiliar**: 60%+ é suficiente
- **Qualidade > Quantidade**: Cobertura alta não garante qualidade se testes são fracos

#### Pirâmide de Testes
- **Base**: Muitos testes unitários (rápidos, baratos)
- **Meio**: Testes de integração (média quantidade, testam fluxos)
- **Topo**: Poucos testes E2E (lentos, caros, máxima confiança)

### Próximos Passos

#### Imediatos
1. **Próxima aula**: SSR e PWA (Aula 5.2)
2. **Praticar**: Escrever testes para componentes existentes
3. **Explorar**: Configurar Jest ou Vitest em projeto pessoal

#### Médio Prazo
1. **Migrar projeto**: Se usando Karma, considerar migração para Jest/Vitest
2. **Configurar E2E**: Escolher entre Cypress ou Playwright e configurar
3. **Aumentar cobertura**: Trabalhar para atingir 80%+ de cobertura

#### Avançado
1. **TDD**: Explorar Test-Driven Development
2. **Testes de Performance**: Adicionar testes de performance
3. **Visual Regression**: Explorar testes de regressão visual
4. **CI/CD Integration**: Integrar testes no pipeline de CI/CD

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
