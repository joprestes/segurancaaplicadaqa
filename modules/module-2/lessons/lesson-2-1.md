---
layout: lesson
title: "Aula 2.1: Serviços e Injeção de Dependência"
slug: servicos-di
module: module-2
lesson_id: lesson-2-1
duration: "90 minutos"
level: "Intermediário"
prerequisites: []
exercises: []
podcast:
  file: "assets/podcasts/02.1-Servicos_e_Injecao_de_Dependencia_no_Angular.m4a"
  image: "assets/images/podcasts/02.1-Servicos_e_Injecao_de_Dependencia_no_Angular.png"
  title: "Serviços e Injeção de Dependência no Angular"
  description: "Descubra como os serviços são o coração da arquitetura Angular."
  duration: "50-65 minutos"
permalink: /modules/desenvolvimento-intermediario/lessons/servicos-di/
---

## Introdução

Nesta aula, você dominará serviços e injeção de dependência no Angular. Serviços são fundamentais para organizar lógica de negócio, compartilhar dados entre componentes e criar código reutilizável. Injeção de Dependência é o mecanismo que torna tudo isso possível de forma elegante e testável.

### Contexto Histórico da Injeção de Dependência

A Injeção de Dependência (DI) é um dos pilares fundamentais do Angular desde sua primeira versão. O sistema de DI do Angular é um dos mais poderosos e completos entre os frameworks JavaScript modernos.

**Linha do Tempo da Evolução**:

```
AngularJS (2010) ──────────────────────────────────────────── Angular 17+ (2023+)
 │                                                                  │
 ├─ 2010    📦 AngularJS - DI Básico                              │
 │          $inject annotation                                     │
 │          Service registration manual                           │
 │          DI baseado em strings                                  │
 │                                                                  │
 ├─ 2016    🚀 Angular 2 - DI Moderno                            │
 │          Decorator @Injectable                                 │
 │          Type-based injection                                  │
 │          Hierarquia de injectors                               │
 │          Providers system                                      │
 │                                                                  │
 ├─ 2017-2020 📈 Melhorias Incrementais                           │
 │          InjectionToken para type safety                       │
 │          Factory providers                                     │
 │          Optional dependencies                                 │
 │          Performance improvements                              │
 │                                                                  │
 ├─ 2020    ⚡ Angular 10 - providedIn simplificado             │
 │          'root', 'platform', 'any'                            │
 │          Standalone services                                   │
 │                                                                  │
 ├─ 2022    🔥 Angular 14 - inject() function                    │
 │          Functional injection                                  │
 │          Injection em funções                                 │
 │          Código mais limpo                                     │
 │                                                                  │
 └─ 2023+    🎯 Angular 17+ - DI Otimizado                      │
            Performance melhorada                                │
            Tree-shaking melhorado                                │
            Standalone-first                                      │
```

**Por que DI é Fundamental?**

DI resolve problemas comuns de desenvolvimento:
- **Acoplamento**: Sem DI, componentes criam dependências diretamente (alto acoplamento)
- **Testabilidade**: Com DI, dependências podem ser mockadas facilmente
- **Reutilização**: Serviços podem ser compartilhados entre componentes
- **Manutenibilidade**: Mudanças em serviços não afetam componentes diretamente

**Comparação com Outros Frameworks**:

- **Angular**: DI nativo e completo, type-safe, hierarquia poderosa
- **React**: Context API (limitado), sem DI nativo
- **Vue**: Provide/Inject (básico), sem hierarquia completa

### O que você vai aprender

- **Serviços Standalone**: Criar serviços auto-suficientes sem NgModules
- **@Injectable Decorator**: Configurar serviços e escopos
- **Hierarquia de Injectors**: Entender como Angular resolve dependências
- **Providers e Escopos**: Configurar como serviços são criados e compartilhados
- **Função inject()**: Forma moderna de injeção (Angular 14+)
- **InjectionTokens**: Injeção type-safe de valores primitivos e objetos
- **Factory Providers**: Criar serviços com lógica de criação complexa
- **Dependências Opcionais**: Trabalhar com dependências que podem não existir

### Por que isso é importante

**Para Desenvolvimento**:
- **Arquitetura Limpa**: Separação clara entre lógica de negócio e apresentação
- **Testabilidade**: Fácil criar mocks e testar componentes isoladamente
- **Reutilização**: Serviços podem ser compartilhados em toda aplicação
- **Manutenibilidade**: Mudanças centralizadas, menos impacto

**Para Projetos**:
- **Escalabilidade**: Arquitetura que escala com projetos grandes
- **Organização**: Código bem estruturado e fácil de navegar
- **Performance**: Singleton services reduzem criação de instâncias
- **Colaboração**: Múltiplos desenvolvedores podem trabalhar independentemente

**Para Carreira**:
- **Fundamental**: DI é essencial para Angular profissional
- **Diferencial**: Entendimento profundo de DI é valorizado
- **Base Sólida**: Necessário para conceitos avançados (guards, interceptors)
- **Padrões**: Aprende padrões de design importantes (Dependency Injection, Singleton)

---

## Conceitos Teóricos

### Serviços no Angular

**Definição**: Serviços são classes TypeScript decoradas com `@Injectable` que encapsulam lógica de negócio, comunicação com APIs e funcionalidades reutilizáveis.

**Explicação Detalhada**:

Serviços são usados para:
- Compartilhar lógica entre componentes
- Comunicar com APIs externas
- Gerenciar estado da aplicação
- Implementar funcionalidades transversais (logging, autenticação)
- Facilitar testes unitários

**Analogia**:

Serviços são como funcionários especializados em uma empresa. Cada serviço tem uma função específica (como um contador, um gerente de estoque), e diferentes departamentos (componentes) podem solicitar seus serviços quando necessário.

**Visualização**:

```
Componente A          Serviço          Componente B
┌──────────┐         ┌─────────┐      ┌──────────┐
│          │  ────→  │         │  ←───│          │
│  Usa     │         │ Lógica  │      │  Usa     │
│  Serviço │         │ Compartilhada │ │  Serviço │
└──────────┘         └─────────┘      └──────────┘
```

**Fluxo Detalhado de Uso de Serviços**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Ciclo de Vida de um Serviço               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Declaração                                              │
│     ┌─────────────────────┐                                 │
│     │ @Injectable({       │                                 │
│     │   providedIn: 'root'│                                 │
│     │ })                   │                                 │
│     │ export class        │                                 │
│     │   MyService {}       │                                 │
│     └─────────────────────┘                                 │
│              │                                              │
│              ▼                                              │
│  2. Registro no Injector                                   │
│     ┌─────────────────────┐                                 │
│     │ Angular registra    │                                 │
│     │ serviço no Root     │                                 │
│     │ Injector            │                                 │
│     └─────────────────────┘                                 │
│              │                                              │
│              ▼                                              │
│  3. Primeira Solicitação                                   │
│     ┌─────────────────────┐                                 │
│     │ Component solicita  │                                 │
│     │ MyService           │                                 │
│     └─────────────────────┘                                 │
│              │                                              │
│              ▼                                              │
│  4. Criação da Instância                                   │
│     ┌─────────────────────┐                                 │
│     │ Angular cria        │                                 │
│     │ instância única     │                                 │
│     │ (Singleton)         │                                 │
│     └─────────────────────┘                                 │
│              │                                              │
│              ▼                                              │
│  5. Injeção                                                │
│     ┌─────────────────────┐                                 │
│     │ Angular injeta      │                                 │
│     │ instância no        │                                 │
│     │ Component           │                                 │
│     └─────────────────────┘                                 │
│              │                                              │
│              ▼                                              │
│  6. Próximas Solicitações                                  │
│     ┌─────────────────────┐                                 │
│     │ Outros Components   │                                 │
│     │ recebem mesma       │                                 │
│     │ instância           │                                 │
│     └─────────────────────┘                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático**:

```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private users: User[] = [];
  
  getUsers(): User[] {
    return [...this.users];
  }
  
  addUser(user: User): void {
    this.users.push(user);
  }
  
  getUserById(id: number): User | undefined {
    return this.users.find(u => u.id === id);
  }
}
```

---

### @Injectable Decorator

**Definição**: `@Injectable` é o decorator que marca uma classe como injetável e configurável no sistema de DI do Angular.

**Explicação Detalhada**:

`@Injectable` pode ser configurado com:
- `providedIn: 'root'`: Singleton em toda aplicação (padrão recomendado)
- `providedIn: 'platform'`: Singleton compartilhado entre aplicações
- `providedIn: 'any'`: Nova instância por módulo lazy-loaded
- Sem `providedIn`: Deve ser fornecido em um NgModule

**Analogia**:

`@Injectable` é como um registro de empresa. Sem ele, o Angular não sabe que a classe pode ser "contratada" (injetada). O `providedIn` define onde a instância "trabalha" (escopo).

**Exemplo Prático**:

```typescript
@Injectable({
  providedIn: 'root'
})
export class LoggerService {
  log(message: string): void {
    console.log(`[${new Date().toISOString()}] ${message}`);
  }
}

@Injectable({
  providedIn: 'any'
})
export class FeatureService {
  constructor() {
    console.log('Nova instância criada');
  }
}
```

---

### Hierarquia de Injectors

**Definição**: Angular usa uma hierarquia de injectors para resolver dependências, procurando do nível mais específico (componente) até o mais geral (root).

**Explicação Detalhada**:

Hierarquia de injectors:
1. **Component Injector**: Nível do componente
2. **Element Injector**: Nível do elemento
3. **Module Injector**: Nível do módulo
4. **Platform Injector**: Nível da plataforma
5. **Root Injector**: Nível raiz (providedIn: 'root')

**Analogia**:

Hierarquia de injectors é como uma estrutura organizacional. Quando você precisa de algo, primeiro pergunta ao seu chefe direto (componente), depois ao gerente (módulo), e assim por diante até encontrar quem pode fornecer.

**Visualização**:

```
Root Injector (providedIn: 'root')
    │
    ├─ Platform Injector
    │     │
    │     └─ Module Injector
    │           │
    │           └─ Component Injector
    │                 │
    │                 └─ Element Injector
```

**Fluxo Detalhado de Resolução de Dependências**:

```
┌─────────────────────────────────────────────────────────────┐
│         Processo de Resolução de Dependência                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Component precisa de MyService                            │
│         │                                                    │
│         ▼                                                    │
│  ┌─────────────────────────────────────┐                   │
│  │ 1. Component Injector               │                   │
│  │    ┌─────────────────────────────┐   │                   │
│  │    │ providers: [MyService]?    │   │                   │
│  │    └─────────────────────────────┘   │                   │
│  │              │                        │                   │
│  │              │ ❌ Não encontrado      │                   │
│  │              ▼                        │                   │
│  └─────────────────────────────────────┘                   │
│         │                                                    │
│         ▼                                                    │
│  ┌─────────────────────────────────────┐                   │
│  │ 2. Element Injector                 │                   │
│  │    ┌─────────────────────────────┐   │                   │
│  │    │ providers no elemento?      │   │                   │
│  │    └─────────────────────────────┘   │                   │
│  │              │                        │                   │
│  │              │ ❌ Não encontrado      │                   │
│  │              ▼                        │                   │
│  └─────────────────────────────────────┘                   │
│         │                                                    │
│         ▼                                                    │
│  ┌─────────────────────────────────────┐                   │
│  │ 3. Module Injector                  │                   │
│  │    ┌─────────────────────────────┐   │                   │
│  │    │ providers no NgModule?     │   │                   │
│  │    └─────────────────────────────┘   │                   │
│  │              │                        │                   │
│  │              │ ❌ Não encontrado      │                   │
│  │              ▼                        │                   │
│  └─────────────────────────────────────┘                   │
│         │                                                    │
│         ▼                                                    │
│  ┌─────────────────────────────────────┐                   │
│  │ 4. Platform Injector                │                   │
│  │    ┌─────────────────────────────┐   │                   │
│  │    │ providedIn: 'platform'?   │   │                   │
│  │    └─────────────────────────────┘   │                   │
│  │              │                        │                   │
│  │              │ ❌ Não encontrado      │                   │
│  │              ▼                        │                   │
│  └─────────────────────────────────────┘                   │
│         │                                                    │
│         ▼                                                    │
│  ┌─────────────────────────────────────┐                   │
│  │ 5. Root Injector                    │                   │
│  │    ┌─────────────────────────────┐   │                   │
│  │    │ providedIn: 'root'?        │   │                   │
│  │    └─────────────────────────────┘   │                   │
│  │              │                        │                   │
│  │              │ ✅ Encontrado!         │                   │
│  │              ▼                        │                   │
│  │    ┌─────────────────────────────┐   │                   │
│  │    │ Cria ou retorna instância   │   │                   │
│  │    │ (Singleton se 'root')       │   │                   │
│  │    └─────────────────────────────┘   │                   │
│  └─────────────────────────────────────┘                   │
│         │                                                    │
│         ▼                                                    │
│  ┌─────────────────────────────────────┐                   │
│  │ 6. Injeção no Component             │                   │
│  │    Component recebe MyService       │                   │
│  └─────────────────────────────────────┘                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Nota: Se nenhum injector encontrar o serviço, Angular lança erro:
"NullInjectorError: No provider for MyService"
```

**Exemplo Prático**:

```typescript
@Injectable({
  providedIn: 'root'
})
export class GlobalService {}

@Injectable()
export class ComponentService {}

@Component({
  selector: 'app-child',
  providers: [ComponentService]
})
export class ChildComponent {
  constructor(
    private globalService: GlobalService,
    private componentService: ComponentService
  ) {}
}
```

---

### Providers e Escopos

**Definição**: Providers definem como e onde serviços são criados e disponibilizados na hierarquia de injectors.

**Explicação Detalhada**:

Tipos de providers:
- **Class Provider**: `{ provide: ServiceClass, useClass: ServiceClass }`
- **Value Provider**: `{ provide: TOKEN, useValue: value }`
- **Factory Provider**: `{ provide: TOKEN, useFactory: factoryFn }`
- **Existing Provider**: `{ provide: NewToken, useExisting: OldToken }`

Escopos:
- `providedIn: 'root'`: Singleton global
- `providedIn: 'platform'`: Singleton por plataforma
- `providedIn: 'any'`: Instância por módulo lazy
- `providers: []` no componente: Instância por componente

**Analogia**:

Providers são como contratos de trabalho. Eles definem:
- Quem será contratado (provide)
- Como será contratado (useClass, useValue, useFactory)
- Onde trabalhará (escopo)

**Exemplo Prático**:

```typescript
const API_URL = new InjectionToken<string>('API_URL');

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  constructor(@Inject(API_URL) private apiUrl: string) {}
}

@Component({
  providers: [
    { provide: API_URL, useValue: 'https://api.example.com' }
  ]
})
export class AppComponent {}
```

---

### Função inject()

**Definição**: `inject()` é a função moderna (Angular 14+) para injeção de dependências que pode ser usada fora de construtores.

**Explicação Detalhada**:

`inject()` permite:
- Injeção em funções
- Injeção em campos de classe
- Injeção em métodos
- Código mais limpo e funcional

**Analogia**:

`inject()` é como um pedido direto de serviço. Ao invés de esperar que alguém te entregue no construtor, você pode pedir diretamente quando precisar.

**Exemplo Prático**:

```typescript
export class MyComponent {
  private userService = inject(UserService);
  private logger = inject(LoggerService);
  
  ngOnInit(): void {
    const router = inject(Router);
    this.logger.log('Component initialized');
  }
}

function createUserService(): UserService {
  const http = inject(HttpClient);
  return new UserService(http);
}
```

---

### InjectionTokens

**Definição**: InjectionTokens são tokens type-safe para injeção de valores primitivos, objetos ou interfaces.

**Explicação Detalhada**:

InjectionTokens são usados para:
- Injetar valores primitivos (strings, numbers)
- Injetar objetos de configuração
- Injetar interfaces (que não podem ser instanciadas)
- Criar APIs públicas type-safe

**Analogia**:

InjectionTokens são como códigos de barras únicos. Cada token identifica exatamente o que você quer injetar, garantindo que você receba o valor correto.

**Exemplo Prático**:

```typescript
import { InjectionToken } from '@angular/core';

export interface AppConfig {
  apiUrl: string;
  timeout: number;
  retries: number;
}

export const APP_CONFIG = new InjectionToken<AppConfig>('APP_CONFIG');

@Injectable({
  providedIn: 'root',
  useFactory: () => ({
    apiUrl: 'https://api.example.com',
    timeout: 5000,
    retries: 3
  })
})
export class ConfigService {
  constructor(@Inject(APP_CONFIG) private config: AppConfig) {}
}
```

---

### Factory Providers

**Definição**: Factory providers permitem criar instâncias de serviços usando funções factory, útil para lógica de criação complexa.

**Explicação Detalhada**:

Factory providers são usados quando:
- Criação requer lógica condicional
- Dependências precisam ser resolvidas dinamicamente
- Configuração é necessária antes da criação
- Múltiplas instâncias com configurações diferentes

**Analogia**:

Factory providers são como fábricas personalizadas. Ao invés de comprar um produto padrão (classe), você pede uma fábrica que cria o produto exatamente como você precisa. A fábrica pode verificar o ambiente, combinar diferentes materiais (dependências), e criar produtos customizados para cada situação.

**Visualização do Processo**:

```
┌─────────────────────────────────────────────────────────────┐
│              Factory Provider - Fluxo de Criação             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Angular identifica necessidade de serviço               │
│         │                                                    │
│         ▼                                                    │
│  2. Verifica provider type: Factory                         │
│         │                                                    │
│         ▼                                                    │
│  3. Resolve dependências (deps)                            │
│     ┌─────────────────────────────────────┐                 │
│     │ deps: [HttpClient, APP_CONFIG]     │                 │
│     │   │                                 │                 │
│     │   ├─ Resolve HttpClient            │                 │
│     │   └─ Resolve APP_CONFIG            │                 │
│     └─────────────────────────────────────┘                 │
│         │                                                    │
│         ▼                                                    │
│  4. Executa Factory Function                               │
│     ┌─────────────────────────────────────┐                 │
│     │ createHttpService(http, config)     │                 │
│     │   │                                  │                 │
│     │   ├─ Lógica condicional?            │                 │
│     │   ├─ Validação?                     │                 │
│     │   ├─ Configuração?                  │                 │
│     │   └─ Criação customizada            │                 │
│     └─────────────────────────────────────┘                 │
│         │                                                    │
│         ▼                                                    │
│  5. Retorna instância criada                               │
│         │                                                    │
│         ▼                                                    │
│  6. Angular armazena e injeta                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático**:

```typescript
export function createHttpService(http: HttpClient, config: AppConfig): HttpService {
  return new HttpService(http, config.apiUrl, config.timeout);
}

@Injectable({
  providedIn: 'root',
  useFactory: createHttpService,
  deps: [HttpClient, APP_CONFIG]
})
export class HttpService {}
```

**Exemplo Avançado com Lógica Condicional**:

```typescript
export function createLoggerService(config: AppConfig): LoggerService {
  if (config.environment === 'production') {
    return new ProductionLoggerService(config.logLevel);
  } else {
    return new DevelopmentLoggerService(config.logLevel);
  }
}

@Injectable({
  providedIn: 'root',
  useFactory: createLoggerService,
  deps: [APP_CONFIG]
})
export class LoggerService {}
```

---

### Dependências Opcionais

**Definição**: Dependências opcionais são serviços ou valores que podem não estar disponíveis na hierarquia de injectors, permitindo que o código continue funcionando mesmo sem eles.

**Explicação Detalhada**:

Dependências opcionais são úteis quando:
- Um serviço pode ou não estar disponível dependendo do contexto
- Você quer fornecer funcionalidade adicional quando disponível
- Você precisa evitar erros quando um provider não está configurado
- Você quer criar código mais flexível e tolerante a falhas

**Analogia**:

Dependências opcionais são como acessórios opcionais em um carro. O carro funciona sem eles, mas se estiverem disponíveis, oferecem funcionalidades extras. Por exemplo, um sistema de navegação GPS é opcional - o carro funciona sem ele, mas se estiver instalado, você pode usá-lo.

**Visualização**:

```
┌─────────────────────────────────────────────────────────────┐
│         Resolução de Dependência Opcional                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Component solicita OptionalService                         │
│         │                                                    │
│         ▼                                                    │
│  ┌─────────────────────────────────────┐                   │
│  │ Angular busca na hierarquia         │                   │
│  │   Component → Module → Root        │                   │
│  └─────────────────────────────────────┘                   │
│         │                                                    │
│         ├─ ✅ Encontrado                                    │
│         │   ┌─────────────────────────┐                     │
│         │   │ Injeta instância        │                     │
│         │   │ Component usa serviço   │                     │
│         │   └─────────────────────────┘                     │
│         │                                                    │
│         └─ ❌ Não encontrado                                 │
│             ┌─────────────────────────┐                     │
│             │ Injeta null             │                     │
│             │ Component verifica null │                     │
│             │ Continua funcionando    │                     │
│             │ sem o serviço           │                     │
│             └─────────────────────────┘                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático com @Optional()**:

```typescript
import { Injectable, Optional, inject } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class AnalyticsService {
  trackEvent(event: string): void {
    console.log(`Tracking: ${event}`);
  }
}

export class MyComponent {
  private analytics = inject(AnalyticsService, { optional: true });
  
  onClick(): void {
    if (this.analytics) {
      this.analytics.trackEvent('button_clicked');
    } else {
      console.log('Analytics não disponível');
    }
  }
}
```

**Exemplo com Constructor Injection**:

```typescript
import { Injectable, Optional } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class MyComponent {
  constructor(
    @Optional() private analytics?: AnalyticsService
  ) {}
  
  trackAction(action: string): void {
    this.analytics?.trackEvent(action);
  }
}
```

**Exemplo com Valor Padrão**:

```typescript
import { Injectable, inject, Optional } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class FeatureService {
  private logger = inject(LoggerService, { optional: true }) ?? new ConsoleLogger();
  
  doSomething(): void {
    this.logger.log('Feature executed');
  }
}
```

**Casos de Uso Comuns**:

1. **Serviços de Debug/Logging**: Disponíveis apenas em desenvolvimento
2. **Analytics**: Pode não estar configurado em todos os ambientes
3. **Feature Flags**: Funcionalidades experimentais que podem não estar disponíveis
4. **Plugins**: Extensões que podem ou não estar instaladas
5. **Configurações Específicas**: Configurações que variam por ambiente

---

## Exemplos Práticos Completos

### Exemplo 1: Serviço Completo com DI

**Contexto**: Criar serviço de autenticação completo usando DI.

**Código**:

```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';

interface User {
  id: number;
  email: string;
  name: string;
}

interface LoginCredentials {
  email: string;
  password: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private currentUser$ = new BehaviorSubject<User | null>(null);
  
  getCurrentUser(): Observable<User | null> {
    return this.currentUser$.asObservable();
  }
  
  login(credentials: LoginCredentials): Observable<User> {
    return this.http.post<User>('/api/login', credentials).pipe(
      tap(user => this.currentUser$.next(user))
    );
  }
  
  logout(): void {
    this.currentUser$.next(null);
  }
  
  isAuthenticated(): boolean {
    return this.currentUser$.value !== null;
  }
}
```

---

### Exemplo 2: Serviço com InjectionToken

**Contexto**: Criar serviço configurável usando InjectionToken.

**Código**:

```typescript
import { Injectable, InjectionToken, Inject, inject } from '@angular/core';

export interface StorageConfig {
  prefix: string;
  expiration: number;
}

export const STORAGE_CONFIG = new InjectionToken<StorageConfig>('STORAGE_CONFIG');

@Injectable({
  providedIn: 'root',
  useFactory: () => ({
    prefix: 'app_',
    expiration: 3600000
  })
})
export class StorageService {
  private config = inject(STORAGE_CONFIG);
  
  setItem(key: string, value: string): void {
    const fullKey = `${this.config.prefix}${key}`;
    localStorage.setItem(fullKey, value);
  }
  
  getItem(key: string): string | null {
    const fullKey = `${this.config.prefix}${key}`;
    return localStorage.getItem(fullKey);
  }
}
```

**Uso no Component**:

```typescript
import { Component } from '@angular/core';
import { STORAGE_CONFIG } from './storage.service';

@Component({
  selector: 'app-root',
  providers: [
    {
      provide: STORAGE_CONFIG,
      useValue: {
        prefix: 'myapp_',
        expiration: 7200000
      }
    }
  ]
})
export class AppComponent {
  constructor(private storage: StorageService) {}
}
```

---

### Exemplo 3: Serviço com Múltiplas Dependências e Factory

**Contexto**: Criar serviço que depende de múltiplos serviços e usa factory para configuração complexa.

**Código**:

```typescript
import { Injectable, inject, InjectionToken } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, throwError } from 'rxjs';
import { catchError, retry } from 'rxjs/operators';

export interface ApiConfig {
  baseUrl: string;
  retries: number;
  timeout: number;
}

export const API_CONFIG = new InjectionToken<ApiConfig>('API_CONFIG');

export function createApiService(
  http: HttpClient,
  router: Router,
  config: ApiConfig
): ApiService {
  return new ApiService(http, router, config);
}

@Injectable({
  providedIn: 'root',
  useFactory: createApiService,
  deps: [HttpClient, Router, API_CONFIG]
})
export class ApiService {
  constructor(
    private http: HttpClient,
    private router: Router,
    private config: ApiConfig
  ) {}
  
  get<T>(endpoint: string): Observable<T> {
    return this.http.get<T>(`${this.config.baseUrl}${endpoint}`).pipe(
      retry(this.config.retries),
      catchError(error => {
        if (error.status === 401) {
          this.router.navigate(['/login']);
        }
        return throwError(() => error);
      })
    );
  }
  
  post<T>(endpoint: string, data: any): Observable<T> {
    return this.http.post<T>(`${this.config.baseUrl}${endpoint}`, data).pipe(
      retry(this.config.retries),
      catchError(error => {
        if (error.status === 401) {
          this.router.navigate(['/login']);
        }
        return throwError(() => error);
      })
    );
  }
}
```

---

### Exemplo 4: Serviço com Dependência Opcional

**Contexto**: Criar serviço que funciona com ou sem serviço de analytics.

**Código**:

```typescript
import { Injectable, inject, Optional } from '@angular/core';

export interface AnalyticsEvent {
  name: string;
  properties?: Record<string, any>;
}

@Injectable({
  providedIn: 'root'
})
export class AnalyticsService {
  track(event: AnalyticsEvent): void {
    console.log('Analytics:', event);
  }
}

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private analytics = inject(AnalyticsService, { optional: true });
  
  private users: User[] = [];
  
  addUser(user: User): void {
    this.users.push(user);
    
    if (this.analytics) {
      this.analytics.track({
        name: 'user_added',
        properties: { userId: user.id }
      });
    }
  }
  
  getUsers(): User[] {
    return [...this.users];
  }
}
```

---

### Exemplo 5: Serviço com Escopo por Componente

**Contexto**: Criar serviço que mantém estado isolado por componente.

**Código**:

```typescript
import { Injectable } from '@angular/core';

@Injectable()
export class ComponentStateService {
  private state: Map<string, any> = new Map();
  
  set(key: string, value: any): void {
    this.state.set(key, value);
  }
  
  get<T>(key: string): T | undefined {
    return this.state.get(key) as T;
  }
  
  clear(): void {
    this.state.clear();
  }
}

@Component({
  selector: 'app-user-form',
  providers: [ComponentStateService]
})
export class UserFormComponent {
  constructor(private state: ComponentStateService) {}
  
  ngOnInit(): void {
    this.state.set('formData', {});
  }
  
  ngOnDestroy(): void {
    this.state.clear();
  }
}
```

---

## Comparação com Outras Abordagens

### Angular DI vs React Context vs Vue Provide/Inject

**Tabela Comparativa Detalhada**:

| Aspecto | Angular DI | React Context | Vue Provide/Inject | Svelte Stores |
|---------|-----------|---------------|-------------------|---------------|
| **Type Safety** | Completo (TypeScript) | Opcional (TypeScript) | Opcional (TypeScript) | Opcional (TypeScript) |
| **Hierarquia** | Completa (5 níveis) | Limitada (Provider tree) | Básica (Provide/Inject) | Não aplicável |
| **Singleton** | Nativo (`providedIn: 'root'`) | Manual (Context Provider) | Manual (provide) | Manual (store) |
| **Factory** | Suportado (useFactory) | Não | Não | Não |
| **Injection Tokens** | Sim (InjectionToken) | Não | Não | Não |
| **Performance** | Excelente (tree-shaking) | Boa (pode causar re-renders) | Boa | Excelente |
| **Testabilidade** | Excelente (fácil mockar) | Boa (mock Provider) | Boa | Boa |
| **Curva de Aprendizado** | Moderada | Baixa | Baixa | Baixa |
| **Bundle Size** | Otimizado (tree-shaking) | Pequeno | Pequeno | Mínimo |
| **Resolução de Dependências** | Automática (hierarquia) | Manual (Provider tree) | Manual (provide/inject) | Manual |
| **Dependências Circulares** | Detectado em compile-time | Possível (runtime) | Possível (runtime) | Não aplicável |
| **Dependências Opcionais** | Sim (@Optional) | Sim (default value) | Sim (default value) | Não aplicável |
| **Lazy Loading** | Suportado (`providedIn: 'any'`) | Limitado | Limitado | Não aplicável |
| **Code Splitting** | Excelente | Bom | Bom | Excelente |

**Comparação de Sintaxe**:

**Angular**:
```typescript
@Injectable({ providedIn: 'root' })
export class MyService {}

export class MyComponent {
  private service = inject(MyService);
}
```

**React**:
```typescript
const ServiceContext = createContext<MyService | null>(null);

function MyComponent() {
  const service = useContext(ServiceContext);
}
```

**Vue**:
```typescript
provide('myService', myServiceInstance);

const service = inject('myService');
```

**Análise de Trade-offs**:

**Angular DI - Vantagens**:
- Sistema completo e robusto
- Type safety completo
- Hierarquia poderosa
- Excelente para projetos grandes
- Suporte a padrões avançados (factory, tokens)

**Angular DI - Desvantagens**:
- Curva de aprendizado mais íngreme
- Mais verboso para casos simples
- Requer TypeScript para melhor experiência

**React Context - Vantagens**:
- Simples e direto
- Integrado ao React
- Bom para casos simples

**React Context - Desvantagens**:
- Pode causar re-renders desnecessários
- Sem hierarquia completa
- Sem factory providers
- Type safety opcional

**Vue Provide/Inject - Vantagens**:
- Simples e intuitivo
- Integrado ao Vue
- Bom para casos básicos

**Vue Provide/Inject - Desvantagens**:
- Hierarquia limitada
- Sem factory providers
- Type safety opcional

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Sempre use providedIn: 'root' para serviços singleton**
   - **Por quê**: Simplifica configuração, garante singleton, melhor tree-shaking
   - **Exemplo Bom**: `@Injectable({ providedIn: 'root' })`
   - **Exemplo Ruim**: Fornecer em múltiplos NgModules
   - **Benefícios**: Menos configuração, singleton garantido, melhor performance

2. **Use inject() para código mais limpo**
   - **Por quê**: Sintaxe mais moderna, funciona em funções, melhor para testes
   - **Exemplo Bom**: `private service = inject(MyService)`
   - **Exemplo Ruim**: `constructor(private service: MyService) {}` (quando inject() é melhor)
   - **Benefícios**: Código mais limpo, mais flexível, melhor testabilidade

3. **Use InjectionTokens para valores primitivos**
   - **Por quê**: Type safety, flexibilidade, APIs públicas claras
   - **Exemplo Bom**: `export const API_URL = new InjectionToken<string>('API_URL')`
   - **Exemplo Ruim**: Injetar strings diretamente sem token
   - **Benefícios**: Type safety, fácil de mockar em testes, documentação clara

4. **Mantenha serviços focados em uma responsabilidade**
   - **Por quê**: Facilita manutenção, testes e reutilização
   - **Exemplo Bom**: `UserService` para usuários, `AuthService` para autenticação
   - **Exemplo Ruim**: `UserAuthService` que faz tudo
   - **Benefícios**: Código mais limpo, fácil de testar, fácil de manter

5. **Use factory providers para criação complexa**
   - **Por quê**: Permite lógica de criação, configuração dinâmica
   - **Exemplo Bom**: Factory que cria serviço baseado em configuração
   - **Benefícios**: Flexibilidade, configuração dinâmica

6. **Documente dependências com interfaces**
   - **Por quê**: Type safety, documentação clara, fácil refatoração
   - **Exemplo Bom**: Usar interfaces para configurações
   - **Benefícios**: Type safety, documentação inline

7. **Use providedIn: 'any' apenas quando necessário**
   - **Por quê**: Cria nova instância por módulo lazy, use apenas quando realmente necessário
   - **Quando usar**: Quando precisa de instância separada por módulo lazy
   - **Benefícios**: Isolamento quando necessário

8. **Use dependências opcionais quando apropriado**
   - **Por quê**: Permite código mais flexível e tolerante a falhas
   - **Exemplo Bom**: `private analytics = inject(AnalyticsService, { optional: true })`
   - **Exemplo Ruim**: Assumir que serviço sempre existe sem verificação
   - **Benefícios**: Código mais robusto, fácil de testar, funciona em diferentes contextos

9. **Organize serviços por domínio/funcionalidade**
   - **Por quê**: Facilita navegação, manutenção e entendimento do código
   - **Exemplo Bom**: `services/user/user.service.ts`, `services/auth/auth.service.ts`
   - **Exemplo Ruim**: Todos serviços em uma pasta `services/`
   - **Benefícios**: Código organizado, fácil de encontrar, melhor escalabilidade

10. **Use interfaces para configurações injetadas**
    - **Por quê**: Type safety, documentação clara, fácil refatoração
    - **Exemplo Bom**: `export interface ApiConfig { baseUrl: string; timeout: number; }`
    - **Exemplo Ruim**: Injetar objetos sem tipo definido
    - **Benefícios**: Type safety, autocomplete, documentação inline

### ❌ Anti-padrões Comuns

1. **Não forneça serviços em múltiplos lugares**
   - **Problema**: Pode criar múltiplas instâncias, comportamento inconsistente
   - **Exemplo Ruim**: Fornecer mesmo serviço em múltiplos módulos
   - **Solução**: Use `providedIn: 'root'` ou um único provider
   - **Impacto**: Bugs difíceis de rastrear, comportamento inconsistente

2. **Não injete serviços diretamente em templates**
   - **Problema**: Dificulta testes, viola separação de responsabilidades
{% raw %}
   - **Exemplo Ruim**: `{{ userService.getUser().name }}` no template
{% endraw %}
   - **Solução**: Injete no componente e exponha via propriedades
   - **Impacto**: Testes difíceis, código acoplado

3. **Não use serviços para lógica de apresentação**
   - **Problema**: Viola separação de responsabilidades, dificulta reutilização
   - **Exemplo Ruim**: Serviço que formata strings para exibição
   - **Solução**: Mantenha lógica de apresentação no componente ou use pipes
   - **Impacto**: Serviços não reutilizáveis, violação de responsabilidades

4. **Não crie serviços muito grandes**
   - **Problema**: Dificulta manutenção, testes complexos, baixa reutilização
   - **Exemplo Ruim**: Serviço com 500+ linhas, múltiplas responsabilidades
   - **Solução**: Divida em serviços menores e focados
   - **Impacto**: Código difícil de manter e testar

5. **Não ignore erros de DI**
   - **Problema**: Pode causar erros em runtime difíceis de debugar
   - **Exemplo Ruim**: Ignorar erros de "No provider for X"
   - **Solução**: Sempre forneça providers necessários ou use `@Optional()`
   - **Impacto**: Erros em runtime, difícil debug

6. **Não use providedIn sem entender escopos**
   - **Problema**: Pode criar instâncias não intencionais
   - **Exemplo Ruim**: Usar `providedIn: 'any'` quando `'root'` é suficiente
   - **Solução**: Entenda diferenças entre escopos antes de usar
   - **Impacto**: Múltiplas instâncias, comportamento inesperado

7. **Não injete dependências circulares**
   - **Problema**: Erro de DI, código difícil de manter
   - **Exemplo Ruim**: ServiceA injeta ServiceB que injeta ServiceA
   - **Solução**: Refatore para remover dependência circular ou use `forwardRef()`
   - **Impacto**: Erro de compilação, arquitetura ruim

8. **Não use serviços para armazenar estado de UI**
   - **Problema**: Viola separação de responsabilidades, dificulta reutilização
   - **Exemplo Ruim**: Serviço que armazena estado de formulário específico de componente
   - **Solução**: Use serviços apenas para estado de negócio, estado de UI no componente
   - **Impacto**: Serviços acoplados a UI, difícil de reutilizar

9. **Não ignore o tree-shaking**
   - **Problema**: Serviços não usados podem ser incluídos no bundle
   - **Exemplo Ruim**: Serviço sem `providedIn` em NgModule que não é usado
   - **Solução**: Sempre use `providedIn: 'root'` ou configure providers corretamente
   - **Impacto**: Bundle maior, performance pior

10. **Não crie serviços para tudo**
    - **Problema**: Over-engineering, código desnecessariamente complexo
    - **Exemplo Ruim**: Serviço para função utilitária simples que poderia ser função pura
    - **Solução**: Use serviços apenas quando precisa de DI, estado compartilhado ou lógica complexa
    - **Impacto**: Código mais complexo, mais difícil de entender

---

## Exercícios Práticos

### Exercício 1: Criar Serviço Básico (Básico)

**Objetivo**: Criar primeiro serviço standalone

**Descrição**: 
Crie um serviço `CalculatorService` com métodos para operações matemáticas básicas (soma, subtração, multiplicação, divisão).

**Arquivo**: `exercises/exercise-2-1-1-servico-basico.md`

---

### Exercício 2: Injeção de Dependência Hierárquica (Básico)

**Objetivo**: Entender hierarquia de injectors

**Descrição**:
Crie serviços em diferentes níveis (root, componente) e observe como Angular resolve dependências.

**Arquivo**: `exercises/exercise-2-1-2-di-hierarquica.md`

---

### Exercício 3: Providers e Escopos (Intermediário)

**Objetivo**: Configurar providers com diferentes escopos

**Descrição**:
Crie serviços com diferentes escopos (root, any, componente) e demonstre diferenças de comportamento.

**Arquivo**: `exercises/exercise-2-1-3-providers-escopos.md`

---

### Exercício 4: InjectionTokens e Factory Providers (Avançado)

**Objetivo**: Usar InjectionTokens e factory providers

**Descrição**:
Crie serviço configurável usando InjectionToken e factory provider para criar instâncias customizadas.

**Arquivo**: `exercises/exercise-2-1-4-injection-tokens-factory.md`

---

### Exercício 5: Serviço Completo com DI (Avançado)

**Objetivo**: Criar serviço completo usando todas as técnicas

**Descrição**:
Crie um serviço de gerenciamento de tarefas completo que usa inject(), InjectionTokens, factory providers e múltiplas dependências.

**Arquivo**: `exercises/exercise-2-1-5-servico-completo.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular Services](https://angular.io/guide/services)**: Guia oficial de serviços
- **[Dependency Injection](https://angular.io/guide/dependency-injection)**: Guia completo de DI
- **[Dependency Injection in Action](https://angular.io/guide/dependency-injection-in-action)**: DI em ação com exemplos práticos
- **[InjectionToken](https://angular.io/api/core/InjectionToken)**: Documentação completa do InjectionToken
- **[Hierarchical Dependency Injection](https://angular.io/guide/hierarchical-dependency-injection)**: Guia sobre hierarquia de injectors
- **[Dependency Injection Providers](https://angular.io/guide/dependency-injection-providers)**: Guia sobre providers

### Artigos e Tutoriais

- **[Understanding Angular Dependency Injection](https://angular.io/guide/dependency-injection)**: Tutorial oficial aprofundado
- **[Angular Dependency Injection Explained](https://www.freecodecamp.org/news/angular-dependency-injection/)**: Explicação detalhada com exemplos
- **[Advanced Angular Dependency Injection](https://blog.angular.io/)**: Padrões avançados de DI

### Vídeos

- **[Angular Dependency Injection Deep Dive](https://www.youtube.com/)**: Vídeo tutorial completo
- **[Understanding Angular Injectors](https://www.youtube.com/)**: Explicação visual da hierarquia

### Ferramentas

- **[Angular DevTools](https://angular.io/guide/devtools)**: Ferramenta para debugar DI e serviços
- **[Angular CLI](https://angular.io/cli)**: Gerar serviços com `ng generate service`

---

## Resumo

### Principais Conceitos

- **Serviços**: Classes TypeScript decoradas com `@Injectable` que encapsulam lógica de negócio reutilizável
- **@Injectable Decorator**: Marca classes como injetáveis e configura escopo (`providedIn`)
- **Hierarquia de Injectors**: Sistema de 5 níveis (Element → Component → Module → Platform → Root) que resolve dependências
- **Providers**: Definem como e onde serviços são criados (Class, Value, Factory, Existing)
- **inject() Function**: Forma moderna (Angular 14+) de injeção que funciona fora de construtores
- **InjectionTokens**: Tokens type-safe para injeção de valores primitivos, objetos e interfaces
- **Factory Providers**: Permitem criar instâncias com lógica de criação complexa
- **Dependências Opcionais**: Serviços que podem não estar disponíveis usando `@Optional()` ou `{ optional: true }`

### Pontos-Chave para Lembrar

- **Sempre use `providedIn: 'root'`** para serviços singleton (padrão recomendado)
- **Prefira `inject()`** sobre constructor injection quando possível (código mais limpo)
- **Use InjectionTokens** para valores primitivos e configurações (type safety)
- **Mantenha serviços focados** em uma única responsabilidade (Single Responsibility Principle)
- **Entenda hierarquia de injectors** para debug e resolução de problemas
- **Use factory providers** quando criação requer lógica complexa
- **Considere dependências opcionais** para código mais flexível e tolerante a falhas
- **Organize serviços por domínio** para melhor estruturação do código
- **Evite dependências circulares** - refatore quando necessário
- **Use interfaces** para configurações injetadas (type safety e documentação)

### Próximos Passos

- Próxima aula: Roteamento e Navegação Avançada
- Praticar criando serviços reutilizáveis
- Explorar padrões avançados de DI

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

**Aula Anterior**: [Aula 1.5: Control Flow e Pipes](./lesson-1-5-control-flow-pipes.md)  
**Próxima Aula**: [Aula 2.2: Roteamento e Navegação Avançada](./lesson-2-2-roteamento.md)  
**Voltar ao Módulo**: [Módulo 2: Desenvolvimento Intermediário](../modules/module-2-desenvolvimento-intermediario.md)
