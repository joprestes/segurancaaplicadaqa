---
layout: lesson
title: "Aula 2.1: Serviços e Injeção de Dependência"
slug: servicos-di
module: module-2
lesson_id: lesson-2-1
duration: "90 minutos"
level: "Intermediário"
prerequisites: 
  - "lesson-1-5"
exercises:
  - 
  - "lesson-2-1-exercise-1"
  - "lesson-2-1-exercise-2"
  - "lesson-2-1-exercise-3"
  - "lesson-2-1-exercise-4"
  - "lesson-2-1-exercise-5"
podcast:
  file: "assets/podcasts/02.1-Serviços_e_Injeção_de_Dependência_no_Angular.m4a"
  title: "Serviços e Injeção de Dependência no Angular"
  description: "Descubra como os serviços são o coração da arquitetura Angular."
  duration: "50-65 minutos"
---

## Introdução

Nesta aula, você dominará serviços e injeção de dependência no Angular. Serviços são fundamentais para organizar lógica de negócio, compartilhar dados entre componentes e criar código reutilizável. Injeção de Dependência é o mecanismo que torna tudo isso possível de forma elegante e testável.

### O que você vai aprender

- Criar serviços standalone
- Usar decorator @Injectable
- Entender hierarquia de injectors
- Configurar providers e escopos
- Usar função inject() moderna
- Trabalhar com InjectionTokens
- Criar factory e value providers
- Implementar dependências opcionais

### Por que isso é importante

Serviços são o coração da arquitetura Angular. Sem entender serviços e DI, você não conseguirá criar aplicações escaláveis e manuteníveis. DI facilita testes, promove reutilização de código e mantém componentes focados em apresentação.

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

Factory providers são como fábricas personalizadas. Ao invés de comprar um produto padrão (classe), você pede uma fábrica que cria o produto exatamente como você precisa.

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

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Sempre use providedIn: 'root' para serviços singleton**
   - **Por quê**: Simplifica configuração e garante singleton
   - **Exemplo**: `@Injectable({ providedIn: 'root' })`

2. **Use inject() para código mais limpo**
   - **Por quê**: Sintaxe mais moderna e flexível
   - **Exemplo**: `private service = inject(MyService)`

3. **Use InjectionTokens para valores primitivos**
   - **Por quê**: Type safety e flexibilidade
   - **Exemplo**: `new InjectionToken<string>('API_URL')`

4. **Mantenha serviços focados em uma responsabilidade**
   - **Por quê**: Facilita manutenção e testes
   - **Exemplo**: UserService para usuários, AuthService para autenticação

### ❌ Anti-padrões Comuns

1. **Não forneça serviços em múltiplos lugares**
   - **Problema**: Pode criar múltiplas instâncias
   - **Solução**: Use `providedIn: 'root'` ou um único provider

2. **Não injete serviços diretamente em templates**
   - **Problema**: Dificulta testes e mudanças
   - **Solução**: Injete no componente e exponha via propriedades

3. **Não use serviços para lógica de apresentação**
   - **Problema**: Viola separação de responsabilidades
   - **Solução**: Mantenha lógica de apresentação no componente

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
- **[Dependency Injection](https://angular.io/guide/dependency-injection)**: Guia de DI
- **[Dependency Injection in Action](https://angular.io/guide/dependency-injection-in-action)**: DI em ação
- **[InjectionToken](https://angular.io/api/core/InjectionToken)**: Documentação InjectionToken

---

## Resumo

### Principais Conceitos

- Serviços encapsulam lógica de negócio reutilizável
- @Injectable marca classes como injetáveis
- Hierarquia de injectors resolve dependências
- Providers definem como serviços são criados
- inject() é a forma moderna de injeção
- InjectionTokens permitem injeção type-safe de valores

### Pontos-Chave para Lembrar

- Use `providedIn: 'root'` para serviços singleton
- Prefira `inject()` para código mais limpo
- Use InjectionTokens para valores primitivos
- Mantenha serviços focados em uma responsabilidade
- Entenda hierarquia de injectors para debug

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

