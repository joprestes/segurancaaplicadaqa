---
layout: lesson
title: "Aula 2.4: HTTP Client e Interceptors"
slug: http-client
module: module-2
lesson_id: lesson-2-4
duration: "90 minutos"
level: "Intermediário"
prerequisites: 
  - "lesson-2-3"
exercises:
  - 
  - "lesson-2-4-exercise-1"
  - "lesson-2-4-exercise-2"
  - "lesson-2-4-exercise-3"
  - "lesson-2-4-exercise-4"
  - "lesson-2-4-exercise-5"
podcast:
  file: "assets/podcasts/02.4-HttpClient_e_Interceptors_no_Angular.m4a"
  title: "HttpClient e Interceptors no Angular"
  description: "Aprenda a consumir APIs REST de forma profissional com HttpClient."
  duration: "50-65 minutos"
---

## Introdução

Nesta aula, você dominará o HttpClient do Angular e Interceptors. HttpClient é a forma moderna e poderosa de fazer requisições HTTP no Angular, usando Observables do RxJS. Interceptors permitem interceptar e modificar requisições/respostas globalmente.

### O que você vai aprender

- Configurar HttpClient
- Fazer requisições GET, POST, PUT, DELETE
- Trabalhar com headers e configuração
- Tratar erros adequadamente
- Criar HTTP Interceptors
- Implementar interceptors de autenticação
- Adicionar retry logic e timeout

### Por que isso é importante

Comunicação HTTP é essencial em qualquer aplicação moderna. HttpClient oferece integração perfeita com RxJS e Angular. Interceptors são fundamentais para autenticação, logging, tratamento de erros e outras funcionalidades transversais.

---

## Conceitos Teóricos

### HttpClient

**Definição**: `HttpClient` é o serviço do Angular para fazer requisições HTTP usando Observables do RxJS.

**Explicação Detalhada**:

HttpClient oferece:
- Métodos para GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- Suporte a Observables
- Type safety com generics
- Interceptors
- Progress events
- JSON parsing automático

**Analogia**:

HttpClient é como um carteiro profissional. Você pede para entregar uma mensagem (requisição), ele vai até o destinatário (servidor), traz a resposta e você pode acompanhar o processo (Observable).

**Visualização**:

```
Component/Service
      │
      ├─ HttpClient.get() ────→ HTTP Request ────→ Server
      │                                                    │
      │                                                    │
      └── Observable<Response> ←─── HTTP Response ←──────┘
```

**Exemplo Prático**:

```typescript
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  constructor(private http: HttpClient) {}
  
  getUsers(): Observable<User[]> {
    return this.http.get<User[]>('/api/users');
  }
  
  getUser(id: number): Observable<User> {
    return this.http.get<User>(`/api/users/${id}`);
  }
  
  createUser(user: User): Observable<User> {
    return this.http.post<User>('/api/users', user);
  }
  
  updateUser(id: number, user: User): Observable<User> {
    return this.http.put<User>(`/api/users/${id}`, user);
  }
  
  deleteUser(id: number): Observable<void> {
    return this.http.delete<void>(`/api/users/${id}`);
  }
}
```

---

### Configuração do HttpClient

**Definição**: HttpClient precisa ser configurado no bootstrap da aplicação usando `provideHttpClient()`.

**Explicação Detalhada**:

Em aplicações standalone, use `provideHttpClient()` com opções:
- `withInterceptors()`: Adiciona interceptors
- `withInterceptorsFromDi()`: Usa interceptors do DI
- `withFetch()`: Usa Fetch API ao invés de XMLHttpRequest
- `withJsonpSupport()`: Suporte a JSONP

**Analogia**:

Configurar HttpClient é como contratar um serviço de entrega. Você precisa contratar (provideHttpClient) antes de usar.

**Exemplo Prático**:

```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app.component';

bootstrapApplication(AppComponent, {
  providers: [
    provideHttpClient()
  ]
});
```

---

### Requisições HTTP

**Definição**: Métodos do HttpClient para diferentes tipos de requisições HTTP.

**Explicação Detalhada**:

Métodos disponíveis:
- `get<T>(url, options)`: Requisição GET
- `post<T>(url, body, options)`: Requisição POST
- `put<T>(url, body, options)`: Requisição PUT
- `delete<T>(url, options)`: Requisição DELETE
- `patch<T>(url, body, options)`: Requisição PATCH
- `head<T>(url, options)`: Requisição HEAD
- `options<T>(url, options)`: Requisição OPTIONS

Todos retornam `Observable<T>`.

**Analogia**:

Cada método HTTP é como um tipo diferente de pedido. GET é "me dê isso", POST é "crie isso", PUT é "atualize isso", DELETE é "remova isso".

**Exemplo Prático**:

```typescript
export class ApiService {
  constructor(private http: HttpClient) {}
  
  getData(): Observable<Data> {
    return this.http.get<Data>('/api/data');
  }
  
  postData(data: Data): Observable<Data> {
    return this.http.post<Data>('/api/data', data);
  }
  
  putData(id: number, data: Data): Observable<Data> {
    return this.http.put<Data>(`/api/data/${id}`, data);
  }
  
  deleteData(id: number): Observable<void> {
    return this.http.delete<void>(`/api/data/${id}`);
  }
}
```

---

### Headers e Configuração

**Definição**: Opções de configuração para requisições HTTP, incluindo headers, params, observe, responseType.

**Explicação Detalhada**:

Opções principais:
- `headers`: HttpHeaders customizados
- `params`: Query parameters
- `observe`: 'body' | 'response' | 'events'
- `responseType`: 'json' | 'text' | 'blob' | 'arraybuffer'
- `reportProgress`: boolean para progress events
- `withCredentials`: boolean para CORS

**Analogia**:

Headers são como informações extras no envelope. Você pode adicionar instruções especiais (headers) antes de enviar.

**Exemplo Prático**:

```typescript
import { HttpHeaders, HttpParams } from '@angular/common/http';

export class ApiService {
  constructor(private http: HttpClient) {}
  
  getDataWithHeaders(): Observable<Data> {
    const headers = new HttpHeaders()
      .set('Authorization', 'Bearer token')
      .set('Content-Type', 'application/json');
    
    const params = new HttpParams()
      .set('page', '1')
      .set('limit', '10');
    
    return this.http.get<Data>('/api/data', {
      headers,
      params
    });
  }
  
  postWithOptions(data: Data): Observable<Data> {
    return this.http.post<Data>('/api/data', data, {
      headers: new HttpHeaders({ 'Custom-Header': 'value' }),
      observe: 'response',
      reportProgress: true
    });
  }
}
```

---

### Tratamento de Erros

**Definição**: Tratamento adequado de erros HTTP usando operadores RxJS como `catchError`, `retry`, `throwError`.

**Explicação Detalhada**:

Estratégias de tratamento:
- `catchError`: Captura e trata erros
- `retry`: Tenta novamente em caso de erro
- `throwError`: Lança novo erro
- `of`: Retorna valor padrão

**Analogia**:

Tratamento de erros é como ter um plano B. Se algo der errado (erro), você tem uma estratégia para lidar (catchError, retry).

**Exemplo Prático**:

```typescript
import { catchError, retry, throwError } from 'rxjs';
import { HttpErrorResponse } from '@angular/common/http';

export class ApiService {
  constructor(private http: HttpClient) {}
  
  getData(): Observable<Data> {
    return this.http.get<Data>('/api/data').pipe(
      retry(3),
      catchError(this.handleError)
    );
  }
  
  private handleError(error: HttpErrorResponse): Observable<never> {
    if (error.error instanceof ErrorEvent) {
      console.error('Erro do cliente:', error.error.message);
    } else {
      console.error(`Erro do servidor: ${error.status}, ${error.message}`);
    }
    
    return throwError(() => new Error('Algo deu errado. Tente novamente.'));
  }
}
```

---

### HTTP Interceptors

**Definição**: Interceptors permitem interceptar e modificar requisições HTTP e respostas antes que cheguem ao destino.

**Explicação Detalhada**:

Interceptors podem:
- Modificar requisições (adicionar headers, tokens)
- Modificar respostas (transformar dados)
- Tratar erros globalmente
- Adicionar logging
- Implementar retry logic

**Analogia**:

Interceptors são como filtros de segurança em um prédio. Toda requisição passa por eles antes de chegar ao servidor, e toda resposta passa por eles antes de chegar ao componente.

**Visualização**:

```
Request Flow:
Component → Interceptor → HttpClient → Server

Response Flow:
Server → HttpClient → Interceptor → Component
```

**Exemplo Prático**:

```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';

export const loggingInterceptor: HttpInterceptorFn = (req, next) => {
  console.log('Request:', req.method, req.url);
  
  return next(req).pipe(
    tap(response => {
      console.log('Response:', response);
    })
  );
};
```

---

### Auth Interceptor

**Definição**: Interceptor específico para adicionar tokens de autenticação em todas as requisições.

**Explicação Detalhada**:

Auth interceptors:
- Adicionam token de autenticação
- Renovam tokens expirados
- Redirecionam em caso de não autenticado
- Gerenciam refresh tokens

**Analogia**:

Auth interceptor é como um porteiro que adiciona um crachá (token) em todas as suas requisições antes de deixá-las passar.

**Exemplo Prático**:

```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const token = authService.getToken();
  
  if (token) {
    const cloned = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
    return next(cloned);
  }
  
  return next(req);
};
```

---

### Retry Logic e Timeout

**Definição**: Implementação de retry automático e timeout para requisições HTTP.

**Explicação Detalhada**:

Retry e timeout:
- `retry(n)`: Tenta novamente n vezes
- `retryWhen()`: Retry com condições customizadas
- `timeout()`: Timeout após tempo específico
- `timeoutWith()`: Timeout com fallback

**Analogia**:

Retry é como tentar ligar novamente quando a linha está ocupada. Timeout é como desistir após esperar muito tempo.

**Exemplo Prático**:

```typescript
import { retry, timeout, catchError, throwError } from 'rxjs';
import { HttpErrorResponse } from '@angular/common/http';

export class ApiService {
  constructor(private http: HttpClient) {}
  
  getData(): Observable<Data> {
    return this.http.get<Data>('/api/data').pipe(
      timeout(5000),
      retry({
        count: 3,
        delay: 1000
      }),
      catchError(this.handleError)
    );
  }
  
  private handleError(error: HttpErrorResponse): Observable<never> {
    if (error.status === 0) {
      return throwError(() => new Error('Erro de conexão'));
    }
    return throwError(() => error);
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Serviço HTTP Completo

**Contexto**: Criar serviço completo para gerenciar usuários via API.

**Código**:

```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, retry } from 'rxjs/operators';
import { User } from './user.model';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private apiUrl = '/api/users';
  
  constructor(private http: HttpClient) {}
  
  getUsers(page: number = 1, limit: number = 10): Observable<User[]> {
    const params = new HttpParams()
      .set('page', page.toString())
      .set('limit', limit.toString());
    
    return this.http.get<User[]>(this.apiUrl, { params }).pipe(
      retry(2),
      catchError(this.handleError)
    );
  }
  
  getUser(id: number): Observable<User> {
    return this.http.get<User>(`${this.apiUrl}/${id}`).pipe(
      catchError(this.handleError)
    );
  }
  
  createUser(user: User): Observable<User> {
    const headers = new HttpHeaders({ 'Content-Type': 'application/json' });
    return this.http.post<User>(this.apiUrl, user, { headers }).pipe(
      catchError(this.handleError)
    );
  }
  
  updateUser(id: number, user: Partial<User>): Observable<User> {
    return this.http.put<User>(`${this.apiUrl}/${id}`, user).pipe(
      catchError(this.handleError)
    );
  }
  
  deleteUser(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`).pipe(
      catchError(this.handleError)
    );
  }
  
  private handleError(error: any): Observable<never> {
    console.error('Erro HTTP:', error);
    return throwError(() => error);
  }
}
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Sempre trate erros HTTP**
   - **Por quê**: Previne crashes e melhora UX
   - **Exemplo**: Use `catchError` em todas as requisições

2. **Use interceptors para funcionalidades transversais**
   - **Por quê**: Evita código duplicado
   - **Exemplo**: Auth, logging, error handling

3. **Use type safety com generics**
   - **Por quê**: Previne erros e melhora autocomplete
   - **Exemplo**: `http.get<User[]>('/api/users')`

4. **Configure timeout para requisições longas**
   - **Por quê**: Evita espera infinita
   - **Exemplo**: `timeout(5000)`

### ❌ Anti-padrões Comuns

1. **Não ignore erros HTTP**
   - **Problema**: Aplicação pode travar
   - **Solução**: Sempre use `catchError`

2. **Não faça requisições no construtor**
   - **Problema**: Pode causar problemas de inicialização
   - **Solução**: Faça em métodos ou lifecycle hooks

3. **Não esqueça de unsubscribe**
   - **Problema**: Memory leaks
   - **Solução**: Use `async` pipe ou `takeUntil`

---

## Exercícios Práticos

### Exercício 1: Requisições HTTP Básicas (Básico)

**Objetivo**: Criar primeiro serviço HTTP

**Descrição**: 
Crie serviço que faz requisições GET, POST, PUT, DELETE para API de produtos.

**Arquivo**: `exercises/exercise-2-4-1-requisicoes-basicas.md`

---

### Exercício 2: Tratamento de Erros (Intermediário)

**Objetivo**: Implementar tratamento robusto de erros

**Descrição**:
Crie serviço com tratamento completo de erros HTTP, incluindo diferentes tipos de erro.

**Arquivo**: `exercises/exercise-2-4-2-tratamento-erros.md`

---

### Exercício 3: HTTP Interceptors Básicos (Intermediário)

**Objetivo**: Criar primeiro interceptor

**Descrição**:
Crie interceptor de logging que registra todas as requisições e respostas.

**Arquivo**: `exercises/exercise-2-4-3-interceptors-basicos.md`

---

### Exercício 4: Auth Interceptor (Avançado)

**Objetivo**: Implementar interceptor de autenticação

**Descrição**:
Crie interceptor que adiciona token de autenticação em todas as requisições e trata erros 401.

**Arquivo**: `exercises/exercise-2-4-4-auth-interceptor.md`

---

### Exercício 5: Interceptor Completo com Retry (Avançado)

**Objetivo**: Criar interceptor completo com retry logic

**Descrição**:
Crie interceptor que implementa retry logic, timeout e tratamento de erros global.

**Arquivo**: `exercises/exercise-2-4-5-interceptor-completo.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular HTTP Client](https://angular.io/guide/http)**: Guia oficial
- **[HttpClient](https://angular.io/api/common/http/HttpClient)**: Documentação HttpClient
- **[HTTP Interceptors](https://angular.io/guide/http-intercept-requests-and-responses)**: Guia interceptors

---

## Resumo

### Principais Conceitos

- HttpClient é o serviço para requisições HTTP
- Requisições retornam Observables
- Headers e configuração permitem customização
- Tratamento de erros é essencial
- Interceptors permitem funcionalidades transversais
- Auth interceptors gerenciam autenticação
- Retry e timeout melhoram confiabilidade

### Pontos-Chave para Lembrar

- Sempre trate erros HTTP
- Use interceptors para código reutilizável
- Use type safety com generics
- Configure timeout para requisições
- Use retry para melhorar confiabilidade

### Próximos Passos

- Próxima aula: Comunicação entre Componentes
- Praticar criando serviços HTTP completos
- Explorar interceptors avançados

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

**Aula Anterior**: [Aula 2.3: Formulários Reativos e Validação](./lesson-2-3-formularios-reativos.md)  
**Próxima Aula**: [Aula 2.5: Comunicação entre Componentes](./lesson-2-5-comunicacao-componentes.md)  
**Voltar ao Módulo**: [Módulo 2: Desenvolvimento Intermediário](../modules/module-2-desenvolvimento-intermediario.md)

