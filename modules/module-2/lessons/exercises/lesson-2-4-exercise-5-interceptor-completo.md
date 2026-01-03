---
layout: exercise
title: "Exercício 2.4.5: Interceptor Completo com Retry"
slug: "interceptor-completo"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **interceptor completo** através da **implementação de interceptor com retry logic, timeout e tratamento de erros global**.

Ao completar este exercício, você será capaz de:

- Criar interceptor completo e robusto
- Implementar retry logic
- Adicionar timeout
- Tratar erros globalmente
- Combinar múltiplos interceptors

---

## Descrição

Você precisa criar um interceptor completo que implementa retry logic, timeout, tratamento de erros e logging.

### Contexto

Uma aplicação precisa de interceptor robusto que melhora confiabilidade e experiência do usuário.

### Tarefa

Crie:

1. **Retry Interceptor**: Implementa retry logic
2. **Timeout**: Adiciona timeout às requisições
3. **Error Handling**: Tratamento global de erros
4. **Logging**: Logging de requisições/respostas
5. **Combinação**: Combine múltiplos interceptors

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Retry logic implementado
- [ ] Timeout configurado
- [ ] Tratamento global de erros
- [ ] Logging implementado
- [ ] Múltiplos interceptors combinados
- [ ] Interceptor funciona corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Interceptor está completo
- [ ] Código é bem organizado

---

## Solução Esperada

### Abordagem Recomendada

**retry.interceptor.ts**
```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { retry, delay, retryWhen, take, concatMap, throwError } from 'rxjs';

export const retryInterceptor: HttpInterceptorFn = (req, next) => {
  const maxRetries = 3;
  const retryDelay = 1000;
  
  return next(req).pipe(
    retryWhen(errors =>
      errors.pipe(
        concatMap((error, index) => {
          if (index < maxRetries && (error.status === 0 || error.status >= 500)) {
            return delay(retryDelay * (index + 1));
          }
          return throwError(() => error);
        }),
        take(maxRetries + 1)
      )
    )
  );
};
```

**timeout.interceptor.ts**
```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { timeout, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

export const timeoutInterceptor: HttpInterceptorFn = (req, next) => {
  const timeoutDuration = 10000;
  
  return next(req).pipe(
    timeout(timeoutDuration),
    catchError((error) => {
      if (error.name === 'TimeoutError') {
        return throwError(() => ({
          status: 408,
          message: 'Request timeout. Please try again.'
        }));
      }
      return throwError(() => error);
    })
  );
};
```

**error-handler.interceptor.ts**
```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { AuthService } from './auth.service';

export const errorHandlerInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const authService = inject(AuthService);
  
  return next(req).pipe(
    catchError((error) => {
      if (error.status === 401) {
        authService.removeToken();
        router.navigate(['/login']);
      } else if (error.status === 403) {
        router.navigate(['/forbidden']);
      } else if (error.status === 404) {
        router.navigate(['/not-found']);
      } else if (error.status >= 500) {
        router.navigate(['/server-error']);
      }
      
      return throwError(() => error);
    })
  );
};
```

**logging.interceptor.ts**
```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { tap } from 'rxjs/operators';

export const loggingInterceptor: HttpInterceptorFn = (req, next) => {
  const startTime = Date.now();
  
  console.log(`[HTTP] ${req.method} ${req.url}`);
  
  return next(req).pipe(
    tap({
      next: (response) => {
        const duration = Date.now() - startTime;
        console.log(`[HTTP] ${req.method} ${req.url} - ${response.status} (${duration}ms)`);
      },
      error: (error) => {
        const duration = Date.now() - startTime;
        console.error(`[HTTP] ${req.method} ${req.url} - ERROR (${duration}ms)`, error);
      }
    })
  );
};
```

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { AppComponent } from './app/app.component';
import { retryInterceptor } from './app/interceptors/retry.interceptor';
import { timeoutInterceptor } from './app/interceptors/timeout.interceptor';
import { errorHandlerInterceptor } from './app/interceptors/error-handler.interceptor';
import { loggingInterceptor } from './app/interceptors/logging.interceptor';

bootstrapApplication(AppComponent, {
  providers: [
    provideHttpClient(
      withInterceptors([
        loggingInterceptor,
        timeoutInterceptor,
        retryInterceptor,
        errorHandlerInterceptor
      ])
    )
  ]
});
```

**Explicação da Solução**:

1. retryInterceptor implementa retry com delay exponencial
2. timeoutInterceptor adiciona timeout de 10s
3. errorHandlerInterceptor trata erros globalmente
4. loggingInterceptor registra todas requisições
5. Interceptors combinados na ordem correta
6. Cada interceptor tem responsabilidade específica

---

## Testes

### Casos de Teste

**Teste 1**: Retry funciona
- **Input**: Requisição que falha temporariamente
- **Output Esperado**: Retry automático até 3 vezes

**Teste 2**: Timeout funciona
- **Input**: Requisição que demora mais que 10s
- **Output Esperado**: Timeout após 10s

**Teste 3**: Error handling funciona
- **Input**: Erro 401
- **Output Esperado**: Redireciona para login

---

## Extensões (Opcional)

1. **Configuração**: Torne retry e timeout configuráveis
2. **Metrics**: Adicione métricas de performance
3. **Caching**: Implemente cache de respostas

---

## Referências Úteis

- **[Advanced Interceptors](https://angular.io/guide/http-intercept-requests-and-responses)**: Guia interceptors avançados
- **[RxJS Operators](https://rxjs.dev/guide/operators)**: Documentação operadores RxJS

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

