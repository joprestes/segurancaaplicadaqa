---
layout: exercise
title: "Exercício 3.1.7: Tratamento de Erros"
slug: "tratamento-erros"
lesson_id: "lesson-3-1"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **tratamento robusto de erros** através da **implementação de padrões completos de tratamento de erros**.

Ao completar este exercício, você será capaz de:

- Usar catchError para tratar erros
- Implementar retry logic
- Usar retryWhen para retry customizado
- Criar fallbacks apropriados
- Tratar diferentes tipos de erro

---

## Descrição

Você precisa criar um serviço HTTP com tratamento completo de erros incluindo retry e fallbacks.

### Contexto

Uma aplicação precisa tratar erros HTTP de forma robusta com retry automático e fallbacks.

### Tarefa

Crie:

1. **catchError**: Tratamento básico de erros
2. **retry**: Retry simples
3. **retryWhen**: Retry com condições
4. **Fallbacks**: Valores padrão em caso de erro
5. **Serviço completo**: Serviço HTTP com tratamento completo

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] catchError implementado
- [ ] retry implementado
- [ ] retryWhen implementado
- [ ] Fallbacks implementados
- [ ] Tratamento funciona corretamente
- [ ] Código robusto

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Tratamento está completo
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**error-handling.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError, timer, of } from 'rxjs';
import { catchError, retry, retryWhen, delay, take, mergeMap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class ErrorHandlingService {
  constructor(private http: HttpClient) {}
  
  getDataWithRetry(): Observable<any> {
    return this.http.get('/api/data').pipe(
      retry(3),
      catchError(this.handleError)
    );
  }
  
  getDataWithRetryWhen(): Observable<any> {
    return this.http.get('/api/data').pipe(
      retryWhen(errors =>
        errors.pipe(
          mergeMap((error, index) => {
            if (index < 3 && error.status >= 500) {
              return timer(1000 * (index + 1));
            }
            return throwError(() => error);
          }),
          take(3)
        )
      ),
      catchError(this.handleError)
    );
  }
  
  getDataWithFallback(): Observable<any> {
    return this.http.get('/api/data').pipe(
      retry(2),
      catchError((error) => {
        console.error('Erro ao buscar dados:', error);
        return of({ data: [], message: 'Usando dados em cache' });
      })
    );
  }
  
  getDataWithMultipleFallbacks(): Observable<any> {
    return this.http.get('/api/data').pipe(
      catchError(() => this.http.get('/api/data-backup')),
      catchError(() => of({ data: [], fromCache: true }))
    );
  }
  
  private handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage = 'Erro desconhecido';
    
    if (error.error instanceof ErrorEvent) {
      errorMessage = `Erro do cliente: ${error.error.message}`;
    } else {
      switch (error.status) {
        case 0:
          errorMessage = 'Erro de conexão';
          break;
        case 404:
          errorMessage = 'Recurso não encontrado';
          break;
        case 500:
          errorMessage = 'Erro no servidor';
          break;
        default:
          errorMessage = `Erro ${error.status}: ${error.message}`;
      }
    }
    
    console.error('Erro HTTP:', errorMessage);
    return throwError(() => new Error(errorMessage));
  }
}
```

**error-handling-demo.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ErrorHandlingService } from './error-handling.service';

@Component({
  selector: 'app-error-handling-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Tratamento de Erros</h2>
      
      <section>
        <h3>Retry Simples</h3>
        <button (click)="testRetry()">Testar Retry</button>
        <p>{{ retryResult }}</p>
      </section>
      
      <section>
        <h3>Retry com Condições</h3>
        <button (click)="testRetryWhen()">Testar RetryWhen</button>
        <p>{{ retryWhenResult }}</p>
      </section>
      
      <section>
        <h3>Fallback</h3>
        <button (click)="testFallback()">Testar Fallback</button>
        <p>{{ fallbackResult }}</p>
      </section>
      
      <section>
        <h3>Múltiplos Fallbacks</h3>
        <button (click)="testMultipleFallbacks()">Testar</button>
        <p>{{ multipleFallbacksResult }}</p>
      </section>
    </div>
  `
})
export class ErrorHandlingDemoComponent {
  retryResult: string = '';
  retryWhenResult: string = '';
  fallbackResult: string = '';
  multipleFallbacksResult: string = '';
  
  constructor(private errorService: ErrorHandlingService) {}
  
  testRetry(): void {
    this.retryResult = 'Testando...';
    this.errorService.getDataWithRetry().subscribe({
      next: (data) => {
        this.retryResult = 'Sucesso: ' + JSON.stringify(data);
      },
      error: (error) => {
        this.retryResult = 'Erro após retry: ' + error.message;
      }
    });
  }
  
  testRetryWhen(): void {
    this.retryWhenResult = 'Testando...';
    this.errorService.getDataWithRetryWhen().subscribe({
      next: (data) => {
        this.retryWhenResult = 'Sucesso: ' + JSON.stringify(data);
      },
      error: (error) => {
        this.retryWhenResult = 'Erro após retryWhen: ' + error.message;
      }
    });
  }
  
  testFallback(): void {
    this.fallbackResult = 'Testando...';
    this.errorService.getDataWithFallback().subscribe({
      next: (data) => {
        this.fallbackResult = 'Resultado: ' + JSON.stringify(data);
      }
    });
  }
  
  testMultipleFallbacks(): void {
    this.multipleFallbacksResult = 'Testando...';
    this.errorService.getDataWithMultipleFallbacks().subscribe({
      next: (data) => {
        this.multipleFallbacksResult = 'Resultado: ' + JSON.stringify(data);
      }
    });
  }
}
```

**Explicação da Solução**:

1. retry() tenta novamente N vezes
2. retryWhen() permite retry customizado com condições
3. catchError() captura e trata erros
4. Fallbacks fornecem valores padrão
5. Múltiplos fallbacks tentam alternativas
6. Tratamento robusto e completo

---

## Testes

### Casos de Teste

**Teste 1**: retry funciona
- **Input**: Requisição que falha temporariamente
- **Output Esperado**: Retry automático até 3 vezes

**Teste 2**: retryWhen funciona
- **Input**: Erro 500
- **Output Esperado**: Retry apenas para erros 500

**Teste 3**: Fallback funciona
- **Input**: Requisição que falha
- **Output Esperado**: Valor padrão retornado

---

## Extensões (Opcional)

1. **Exponential Backoff**: Implemente retry com backoff exponencial
2. **Error Logging**: Adicione logging de erros
3. **User Notification**: Notifique usuário sobre erros

---

## Referências Úteis

- **[catchError](https://rxjs.dev/api/operators/catchError)**: Documentação catchError
- **[retry](https://rxjs.dev/api/operators/retry)**: Documentação retry
- **[retryWhen](https://rxjs.dev/api/operators/retryWhen)**: Documentação retryWhen

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

