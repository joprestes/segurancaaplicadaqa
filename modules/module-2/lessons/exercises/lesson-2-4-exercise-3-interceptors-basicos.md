---
layout: exercise
title: "Exercício 2.4.3: HTTP Interceptors Básicos"
slug: "interceptors-basicos"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **HTTP Interceptors básicos** através da **criação de um interceptor de logging**.

Ao completar este exercício, você será capaz de:

- Criar interceptor funcional (HttpInterceptorFn)
- Interceptar requisições
- Interceptar respostas
- Modificar requisições/respostas
- Configurar interceptors no bootstrap

---

## Descrição

Você precisa criar um interceptor de logging que registra todas as requisições e respostas HTTP.

### Contexto

Uma aplicação precisa registrar todas as requisições HTTP para debugging e monitoramento.

### Tarefa

Crie:

1. **Logging Interceptor**: Interceptor que registra requisições e respostas
2. **Configuração**: Configure interceptor no bootstrap
3. **Logging**: Registre método, URL, headers, body, status

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] LoggingInterceptor criado
- [ ] Requisições são logadas
- [ ] Respostas são logadas
- [ ] Interceptor configurado no bootstrap
- [ ] Logs são informativos
- [ ] Interceptor funciona corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Interceptor está bem estruturado
- [ ] Logs são úteis

---

## Solução Esperada

### Abordagem Recomendada

**logging.interceptor.ts**
```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { tap } from 'rxjs/operators';

export const loggingInterceptor: HttpInterceptorFn = (req, next) => {
  const startTime = Date.now();
  
  console.group(`🚀 ${req.method} ${req.url}`);
  console.log('Request:', {
    method: req.method,
    url: req.url,
    headers: req.headers.keys().reduce((acc, key) => {
      acc[key] = req.headers.get(key);
      return acc;
    }, {} as Record<string, string | null>),
    body: req.body
  });
  
  return next(req).pipe(
    tap({
      next: (response) => {
        const duration = Date.now() - startTime;
        console.log('Response:', {
          status: response.status,
          statusText: response.statusText,
          duration: `${duration}ms`,
          body: response.body
        });
        console.groupEnd();
      },
      error: (error) => {
        const duration = Date.now() - startTime;
        console.error('Error:', {
          status: error.status,
          statusText: error.statusText,
          duration: `${duration}ms`,
          message: error.message
        });
        console.groupEnd();
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
import { loggingInterceptor } from './app/interceptors/logging.interceptor';

bootstrapApplication(AppComponent, {
  providers: [
    provideHttpClient(
      withInterceptors([loggingInterceptor])
    )
  ]
});
```

**product.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Product } from './product.model';

@Injectable({
  providedIn: 'root'
})
export class ProductService {
  private apiUrl = 'https://api.example.com/products';
  
  constructor(private http: HttpClient) {}
  
  getProducts(): Observable<Product[]> {
    return this.http.get<Product[]>(this.apiUrl);
  }
  
  createProduct(product: Omit<Product, 'id'>): Observable<Product> {
    return this.http.post<Product>(this.apiUrl, product);
  }
}
```

**Explicação da Solução**:

1. HttpInterceptorFn é função funcional moderna
2. Interceptor intercepta requisição antes de enviar
3. next(req) passa requisição adiante
4. tap operator intercepta resposta
5. Logs incluem método, URL, headers, body, status
6. Duração calculada para performance
7. withInterceptors configura interceptor

---

## Testes

### Casos de Teste

**Teste 1**: Requisições são logadas
- **Input**: Fazer requisição GET
- **Output Esperado**: Log aparece no console

**Teste 2**: Respostas são logadas
- **Input**: Receber resposta
- **Output Esperado**: Log de resposta aparece

**Teste 3**: Erros são logados
- **Input**: Requisição com erro
- **Output Esperado**: Log de erro aparece

---

## Extensões (Opcional)

1. **Filter**: Adicione filtro para não logar certas URLs
2. **Formatting**: Melhore formatação dos logs
3. **Storage**: Salve logs em localStorage

---

## Referências Úteis

- **[HTTP Interceptors](https://angular.io/guide/http-intercept-requests-and-responses)**: Guia oficial
- **[HttpInterceptorFn](https://angular.io/api/common/http/HttpInterceptorFn)**: Documentação HttpInterceptorFn

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

