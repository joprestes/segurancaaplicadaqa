---
layout: exercise
title: "Exercício 2.4.2: Tratamento de Erros"
slug: "tratamento-erros"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **tratamento robusto de erros HTTP** através da **implementação de tratamento completo de diferentes tipos de erro**.

Ao completar este exercício, você será capaz de:

- Tratar erros HTTP adequadamente
- Usar catchError operator
- Diferenciar tipos de erro
- Fornecer feedback ao usuário
- Implementar fallbacks

---

## Descrição

Você precisa criar um serviço com tratamento completo de erros HTTP, incluindo diferentes tipos de erro e mensagens apropriadas.

### Contexto

Uma aplicação precisa tratar erros HTTP de forma robusta para melhorar experiência do usuário.

### Tarefa

Crie:

1. **Error Handler**: Método centralizado para tratar erros
2. **Error Types**: Tratamento para diferentes status codes
3. **User Feedback**: Mensagens de erro amigáveis
4. **Fallbacks**: Valores padrão quando apropriado

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Error handler centralizado criado
- [ ] Diferentes tipos de erro tratados
- [ ] Mensagens de erro amigáveis
- [ ] catchError usado em todas requisições
- [ ] Feedback visual ao usuário
- [ ] Tratamento funciona corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Tratamento de erros está completo
- [ ] Mensagens são claras

---

## Solução Esperada

### Abordagem Recomendada

**error-handler.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';

export interface ErrorMessage {
  message: string;
  code: string;
}

@Injectable({
  providedIn: 'root'
})
export class ErrorHandlerService {
  handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage: ErrorMessage;
    
    if (error.error instanceof ErrorEvent) {
      errorMessage = {
        message: 'Erro de conexão. Verifique sua internet.',
        code: 'CLIENT_ERROR'
      };
    } else {
      switch (error.status) {
        case 400:
          errorMessage = {
            message: 'Dados inválidos. Verifique as informações.',
            code: 'BAD_REQUEST'
          };
          break;
        case 401:
          errorMessage = {
            message: 'Não autorizado. Faça login novamente.',
            code: 'UNAUTHORIZED'
          };
          break;
        case 403:
          errorMessage = {
            message: 'Acesso negado. Você não tem permissão.',
            code: 'FORBIDDEN'
          };
          break;
        case 404:
          errorMessage = {
            message: 'Recurso não encontrado.',
            code: 'NOT_FOUND'
          };
          break;
        case 500:
          errorMessage = {
            message: 'Erro no servidor. Tente novamente mais tarde.',
            code: 'SERVER_ERROR'
          };
          break;
        default:
          errorMessage = {
            message: 'Erro desconhecido. Tente novamente.',
            code: 'UNKNOWN_ERROR'
          };
      }
    }
    
    console.error('Erro HTTP:', errorMessage, error);
    return throwError(() => errorMessage);
  }
}
```

**product.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError } from 'rxjs';
import { Product } from './product.model';
import { ErrorHandlerService, ErrorMessage } from './error-handler.service';

@Injectable({
  providedIn: 'root'
})
export class ProductService {
  private apiUrl = 'https://api.example.com/products';
  
  constructor(
    private http: HttpClient,
    private errorHandler: ErrorHandlerService
  ) {}
  
  getProducts(): Observable<Product[] | ErrorMessage> {
    return this.http.get<Product[]>(this.apiUrl).pipe(
      catchError(this.errorHandler.handleError.bind(this.errorHandler))
    );
  }
  
  getProduct(id: number): Observable<Product | ErrorMessage> {
    return this.http.get<Product>(`${this.apiUrl}/${id}`).pipe(
      catchError(this.errorHandler.handleError.bind(this.errorHandler))
    );
  }
  
  createProduct(product: Omit<Product, 'id'>): Observable<Product | ErrorMessage> {
    return this.http.post<Product>(this.apiUrl, product).pipe(
      catchError(this.errorHandler.handleError.bind(this.errorHandler))
    );
  }
  
  updateProduct(id: number, product: Partial<Product>): Observable<Product | ErrorMessage> {
    return this.http.put<Product>(`${this.apiUrl}/${id}`, product).pipe(
      catchError(this.errorHandler.handleError.bind(this.errorHandler))
    );
  }
  
  deleteProduct(id: number): Observable<void | ErrorMessage> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`).pipe(
      catchError(this.errorHandler.handleError.bind(this.errorHandler))
    );
  }
}
```

**product-list.component.ts**
{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ProductService } from './product.service';
import { Product } from './product.model';
import { ErrorMessage } from './error-handler.service';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Produtos</h2>
      
      @if (loading) {
        <p>Carregando...</p>
      } @else if (error) {
        <div class="error">
          <p>{{ error.message }}</p>
          <button (click)="loadProducts()">Tentar Novamente</button>
        </div>
      } @else {
        <ul>
          @for (product of products; track product.id) {
            <li>
              <h3>{{ product.name }}</h3>
              <p>{{ product.description }}</p>
              <p>R$ {{ product.price }}</p>
            </li>
          }
        </ul>
      }
      
      <button (click)="loadProducts()">Recarregar</button>
    </div>
  `,
  styles: [`
{% endraw %}
    .error {
      color: #f44336;
      padding: 1rem;
      background-color: #ffebee;
      border-radius: 4px;
    }
  `]
})
export class ProductListComponent implements OnInit {
  products: Product[] = [];
  loading = false;
  error: ErrorMessage | null = null;
  
  constructor(private productService: ProductService) {}
  
  ngOnInit(): void {
    this.loadProducts();
  }
  
  loadProducts(): void {
    this.loading = true;
    this.error = null;
    
    this.productService.getProducts().subscribe({
      next: (result) => {
        if ('id' in result && Array.isArray(result)) {
          this.products = result;
        } else {
          this.error = result as ErrorMessage;
        }
        this.loading = false;
      },
      error: (error) => {
        this.error = error;
        this.loading = false;
      }
    });
  }
}
```

**Explicação da Solução**:

1. ErrorHandlerService centraliza tratamento de erros
2. Diferentes status codes tratados adequadamente
3. Mensagens amigáveis para o usuário
4. catchError usado em todas requisições
5. Componente exibe erros visualmente
6. Botão de retry implementado

---

## Testes

### Casos de Teste

**Teste 1**: Erro 404 tratado
- **Input**: Requisição para recurso inexistente
- **Output Esperado**: Mensagem "Recurso não encontrado"

**Teste 2**: Erro 500 tratado
- **Input**: Erro do servidor
- **Output Esperado**: Mensagem "Erro no servidor"

**Teste 3**: Erro de conexão tratado
- **Input**: Sem conexão
- **Output Esperado**: Mensagem "Erro de conexão"

---

## Extensões (Opcional)

1. **Toast Notifications**: Adicione notificações toast para erros
2. **Retry Logic**: Implemente retry automático
3. **Error Logging**: Adicione logging de erros

---

## Referências Úteis

- **[Error Handling](https://angular.io/guide/http#error-handling)**: Guia tratamento de erros
- **[HttpErrorResponse](https://angular.io/api/common/http/HttpErrorResponse)**: Documentação HttpErrorResponse

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

