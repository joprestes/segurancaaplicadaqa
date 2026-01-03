---
layout: exercise
title: "Exercício 2.4.1: Requisições HTTP Básicas"
slug: "requisicoes-basicas"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **requisições HTTP básicas** através da **criação de um serviço que faz CRUD completo usando HttpClient**.

Ao completar este exercício, você será capaz de:

- Configurar HttpClient
- Fazer requisições GET, POST, PUT, DELETE
- Trabalhar com Observables
- Usar type safety com generics
- Criar serviço HTTP completo

---

## Descrição

Você precisa criar um serviço que gerencia produtos via API REST, implementando operações CRUD completas.

### Contexto

Uma aplicação precisa consumir uma API REST para gerenciar produtos.

### Tarefa

Crie:

1. **ProductService**: Serviço com métodos CRUD
2. **Configuração**: Configure HttpClient no bootstrap
3. **Métodos**: getProducts, getProduct, createProduct, updateProduct, deleteProduct
4. **Componente**: Componente que usa o serviço

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] HttpClient configurado com provideHttpClient
- [ ] ProductService criado
- [ ] Métodos GET, POST, PUT, DELETE implementados
- [ ] Type safety com generics
- [ ] Componente que usa o serviço
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Serviço está bem estruturado
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**product.model.ts**
```typescript
export interface Product {
  id: number;
  name: string;
  description: string;
  price: number;
  category: string;
}
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
  
  getProduct(id: number): Observable<Product> {
    return this.http.get<Product>(`${this.apiUrl}/${id}`);
  }
  
  createProduct(product: Omit<Product, 'id'>): Observable<Product> {
    return this.http.post<Product>(this.apiUrl, product);
  }
  
  updateProduct(id: number, product: Partial<Product>): Observable<Product> {
    return this.http.put<Product>(`${this.apiUrl}/${id}`, product);
  }
  
  deleteProduct(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }
}
```

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app/app.component';

bootstrapApplication(AppComponent, {
  providers: [
    provideHttpClient()
  ]
});
```

**product-list.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ProductService } from './product.service';
import { Product } from './product.model';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Produtos</h2>
      @if (loading) {
        <p>Carregando...</p>
      } @else {
        <ul>
          @for (product of products; track product.id) {
            <li>
              <h3>{{ product.name }}</h3>
              <p>{{ product.description }}</p>
              <p>R$ {{ product.price }}</p>
              <button (click)="deleteProduct(product.id)">Deletar</button>
            </li>
          }
        </ul>
      }
      
      <button (click)="loadProducts()">Recarregar</button>
    </div>
  `
})
export class ProductListComponent implements OnInit {
  products: Product[] = [];
  loading = false;
  
  constructor(private productService: ProductService) {}
  
  ngOnInit(): void {
    this.loadProducts();
  }
  
  loadProducts(): void {
    this.loading = true;
    this.productService.getProducts().subscribe({
      next: (products) => {
        this.products = products;
        this.loading = false;
      },
      error: (error) => {
        console.error('Erro ao carregar produtos:', error);
        this.loading = false;
      }
    });
  }
  
  deleteProduct(id: number): void {
    this.productService.deleteProduct(id).subscribe({
      next: () => {
        this.products = this.products.filter(p => p.id !== id);
      },
      error: (error) => {
        console.error('Erro ao deletar produto:', error);
      }
    });
  }
}
```

**Explicação da Solução**:

1. HttpClient configurado com provideHttpClient
2. ProductService implementa CRUD completo
3. Type safety com generics em todos os métodos
4. Componente usa serviço com subscribe
5. Tratamento básico de loading e erros
6. Estrutura clara e organizada

---

## Testes

### Casos de Teste

**Teste 1**: GET funciona
- **Input**: Chamar getProducts()
- **Output Esperado**: Lista de produtos retornada

**Teste 2**: POST funciona
- **Input**: Criar novo produto
- **Output Esperado**: Produto criado e retornado

**Teste 3**: PUT funciona
- **Input**: Atualizar produto existente
- **Output Esperado**: Produto atualizado

**Teste 4**: DELETE funciona
- **Input**: Deletar produto
- **Output Esperado**: Produto deletado

---

## Extensões (Opcional)

1. **Tratamento de Erros**: Adicione tratamento robusto de erros
2. **Loading States**: Melhore indicadores de loading
3. **Optimistic Updates**: Implemente atualizações otimistas

---

## Referências Úteis

- **[HttpClient](https://angular.io/api/common/http/HttpClient)**: Documentação HttpClient
- **[HTTP Guide](https://angular.io/guide/http)**: Guia oficial

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

