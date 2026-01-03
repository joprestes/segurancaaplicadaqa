---
layout: exercise
title: "Exercício 5.1.4: Testes de Serviços"
slug: "testes-servicos"
lesson_id: "lesson-5-1"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **testes de serviços** através da **criação de testes para serviços que fazem chamadas HTTP**.

Ao completar este exercício, você será capaz de:

- Testar serviços isoladamente
- Mockar HttpClient
- Usar HttpClientTestingModule
- Verificar requisições HTTP
- Testar tratamento de erros

---

## Descrição

Você precisa criar testes para um serviço que faz chamadas HTTP.

### Contexto

Uma aplicação precisa testar serviços que interagem com APIs.

### Tarefa

Crie:

1. **Serviço**: Criar serviço com métodos HTTP
2. **Testes**: Escrever testes usando HttpClientTestingModule
3. **Verificação**: Verificar requisições e respostas
4. **Erros**: Testar tratamento de erros

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Serviço criado
- [ ] HttpClientTestingModule configurado
- [ ] Testes de requisições escritos
- [ ] Testes de erros escritos
- [ ] Todos testes passam

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Testes estão completos
- [ ] Mocks estão corretos

---

## Solução Esperada

### Abordagem Recomendada

**product.service.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
}

@Injectable({
  providedIn: 'root'
})
export class ProductService {
  private http = inject(HttpClient);
  private apiUrl = '/api/products';
  
  getProducts(): Observable<Product[]> {
    return this.http.get<Product[]>(this.apiUrl);
  }
  
  getProductById(id: number): Observable<Product> {
    return this.http.get<Product>(`${this.apiUrl}/${id}`);
  }
  
  createProduct(product: Omit<Product, 'id'>): Observable<Product> {
    return this.http.post<Product>(this.apiUrl, product);
  }
  
  updateProduct(id: number, product: Partial<Product>): Observable<Product> {
    return this.http.patch<Product>(`${this.apiUrl}/${id}`, product);
  }
  
  deleteProduct(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }
  
  getProductsByCategory(category: string): Observable<Product[]> {
    return this.http.get<Product[]>(`${this.apiUrl}?category=${category}`);
  }
}
```

**product.service.spec.ts**
```typescript
import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { ProductService, Product } from './product.service';

describe('ProductService', () => {
  let service: ProductService;
  let httpMock: HttpTestingController;
  
  const mockProducts: Product[] = [
    { id: 1, name: 'Product 1', price: 100, category: 'Electronics' },
    { id: 2, name: 'Product 2', price: 200, category: 'Clothing' }
  ];

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [ProductService]
    });
    
    service = TestBed.inject(ProductService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch all products', () => {
    service.getProducts().subscribe(products => {
      expect(products).toEqual(mockProducts);
      expect(products.length).toBe(2);
    });

    const req = httpMock.expectOne('/api/products');
    expect(req.request.method).toBe('GET');
    req.flush(mockProducts);
  });

  it('should fetch product by id', () => {
    const mockProduct = mockProducts[0];
    
    service.getProductById(1).subscribe(product => {
      expect(product).toEqual(mockProduct);
    });

    const req = httpMock.expectOne('/api/products/1');
    expect(req.request.method).toBe('GET');
    req.flush(mockProduct);
  });

  it('should create a product', () => {
    const newProduct: Omit<Product, 'id'> = {
      name: 'New Product',
      price: 300,
      category: 'Electronics'
    };
    
    const createdProduct: Product = { id: 3, ...newProduct };

    service.createProduct(newProduct).subscribe(product => {
      expect(product).toEqual(createdProduct);
    });

    const req = httpMock.expectOne('/api/products');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual(newProduct);
    req.flush(createdProduct);
  });

  it('should update a product', () => {
    const updates = { price: 150 };
    const updatedProduct = { ...mockProducts[0], ...updates };

    service.updateProduct(1, updates).subscribe(product => {
      expect(product).toEqual(updatedProduct);
    });

    const req = httpMock.expectOne('/api/products/1');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual(updates);
    req.flush(updatedProduct);
  });

  it('should delete a product', () => {
    service.deleteProduct(1).subscribe(() => {
      expect(true).toBe(true);
    });

    const req = httpMock.expectOne('/api/products/1');
    expect(req.request.method).toBe('DELETE');
    req.flush(null);
  });

  it('should handle HTTP errors', () => {
    service.getProducts().subscribe({
      next: () => fail('should have failed'),
      error: (error) => {
        expect(error.status).toBe(500);
        expect(error.statusText).toBe('Internal Server Error');
      }
    });

    const req = httpMock.expectOne('/api/products');
    req.flush('Server Error', { status: 500, statusText: 'Internal Server Error' });
  });

  it('should filter products by category', () => {
    const filteredProducts = mockProducts.filter(p => p.category === 'Electronics');

    service.getProductsByCategory('Electronics').subscribe(products => {
      expect(products).toEqual(filteredProducts);
    });

    const req = httpMock.expectOne('/api/products?category=Electronics');
    expect(req.request.method).toBe('GET');
    req.flush(filteredProducts);
  });
});
```

**Explicação da Solução**:

1. HttpClientTestingModule importado
2. HttpTestingController usado para mockar HTTP
3. Testes verificam método HTTP correto
4. Testes verificam URL e body corretos
5. Testes verificam tratamento de erros
6. afterEach() verifica que todas requisições foram tratadas

---

## Testes

### Casos de Teste

**Teste 1**: GET funciona
- **Input**: Chamar getProducts()
- **Output Esperado**: Requisição GET feita corretamente

**Teste 2**: POST funciona
- **Input**: Chamar createProduct()
- **Output Esperado**: Requisição POST com body correto

**Teste 3**: Erros tratados
- **Input**: Simular erro HTTP
- **Output Esperado**: Erro tratado corretamente

---

## Extensões (Opcional)

1. **Retry Logic**: Teste lógica de retry
2. **Interceptors**: Teste interceptors
3. **Timeout**: Teste timeout de requisições

---

## Referências Úteis

- **[HTTP Testing](https://angular.io/guide/http-test-requests)**: Guia testes HTTP
- **[HttpTestingController](https://angular.io/api/common/http/testing/HttpTestingController)**: Documentação

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

