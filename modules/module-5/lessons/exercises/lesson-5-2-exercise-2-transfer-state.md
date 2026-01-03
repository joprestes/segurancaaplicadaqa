---
layout: exercise
title: "Exercício 5.2.2: Transfer State"
slug: "transfer-state"
lesson_id: "lesson-5-2"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Transfer State** através da **implementação de Transfer State para evitar requisições duplicadas**.

Ao completar este exercício, você será capaz de:

- Entender Transfer State
- Implementar Transfer State
- Evitar requisições duplicadas
- Otimizar performance SSR
- Transferir dados do servidor

---

## Descrição

Você precisa implementar Transfer State em um serviço que faz requisições HTTP.

### Contexto

Uma aplicação SSR precisa evitar requisições duplicadas entre servidor e cliente.

### Tarefa

Crie:

1. **Serviço**: Criar serviço que usa Transfer State
2. **Transfer State**: Implementar Transfer State
3. **Verificação**: Verificar que funciona
4. **Otimização**: Otimizar performance

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Transfer State implementado
- [ ] Requisições duplicadas evitadas
- [ ] Dados transferidos corretamente
- [ ] Performance otimizada
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Transfer State está implementado corretamente
- [ ] Performance é otimizada

---

## Solução Esperada

### Abordagem Recomendada

**product.service.ts**
```typescript
import { Injectable, inject, PLATFORM_ID } from '@angular/core';
import { isPlatformServer } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { TransferState, makeStateKey } from '@angular/platform-browser';
import { Observable, of } from 'rxjs';
import { tap } from 'rxjs/operators';

export interface Product {
  id: number;
  name: string;
  price: number;
}

const PRODUCTS_KEY = makeStateKey<Product[]>('products');
const PRODUCT_KEY = makeStateKey<Product>('product');

@Injectable({
  providedIn: 'root'
})
export class ProductService {
  private http = inject(HttpClient);
  private transferState = inject(TransferState);
  private platformId = inject(PLATFORM_ID);

  getProducts(): Observable<Product[]> {
    if (isPlatformServer(this.platformId)) {
      return this.http.get<Product[]>('/api/products').pipe(
        tap(products => {
          this.transferState.set(PRODUCTS_KEY, products);
        })
      );
    }

    const stored = this.transferState.get(PRODUCTS_KEY, null);
    if (stored) {
      return of(stored);
    }

    return this.http.get<Product[]>('/api/products');
  }

  getProductById(id: number): Observable<Product> {
    const key = makeStateKey<Product>(`product-${id}`);
    
    if (isPlatformServer(this.platformId)) {
      return this.http.get<Product>(`/api/products/${id}`).pipe(
        tap(product => {
          this.transferState.set(key, product);
        })
      );
    }

    const stored = this.transferState.get(key, null);
    if (stored) {
      return of(stored);
    }

    return this.http.get<Product>(`/api/products/${id}`);
  }
}
```

**app.config.ts**
```typescript
import { ApplicationConfig, provideZoneChangeDetection } from '@angular/core';
import { provideHttpClient, withFetch } from '@angular/common/http';
import { provideClientHydration } from '@angular/platform-browser';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideHttpClient(withFetch()),
    provideClientHydration()
  ]
};
```

**product-list.component.ts**
```typescript
import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ProductService, Product } from './product.service';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Produtos</h2>
      <ul>
        @for (product of products(); track product.id) {
          <li>{{ product.name }} - ${{ product.price }}</li>
        }
      </ul>
    </div>
  `
})
export class ProductListComponent implements OnInit {
  products = signal<Product[]>([]);

  constructor(private productService: ProductService) {}

  ngOnInit(): void {
    this.productService.getProducts().subscribe(products => {
      this.products.set(products);
    });
  }
}
```

**Explicação da Solução**:

1. TransferState injetado no serviço
2. makeStateKey cria chaves únicas
3. isPlatformServer verifica se está no servidor
4. Servidor armazena dados no TransferState
5. Cliente recupera dados do TransferState
6. Requisições duplicadas evitadas

---

## Testes

### Casos de Teste

**Teste 1**: Transfer State funciona
- **Input**: Carregar dados no servidor
- **Output Esperado**: Dados transferidos para cliente

**Teste 2**: Requisições evitadas
- **Input**: Verificar Network tab
- **Output Esperado**: Sem requisições duplicadas

**Teste 3**: Performance melhorada
- **Input**: Medir tempo de carregamento
- **Output Esperado**: Tempo reduzido

---

## Extensões (Opcional)

1. **Cache Strategy**: Implemente estratégia de cache
2. **Error Handling**: Adicione tratamento de erros
3. **Multiple Keys**: Use múltiplas chaves

---

## Referências Úteis

- **[Transfer State](https://angular.io/guide/ssr#transfer-state)**: Guia Transfer State
- **[makeStateKey](https://angular.io/api/platform-browser/makeStateKey)**: Documentação

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

