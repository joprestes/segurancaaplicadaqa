---
layout: exercise
title: "Exercício 2.2.4: Resolvers"
slug: "resolvers"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Resolvers** através da **implementação de pré-carregamento de dados antes da ativação de rotas**.

Ao completar este exercício, você será capaz de:

- Criar resolvers funcionais (ResolveFn)
- Pré-carregar dados antes de ativar rota
- Acessar dados resolvidos via ActivatedRoute.data
- Tratar erros em resolvers
- Combinar múltiplos resolvers

---

## Descrição

Você precisa criar um sistema onde dados de produtos são pré-carregados antes de exibir a página de detalhes, garantindo que dados estejam disponíveis imediatamente.

### Contexto

Uma aplicação de e-commerce precisa garantir que dados de produtos estejam disponíveis antes de renderizar a página de detalhes, evitando estados de loading.

### Tarefa

Crie:

1. **ProductService**: Serviço que busca produtos
2. **ProductResolver**: Resolver que pré-carrega produto
3. **ProductListResolver**: Resolver que pré-carrega lista
4. **Rotas com Resolvers**: Configure resolvers nas rotas
5. **Componentes**: Componentes que usam dados resolvidos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] ProductService criado
- [ ] ProductResolver implementado
- [ ] ProductListResolver implementado
- [ ] Rotas configuradas com resolvers
- [ ] Componentes acessam dados via route.data
- [ ] Tratamento de erros implementado
- [ ] Dados disponíveis antes de renderizar

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Resolvers são funcionais (ResolveFn)
- [ ] Erros são tratados adequadamente
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
import { Observable, of, delay } from 'rxjs';
import { Product } from './product.model';

@Injectable({
  providedIn: 'root'
})
export class ProductService {
  private products: Product[] = [
    { id: 1, name: 'Notebook', description: 'Notebook gamer', price: 2500, category: 'electronics' },
    { id: 2, name: 'Smartphone', description: 'Smartphone top', price: 1500, category: 'electronics' },
    { id: 3, name: 'Livro', description: 'Livro Angular', price: 80, category: 'books' }
  ];
  
  getProduct(id: number): Observable<Product> {
    const product = this.products.find(p => p.id === id);
    if (!product) {
      throw new Error(`Product with id ${id} not found`);
    }
    return of(product).pipe(delay(500));
  }
  
  getProducts(): Observable<Product[]> {
    return of(this.products).pipe(delay(500));
  }
}
```

**product.resolver.ts**
```typescript
import { inject } from '@angular/core';
import { ResolveFn, Router } from '@angular/router';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { ProductService } from './product.service';
import { Product } from './product.model';

export const productResolver: ResolveFn<Product> = (route, state) => {
  const productService = inject(ProductService);
  const router = inject(Router);
  const productId = Number(route.paramMap.get('id'));
  
  return productService.getProduct(productId).pipe(
    catchError(error => {
      console.error('Error loading product:', error);
      router.navigate(['/products']);
      return of(null as any);
    })
  );
};
```

**product-list.resolver.ts**
```typescript
import { inject } from '@angular/core';
import { ResolveFn } from '@angular/router';
import { ProductService } from './product.service';
import { Product } from './product.model';

export const productListResolver: ResolveFn<Product[]> = (route, state) => {
  const productService = inject(ProductService);
  return productService.getProducts();
};
```

**app.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { ProductListComponent } from './products/product-list.component';
import { ProductDetailComponent } from './products/product-detail.component';
import { productResolver } from './resolvers/product.resolver';
import { productListResolver } from './resolvers/product-list.resolver';

export const routes: Routes = [
  {
    path: 'products',
    component: ProductListComponent,
    resolve: { products: productListResolver }
  },
  {
    path: 'products/:id',
    component: ProductDetailComponent,
    resolve: { product: productResolver }
  }
];
```

**product-list.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { Product } from './product.model';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <div>
      <h1>Produtos</h1>
      <ul>
        @for (product of products; track product.id) {
          <li>
            <a [routerLink]="['/products', product.id]">
              {{ product.name }} - R$ {{ product.price }}
            </a>
          </li>
        }
      </ul>
    </div>
  `
})
export class ProductListComponent implements OnInit {
  products: Product[] = [];
  
  constructor(private route: ActivatedRoute) {}
  
  ngOnInit(): void {
    this.products = this.route.snapshot.data['products'] || [];
    
    this.route.data.subscribe(data => {
      this.products = data['products'] || [];
    });
  }
}
```

**product-detail.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { Product } from './product.model';

@Component({
  selector: 'app-product-detail',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      @if (product) {
        <h1>{{ product.name }}</h1>
        <p>{{ product.description }}</p>
        <p><strong>Preço:</strong> R$ {{ product.price }}</p>
        <p><strong>Categoria:</strong> {{ product.category }}</p>
        <button (click)="goBack()">Voltar</button>
      } @else {
        <p>Produto não encontrado</p>
      }
    </div>
  `
})
export class ProductDetailComponent implements OnInit {
  product: Product | null = null;
  
  constructor(
    private route: ActivatedRoute,
    private router: Router
  ) {}
  
  ngOnInit(): void {
    this.product = this.route.snapshot.data['product'] || null;
    
    if (!this.product) {
      this.router.navigate(['/products']);
    }
    
    this.route.data.subscribe(data => {
      this.product = data['product'] || null;
    });
  }
  
  goBack(): void {
    this.router.navigate(['/products']);
  }
}
```

**Explicação da Solução**:

1. Resolvers pré-carregam dados antes de ativar rota
2. Dados acessados via route.snapshot.data ou route.data
3. Tratamento de erros com catchError
4. Redirecionamento em caso de erro
5. Múltiplos resolvers podem ser combinados
6. Componente não precisa lidar com loading states

---

## Testes

### Casos de Teste

**Teste 1**: Resolver carrega dados
- **Input**: Navegar para /products/1
- **Output Esperado**: Dados do produto disponíveis imediatamente

**Teste 2**: Resolver trata erro
- **Input**: Navegar para /products/999 (inexistente)
- **Output Esperado**: Redireciona para /products

**Teste 3**: Lista resolver funciona
- **Input**: Navegar para /products
- **Output Esperado**: Lista de produtos disponível imediatamente

---

## Extensões (Opcional)

1. **Múltiplos Resolvers**: Combine múltiplos resolvers em uma rota
2. **Resolvers Assíncronos**: Implemente resolvers com operações assíncronas complexas
3. **Cache**: Implemente cache de dados resolvidos

---

## Referências Úteis

- **[Resolvers](https://angular.io/guide/router#resolve-pre-fetching-component-data)**: Guia oficial
- **[ResolveFn](https://angular.io/api/router/ResolveFn)**: Documentação ResolveFn

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

