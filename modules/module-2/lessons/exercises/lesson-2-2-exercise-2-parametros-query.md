---
layout: exercise
title: "Exercício 2.2.2: Parâmetros de Rota e Query Params"
slug: "parametros-query"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **parâmetros de rota e query parameters** através da **criação de rotas dinâmicas que recebem e processam parâmetros**.

Ao completar este exercício, você será capaz de:

- Definir rotas com parâmetros dinâmicos
- Ler parâmetros de rota usando ActivatedRoute
- Trabalhar com query parameters
- Navegar programaticamente com parâmetros
- Atualizar query params sem perder outros

---

## Descrição

Você precisa criar uma aplicação de produtos onde cada produto tem uma página de detalhes acessível via `/products/:id` e suporta filtros via query params.

### Contexto

Uma aplicação de e-commerce precisa exibir detalhes de produtos específicos e permitir filtros na lista de produtos.

### Tarefa

Crie:

1. **Lista de Produtos**: Componente que lista produtos com links
2. **Detalhes do Produto**: Componente que exibe detalhes baseado em ID
3. **Filtros**: Query params para filtrar lista (categoria, preço)
4. **Navegação**: Navegação programática entre produtos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Rota com parâmetro :id configurada
- [ ] Componente lê parâmetro da rota
- [ ] Query params funcionam para filtros
- [ ] Navegação programática implementada
- [ ] Query params são preservados ao navegar
- [ ] Componente reage a mudanças de parâmetros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Parâmetros são validados
- [ ] Navegação é intuitiva
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**app.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { ProductListComponent } from './products/product-list.component';
import { ProductDetailComponent } from './products/product-detail.component';

export const routes: Routes = [
  { path: '', redirectTo: '/products', pathMatch: 'full' },
  { path: 'products', component: ProductListComponent },
  { path: 'products/:id', component: ProductDetailComponent }
];
```

**product.model.ts**
```typescript
export interface Product {
  id: number;
  name: string;
  category: string;
  price: number;
  description: string;
}
```

**product-list.component.ts**
{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, ActivatedRoute, RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { Product } from './product.model';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule, RouterModule, FormsModule],
{% raw %}
  template: `
    <div class="product-list">
      <h1>Produtos</h1>
      
      <div class="filters">
        <select [(ngModel)]="selectedCategory" (change)="applyFilters()">
          <option value="">Todas as categorias</option>
          <option value="electronics">Eletrônicos</option>
          <option value="clothing">Roupas</option>
          <option value="books">Livros</option>
        </select>
        
        <input 
          type="number" 
          [(ngModel)]="maxPrice" 
          placeholder="Preço máximo"
          (input)="applyFilters()">
      </div>
      
      <ul>
        @for (product of filteredProducts; track product.id) {
          <li>
            <a [routerLink]="['/products', product.id]">
              {{ product.name }} - R$ {{ product.price }}
            </a>
          </li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class ProductListComponent implements OnInit {
  products: Product[] = [
    { id: 1, name: 'Notebook', category: 'electronics', price: 2500, description: 'Notebook gamer' },
    { id: 2, name: 'Camiseta', category: 'clothing', price: 50, description: 'Camiseta básica' },
    { id: 3, name: 'Livro Angular', category: 'books', price: 80, description: 'Guia completo' },
    { id: 4, name: 'Smartphone', category: 'electronics', price: 1500, description: 'Smartphone top' }
  ];
  
  filteredProducts: Product[] = [];
  selectedCategory: string = '';
  maxPrice: number | null = null;
  
  constructor(
    private router: Router,
    private route: ActivatedRoute
  ) {}
  
  ngOnInit(): void {
    this.route.queryParamMap.subscribe(params => {
      this.selectedCategory = params.get('category') || '';
      const priceParam = params.get('maxPrice');
      this.maxPrice = priceParam ? Number(priceParam) : null;
      this.applyFilters();
    });
  }
  
  applyFilters(): void {
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: {
        category: this.selectedCategory || null,
        maxPrice: this.maxPrice || null
      },
      queryParamsHandling: 'merge'
    });
    
    this.filteredProducts = this.products.filter(product => {
      const categoryMatch = !this.selectedCategory || product.category === this.selectedCategory;
      const priceMatch = !this.maxPrice || product.price <= this.maxPrice;
      return categoryMatch && priceMatch;
    });
  }
}
```
{% endraw %}

**product-detail.component.ts**
{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { Product } from './product.model';

@Component({
  selector: 'app-product-detail',
  standalone: true,
  imports: [CommonModule, RouterModule],
{% raw %}
  template: `
    <div class="product-detail">
      @if (product) {
        <h1>{{ product.name }}</h1>
        <p><strong>Categoria:</strong> {{ product.category }}</p>
        <p><strong>Preço:</strong> R$ {{ product.price }}</p>
        <p><strong>Descrição:</strong> {{ product.description }}</p>
        
        <div class="navigation">
          <button (click)="goToPrevious()">Anterior</button>
          <button (click)="goToNext()">Próximo</button>
          <button routerLink="/products">Voltar à Lista</button>
        </div>
      } @else {
        <p>Produto não encontrado</p>
      }
    </div>
  `
{% endraw %}
})
export class ProductDetailComponent implements OnInit {
  product: Product | null = null;
  productId: number | null = null;
  
  private products: Product[] = [
    { id: 1, name: 'Notebook', category: 'electronics', price: 2500, description: 'Notebook gamer' },
    { id: 2, name: 'Camiseta', category: 'clothing', price: 50, description: 'Camiseta básica' },
    { id: 3, name: 'Livro Angular', category: 'books', price: 80, description: 'Guia completo' },
    { id: 4, name: 'Smartphone', category: 'electronics', price: 1500, description: 'Smartphone top' }
  ];
  
  constructor(
    private route: ActivatedRoute,
    private router: Router
  ) {}
  
  ngOnInit(): void {
    this.route.paramMap.subscribe(params => {
      const id = params.get('id');
      if (id) {
        this.productId = Number(id);
        this.loadProduct();
      }
    });
  }
  
  loadProduct(): void {
    if (this.productId) {
      this.product = this.products.find(p => p.id === this.productId) || null;
    }
  }
  
  goToPrevious(): void {
    if (this.productId && this.productId > 1) {
      this.router.navigate(['/products', this.productId - 1]);
    }
  }
  
  goToNext(): void {
    if (this.productId && this.productId < this.products.length) {
      this.router.navigate(['/products', this.productId + 1]);
    }
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. Rota com parâmetro :id para detalhes
2. ActivatedRoute usado para ler parâmetros
3. Query params usados para filtros
4. queryParamsHandling: 'merge' preserva outros params
5. Navegação programática implementada
6. Componente reage a mudanças via subscribe

---

## Testes

### Casos de Teste

**Teste 1**: Parâmetro de rota funciona
- **Input**: Navegar para /products/2
- **Output Esperado**: Produto com ID 2 é exibido

**Teste 2**: Query params funcionam
- **Input**: Adicionar ?category=electronics&maxPrice=2000
- **Output Esperado**: Apenas produtos eletrônicos abaixo de 2000 são exibidos

**Teste 3**: Navegação programática funciona
- **Input**: Clicar em "Próximo" no detalhe
- **Output Esperado**: Próximo produto é exibido

---

## Extensões (Opcional)

1. **Paginação**: Adicione paginação com query params
2. **Ordenação**: Adicione ordenação via query params
3. **Histórico**: Mantenha histórico de navegação

---

## Referências Úteis

- **[ActivatedRoute](https://angular.io/api/router/ActivatedRoute)**: Documentação ActivatedRoute
- **[Query Parameters](https://angular.io/guide/router#query-parameters-and-fragments)**: Guia query params

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

