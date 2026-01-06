---
layout: exercise
title: "Exercício 2.5.4: Padrão Master/Detail Completo"
slug: "master-detail"
lesson_id: "lesson-2-5"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **padrão Master/Detail completo** através da **criação de aplicação completa usando todas as técnicas de comunicação aprendidas**.

Ao completar este exercício, você será capaz de:

- Implementar padrão Master/Detail
- Combinar todas as técnicas de comunicação
- Criar aplicação completa e funcional
- Gerenciar estado compartilhado
- Aplicar padrões Smart/Dumb Components

---

## Descrição

Você precisa criar uma aplicação Master/Detail completa para gerenciar produtos, usando todas as técnicas de comunicação aprendidas.

### Contexto

Uma aplicação precisa de interface Master/Detail onde lista de produtos é exibida e detalhes do produto selecionado são mostrados.

### Tarefa

Crie:

1. **ProductService**: Serviço com dados e seleção
2. **ProductListComponent**: Componente Master (Smart)
3. **ProductItemComponent**: Componente Dumb para item
4. **ProductDetailComponent**: Componente Detail
5. **Comunicação**: Use todas as técnicas aprendidas

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] ProductService gerencia estado e seleção
- [ ] ProductListComponent exibe lista
- [ ] ProductItemComponent é componente dumb
- [ ] ProductDetailComponent exibe detalhes
- [ ] Seleção funciona via serviço
- [ ] Todas técnicas de comunicação aplicadas
- [ ] Aplicação completa e funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Padrão Master/Detail está bem implementado
- [ ] Código é bem organizado

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
  image?: string;
}
```

**product.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { Product } from './product.model';

@Injectable({
  providedIn: 'root'
})
export class ProductService {
  private products: Product[] = [
    { id: 1, name: 'Notebook', description: 'Notebook gamer', price: 2500, category: 'Electronics' },
    { id: 2, name: 'Smartphone', description: 'Smartphone top', price: 1500, category: 'Electronics' },
    { id: 3, name: 'Livro', description: 'Livro Angular', price: 80, category: 'Books' }
  ];
  
  private selectedProduct$ = new BehaviorSubject<Product | null>(null);
  private products$ = new BehaviorSubject<Product[]>(this.products);
  
  getProducts(): Observable<Product[]> {
    return this.products$.asObservable();
  }
  
  getSelectedProduct(): Observable<Product | null> {
    return this.selectedProduct$.asObservable();
  }
  
  selectProduct(product: Product): void {
    this.selectedProduct$.next(product);
  }
  
  clearSelection(): void {
    this.selectedProduct$.next(null);
  }
}
```

**product-item.component.ts**

```typescript
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Product } from './product.model';

@Component({
  selector: 'app-product-item',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div 
      class="product-item" 
      [class.selected]="isSelected"
      (click)="select()">
      <h4>{{ product.name }}</h4>
      <p>{{ product.description }}</p>
      <p class="price">R$ {{ product.price }}</p>
    </div>
  `,
  styles: [`
    .product-item {
      padding: 1rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      margin-bottom: 0.5rem;
      cursor: pointer;
      transition: background-color 0.2s;
    }
    
    .product-item:hover {
      background-color: #f0f0f0;
    }
    
    .product-item.selected {
      background-color: #e3f2fd;
      border-color: #2196f3;
    }
    
    .price {
      font-weight: bold;
      color: #4caf50;
    }
  `]
})
export class ProductItemComponent {
  @Input() product!: Product;
  @Input() isSelected: boolean = false;
  @Output() selected = new EventEmitter<Product>();
  
  select(): void {
    this.selected.emit(this.product);
  }
}
```

**product-list.component.ts**

```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { ProductService } from './product.service';
import { Product } from './product.model';
import { ProductItemComponent } from './product-item.component';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule, ProductItemComponent],
  template: `
    <div class="product-list">
      <h2>Produtos</h2>
      @if (loading) {
        <p>Carregando...</p>
      } @else {
        @for (product of products; track product.id) {
          <app-product-item
            [product]="product"
            [isSelected]="product.id === selectedProductId"
            (selected)="onProductSelected($event)">
          </app-product-item>
        }
      }
    </div>
  `
})
export class ProductListComponent implements OnInit, OnDestroy {
  products: Product[] = [];
  selectedProductId: number | null = null;
  loading = false;
  private subscriptions: Subscription[] = [];
  
  constructor(private productService: ProductService) {}
  
  ngOnInit(): void {
    this.loading = true;
    const productsSub = this.productService.getProducts().subscribe({
      next: (products) => {
        this.products = products;
        this.loading = false;
      }
    });
    
    const selectedSub = this.productService.getSelectedProduct().subscribe(
      product => {
        this.selectedProductId = product?.id || null;
      }
    );
    
    this.subscriptions.push(productsSub, selectedSub);
  }
  
  ngOnDestroy(): void {
    this.subscriptions.forEach(sub => sub.unsubscribe());
  }
  
  onProductSelected(product: Product): void {
    this.productService.selectProduct(product);
  }
}
```

**product-detail.component.ts**

```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { ProductService } from './product.service';
import { Product } from './product.model';

@Component({
  selector: 'app-product-detail',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="product-detail">
      @if (product) {
        <h2>{{ product.name }}</h2>
        <p class="description">{{ product.description }}</p>
        <div class="info">
          <p><strong>Preço:</strong> R$ {{ product.price }}</p>
          <p><strong>Categoria:</strong> {{ product.category }}</p>
        </div>
        <button (click)="clearSelection()">Fechar</button>
      } @else {
        <p>Selecione um produto para ver os detalhes</p>
      }
    </div>
  `,
  styles: [`
    .product-detail {
      padding: 1rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      background-color: #f9f9f9;
    }
    
    .description {
      font-size: 1.1rem;
      margin: 1rem 0;
    }
    
    .info {
      margin: 1rem 0;
    }
    
    button {
      padding: 0.5rem 1rem;
      background-color: #2196f3;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
  `]
})
export class ProductDetailComponent implements OnInit, OnDestroy {
  product: Product | null = null;
  private subscription?: Subscription;
  
  constructor(private productService: ProductService) {}
  
  ngOnInit(): void {
    this.subscription = this.productService.getSelectedProduct().subscribe(
      product => {
        this.product = product;
      }
    );
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }
  
  clearSelection(): void {
    this.productService.clearSelection();
  }
}
```

**app.component.ts**

```typescript
import { Component } from '@angular/core';
import { ProductListComponent } from './products/product-list.component';
import { ProductDetailComponent } from './products/product-detail.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [ProductListComponent, ProductDetailComponent],
  template: `
    <div class="app-container">
      <h1>Master/Detail - Produtos</h1>
      <div class="content">
        <div class="master">
          <app-product-list></app-product-list>
        </div>
        <div class="detail">
          <app-product-detail></app-product-detail>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .app-container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    .content {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 2rem;
    }
    
    @media (max-width: 768px) {
      .content {
        grid-template-columns: 1fr;
      }
    }
  `]
})
export class AppComponent {}
```

**Explicação da Solução**:

1. ProductService gerencia estado e seleção via BehaviorSubject
2. ProductListComponent é Smart Component que gerencia lista
3. ProductItemComponent é Dumb Component que apenas exibe
4. ProductDetailComponent exibe detalhes do selecionado
5. Comunicação via serviço entre componentes irmãos
6. @Input/@Output usado em ProductItemComponent
7. Padrão Master/Detail completo e funcional

---

## Testes

### Casos de Teste

**Teste 1**: Seleção funciona
- **Input**: Clicar em produto na lista
- **Output Esperado**: Detalhes aparecem no Detail

**Teste 2**: Múltiplas seleções funcionam
- **Input**: Selecionar diferentes produtos
- **Output Esperado**: Detalhes atualizam corretamente

**Teste 3**: Limpar seleção funciona
- **Input**: Clicar em "Fechar"
- **Output Esperado**: Seleção é limpa

---

## Extensões (Opcional)

1. **Edição**: Adicione edição de produtos
2. **Filtros**: Implemente filtros na lista
3. **Busca**: Adicione busca de produtos

---

## Referências Úteis

- **[Master/Detail Pattern](https://angular.io/guide/component-interaction)**: Padrão Master/Detail
- **[All Communication Techniques](https://angular.io/guide/component-interaction)**: Todas as técnicas

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

