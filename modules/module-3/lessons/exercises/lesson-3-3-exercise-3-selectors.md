---
layout: exercise
title: "Exercício 3.3.3: Selectors"
slug: "selectors"
lesson_id: "lesson-3-3"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Selectors** através da **criação de selectors básicos e compostos**.

Ao completar este exercício, você será capaz de:

- Criar selectors básicos
- Criar selectors compostos
- Entender memoização automática
- Derivar dados do estado
- Usar selectors em componentes

---

## Descrição

Você precisa criar selectors para acessar e derivar dados do Store de produtos.

### Contexto

Uma aplicação precisa de selectors para acessar estado de forma eficiente e derivar dados computados.

### Tarefa

Crie:

1. **Feature Selector**: Selector para feature state
2. **Basic Selectors**: Selectors para propriedades básicas
3. **Composed Selectors**: Selectors que derivam dados
4. **Component**: Componente que usa selectors

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Feature selector criado
- [ ] Selectors básicos criados
- [ ] Selectors compostos criados
- [ ] Component usa selectors
- [ ] Memoização funciona
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Selectors estão bem estruturados
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**product.selectors.ts**
```typescript
import { createFeatureSelector, createSelector } from '@ngrx/store';
import { ProductState } from './product.reducer';
import { Product } from './product.model';

export const selectProductState = createFeatureSelector<ProductState>('products');

export const selectAllProducts = createSelector(
  selectProductState,
  (state) => state.products
);

export const selectLoading = createSelector(
  selectProductState,
  (state) => state.loading
);

export const selectError = createSelector(
  selectProductState,
  (state) => state.error
);

export const selectProductsByCategory = (category: string) => createSelector(
  selectAllProducts,
  (products) => products.filter(p => p.category === category)
);

export const selectExpensiveProducts = createSelector(
  selectAllProducts,
  (products) => products.filter(p => p.price > 100)
);

export const selectTotalPrice = createSelector(
  selectAllProducts,
  (products) => products.reduce((sum, p) => sum + p.price, 0)
);

export const selectProductById = (id: number) => createSelector(
  selectAllProducts,
  (products) => products.find(p => p.id === id)
);

export const selectProductStats = createSelector(
  selectAllProducts,
  selectTotalPrice,
  (products, totalPrice) => ({
    count: products.length,
    totalPrice,
    averagePrice: products.length > 0 ? totalPrice / products.length : 0
  })
);
```

**product-list.component.ts**

{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Store } from '@ngrx/store';
import { Observable } from 'rxjs';
import { loadProducts } from './store/product.actions';
import { 
  selectAllProducts, 
  selectLoading, 
  selectExpensiveProducts,
  selectProductStats
} from './store/product.selectors';
import { Product } from './product.model';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Produtos</h2>
      <button (click)="load()">Carregar</button>
      
      @if (loading$ | async) {
        <p>Carregando...</p>
      }
      
      <div class="stats">
        <p>Total: {{ (stats$ | async)?.count }}</p>
        <p>Preço Total: R$ {{ (stats$ | async)?.totalPrice }}</p>
        <p>Preço Médio: R$ {{ (stats$ | async)?.averagePrice }}</p>
      </div>
      
      <h3>Todos os Produtos</h3>
      <ul>
        @for (product of products$ | async; track product.id) {
          <li>{{ product.name }} - R$ {{ product.price }}</li>
        }
      </ul>
      
      <h3>Produtos Caros (> R$ 100)</h3>
      <ul>
        @for (product of expensiveProducts$ | async; track product.id) {
          <li>{{ product.name }} - R$ {{ product.price }}</li>
        }
      </ul>
    </div>
  `
})
export class ProductListComponent implements OnInit {
  products$: Observable<Product[]>;
  expensiveProducts$: Observable<Product[]>;
  stats$: Observable<any>;
  loading$: Observable<boolean>;
  
  constructor(private store: Store) {
    this.products$ = this.store.select(selectAllProducts);
    this.expensiveProducts$ = this.store.select(selectExpensiveProducts);
    this.stats$ = this.store.select(selectProductStats);
    this.loading$ = this.store.select(selectLoading);
  }
  
  ngOnInit(): void {
    this.load();
  }
  
  load(): void {
    this.store.dispatch(loadProducts());
  }
}
```
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Store } from '@ngrx/store';
import { Observable } from 'rxjs';
import { loadProducts } from './store/product.actions';
import { 
  selectAllProducts, 
  selectLoading, 
  selectExpensiveProducts,
  selectProductStats
} from './store/product.selectors';
import { Product } from './product.model';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Produtos</h2>
      <button (click)="load()">Carregar</button>
      
      @if (loading$ | async) {
        <p>Carregando...</p>
      }
      
      <div class="stats">
        <p>Total: {{ (stats$ | async)?.count }}</p>
        <p>Preço Total: R$ {{ (stats$ | async)?.totalPrice }}</p>
        <p>Preço Médio: R$ {{ (stats$ | async)?.averagePrice }}</p>
      </div>
      
      <h3>Todos os Produtos</h3>
      <ul>
        @for (product of products$ | async; track product.id) {
          <li>{{ product.name }} - R$ {{ product.price }}</li>
        }
      </ul>
      
      <h3>Produtos Caros (> R$ 100)</h3>
      <ul>
        @for (product of expensiveProducts$ | async; track product.id) {
          <li>{{ product.name }} - R$ {{ product.price }}</li>
        }
      </ul>
    </div>
  `
})
export class ProductListComponent implements OnInit {
  products$: Observable<Product[]>;
  expensiveProducts$: Observable<Product[]>;
  stats$: Observable<any>;
  loading$: Observable<boolean>;
  
  constructor(private store: Store) {
    this.products$ = this.store.select(selectAllProducts);
    this.expensiveProducts$ = this.store.select(selectExpensiveProducts);
    this.stats$ = this.store.select(selectProductStats);
    this.loading$ = this.store.select(selectLoading);
  }
  
  ngOnInit(): void {
    this.load();
  }
  
  load(): void {
    this.store.dispatch(loadProducts());
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. Feature selector acessa feature state
2. Selectors básicos extraem propriedades
3. Selectors compostos derivam dados
4. Selectors com parâmetros são factories
5. Memoização automática melhora performance
6. Component usa selectors para acessar estado

---

## Testes

### Casos de Teste

**Teste 1**: Selectors básicos funcionam
- **Input**: Selecionar produtos
- **Output Esperado**: Lista de produtos retornada

**Teste 2**: Selectors compostos funcionam
- **Input**: Selecionar produtos caros
- **Output Esperado**: Apenas produtos caros retornados

**Teste 3**: Memoização funciona
- **Input**: Selecionar mesmo selector múltiplas vezes
- **Output Esperado**: Valor calculado apenas uma vez

---

## Extensões (Opcional)

1. **Mais Selectors**: Adicione mais selectors derivados
2. **Performance**: Compare performance com e sem selectors
3. **Testing**: Teste selectors isoladamente

---

## Referências Úteis

- **[Selectors](https://ngrx.io/guide/store/selectors)**: Guia Selectors
- **[createSelector](https://ngrx.io/api/store/createSelector)**: Documentação createSelector

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

