---
layout: exercise
title: "Exercício 1.2.5: Integração TypeScript + Angular"
slug: "integracao-angular"
lesson_id: "lesson-1-2"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **integração TypeScript com Angular** através da **criação de um componente Angular tipado corretamente**.

Ao completar este exercício, você será capaz de:

- Criar componente Angular usando TypeScript corretamente
- Aplicar interfaces e tipos em componentes Angular
- Usar decorators do Angular com type safety
- Integrar serviços tipados em componentes
- Aplicar todas as práticas TypeScript aprendidas em contexto Angular

---

## Descrição

Você precisa criar um componente Angular completo que demonstra todas as práticas TypeScript aprendidas. O componente deve exibir uma lista de produtos e permitir interações tipadas.

### Contexto

Um componente Angular precisa ser criado para exibir produtos de uma loja. O componente deve usar TypeScript de forma correta e demonstrar type safety em todas as operações.

### Tarefa

Crie um componente Angular `ProductListComponent` com:

1. **Interface `Product`**: Defina interface para produto (ou importe de módulo separado)

2. **Classe do Componente**: 
   - Use decorator `@Component`
   - Propriedades tipadas: `products: Product[]`, `selectedProduct: Product | null`
   - Métodos tipados: `selectProduct(id: number): void`, `getTotalPrice(): number`

3. **Serviço Tipado**: Crie ou use `ProductService` tipado

4. **Template Tipado**: Use interpolação e event binding com tipos corretos

5. **Dependency Injection**: Injete `ProductService` no construtor com tipos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente criado com decorator `@Component`
- [ ] Interface `Product` definida ou importada
- [ ] Propriedades do componente são tipadas
- [ ] Métodos têm tipos de parâmetros e retorno explícitos
- [ ] `ProductService` é injetado no construtor com tipo
- [ ] Template usa interpolação e event binding
- [ ] Código compila sem erros TypeScript

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todos os tipos são explícitos (não usa `any`)
- [ ] Decorators são usados corretamente
- [ ] Dependency injection está tipada
- [ ] Código é legível e bem organizado

---

## Dicas

### Dica 1: Estrutura de Componente Angular

```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-product-list',
  templateUrl: './product-list.component.html'
})
export class ProductListComponent {
  // propriedades e métodos
}
```

### Dica 2: Dependency Injection Tipada

```typescript
constructor(private productService: ProductService) {}
```

### Dica 3: Métodos Tipados

```typescript
selectProduct(id: number): void {
  // implementação
}

getTotalPrice(): number {
  return this.products.reduce((sum, p) => sum + p.price, 0);
}
```

### Dica 4: Propriedades Opcionais

```typescript
selectedProduct: Product | null = null;
```

### Dica 5: Usar Serviço Existente

Importe `ProductService` de módulo separado ou crie inline para o exercício.

---

## Solução Esperada

### Abordagem Recomendada

**product-list.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { Product, ProductService } from '../services/product.service';

@Component({
  selector: 'app-product-list',
  templateUrl: './product-list.component.html',
  styleUrls: ['./product-list.component.css']
})
export class ProductListComponent implements OnInit {
  products: Product[] = [];
  selectedProduct: Product | null = null;
  totalPrice: number = 0;

  constructor(private productService: ProductService) {}

  ngOnInit(): void {
    this.loadProducts();
  }

  loadProducts(): void {
    this.products = this.productService.getAllProducts();
    this.calculateTotalPrice();
  }

  selectProduct(id: number): void {
    this.selectedProduct = this.productService.getProductById(id) || null;
  }

  calculateTotalPrice(): void {
    this.totalPrice = this.products.reduce((sum, product) => sum + product.price, 0);
  }

  getTotalPrice(): number {
    return this.totalPrice;
  }

  getProductCount(): number {
    return this.products.length;
  }
}
```

**product-list.component.html**
{% raw %}
```html
<div class="product-list">
  <h2>Lista de Produtos</h2>
  <p>Total de produtos: {{ getProductCount() }}</p>
  <p>Preço total: {{ getTotalPrice() | currency:'BRL' }}</p>

  <div class="products">
    <div 
      *ngFor="let product of products" 
      class="product-item"
      (click)="selectProduct(product.id)"
      [class.selected]="selectedProduct?.id === product.id">
      <h3>{{ product.name }}</h3>
      <p>{{ product.description }}</p>
      <p class="price">{{ product.price | currency:'BRL' }}</p>
      <span class="category">{{ product.category.name }}</span>
    </div>
  </div>

  <div *ngIf="selectedProduct" class="selected-product">
    <h3>Produto Selecionado</h3>
    <p><strong>Nome:</strong> {{ selectedProduct.name }}</p>
    <p><strong>Preço:</strong> {{ selectedProduct.price | currency:'BRL' }}</p>
    <p><strong>Estoque:</strong> {{ selectedProduct.stock }}</p>
  </div>
</div>
```
{% raw %}
<div class="product-list">
  <h2>Lista de Produtos</h2>
  <p>Total de produtos: {{ getProductCount() }}</p>
  <p>Preço total: {{ getTotalPrice() | currency:'BRL' }}</p>

  <div class="products">
    <div 
      *ngFor="let product of products" 
      class="product-item"
      (click)="selectProduct(product.id)"
      [class.selected]="selectedProduct?.id === product.id">
      <h3>{{ product.name }}</h3>
      <p>{{ product.description }}</p>
      <p class="price">{{ product.price | currency:'BRL' }}</p>
      <span class="category">{{ product.category.name }}</span>
    </div>
  </div>

  <div *ngIf="selectedProduct" class="selected-product">
    <h3>Produto Selecionado</h3>
    <p><strong>Nome:</strong> {{ selectedProduct.name }}</p>
    <p><strong>Preço:</strong> {{ selectedProduct.price | currency:'BRL' }}</p>
    <p><strong>Estoque:</strong> {{ selectedProduct.stock }}</p>
  </div>
</div>
```
{% endraw %}

**product.service.ts** (se não existir)
```typescript
import { Injectable } from '@angular/core';

export interface Product {
  id: number;
  name: string;
  price: number;
  description: string;
  category: { id: number; name: string };
  stock: number;
  available: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class ProductService {
  private products: Product[] = [
    {
      id: 1,
      name: "Notebook",
      price: 2500,
      description: "Notebook gamer",
      category: { id: 1, name: "Eletrônicos" },
      stock: 10,
      available: true
    },
    {
      id: 2,
      name: "Mouse",
      price: 50,
      description: "Mouse sem fio",
      category: { id: 1, name: "Eletrônicos" },
      stock: 20,
      available: true
    }
  ];

  getAllProducts(): Product[] {
    return [...this.products];
  }

  getProductById(id: number): Product | undefined {
    return this.products.find(p => p.id === id);
  }
}
```

**Explicação da Solução**:

1. Componente usa `@Component` decorator com metadados
2. `implements OnInit` garante tipo correto para lifecycle hook
3. Propriedades são tipadas explicitamente
4. Métodos têm tipos de parâmetros e retorno
5. `ProductService` é injetado com tipo no construtor
6. Template usa interpolação e event binding tipados
7. Tudo mantém type safety completo

**Decisões de Design**:

- `selectedProduct` usa `Product | null` para representar estado vazio
- Métodos calculam valores em vez de propriedades computadas
- Serviço usa `providedIn: 'root'` para singleton
- Interface `Product` é exportada para reutilização

---

## Testes

### Casos de Teste

**Teste 1**: Componente inicializa corretamente
- **Input**: Componente carregado
- **Output Esperado**: `products` deve ser array vazio ou populado, `selectedProduct` deve ser `null`

**Teste 2**: Selecionar produto
- **Input**: Chamar `selectProduct(1)`
- **Output Esperado**: `selectedProduct` deve ser produto com id 1 ou `null` se não encontrado

**Teste 3**: Calcular preço total
- **Input**: Produtos com preços [100, 200, 300]
- **Output Esperado**: `getTotalPrice()` deve retornar 600

**Teste 4**: Contar produtos
- **Input**: Array com 3 produtos
- **Output Esperado**: `getProductCount()` deve retornar 3

**Teste 5**: Template renderiza corretamente
- **Input**: Componente renderizado com produtos
- **Output Esperado**: Lista de produtos deve aparecer no template

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Adicionar Filtro**: Crie método `filterByCategory(categoryId: number): Product[]`
2. **Ordenação**: Adicione método `sortByPrice(ascending: boolean): void`
3. **Busca**: Implemente busca por nome com método `searchProducts(query: string): Product[]`
4. **Formulário**: Crie componente de formulário tipado para adicionar produtos

---

## Referências Úteis

- **[Angular Components](https://angular.io/guide/component-overview)**: Documentação oficial sobre componentes
- **[TypeScript in Angular](https://angular.io/guide/typescript-configuration)**: Configuração TypeScript
- **[Dependency Injection](https://angular.io/guide/dependency-injection)**: Guia de DI em Angular

---

## Checklist de Qualidade

Antes de considerar este exercício completo:

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais e edge cases
- [x] Referências úteis estão incluídas

