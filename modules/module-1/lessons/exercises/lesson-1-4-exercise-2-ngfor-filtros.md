---
layout: exercise
title: "Exercício 1.4.2: Lista com *ngFor e Filtros"
slug: "ngfor-filtros"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **diretiva *ngFor** através da **criação de uma lista de produtos com filtros por categoria**.

Ao completar este exercício, você será capaz de:

- Usar `*ngFor` para renderizar listas
- Implementar `trackBy` para otimização
- Criar filtros dinâmicos
- Combinar `*ngFor` com outras diretivas

---

## Descrição

Você precisa criar um componente `ProductListComponent` que exibe uma lista de produtos e permite filtrar por categoria. A lista deve ser otimizada com `trackBy`.

### Contexto

Uma loja online precisa exibir produtos em uma lista com capacidade de filtrar por categoria. A lista deve ser performática mesmo com muitos produtos.

### Tarefa

Crie um componente `ProductListComponent` com:

1. **Lista de Produtos**: Array de produtos com id, nome, preço, categoria
2. ***ngFor**: Renderizar produtos usando `*ngFor` com `trackBy`
3. **Filtro por Categoria**: Dropdown ou botões para filtrar
4. **Contador**: Mostrar quantidade de produtos filtrados
5. **Mensagem Vazia**: Mostrar mensagem quando não houver produtos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Lista de produtos renderizada com `*ngFor`
- [ ] `trackBy` implementado corretamente
- [ ] Filtro por categoria funcional
- [ ] Contador de produtos filtrados
- [ ] Mensagem quando lista vazia
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] `trackBy` usa propriedade única (id)
- [ ] Filtros são eficientes
- [ ] Código é legível e bem organizado

---

## Dicas

### Dica 1: *ngFor Básico

```html
<div *ngFor="let product of products">
  {{ product.name }}
</div>
```

### Dica 2: trackBy

```typescript
trackByProductId(index: number, product: Product): number {
  return product.id;
}
```

```html
<div *ngFor="let product of products; trackBy: trackByProductId">
```

### Dica 3: Filtro Simples

```typescript
filteredProducts: Product[] = [];

filterByCategory(category: string): void {
  if (category === 'all') {
    this.filteredProducts = this.products;
  } else {
    this.filteredProducts = this.products.filter(p => p.category === category);
  }
}
```

### Dica 4: Obter Categorias Únicas

```typescript
getCategories(): string[] {
  return ['all', ...new Set(this.products.map(p => p.category))];
}
```

---

## Solução Esperada

### Abordagem Recomendada

**product-list.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
  imageUrl?: string;
}

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './product-list.component.html',
  styleUrls: ['./product-list.component.css']
})
export class ProductListComponent implements OnInit {
  products: Product[] = [
    { id: 1, name: 'Notebook', price: 2500, category: 'Eletrônicos' },
    { id: 2, name: 'Mouse', price: 50, category: 'Eletrônicos' },
    { id: 3, name: 'Mesa', price: 300, category: 'Móveis' },
    { id: 4, name: 'Cadeira', price: 200, category: 'Móveis' },
    { id: 5, name: 'Monitor', price: 800, category: 'Eletrônicos' },
    { id: 6, name: 'Teclado', price: 150, category: 'Eletrônicos' }
  ];
  
  filteredProducts: Product[] = [];
  selectedCategory: string = 'all';
  categories: string[] = [];
  
  ngOnInit(): void {
    this.categories = this.getCategories();
    this.filterByCategory('all');
  }
  
  getCategories(): string[] {
    const uniqueCategories = new Set(this.products.map(p => p.category));
    return ['all', ...Array.from(uniqueCategories)];
  }
  
  filterByCategory(category: string): void {
    this.selectedCategory = category;
    
    if (category === 'all') {
      this.filteredProducts = [...this.products];
    } else {
      this.filteredProducts = this.products.filter(p => p.category === category);
    }
  }
  
  trackByProductId(index: number, product: Product): number {
    return product.id;
  }
  
  getProductCount(): number {
    return this.filteredProducts.length;
  }
}
```

**product-list.component.html**
{% raw %}
```html
<div class="product-list">
  <h2>Lista de Produtos</h2>
  
  <div class="filters">
    <label>Filtrar por categoria:</label>
    <div class="filter-buttons">
      <button 
        *ngFor="let category of categories"
        [class.active]="selectedCategory === category"
        (click)="filterByCategory(category)">
        {{ category === 'all' ? 'Todos' : category }}
      </button>
    </div>
    <p class="product-count">
      Mostrando {{ getProductCount() }} de {{ products.length }} produtos
    </p>
  </div>
  
  <div class="products-grid" *ngIf="filteredProducts.length > 0">
    <div 
      *ngFor="let product of filteredProducts; trackBy: trackByProductId"
      class="product-card">
      <h3>{{ product.name }}</h3>
      <p class="category">{{ product.category }}</p>
      <p class="price">{{ product.price | currency:'BRL' }}</p>
    </div>
  </div>
  
  <div class="empty-message" *ngIf="filteredProducts.length === 0">
    <p>Nenhum produto encontrado nesta categoria.</p>
  </div>
</div>
```
{% raw %}
<div class="product-list">
  <h2>Lista de Produtos</h2>
  
  <div class="filters">
    <label>Filtrar por categoria:</label>
    <div class="filter-buttons">
      <button 
        *ngFor="let category of categories"
        [class.active]="selectedCategory === category"
        (click)="filterByCategory(category)">
        {{ category === 'all' ? 'Todos' : category }}
      </button>
    </div>
    <p class="product-count">
      Mostrando {{ getProductCount() }} de {{ products.length }} produtos
    </p>
  </div>
  
  <div class="products-grid" *ngIf="filteredProducts.length > 0">
    <div 
      *ngFor="let product of filteredProducts; trackBy: trackByProductId"
      class="product-card">
      <h3>{{ product.name }}</h3>
      <p class="category">{{ product.category }}</p>
      <p class="price">{{ product.price | currency:'BRL' }}</p>
    </div>
  </div>
  
  <div class="empty-message" *ngIf="filteredProducts.length === 0">
    <p>Nenhum produto encontrado nesta categoria.</p>
  </div>
</div>
```
{% endraw %}

**product-list.component.css**
```css
.product-list {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem;
}

.filters {
  margin-bottom: 2rem;
  padding: 1.5rem;
  background-color: #f5f5f5;
  border-radius: 8px;
}

.filter-buttons {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-top: 1rem;
}

.filter-buttons button {
  padding: 0.5rem 1rem;
  border: 1px solid #ddd;
  background-color: white;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.3s;
}

.filter-buttons button:hover {
  background-color: #e3f2fd;
}

.filter-buttons button.active {
  background-color: #1976d2;
  color: white;
  border-color: #1976d2;
}

.product-count {
  margin-top: 1rem;
  color: #666;
  font-size: 0.9rem;
}

.products-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 1.5rem;
}

.product-card {
  padding: 1.5rem;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  background-color: white;
  transition: transform 0.2s, box-shadow 0.2s;
}

.product-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.product-card h3 {
  margin: 0 0 0.5rem 0;
  color: #333;
}

.category {
  color: #666;
  font-size: 0.875rem;
  margin: 0.5rem 0;
}

.price {
  font-size: 1.25rem;
  font-weight: bold;
  color: #1976d2;
  margin: 1rem 0 0 0;
}

.empty-message {
  text-align: center;
  padding: 3rem;
  color: #666;
}

.empty-message p {
  font-size: 1.1rem;
}
```

**Explicação da Solução**:

1. Array `products` com dados de exemplo
2. `filteredProducts` contém produtos filtrados
3. `getCategories()` extrai categorias únicas
4. `filterByCategory()` filtra produtos por categoria
5. `trackByProductId()` otimiza renderização
6. Template usa `*ngFor` com `trackBy`
7. Mensagem vazia quando não há produtos

**Decisões de Design**:

- `trackBy` usa `id` único para performance
- Filtros como botões para melhor UX
- Grid responsivo para produtos
- Contador mostra quantidade filtrada
- Hover effects para interatividade

---

## Testes

### Casos de Teste

**Teste 1**: Lista renderiza todos os produtos
- **Input**: Componente carregado
- **Output Esperado**: Todos os produtos devem aparecer

**Teste 2**: Filtro por categoria funciona
- **Input**: Clicar em botão de categoria
- **Output Esperado**: Apenas produtos da categoria devem aparecer

**Teste 3**: Contador atualiza corretamente
- **Input**: Filtrar produtos
- **Output Esperado**: Contador deve mostrar quantidade correta

**Teste 4**: Mensagem vazia aparece
- **Input**: Filtrar categoria sem produtos
- **Output Esperado**: Mensagem "Nenhum produto encontrado" deve aparecer

**Teste 5**: trackBy otimiza renderização
- **Input**: Filtrar e desfiltrar produtos
- **Output Esperado**: Elementos DOM não devem ser recriados desnecessariamente

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Busca por Nome**: Adicione campo de busca para filtrar por nome
2. **Ordenação**: Adicione opções de ordenação (preço, nome)
3. **Paginação**: Implemente paginação para listas grandes
4. **Filtros Múltiplos**: Permita selecionar múltiplas categorias

---

## Referências Úteis

- **[ngFor](https://angular.io/api/common/NgForOf)**: Documentação oficial
- **[trackBy](https://angular.io/api/common/NgForOf#change-propagation)**: Sobre trackBy
- **[Structural Directives](https://angular.io/guide/structural-directives)**: Guia de diretivas estruturais

---

## Checklist de Qualidade

Antes de considerar este exercício completo:

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

