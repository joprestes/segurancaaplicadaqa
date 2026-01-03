---
layout: exercise
title: "Exercício 4.1.4: trackBy Functions"
slug: "trackby"
lesson_id: "lesson-4-1"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **trackBy functions** através da **implementação de lista otimizada usando trackBy**.

Ao completar este exercício, você será capaz de:

- Implementar trackBy functions
- Otimizar performance de listas grandes
- Entender impacto de trackBy
- Usar trackBy com @for
- Melhorar change detection em listas

---

## Descrição

Você precisa criar componente com lista grande usando trackBy para otimização.

### Contexto

Uma aplicação precisa exibir lista grande de itens com boa performance.

### Tarefa

Crie:

1. **Lista Grande**: Criar lista com muitos itens
2. **trackBy Function**: Implementar trackBy function
3. **Comparação**: Comparar com e sem trackBy
4. **Otimização**: Verificar melhoria de performance

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Lista grande criada
- [ ] trackBy function implementada
- [ ] Performance melhorada
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] trackBy está implementado corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**product-list.component.ts**
{% raw %}
```typescript
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
}

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>Lista de Produtos (trackBy)</h2>
      
      <div class="controls">
        <button (click)="addProducts()">Adicionar 100 Produtos</button>
        <button (click)="updateRandom()">Atualizar Aleatório</button>
        <button (click)="shuffle()">Embaralhar</button>
        <button (click)="reset()">Resetar</button>
      </div>
      
      <p>Total: {{ products().length }} produtos</p>
      
      <ul class="product-list">
        @for (product of products(); track trackById($index, product)) {
          <li class="product-item">
            <span class="id">#{{ product.id }}</span>
            <span class="name">{{ product.name }}</span>
            <span class="price">R$ {{ product.price }}</span>
            <span class="category">{{ product.category }}</span>
          </li>
        }
      </ul>
    </div>
  `,
  styles: [`
    .product-list {
      max-height: 400px;
      overflow-y: auto;
      list-style: none;
      padding: 0;
    }
    
    .product-item {
      display: flex;
      gap: 1rem;
      padding: 0.5rem;
      border-bottom: 1px solid #eee;
    }
    
    .id {
      font-weight: bold;
      width: 60px;
    }
    
    .name {
      flex: 1;
    }
    
    .price {
      width: 100px;
      text-align: right;
    }
    
    .category {
      width: 100px;
    }
  `]
})
export class ProductListComponent {
  products = signal<Product[]>([]);
  private nextId = 1;
  
  constructor() {
    this.generateProducts(50);
  }
  
  trackById(index: number, product: Product): number {
    return product.id;
  }
  
  addProducts(): void {
    const newProducts = this.generateProducts(100);
    this.products.update(products => [...products, ...newProducts]);
  }
  
  updateRandom(): void {
    const products = this.products();
    if (products.length === 0) return;
    
    const randomIndex = Math.floor(Math.random() * products.length);
    const product = products[randomIndex];
    
    this.products.update(ps =>
      ps.map(p => 
        p.id === product.id 
          ? { ...p, price: Math.random() * 1000, name: `Updated ${p.name}` }
          : p
      )
    );
  }
  
  shuffle(): void {
    const products = [...this.products()];
    for (let i = products.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [products[i], products[j]] = [products[j], products[i]];
    }
    this.products.set(products);
  }
  
  reset(): void {
    this.nextId = 1;
    this.products.set(this.generateProducts(50));
  }
  
  private generateProducts(count: number): Product[] {
    const categories = ['Eletrônicos', 'Roupas', 'Casa', 'Esportes', 'Livros'];
    const products: Product[] = [];
    
    for (let i = 0; i < count; i++) {
      products.push({
        id: this.nextId++,
        name: `Produto ${this.nextId - 1}`,
        price: Math.random() * 1000,
        category: categories[Math.floor(Math.random() * categories.length)]
      });
    }
    
    return products;
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. trackBy function retorna ID único do item
2. @for usa trackBy para identificar itens
3. Angular reutiliza elementos DOM quando possível
4. Performance melhorada significativamente
5. Mudanças detectadas apenas em itens alterados
6. Lista grande renderizada eficientemente

---

## Testes

### Casos de Teste

**Teste 1**: trackBy funciona
- **Input**: Atualizar item específico
- **Output Esperado**: Apenas item atualizado re-renderizado

**Teste 2**: Performance melhorada
- **Input**: Comparar com e sem trackBy
- **Output Esperado**: Melhor performance com trackBy

**Teste 3**: Lista grande funciona
- **Input**: Lista com muitos itens
- **Output Esperado**: Renderização eficiente

---

## Extensões (Opcional)

1. **Benchmark**: Compare performance real
2. **Virtual Scrolling**: Implemente virtual scrolling
3. **Pagination**: Adicione paginação

---

## Referências Úteis

- **[trackBy](https://angular.io/api/common/NgForOf#change-propagation)**: Documentação trackBy
- **[Performance](https://angular.io/guide/change-detection#optimize-change-detection)**: Guia performance

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

