---
layout: exercise
title: "Exercício 1.5.2: Lista com @for e Pipes"
slug: "for-pipes"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **@for com pipes** através da **criação de lista de produtos com formatação de dados**.

Ao completar este exercício, você será capaz de:

- Usar @for para renderizar listas
- Aplicar pipes embutidos para formatação
- Combinar múltiplos pipes
- Formatar diferentes tipos de dados

---

## Descrição

Você precisa criar um componente `ProductListComponent` que exibe uma lista de produtos usando `@for` e formata preços, datas e números usando pipes embutidos do Angular.

### Contexto

Uma loja online precisa exibir produtos com dados formatados corretamente. Pipes são essenciais para apresentar informações de forma legível.

### Tarefa

Crie um componente `ProductListComponent` com:

1. **Lista de Produtos**: Array com id, nome, preço, data de lançamento, desconto
2. **@for**: Renderizar produtos usando `@for` com track
3. **CurrencyPipe**: Formatar preços em BRL
4. **DatePipe**: Formatar datas
5. **PercentPipe**: Formatar descontos
6. **Encadeamento**: Combinar múltiplos pipes quando necessário

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Lista renderizada com @for
- [ ] Preços formatados com CurrencyPipe
- [ ] Datas formatadas com DatePipe
- [ ] Descontos formatados com PercentPipe
- [ ] Track usado corretamente
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Pipes são aplicados corretamente
- [ ] Formatação é consistente
- [ ] Código é legível

---

## Dicas

### Dica 1: CurrencyPipe

```html
{{ price | currency:'BRL':'symbol':'1.2-2' }}
```

### Dica 2: DatePipe

```html
{{ date | date:'dd/MM/yyyy' }}
```

### Dica 3: PercentPipe

```html
{{ discount | percent:'1.0-2' }}
```

### Dica 4: Encadeamento

```html
{{ value | pipe1 | pipe2 }}
```

---

## Solução Esperada

### Abordagem Recomendada

**product-list.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Product {
  id: number;
  name: string;
  price: number;
  releaseDate: Date;
  discount: number;
  category: string;
}

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './product-list.component.html',
  styleUrls: ['./product-list.component.css']
})
export class ProductListComponent {
  products: Product[] = [
    {
      id: 1,
      name: 'Notebook Gamer',
      price: 3500.99,
      releaseDate: new Date('2024-01-15'),
      discount: 0.15,
      category: 'Eletrônicos'
    },
    {
      id: 2,
      name: 'Mouse Sem Fio',
      price: 89.50,
      releaseDate: new Date('2024-03-20'),
      discount: 0.10,
      category: 'Acessórios'
    },
    {
      id: 3,
      name: 'Teclado Mecânico',
      price: 450.00,
      releaseDate: new Date('2024-02-10'),
      discount: 0.20,
      category: 'Acessórios'
    }
  ];
  
  calculateFinalPrice(product: Product): number {
    return product.price * (1 - product.discount);
  }
  
  formatReleaseDate(date: Date): string {
    return date.toLocaleDateString('pt-BR');
  }
}
```

**product-list.component.html**
```html
<div class="product-list">
  <h2>Lista de Produtos</h2>
  
  <div class="products-grid">
    @for (product of products; track product.id) {
      <div class="product-card">
        <h3>{{ product.name }}</h3>
        <p class="category">{{ product.category }}</p>
        
        <div class="pricing">
          <p class="original-price" *ngIf="product.discount > 0">
            De: <span class="strikethrough">{{ product.price | currency:'BRL':'symbol':'1.2-2' }}</span>
          </p>
          <p class="final-price">
            Por: <strong>{{ calculateFinalPrice(product) | currency:'BRL':'symbol':'1.2-2' }}</strong>
          </p>
          @if (product.discount > 0) {
            <span class="discount-badge">
              {{ product.discount | percent:'1.0-0' }} OFF
            </span>
          }
        </div>
        
        <p class="release-date">
          Lançado em: {{ product.releaseDate | date:'dd/MM/yyyy' }}
        </p>
        
        <p class="release-time">
          {{ product.releaseDate | date:'short' }}
        </p>
      </div>
    } @empty {
      <p class="empty-message">Nenhum produto disponível</p>
    }
  </div>
  
  <div class="summary">
    <h3>Resumo</h3>
    <p>Total de produtos: {{ products.length }}</p>
    <p>Valor total: {{ getTotalValue() | currency:'BRL':'symbol':'1.2-2' }}</p>
    <p>Desconto médio: {{ getAverageDiscount() | percent:'1.0-2' }}</p>
  </div>
</div>
```

**product-list.component.css**
```css
.product-list {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem;
}

.products-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.product-card {
  padding: 1.5rem;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  background-color: white;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
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

.pricing {
  margin: 1rem 0;
}

.original-price {
  color: #999;
  font-size: 0.9rem;
}

.strikethrough {
  text-decoration: line-through;
}

.final-price {
  font-size: 1.25rem;
  color: #1976d2;
  margin: 0.5rem 0;
}

.discount-badge {
  display: inline-block;
  background-color: #4caf50;
  color: white;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.875rem;
  font-weight: bold;
  margin-left: 0.5rem;
}

.release-date, .release-time {
  color: #666;
  font-size: 0.875rem;
  margin: 0.5rem 0;
}

.empty-message {
  text-align: center;
  padding: 3rem;
  color: #666;
}

.summary {
  padding: 1.5rem;
  background-color: #f5f5f5;
  border-radius: 8px;
}

.summary h3 {
  margin-top: 0;
}
```

**Métodos adicionais no componente**:
```typescript
getTotalValue(): number {
  return this.products.reduce((sum, p) => sum + this.calculateFinalPrice(p), 0);
}

getAverageDiscount(): number {
  if (this.products.length === 0) return 0;
  const totalDiscount = this.products.reduce((sum, p) => sum + p.discount, 0);
  return totalDiscount / this.products.length;
}
```

**Explicação da Solução**:

1. `@for` renderiza produtos com `track product.id`
2. `CurrencyPipe` formata preços em BRL
3. `DatePipe` formata datas em diferentes formatos
4. `PercentPipe` formata descontos
5. `@empty` mostra mensagem quando lista vazia
6. Métodos helper calculam valores formatados
7. Encadeamento de pipes quando necessário

**Decisões de Design**:

- Track integrado no @for
- Múltiplos formatos de data para demonstração
- Cálculo de preço final com desconto
- Resumo com estatísticas formatadas

---

## Testes

### Casos de Teste

**Teste 1**: Preços formatados corretamente
- **Input**: Produto com preço 3500.99
- **Output Esperado**: Deve aparecer "R$ 3.500,99"

**Teste 2**: Datas formatadas corretamente
- **Input**: Data de lançamento
- **Output Esperado**: Deve aparecer formato brasileiro

**Teste 3**: Descontos formatados
- **Input**: Desconto 0.15
- **Output Esperado**: Deve aparecer "15%"

**Teste 4**: Lista vazia
- **Input**: `products = []`
- **Output Esperado**: Mensagem "Nenhum produto disponível"

---

## Extensões (Opcional)

1. **Mais Formatos**: Adicione mais formatos de data e moeda
2. **Filtros**: Adicione filtros com pipes customizados
3. **Ordenação**: Ordene produtos por preço ou data
4. **Paginação**: Implemente paginação na lista

---

## Referências Úteis

- **[CurrencyPipe](https://angular.io/api/common/CurrencyPipe)**: Documentação CurrencyPipe
- **[DatePipe](https://angular.io/api/common/DatePipe)**: Documentação DatePipe
- **[PercentPipe](https://angular.io/api/common/PercentPipe)**: Documentação PercentPipe

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

