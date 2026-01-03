---
layout: exercise
title: "Exercício 1.5.4: Pipe Customizado Avançado"
slug: "pipe-avancado"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **pipes customizados avançados** através da **criação de um pipe filter que filtra arrays baseado em função predicado**.

Ao completar este exercício, você será capaz de:

- Criar pipes com lógica complexa
- Entender quando usar impure pipes
- Trabalhar com arrays e funções
- Considerar implicações de performance
- Criar pipes reutilizáveis

---

## Descrição

Você precisa criar um pipe `FilterPipe` que filtra arrays baseado em uma função predicado. Este pipe pode precisar ser impure dependendo do uso.

### Contexto

Um sistema precisa filtrar listas dinamicamente no template. Um pipe filter pode ser útil, mas requer cuidado com performance.

### Tarefa

Crie um pipe `FilterPipe` com:

1. **Filtro Genérico**: Funciona com qualquer tipo de array
2. **Função Predicado**: Aceita função para filtrar
3. **Múltiplos Argumentos**: Suporta múltiplos critérios de filtro
4. **Type Safety**: Mantém type safety com generics
5. **Performance**: Considerar pure vs impure

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Pipe criado com generics
- [ ] Aceita função predicado
- [ ] Funciona com diferentes tipos
- [ ] Type safety mantido
- [ ] Documentação sobre pure/impure
- [ ] Exemplos de uso

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Generics usados corretamente
- [ ] Performance considerada
- [ ] Código é bem documentado

---

## Dicas

### Dica 1: Pipe com Generics

```typescript
@Pipe({
  name: 'filter',
  standalone: true
})
export class FilterPipe<T> implements PipeTransform {
  transform(items: T[], predicate: (item: T) => boolean): T[] {
    // implementação
  }
}
```

### Dica 2: Impure Pipe

```typescript
@Pipe({
  name: 'filter',
  standalone: true,
  pure: false
})
```

### Dica 3: Múltiplos Argumentos

```typescript
transform(items: T[], ...predicates: ((item: T) => boolean)[]): T[] {
  return items.filter(item => 
    predicates.every(predicate => predicate(item))
  );
}
```

---

## Solução Esperada

### Abordagem Recomendada

**filter.pipe.ts**
```typescript
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'filter',
  standalone: true,
  pure: false
})
export class FilterPipe<T> implements PipeTransform {
  transform(
    items: T[] | null | undefined,
    predicate: (item: T) => boolean
  ): T[] {
    if (!items || !predicate) {
      return items || [];
    }
    
    return items.filter(predicate);
  }
}

@Pipe({
  name: 'filterBy',
  standalone: true,
  pure: false
})
export class FilterByPipe<T> implements PipeTransform {
  transform(
    items: T[] | null | undefined,
    property: keyof T,
    value: any
  ): T[] {
    if (!items || !property) {
      return items || [];
    }
    
    return items.filter(item => item[property] === value);
  }
}

@Pipe({
  name: 'filterMultiple',
  standalone: true,
  pure: false
})
export class FilterMultiplePipe<T> implements PipeTransform {
  transform(
    items: T[] | null | undefined,
    ...predicates: ((item: T) => boolean)[]
  ): T[] {
    if (!items || predicates.length === 0) {
      return items || [];
    }
    
    return items.filter(item => 
      predicates.every(predicate => predicate(item))
    );
  }
}
```

**exemplo-uso.component.ts**
```typescript
import { Component } from '@angular/core';
import { FilterPipe, FilterByPipe, FilterMultiplePipe } from './filter.pipe';
import { CommonModule } from '@angular/common';

interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
  inStock: boolean;
}

@Component({
  selector: 'app-exemplo-uso',
  standalone: true,
  imports: [FilterPipe, FilterByPipe, FilterMultiplePipe, CommonModule],
  template: `
    <div class="filter-examples">
      <h2>Exemplos de Filter Pipes</h2>
      
      <div class="controls">
        <input 
          type="text" 
          [(ngModel)]="searchTerm"
          placeholder="Buscar produtos...">
        <select [(ngModel)]="selectedCategory">
          <option value="">Todas as categorias</option>
          <option value="Eletrônicos">Eletrônicos</option>
          <option value="Móveis">Móveis</option>
        </select>
        <label>
          <input type="checkbox" [(ngModel)]="onlyInStock">
          Apenas em estoque
        </label>
      </div>
      
      <div class="products">
        @for (product of getFilteredProducts(); track product.id) {
          <div class="product-card">
            <h3>{{ product.name }}</h3>
            <p>Categoria: {{ product.category }}</p>
            <p>Preço: {{ product.price | currency:'BRL' }}</p>
            <span [class.in-stock]="product.inStock">
              {{ product.inStock ? 'Em Estoque' : 'Fora de Estoque' }}
            </span>
          </div>
        } @empty {
          <p>Nenhum produto encontrado</p>
        }
      </div>
    </div>
  `
})
export class ExemploUsoComponent {
  products: Product[] = [
    { id: 1, name: 'Notebook', price: 2500, category: 'Eletrônicos', inStock: true },
    { id: 2, name: 'Mouse', price: 50, category: 'Eletrônicos', inStock: false },
    { id: 3, name: 'Mesa', price: 300, category: 'Móveis', inStock: true },
    { id: 4, name: 'Cadeira', price: 200, category: 'Móveis', inStock: true }
  ];
  
  searchTerm: string = '';
  selectedCategory: string = '';
  onlyInStock: boolean = false;
  
  getFilteredProducts(): Product[] {
    let filtered = this.products;
    
    if (this.searchTerm) {
      filtered = filtered.filter(p => 
        p.name.toLowerCase().includes(this.searchTerm.toLowerCase())
      );
    }
    
    if (this.selectedCategory) {
      filtered = filtered.filter(p => p.category === this.selectedCategory);
    }
    
    if (this.onlyInStock) {
      filtered = filtered.filter(p => p.inStock);
    }
    
    return filtered;
  }
}
```

**Explicação da Solução**:

1. Três pipes diferentes para diferentes casos de uso
2. `FilterPipe` genérico com função predicado
3. `FilterByPipe` para filtro simples por propriedade
4. `FilterMultiplePipe` para múltiplos predicados
5. Todos são impure porque dependem de mudanças externas
6. Type safety mantido com generics
7. Exemplo mostra uso prático

**Decisões de Design**:

- Impure pipes porque filtros podem mudar dinamicamente
- Múltiplos pipes para diferentes casos de uso
- Generics para type safety
- Método helper no componente para lógica complexa

**⚠️ Nota sobre Performance**:

Pipes impure são recalculados a cada change detection, o que pode impactar performance. Para listas grandes ou filtros complexos, considere:
- Mover lógica para componente
- Usar OnPush change detection
- Implementar debounce para busca

---

## Testes

### Casos de Teste

**Teste 1**: Filtro por função funciona
- **Input**: `products | filter:p => p.inStock`
- **Output Esperado**: Apenas produtos em estoque

**Teste 2**: Filtro por propriedade funciona
- **Input**: `products | filterBy:'category':'Eletrônicos'`
- **Output Esperado**: Apenas produtos da categoria

**Teste 3**: Múltiplos filtros funcionam
- **Input**: Múltiplos predicados
- **Output Esperado**: Produtos que atendem todos

**Teste 4**: Array vazio
- **Input**: `[] | filter:p => true`
- **Output Esperado**: Array vazio

---

## Extensões (Opcional)

1. **Filtro por Range**: Adicione filtro para ranges numéricos
2. **Filtro por Texto**: Adicione busca fuzzy
3. **Ordenação**: Combine com pipe de ordenação
4. **Cache**: Implemente cache para melhorar performance

---

## Referências Úteis

- **[Pure vs Impure Pipes](https://angular.io/guide/pipes#pure-and-impure-pipes)**: Explicação sobre pure/impure
- **[Pipe Performance](https://angular.io/guide/pipes#no-filter-pipe)**: Considerações de performance

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

