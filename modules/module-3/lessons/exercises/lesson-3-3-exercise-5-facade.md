---
layout: exercise
title: "Exercício 3.3.5: Facade Pattern"
slug: "facade"
lesson_id: "lesson-3-3"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Facade Pattern** através da **criação de Facade que encapsula complexidade do NgRx**.

Ao completar este exercício, você será capaz de:

- Criar Facade service
- Encapsular Store, Actions e Selectors
- Fornecer API simples para componentes
- Melhorar separação de responsabilidades
- Facilitar testes e manutenção

---

## Descrição

Você precisa criar um Facade que encapsula toda a complexidade do NgRx para gerenciamento de produtos.

### Contexto

Uma aplicação precisa simplificar uso do NgRx em componentes através de Facade Pattern.

### Tarefa

Crie:

1. **Facade Service**: Serviço que encapsula NgRx
2. **API Simples**: Métodos simples para componentes
3. **Selectors Expostos**: Observables expostos via Facade
4. **Component**: Componente que usa Facade
5. **Comparação**: Demonstre diferença com e sem Facade

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Facade service criado
- [ ] Store encapsulado
- [ ] Actions encapsuladas
- [ ] Selectors expostos como Observables
- [ ] API simples e clara
- [ ] Component usa Facade
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Facade está bem estruturado
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**product.facade.ts**
```typescript
import { Injectable } from '@angular/core';
import { Store } from '@ngrx/store';
import { Observable } from 'rxjs';
import { Product } from './product.model';
import { ProductActions } from './product.actions';
import {
  selectAllProducts,
  selectLoading,
  selectError,
  selectProductById,
  selectExpensiveProducts
} from './product.selectors';

@Injectable({
  providedIn: 'root'
})
export class ProductFacade {
  products$: Observable<Product[]> = this.store.select(selectAllProducts);
  loading$: Observable<boolean> = this.store.select(selectLoading);
  error$: Observable<string | null> = this.store.select(selectError);
  expensiveProducts$: Observable<Product[]> = this.store.select(selectExpensiveProducts);
  
  constructor(private store: Store) {}
  
  loadProducts(): void {
    this.store.dispatch(ProductActions.loadProducts());
  }
  
  addProduct(product: Omit<Product, 'id'>): void {
    this.store.dispatch(ProductActions.addProduct({ product }));
  }
  
  updateProduct(id: number, changes: Partial<Product>): void {
    this.store.dispatch(ProductActions.updateProduct({ id, changes }));
  }
  
  deleteProduct(id: number): void {
    this.store.dispatch(ProductActions.deleteProduct({ id }));
  }
  
  getProductById(id: number): Observable<Product | undefined> {
    return this.store.select(selectProductById(id));
  }
}
```

**product-list.component.ts**
{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ProductFacade } from './store/product.facade';
import { Product } from './product.model';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Produtos (Facade Pattern)</h2>
      <button (click)="load()">Carregar</button>
      
      @if (facade.loading$ | async) {
        <p>Carregando...</p>
      }
      
      @if (facade.error$ | async) {
        <p class="error">{{ facade.error$ | async }}</p>
      }
      
      <ul>
        @for (product of facade.products$ | async; track product.id) {
          <li>
            {{ product.name }} - R$ {{ product.price }}
            <button (click)="delete(product.id)">Deletar</button>
          </li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class ProductListComponent implements OnInit {
  constructor(public facade: ProductFacade) {}
  
  ngOnInit(): void {
    this.load();
  }
  
  load(): void {
    this.facade.loadProducts();
  }
  
  delete(id: number): void {
    this.facade.deleteProduct(id);
  }
}
```

**Explicação da Solução**:

1. Facade encapsula Store, Actions e Selectors
2. Observables expostos diretamente
3. Métodos simples para dispatch actions
4. Component não conhece NgRx internamente
5. API limpa e fácil de usar
6. Facilita testes e manutenção

---

## Testes

### Casos de Teste

**Teste 1**: Facade funciona
- **Input**: Usar métodos do Facade
- **Output Esperado**: Funciona como esperado

**Teste 2**: Component simplificado
- **Input**: Comparar com componente sem Facade
- **Output Esperado**: Código mais simples

**Teste 3**: Testabilidade melhorada
- **Input**: Mockar Facade em testes
- **Output Esperado**: Testes mais fáceis

---

## Extensões (Opcional)

1. **Múltiplos Facades**: Crie Facades para diferentes features
2. **Facade Composition**: Compose múltiplos Facades
3. **Facade Testing**: Teste Facade isoladamente

---

## Referências Úteis

- **[Facade Pattern](https://ngrx.io/guide/store/selectors#using-selectors-for-multiple-pieces-of-state)**: Padrão Facade
- **[Best Practices](https://ngrx.io/guide/store/selectors#best-practices)**: Boas práticas NgRx

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

