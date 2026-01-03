---
layout: exercise
title: "Exercício 3.5.1: toSignal() e toObservable()"
slug: "tosignal-toobservable"
lesson_id: "lesson-3-5"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **toSignal() e toObservable()** através da **conversão entre Signals e Observables**.

Ao completar este exercício, você será capaz de:

- Converter Observable para Signal usando toSignal()
- Converter Signal para Observable usando toObservable()
- Entender quando usar cada conversão
- Integrar Signals com código baseado em Observables
- Aplicar operadores RxJS em Signals

---

## Descrição

Você precisa criar componente que demonstra conversão bidirecional entre Signals e Observables.

### Contexto

Uma aplicação precisa integrar Signals com código existente baseado em Observables.

### Tarefa

Crie:

1. **toSignal()**: Converter Observable HTTP para Signal
2. **toObservable()**: Converter Signal para Observable
3. **Operators**: Aplicar operadores RxJS em Signal convertido
4. **Component**: Componente completo demonstrando ambas conversões

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] toSignal() usado para converter Observable
- [ ] toObservable() usado para converter Signal
- [ ] Operadores RxJS aplicados
- [ ] Conversões funcionam corretamente
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Conversões estão corretas
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**interop.component.ts**
```typescript
import { Component, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';
import { toObservable } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged, switchMap } from 'rxjs/operators';
import { of } from 'rxjs';

interface Product {
  id: number;
  name: string;
  price: number;
}

@Component({
  selector: 'app-interop',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Integração Signals + Observables</h2>
      
      <div class="section">
        <h3>1. Observable → Signal (toSignal)</h3>
        <button (click)="loadProducts()">Carregar Produtos</button>
        <ul>
          @for (product of products(); track product.id) {
            <li>{{ product.name }} - R$ {{ product.price }}</li>
          }
        </ul>
      </div>
      
      <div class="section">
        <h3>2. Signal → Observable (toObservable)</h3>
        <input 
          [value]="searchTerm()" 
          (input)="searchTerm.set($any($event.target).value)"
          placeholder="Buscar...">
        <p>Termo buscado: {{ searchTerm() }}</p>
        <p>Resultados: {{ searchResults().length }}</p>
        <ul>
          @for (result of searchResults(); track result.id) {
            <li>{{ result.name }}</li>
          }
        </ul>
      </div>
      
      <div class="section">
        <h3>3. Computed Signal</h3>
        <p>Total de produtos: {{ productCount() }}</p>
        <p>Preço total: R$ {{ totalPrice() }}</p>
      </div>
    </div>
  `,
  styles: [`
    .section {
      margin: 2rem 0;
      padding: 1rem;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
  `]
})
export class InteropComponent {
  private http = inject(HttpClient);
  
  searchTerm = signal('');
  
  products = toSignal(
    this.http.get<Product[]>('/api/products'),
    { initialValue: [] }
  );
  
  searchResults = toSignal(
    toObservable(this.searchTerm).pipe(
      debounceTime(300),
      distinctUntilChanged(),
      switchMap(term => {
        if (!term.trim()) {
          return of([]);
        }
        return this.http.get<Product[]>(`/api/products/search?q=${term}`);
      })
    ),
    { initialValue: [] }
  );
  
  productCount = computed(() => this.products().length);
  
  totalPrice = computed(() => 
    this.products().reduce((sum, p) => sum + p.price, 0)
  );
  
  loadProducts(): void {
    this.products = toSignal(
      this.http.get<Product[]>('/api/products'),
      { initialValue: [] }
    );
  }
}
```

**Explicação da Solução**:

1. toSignal() converte Observable HTTP para Signal
2. toObservable() converte Signal para Observable
3. Operadores RxJS aplicados no Observable convertido
4. Computed signals derivam valores dos Signals
5. Integração completa Signals + Observables
6. Código limpo e funcional

---

## Testes

### Casos de Teste

**Teste 1**: toSignal funciona
- **Input**: Carregar produtos
- **Output Esperado**: Produtos exibidos como Signal

**Teste 2**: toObservable funciona
- **Input**: Digitar no campo de busca
- **Output Esperado**: Busca funciona com debounce

**Teste 3**: Integração funciona
- **Input**: Usar ambos Signals e Observables
- **Output Esperado**: Tudo funciona corretamente

---

## Extensões (Opcional)

1. **Error Handling**: Adicione tratamento de erros
2. **Loading States**: Adicione estados de loading
3. **Caching**: Implemente cache de resultados

---

## Referências Úteis

- **[toSignal()](https://angular.io/api/core/rxjs-interop/toSignal)**: Documentação toSignal()
- **[toObservable()](https://angular.io/api/core/rxjs-interop/toObservable)**: Documentação toObservable()

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

