---
layout: exercise
title: "Exercício 3.1.4: Operators de Filtragem"
slug: "operators-filtragem"
lesson_id: "lesson-3-1"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **operators de filtragem** através da **implementação de busca com debounce e outros filtros**.

Ao completar este exercício, você será capaz de:

- Usar filter para filtrar valores
- Usar debounceTime para evitar requisições excessivas
- Usar throttleTime para limitar frequência
- Usar distinctUntilChanged para evitar valores duplicados
- Implementar busca eficiente

---

## Descrição

Você precisa criar um componente de busca que usa operators de filtragem para otimizar performance.

### Contexto

Uma aplicação precisa de busca que não faça requisições excessivas ao servidor.

### Tarefa

Crie:

1. **Busca com debounceTime**: Busca que espera usuário parar de digitar
2. **Filtro de valores**: Filtrar resultados baseado em critério
3. **distinctUntilChanged**: Evitar buscas duplicadas
4. **throttleTime**: Limitar frequência de eventos
5. **Componente completo**: Busca funcional e otimizada

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] debounceTime implementado
- [ ] filter implementado
- [ ] distinctUntilChanged implementado
- [ ] throttleTime implementado
- [ ] Busca funciona corretamente
- [ ] Performance otimizada

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Busca está otimizada
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**search-demo.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subject, of } from 'rxjs';
import { debounceTime, distinctUntilChanged, filter, throttleTime, switchMap, map } from 'rxjs/operators';

@Component({
  selector: 'app-search-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Operators de Filtragem</h2>
      
      <section>
        <h3>Busca com debounceTime</h3>
        <input 
          #searchInput
          (input)="onSearch(searchInput.value)"
          placeholder="Digite para buscar...">
        <p>Termo buscado: {{ searchTerm }}</p>
        <ul>
          @for (result of searchResults; track result) {
            <li>{{ result }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>Eventos com throttleTime</h3>
        <button #throttleBtn (click)="onThrottleClick()">Clique Rápido</button>
        <p>Cliques registrados: {{ throttleCount }}</p>
      </section>
      
      <section>
        <h3>Filtro de Valores</h3>
        <button (click)="demonstrateFilter()">Demonstrar filter()</button>
        <ul>
          @for (value of filteredValues; track value) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
    </div>
  `
})
export class SearchDemoComponent {
  searchTerm: string = '';
  searchResults: string[] = [];
  throttleCount: number = 0;
  filteredValues: number[] = [];
  
  private searchSubject = new Subject<string>();
  
  constructor() {
    this.setupSearch();
  }
  
  setupSearch(): void {
    this.searchSubject.pipe(
      debounceTime(300),
      distinctUntilChanged(),
      filter(term => term.length >= 2),
      switchMap(term => this.performSearch(term))
    ).subscribe({
      next: (results) => {
        this.searchResults = results;
      }
    });
  }
  
  onSearch(term: string): void {
    this.searchTerm = term;
    this.searchSubject.next(term);
  }
  
  onThrottleClick(): void {
    of(1).pipe(
      throttleTime(1000)
    ).subscribe(() => {
      this.throttleCount++;
    });
  }
  
  demonstrateFilter(): void {
    this.filteredValues = [];
    
    of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10).pipe(
      filter(x => x % 2 === 0),
      filter(x => x > 4)
    ).subscribe({
      next: (value) => {
        this.filteredValues.push(value);
      }
    });
  }
  
  private performSearch(term: string): Observable<string[]> {
    const mockResults = [
      `${term} - Resultado 1`,
      `${term} - Resultado 2`,
      `${term} - Resultado 3`
    ];
    return of(mockResults).pipe(
      delay(500)
    );
  }
}
```

**Explicação da Solução**:

1. debounceTime espera 300ms após último input
2. distinctUntilChanged evita buscas duplicadas
3. filter garante mínimo de 2 caracteres
4. switchMap cancela buscas anteriores
5. throttleTime limita frequência de cliques
6. Busca otimizada e eficiente

---

## Testes

### Casos de Teste

**Teste 1**: debounceTime funciona
- **Input**: Digitar rapidamente
- **Output Esperado**: Busca acontece apenas após parar de digitar

**Teste 2**: distinctUntilChanged funciona
- **Input**: Digitar mesmo termo duas vezes
- **Output Esperado**: Segunda busca não acontece

**Teste 3**: filter funciona
- **Input**: Digitar menos de 2 caracteres
- **Output Esperado**: Busca não acontece

---

## Extensões (Opcional)

1. **takeUntil**: Adicione cancelamento de busca
2. **take**: Adicione limite de resultados
3. **skip**: Adicione paginação

---

## Referências Úteis

- **[debounceTime](https://rxjs.dev/api/operators/debounceTime)**: Documentação debounceTime
- **[filter](https://rxjs.dev/api/operators/filter)**: Documentação filter
- **[distinctUntilChanged](https://rxjs.dev/api/operators/distinctUntilChanged)**: Documentação distinctUntilChanged

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

