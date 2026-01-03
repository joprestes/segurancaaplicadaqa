---
layout: exercise
title: "Exercício 3.1.8: Padrão Completo com RxJS"
slug: "padrao-completo"
lesson_id: "lesson-3-1"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **todas as técnicas de RxJS** através da **criação de serviço completo que usa todos os operators aprendidos**.

Ao completar este exercício, você será capaz de:

- Combinar todos os operators aprendidos
- Criar padrão reativo completo e eficiente
- Implementar busca avançada com todas otimizações
- Tratar erros adequadamente
- Criar código reutilizável e manutenível

---

## Descrição

Você precisa criar um serviço de busca completo que usa todos os operators RxJS aprendidos: transformação, combinação, filtragem, tratamento de erros e compartilhamento.

### Contexto

Uma aplicação precisa de serviço de busca robusto e otimizado que demonstra uso correto de todos os operators RxJS.

### Tarefa

Crie:

1. **Serviço Completo**: Busca com todos os operators
2. **Debounce**: Evitar requisições excessivas
3. **Distinct**: Evitar buscas duplicadas
4. **SwitchMap**: Cancelar requisições anteriores
5. **Retry**: Retry em caso de erro
6. **ShareReplay**: Cache de resultados
7. **Tratamento de Erros**: Fallbacks apropriados

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Todos os operators aplicados
- [ ] Busca otimizada
- [ ] Tratamento de erros completo
- [ ] Cache implementado
- [ ] Retry implementado
- [ ] Código completo e funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todos os padrões estão aplicados
- [ ] Código é bem organizado

---

## Solução Esperada

### Abordagem Recomendada

**advanced-search.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, Subject, throwError, of } from 'rxjs';
import { 
  debounceTime, 
  distinctUntilChanged, 
  filter, 
  switchMap, 
  retry, 
  catchError, 
  shareReplay,
  map,
  tap
} from 'rxjs/operators';

export interface SearchResult {
  id: number;
  title: string;
  description: string;
}

@Injectable({
  providedIn: 'root'
})
export class AdvancedSearchService {
  private searchSubject = new Subject<string>();
  private searchResults$: Observable<SearchResult[]>;
  
  constructor(private http: HttpClient) {
    this.setupSearch();
  }
  
  private setupSearch(): void {
    this.searchResults$ = this.searchSubject.pipe(
      debounceTime(300),
      distinctUntilChanged(),
      filter(term => term.length >= 2),
      switchMap(term => 
        this.performSearch(term).pipe(
          retry({
            count: 2,
            delay: 1000
          }),
          catchError(this.handleSearchError)
        )
      ),
      shareReplay(1)
    );
  }
  
  search(term: string): void {
    this.searchSubject.next(term);
  }
  
  getResults(): Observable<SearchResult[]> {
    return this.searchResults$;
  }
  
  private performSearch(term: string): Observable<SearchResult[]> {
    return this.http.get<SearchResult[]>(`/api/search?q=${term}`).pipe(
      map(results => results.map(r => ({
        ...r,
        title: this.highlightTerm(r.title, term)
      }))),
      tap(results => console.log(`Search completed: ${results.length} results`))
    );
  }
  
  private handleSearchError(error: HttpErrorResponse): Observable<SearchResult[]> {
    console.error('Search error:', error);
    
    if (error.status === 0) {
      return of([{
        id: -1,
        title: 'Erro de conexão',
        description: 'Verifique sua conexão com a internet'
      }]);
    }
    
    return of([]);
  }
  
  private highlightTerm(text: string, term: string): string {
    const regex = new RegExp(`(${term})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
  }
}
```

**advanced-search.component.ts**
{% raw %}
```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { AdvancedSearchService, SearchResult } from './advanced-search.service';

@Component({
  selector: 'app-advanced-search',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Busca Avançada com RxJS</h2>
      
      <div class="search-box">
        <input 
          #searchInput
          type="text"
          (input)="onSearch(searchInput.value)"
          placeholder="Digite para buscar...">
        @if (loading) {
          <span class="loading">Buscando...</span>
        }
      </div>
      
      @if (error) {
        <div class="error">{{ error }}</div>
      }
      
      @if (results.length > 0) {
        <ul class="results">
          @for (result of results; track result.id) {
            <li>
              <h3 [innerHTML]="result.title"></h3>
              <p>{{ result.description }}</p>
            </li>
          }
        </ul>
      } @else if (!loading && searchTerm.length >= 2) {
        <p>Nenhum resultado encontrado</p>
      }
    </div>
  `,
  styles: [`
    .search-box {
      margin-bottom: 1rem;
    }
    
    input {
      width: 100%;
      padding: 0.5rem;
    }
    
    .loading {
      color: #666;
      font-style: italic;
    }
    
    .error {
      color: #f44336;
      padding: 1rem;
      background-color: #ffebee;
      border-radius: 4px;
    }
    
    .results {
      list-style: none;
      padding: 0;
    }
    
    .results li {
      padding: 1rem;
      margin-bottom: 0.5rem;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    
    mark {
      background-color: yellow;
    }
  `]
})
export class AdvancedSearchComponent implements OnInit, OnDestroy {
  searchTerm: string = '';
  results: SearchResult[] = [];
  loading: boolean = false;
  error: string = '';
  private subscription?: Subscription;
  
  constructor(private searchService: AdvancedSearchService) {}
  
  ngOnInit(): void {
    this.subscription = this.searchService.getResults().subscribe({
      next: (results) => {
        this.results = results;
        this.loading = false;
        this.error = '';
      },
      error: (error) => {
        this.error = error.message;
        this.loading = false;
      }
    });
  }
  
  onSearch(term: string): void {
    this.searchTerm = term;
    if (term.length >= 2) {
      this.loading = true;
      this.searchService.search(term);
    } else {
      this.results = [];
      this.loading = false;
    }
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. debounceTime evita requisições excessivas
2. distinctUntilChanged evita buscas duplicadas
3. filter garante mínimo de caracteres
4. switchMap cancela requisições anteriores
5. retry tenta novamente em caso de erro
6. catchError trata erros com fallback
7. shareReplay cache resultados
8. Padrão completo e otimizado

---

## Testes

### Casos de Teste

**Teste 1**: Busca funciona
- **Input**: Digitar termo de busca
- **Output Esperado**: Resultados aparecem após debounce

**Teste 2**: Debounce funciona
- **Input**: Digitar rapidamente
- **Output Esperado**: Apenas uma busca acontece

**Teste 3**: Retry funciona
- **Input**: Simular erro temporário
- **Output Esperado**: Retry automático

**Teste 4**: Cache funciona
- **Input**: Buscar mesmo termo duas vezes
- **Output Esperado**: Segunda busca usa cache

---

## Extensões (Opcional)

1. **Pagination**: Adicione paginação
2. **Filters**: Adicione filtros adicionais
3. **History**: Mantenha histórico de buscas

---

## Referências Úteis

- **[RxJS Guide](https://rxjs.dev/guide/overview)**: Guia completo RxJS
- **[All Operators](https://rxjs.dev/api/operators)**: Todos os operators

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

