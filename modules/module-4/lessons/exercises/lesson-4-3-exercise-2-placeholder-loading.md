---
layout: exercise
title: "Exercício 4.3.2: Placeholder e Loading"
slug: "placeholder-loading"
lesson_id: "lesson-4-3"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **@placeholder e @loading** através da **criação de componente que usa @defer com estados de placeholder e loading**.

Ao completar este exercício, você será capaz de:

- Implementar @placeholder
- Implementar @loading
- Implementar @error
- Melhorar UX com estados apropriados
- Criar skeleton loaders

---

## Descrição

Você precisa criar um componente que usa @defer com @placeholder, @loading e @error states.

### Contexto

Uma aplicação precisa fornecer feedback visual adequado durante carregamento de componentes defer.

### Tarefa

Crie:

1. **@placeholder**: Criar placeholder content
2. **@loading**: Criar loading state
3. **@error**: Criar error state
4. **Component**: Componente completo com todos estados

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] @placeholder implementado
- [ ] @loading implementado
- [ ] @error implementado
- [ ] Estados funcionam corretamente
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Estados estão bem implementados
- [ ] UX é melhorada

---

## Solução Esperada

### Abordagem Recomendada

**product-list.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HeavyProductListComponent } from './heavy-product-list.component';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule, HeavyProductListComponent],
  template: `
    <div>
      <h2>Lista de Produtos</h2>
      
      @defer {
        <app-heavy-product-list></app-heavy-product-list>
      } @placeholder {
        <div class="placeholder">
          <h3>Preparando lista de produtos...</h3>
          <div class="skeleton">
            @for (item of skeletonItems; track item) {
              <div class="skeleton-item">
                <div class="skeleton-image"></div>
                <div class="skeleton-content">
                  <div class="skeleton-line"></div>
                  <div class="skeleton-line short"></div>
                </div>
              </div>
            }
          </div>
        </div>
      } @loading (minimum 500ms) {
        <div class="loading">
          <div class="spinner"></div>
          <p>Carregando produtos...</p>
        </div>
      } @error {
        <div class="error">
          <h3>Erro ao carregar produtos</h3>
          <p>Não foi possível carregar a lista de produtos.</p>
          <button (click)="retry()">Tentar novamente</button>
        </div>
      }
    </div>
  `,
  styles: [`
    .placeholder, .loading, .error {
      padding: 2rem;
    }
    
    .skeleton {
      margin-top: 1rem;
    }
    
    .skeleton-item {
      display: flex;
      gap: 1rem;
      padding: 1rem;
      margin-bottom: 1rem;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
    }
    
    .skeleton-image {
      width: 100px;
      height: 100px;
      background: #f0f0f0;
      border-radius: 4px;
      animation: pulse 1.5s ease-in-out infinite;
    }
    
    .skeleton-content {
      flex: 1;
    }
    
    .skeleton-line {
      height: 16px;
      background: #f0f0f0;
      border-radius: 4px;
      margin-bottom: 0.5rem;
      animation: pulse 1.5s ease-in-out infinite;
    }
    
    .skeleton-line.short {
      width: 60%;
    }
    
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    
    .loading {
      text-align: center;
    }
    
    .spinner {
      border: 4px solid #f3f3f3;
      border-top: 4px solid #3498db;
      border-radius: 50%;
      width: 50px;
      height: 50px;
      animation: spin 1s linear infinite;
      margin: 1rem auto;
    }
    
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    
    .error {
      text-align: center;
      color: #e74c3c;
    }
    
    .error button {
      margin-top: 1rem;
      padding: 0.75rem 1.5rem;
      background: #3498db;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
  `]
})
export class ProductListComponent {
  skeletonItems = [1, 2, 3, 4, 5];
  
  retry(): void {
    window.location.reload();
  }
}
```

**Explicação da Solução**:

1. @placeholder mostra skeleton loader
2. @loading mostra spinner após mínimo de 500ms
3. @error mostra mensagem de erro com retry
4. Estados melhoram UX significativamente
5. Animações tornam experiência mais polida

---

## Testes

### Casos de Teste

**Teste 1**: Placeholder aparece
- **Input**: Renderizar componente
- **Output Esperado**: Placeholder exibido inicialmente

**Teste 2**: Loading aparece
- **Input**: Durante carregamento
- **Output Esperado**: Loading state exibido

**Teste 3**: Error funciona
- **Input**: Simular erro
- **Output Esperado**: Error state exibido

---

## Extensões (Opcional)

1. **Custom Animations**: Adicione animações customizadas
2. **Progressive Loading**: Implemente loading progressivo
3. **Error Recovery**: Melhore recuperação de erros

---

## Referências Úteis

- **[@placeholder](https://angular.io/guide/defer#placeholder)**: Guia @placeholder
- **[@loading](https://angular.io/guide/defer#loading)**: Guia @loading
- **[@error](https://angular.io/guide/defer#error)**: Guia @error

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

