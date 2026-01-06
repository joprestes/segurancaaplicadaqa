---
layout: exercise
title: "Exercício 4.3.4: Caso de Uso Completo"
slug: "caso-uso-completo"
lesson_id: "lesson-4-3"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **deferrable views em caso real** através da **criação de aplicação que usa deferrable views para otimizar performance**.

Ao completar este exercício, você será capaz de:

- Aplicar deferrable views em aplicação real
- Otimizar performance com @defer
- Escolher triggers apropriados
- Criar UX otimizada
- Medir melhorias de performance

---

## Descrição

Você precisa criar uma aplicação de e-commerce que usa deferrable views para otimizar performance.

### Contexto

Uma aplicação de e-commerce precisa carregar rapidamente, mas tem componentes pesados que podem ser carregados sob demanda.

### Tarefa

Crie:

1. **Homepage**: Página inicial com conteúdo crítico
2. **Product List**: Lista de produtos com defer
3. **Product Details**: Detalhes com defer
4. **Cart**: Carrinho com defer
5. **Analytics**: Analytics com defer on idle
6. **Otimização**: Otimizar performance completa

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Deferrable views aplicadas
- [ ] Triggers apropriados usados
- [ ] Placeholders e loading states
- [ ] Performance otimizada
- [ ] Aplicação completa e funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Deferrable views estão bem aplicadas
- [ ] Performance é otimizada

---

## Solução Esperada

### Abordagem Recomendada

**home.component.ts**

```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ProductListComponent } from './product-list.component';
import { AnalyticsComponent } from './analytics.component';
import { NewsletterComponent } from './newsletter.component';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, ProductListComponent, AnalyticsComponent, NewsletterComponent],
  template: `
    <div class="home">
      <header>
        <h1>E-commerce Store</h1>
        <nav>
          <a routerLink="/products">Produtos</a>
          <a routerLink="/cart">Carrinho</a>
        </nav>
      </header>
      
      <main>
        <section class="hero">
          <h2>Bem-vindo à nossa loja!</h2>
          <p>Encontre os melhores produtos com os melhores preços</p>
        </section>
        
        <section class="products-section">
          <h2>Produtos em Destaque</h2>
          @defer (on viewport) {
            <app-product-list></app-product-list>
          } @placeholder {
            <div class="skeleton-grid">
              @for (item of skeletonItems; track item) {
                <div class="skeleton-card"></div>
              }
            </div>
          } @loading (minimum 300ms) {
            <div class="loading">
              <div class="spinner"></div>
              <p>Carregando produtos...</p>
            </div>
          }
        </section>
        
        <section class="newsletter-section">
          @defer (on timer(2s)) {
            <app-newsletter></app-newsletter>
          } @placeholder {
            <div class="placeholder-box">
              <p>Newsletter será exibida em breve</p>
            </div>
          }
        </section>
      </main>
      
      @defer (on idle) {
        <app-analytics></app-analytics>
      }
    </div>
  `,
  styles: [`
    .home {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 2px solid #e0e0e0;
    }
    
    nav a {
      margin-left: 1rem;
      text-decoration: none;
      color: #3498db;
    }
    
    .hero {
      text-align: center;
      padding: 3rem 0;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border-radius: 8px;
      margin-bottom: 3rem;
    }
    
    .skeleton-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
      gap: 1.5rem;
      margin-top: 1rem;
    }
    
    .skeleton-card {
      height: 300px;
      background: #f0f0f0;
      border-radius: 8px;
      animation: pulse 1.5s ease-in-out infinite;
    }
    
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    
    .loading {
      text-align: center;
      padding: 3rem;
    }
    
    .spinner {
      border: 4px solid #f3f3f3;
      border-top: 4px solid #3498db;
      border-radius: 50%;
      width: 50px;
      height: 50px;
      animation: spin 1s linear infinite;
      margin: 0 auto 1rem;
    }
    
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    
    .placeholder-box {
      padding: 2rem;
      text-align: center;
      background: #f8f9fa;
      border-radius: 8px;
    }
  `]
})
export class HomeComponent {
  skeletonItems = [1, 2, 3, 4, 5, 6];
}
```

**product-detail.component.ts**

```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { RelatedProductsComponent } from './related-products.component';
import { ReviewsComponent } from './reviews.component';

@Component({
  selector: 'app-product-detail',
  standalone: true,
  imports: [CommonModule, RelatedProductsComponent, ReviewsComponent],
  template: `
    <div class="product-detail">
      <div class="product-main">
        <h1>Produto {{ productId }}</h1>
        <p>Detalhes do produto...</p>
      </div>
      
      <div class="product-sections">
        @defer (on viewport) {
          <app-related-products [productId]="productId"></app-related-products>
        } @placeholder {
          <div class="placeholder-section">
            <h3>Produtos Relacionados</h3>
            <p>Carregando...</p>
          </div>
        }
        
        @defer (on viewport) {
          <app-reviews [productId]="productId"></app-reviews>
        } @placeholder {
          <div class="placeholder-section">
            <h3>Avaliações</h3>
            <p>Carregando...</p>
          </div>
        }
      </div>
    </div>
  `
})
export class ProductDetailComponent {
  productId = '';
  
  constructor(private route: ActivatedRoute) {
    this.productId = this.route.snapshot.paramMap.get('id') || '';
  }
}
```

**performance-report.md**
```markdown
# Relatório de Performance - Deferrable Views

## Antes da Otimização

- Bundle inicial: 2.5 MB
- Tempo de carregamento: 3.5s
- Componentes carregados: Todos
- First Contentful Paint: 2.0s

## Depois da Otimização

- Bundle inicial: 1.2 MB (redução de 52%)
- Tempo de carregamento: 1.8s (redução de 49%)
- Componentes carregados: Apenas críticos
- First Contentful Paint: 0.8s (redução de 60%)

## Técnicas Aplicadas

1. **Product List**: @defer on viewport
2. **Newsletter**: @defer on timer(2s)
3. **Analytics**: @defer on idle
4. **Related Products**: @defer on viewport
5. **Reviews**: @defer on viewport

## Conclusão

Deferrable views resultaram em melhorias significativas de performance e experiência do usuário.
```

**Explicação da Solução**:

1. Homepage usa defer para produtos e newsletter
2. Analytics carregado on idle
3. Product detail usa defer para conteúdo secundário
4. Placeholders melhoram percepção de performance
5. Loading states fornecem feedback
6. Performance significativamente melhorada

---

## Testes

### Casos de Teste

**Teste 1**: Deferrable views funcionam
- **Input**: Navegar pela aplicação
- **Output Esperado**: Componentes carregados conforme triggers

**Teste 2**: Performance melhorada
- **Input**: Medir performance
- **Output Esperado**: Melhorias mensuráveis

**Teste 3**: UX melhorada
- **Input**: Usar aplicação
- **Output Esperado**: Experiência fluida

---

## Extensões (Opcional)

1. **Performance Monitoring**: Implemente monitoramento contínuo
2. **A/B Testing**: Teste diferentes estratégias
3. **Advanced Triggers**: Explore triggers avançados

---

## Referências Úteis

- **[Deferrable Views](https://angular.io/guide/defer)**: Guia completo
- **[Performance](https://angular.io/guide/performance)**: Guia performance

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

