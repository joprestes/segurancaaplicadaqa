---
layout: lesson
title: "Aula 4.2: Lazy Loading e Code Splitting"
slug: lazy-loading
module: module-4
lesson_id: lesson-4-2
duration: "120 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-4-1"
exercises:
  - 
  - "lesson-4-2-exercise-1"
  - "lesson-4-2-exercise-2"
  - "lesson-4-2-exercise-3"
  - "lesson-4-2-exercise-4"
  - "lesson-4-2-exercise-5"
podcast:
  file: "assets/podcasts/04.2-Lazy_Loading_e_Code_Splitting_na_Web.m4a"
  title: "Lazy Loading e Code Splitting na Web"
  description: "Otimize o carregamento inicial da sua aplicação com lazy loading avançado."
  duration: "55-70 minutos"
---

## Introdução

Nesta aula, você dominará lazy loading e code splitting no Angular. Essas técnicas são essenciais para criar aplicações grandes e performáticas, reduzindo o tamanho inicial do bundle e melhorando o tempo de carregamento.

### O que você vai aprender

- Implementar lazy loading de módulos e rotas
- Configurar estratégias de preloading
- Criar custom preloading strategies
- Otimizar code splitting
- Analisar e otimizar bundles
- Entender tree-shaking e minificação

### Por que isso é importante

Lazy loading é uma das técnicas mais importantes para performance em aplicações Angular grandes. Permite carregar código apenas quando necessário, reduzindo drasticamente o tamanho inicial do bundle e melhorando o tempo de carregamento inicial.

---

## Conceitos Teóricos

### Lazy Loading Básico

**Definição**: Lazy loading carrega módulos/rotas apenas quando são acessados, ao invés de carregar tudo no início.

**Explicação Detalhada**:

Lazy Loading:
- Carrega código sob demanda
- Reduz bundle inicial
- Melhora tempo de carregamento
- Usa loadChildren com função import()
- Cria chunks separados automaticamente

**Analogia**:

Lazy loading é como uma biblioteca onde você pega apenas os livros que precisa, ao invés de carregar todos os livros de uma vez.

**Visualização**:

```
Initial Bundle ──→ Main App
                     │
                     ├──→ Route 1 (Lazy) ──→ Chunk 1
                     ├──→ Route 2 (Lazy) ──→ Chunk 2
                     └──→ Route 3 (Lazy) ──→ Chunk 3
```

**Exemplo Prático**:

```typescript
import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: 'home',
    loadComponent: () => import('./home/home.component').then(m => m.HomeComponent)
  },
  {
    path: 'products',
    loadChildren: () => import('./products/products.routes').then(m => m.routes)
  },
  {
    path: 'admin',
    loadChildren: () => import('./admin/admin.routes').then(m => m.adminRoutes)
  }
];
```

---

### Preloading Strategies

**Definição**: Preloading strategies determinam quando e como módulos lazy-loaded são pré-carregados.

**Explicação Detalhada**:

Preloading Strategies:
- NoPreloading: Não pré-carrega nada
- PreloadAllModules: Pré-carrega tudo após inicialização
- Custom Preloading Strategy: Estratégia personalizada
- Melhora experiência do usuário
- Balanceia entre performance e UX

**Analogia**:

Preloading é como pré-carregar páginas de um site que o usuário provavelmente vai visitar, melhorando a experiência sem sobrecarregar o carregamento inicial.

**Exemplo Prático**:

```typescript
import { PreloadAllModules, RouterModule } from '@angular/router';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes, {
      preloadingStrategy: PreloadAllModules
    })
  ]
});
```

---

### Custom Preloading Strategy

**Definição**: Estratégia personalizada que decide quais módulos pré-carregar baseado em regras específicas.

**Explicação Detalhada**:

Custom Preloading:
- Implementa PreloadingStrategy interface
- Decide quais rotas pré-carregar
- Pode usar dados de rota (data property)
- Pode usar condições customizadas
- Flexível e poderoso

**Exemplo Prático**:

```typescript
import { PreloadingStrategy, Route } from '@angular/router';
import { Observable, of, timer } from 'rxjs';
import { mergeMap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class SelectivePreloadingStrategy implements PreloadingStrategy {
  preload(route: Route, load: () => Observable<any>): Observable<any> {
    if (route.data && route.data['preload']) {
      return load();
    }
    return of(null);
  }
}

export const routes: Routes = [
  {
    path: 'products',
    loadChildren: () => import('./products/products.routes').then(m => m.routes),
    data: { preload: true }
  },
  {
    path: 'admin',
    loadChildren: () => import('./admin/admin.routes').then(m => m.adminRoutes),
    data: { preload: false }
  }
];
```

---

### Code Splitting Avançado

**Definição**: Code splitting divide código em chunks menores e mais gerenciáveis.

**Explicação Detalhada**:

Code Splitting:
- Divide código em chunks
- Carrega chunks sob demanda
- Otimiza bundle size
- Melhora cacheability
- Facilita otimização

**Analogia**:

Code splitting é como dividir um livro grande em capítulos. Você carrega apenas os capítulos que precisa, não o livro inteiro.

**Exemplo Prático**:

```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-lazy',
  standalone: true,
  template: `<p>Lazy Component</p>`
})
export class LazyComponent {}

export const routes: Routes = [
  {
    path: 'lazy',
    loadComponent: () => import('./lazy.component').then(m => m.LazyComponent)
  }
];
```

---

### Tree-shaking

**Definição**: Tree-shaking remove código não utilizado do bundle final.

**Explicação Detalhada**:

Tree-shaking:
- Remove código morto
- Reduz bundle size
- Funciona melhor com ES modules
- Requer imports nomeados
- Automático no Angular

**Analogia**:

Tree-shaking é como podar uma árvore, removendo galhos mortos para deixá-la mais leve e saudável.

**Exemplo Prático**:

```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-optimized',
  standalone: true,
  imports: [CommonModule],
  template: `<p>Optimized</p>`
})
export class OptimizedComponent {}
```

---

### Bundle Analysis

**Definição**: Análise de bundles para entender tamanho e composição dos chunks.

**Explicação Detalhada**:

Bundle Analysis:
- Identifica bundles grandes
- Mostra dependências
- Ajuda a otimizar
- Usa ferramentas como webpack-bundle-analyzer
- Essencial para otimização

**Exemplo Prático**:

```bash
npm install --save-dev webpack-bundle-analyzer
ng build --stats-json
npx webpack-bundle-analyzer dist/stats.json
```

---

## Exemplos Práticos Completos

### Exemplo 1: Aplicação com Lazy Loading Completo

**Contexto**: Criar aplicação completa com lazy loading em todas rotas.

**Código**:

```typescript
import { Routes } from '@angular/router';
import { PreloadAllModules } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    redirectTo: '/home',
    pathMatch: 'full'
  },
  {
    path: 'home',
    loadComponent: () => import('./features/home/home.component').then(m => m.HomeComponent)
  },
  {
    path: 'products',
    loadChildren: () => import('./features/products/products.routes').then(m => m.routes)
  },
  {
    path: 'cart',
    loadComponent: () => import('./features/cart/cart.component').then(m => m.CartComponent)
  },
  {
    path: 'admin',
    loadChildren: () => import('./features/admin/admin.routes').then(m => m.adminRoutes),
    data: { requiresAuth: true }
  }
];

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes, {
      preloadingStrategy: PreloadAllModules
    })
  ]
});
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use lazy loading para rotas grandes**
   - **Por quê**: Reduz bundle inicial
   - **Exemplo**: `loadChildren: () => import(...)`

2. **Configure preloading strategy**
   - **Por quê**: Melhora UX sem sacrificar performance
   - **Exemplo**: `PreloadAllModules` ou custom strategy

3. **Analise bundles regularmente**
   - **Por quê**: Identifica oportunidades de otimização
   - **Exemplo**: webpack-bundle-analyzer

4. **Use imports nomeados**
   - **Por quê**: Melhor tree-shaking
   - **Exemplo**: `import { Component } from '@angular/core'`

### ❌ Anti-padrões Comuns

1. **Não carregar tudo no bundle inicial**
   - **Problema**: Bundle muito grande
   - **Solução**: Use lazy loading

2. **Não ignorar preloading**
   - **Problema**: UX ruim
   - **Solução**: Configure preloading strategy

3. **Não usar imports default desnecessariamente**
   - **Problema**: Tree-shaking menos eficiente
   - **Solução**: Use imports nomeados

---

## Exercícios Práticos

### Exercício 1: Lazy Loading Básico (Básico)

**Objetivo**: Implementar lazy loading básico

**Descrição**: 
Configure lazy loading para uma rota simples.

**Arquivo**: `exercises/exercise-4-2-1-lazy-basico.md`

---

### Exercício 2: Preloading Strategies (Intermediário)

**Objetivo**: Configurar preloading strategies

**Descrição**:
Configure diferentes estratégias de preloading e compare resultados.

**Arquivo**: `exercises/exercise-4-2-2-preloading.md`

---

### Exercício 3: Custom Preloading Strategy (Intermediário)

**Objetivo**: Criar custom preloading strategy

**Descrição**:
Crie estratégia personalizada que pré-carrega módulos baseado em condições.

**Arquivo**: `exercises/exercise-4-2-3-custom-preloading.md`

---

### Exercício 4: Bundle Analysis (Avançado)

**Objetivo**: Analisar e otimizar bundles

**Descrição**:
Analise bundles de aplicação e identifique oportunidades de otimização.

**Arquivo**: `exercises/exercise-4-2-4-bundle-analysis.md`

---

### Exercício 5: Otimização Completa (Avançado)

**Objetivo**: Otimizar aplicação completa

**Descrição**:
Aplique todas técnicas de lazy loading e code splitting em aplicação real.

**Arquivo**: `exercises/exercise-4-2-5-otimizacao-completa.md`

---

## Referências Externas

### Documentação Oficial

- **[Lazy Loading](https://angular.io/guide/lazy-loading-ngmodules)**: Guia lazy loading
- **[Preloading](https://angular.io/guide/router#preloading)**: Guia preloading
- **[Code Splitting](https://angular.io/guide/code-splitting)**: Guia code splitting

---

## Resumo

### Principais Conceitos

- Lazy loading carrega código sob demanda
- Preloading strategies melhoram UX
- Custom preloading oferece flexibilidade
- Code splitting divide código em chunks
- Tree-shaking remove código não usado
- Bundle analysis ajuda otimização

### Pontos-Chave para Lembrar

- Use lazy loading para rotas grandes
- Configure preloading strategy
- Analise bundles regularmente
- Use imports nomeados
- Otimize baseado em análise

### Próximos Passos

- Próxima aula: Deferrable Views e Performance
- Praticar lazy loading em aplicações
- Explorar otimizações avançadas

---

## Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 4.1: Change Detection Strategies](./lesson-4-1-change-detection.md)  
**Próxima Aula**: [Aula 4.3: Deferrable Views e Performance](./lesson-4-3-deferrable-views.md)  
**Voltar ao Módulo**: [Módulo 4: Performance e Otimização](../modules/module-4-performance-otimizacao.md)

