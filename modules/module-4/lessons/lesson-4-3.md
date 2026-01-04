---
layout: lesson
title: "Aula 4.3: Deferrable Views e Performance"
slug: deferrable-views
module: module-4
lesson_id: lesson-4-3
duration: "90 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-4-2"
exercises:
  - 
  - "lesson-4-3-exercise-1"
  - "lesson-4-3-exercise-2"
  - "lesson-4-3-exercise-3"
  - "lesson-4-3-exercise-4"
podcast:
  file: "assets/podcasts/04.3-Angular_Deferrable_Views_no_Codigo_defer_.m4a"
  image: "assets/images/podcasts/04.3-Angular_Deferrable_Views_no_Codigo_defer_.png"
  title: "Angular Deferrable Views no Código (@defer)"
  description: "Deferrable Views são a nova forma de lazy loading de componentes no Angular."
  duration: "50-65 minutos"
permalink: /modules/performance-otimizacao/lessons/deferrable-views/
---

## Introdução

Nesta aula, você dominará Deferrable Views, uma feature poderosa do Angular 17+ que permite carregar componentes e templates sob demanda. Esta é uma das técnicas mais modernas e eficientes para otimizar performance em aplicações Angular.

### O que você vai aprender

- Usar @defer block para carregamento sob demanda
- Implementar @placeholder, @loading e @error
- Configurar triggers (on idle, on timer, on viewport, on interaction)
- Otimizar performance com deferrable views
- Aplicar em casos de uso práticos

### Por que isso é importante

Deferrable Views permitem carregar componentes apenas quando necessário, reduzindo o bundle inicial e melhorando significativamente o tempo de carregamento. É especialmente útil para componentes pesados, modais, e conteúdo abaixo da dobra (below the fold).

---

## Conceitos Teóricos

### @defer Block

**Definição**: `@defer` block permite carregar componentes e templates sob demanda, melhorando performance.

**Explicação Detalhada**:

@defer Block:
- Carrega conteúdo sob demanda
- Reduz bundle inicial
- Melhora tempo de carregamento
- Suporta múltiplos triggers
- Integrado com Angular

**Analogia**:

@defer é como uma porta que só abre quando você realmente precisa entrar, economizando energia e recursos.

**Visualização**:

```
Template ──@defer──→ Component (Lazy)
    │                    │
    ├──@placeholder──→ Placeholder Content
    ├──@loading─────→ Loading State
    └──@error───────→ Error State
```

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-defer',
  standalone: true,
  template: `
    <div>
      <h2>Conteúdo Principal</h2>
      
      @defer {
        <app-heavy-component></app-heavy-component>
      }
    </div>
  `
})
export class DeferComponent {}
```

---

### @placeholder

**Definição**: `@placeholder` define conteúdo exibido enquanto componente defer está sendo carregado.

**Explicação Detalhada**:

@placeholder:
- Exibido antes do carregamento
- Melhora percepção de performance
- Pode conter skeleton loaders
- Opcional mas recomendado
- Melhora UX

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-defer-placeholder',
  standalone: true,
  template: `
    @defer {
      <app-heavy-component></app-heavy-component>
    } @placeholder {
      <div class="skeleton">
        <div class="skeleton-line"></div>
        <div class="skeleton-line"></div>
      </div>
    }
  `
})
export class DeferPlaceholderComponent {}
```

---

### @loading e @error

**Definição**: `@loading` exibe conteúdo durante carregamento e `@error` exibe em caso de erro.

**Explicação Detalhada**:

@loading e @error:
- @loading: Durante carregamento do componente
- @error: Se carregamento falhar
- Melhoram feedback ao usuário
- Opcionais mas recomendados
- Essenciais para boa UX

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-defer-states',
  standalone: true,
  template: `
    @defer {
      <app-heavy-component></app-heavy-component>
    } @placeholder {
      <div>Preparando...</div>
    } @loading (minimum 500ms) {
      <div>Carregando...</div>
    } @error {
      <div>Erro ao carregar componente</div>
    }
  `
})
export class DeferStatesComponent {}
```

---

### Triggers

**Definição**: Triggers determinam quando componente defer é carregado.

**Explicação Detalhada**:

Triggers:
- on idle: Quando navegador está idle
- on timer: Após tempo especificado
- on viewport: Quando entra no viewport
- on interaction: Quando usuário interage
- on hover: Quando mouse passa sobre
- on immediate: Imediatamente
- Combináveis para controle fino

**Analogia**:

Triggers são como sensores que detectam quando é o momento certo para carregar o conteúdo.

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-defer-triggers',
  standalone: true,
  template: `
    @defer (on viewport) {
      <app-heavy-component></app-heavy-component>
    } @placeholder {
      <div>Role para baixo para carregar</div>
    }
    
    @defer (on timer(2s)) {
      <app-ad-component></app-ad-component>
    }
    
    @defer (on idle) {
      <app-analytics></app-analytics>
    }
    
    @defer (on interaction(button)) {
      <app-modal></app-modal>
    } @placeholder {
      <button #button>Abrir Modal</button>
    }
  `
})
export class DeferTriggersComponent {}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Defer Completo com Todos Estados

**Contexto**: Criar componente que usa defer com todos estados e triggers.

**Código**:

```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HeavyComponent } from './heavy.component';

@Component({
  selector: 'app-defer-complete',
  standalone: true,
  imports: [CommonModule, HeavyComponent],
  template: `
    <div>
      <h2>Conteúdo Principal</h2>
      <p>Este conteúdo é carregado imediatamente</p>
      
      @defer (on viewport) {
        <app-heavy-component></app-heavy-component>
      } @placeholder {
        <div class="placeholder">
          <p>Conteúdo pesado será carregado quando visível</p>
          <div class="skeleton">
            <div class="skeleton-item"></div>
            <div class="skeleton-item"></div>
            <div class="skeleton-item"></div>
          </div>
        </div>
      } @loading (minimum 300ms) {
        <div class="loading">
          <p>Carregando componente pesado...</p>
          <div class="spinner"></div>
        </div>
      } @error {
        <div class="error">
          <p>Erro ao carregar componente</p>
          <button (click)="retry()">Tentar novamente</button>
        </div>
      }
    </div>
  `,
  styles: [`
    .placeholder, .loading, .error {
      padding: 2rem;
      text-align: center;
    }
    
    .skeleton {
      margin-top: 1rem;
    }
    
    .skeleton-item {
      height: 20px;
      background: #f0f0f0;
      margin-bottom: 0.5rem;
      border-radius: 4px;
      animation: pulse 1.5s ease-in-out infinite;
    }
    
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    
    .spinner {
      border: 3px solid #f3f3f3;
      border-top: 3px solid #3498db;
      border-radius: 50%;
      width: 40px;
      height: 40px;
      animation: spin 1s linear infinite;
      margin: 1rem auto;
    }
    
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
  `]
})
export class DeferCompleteComponent {
  retry(): void {
    window.location.reload();
  }
}
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use @defer para componentes pesados**
   - **Por quê**: Reduz bundle inicial
   - **Exemplo**: Modais, gráficos, componentes grandes

2. **Sempre forneça @placeholder**
   - **Por quê**: Melhora percepção de performance
   - **Exemplo**: Skeleton loaders

3. **Use triggers apropriados**
   - **Por quê**: Carrega no momento certo
   - **Exemplo**: on viewport para conteúdo abaixo da dobra

4. **Trate erros com @error**
   - **Por quê**: Melhor UX em caso de falha
   - **Exemplo**: Mensagem de erro e retry

### ❌ Anti-padrões Comuns

1. **Não usar @defer para componentes críticos**
   - **Problema**: Delay desnecessário
   - **Solução**: Use apenas para componentes não críticos

2. **Não esquecer @placeholder**
   - **Problema**: Layout shift
   - **Solução**: Sempre forneça placeholder

3. **Não usar triggers inadequados**
   - **Problema**: Carregamento no momento errado
   - **Solução**: Escolha trigger apropriado

---

## Exercícios Práticos

### Exercício 1: @defer Básico (Básico)

**Objetivo**: Implementar @defer básico

**Descrição**: 
Crie componente que usa @defer para carregar componente pesado.

**Arquivo**: `exercises/exercise-4-3-1-defer-basico.md`

---

### Exercício 2: Placeholder e Loading (Intermediário)

**Objetivo**: Implementar @placeholder e @loading

**Descrição**:
Crie componente que usa @defer com @placeholder e @loading states.

**Arquivo**: `exercises/exercise-4-3-2-placeholder-loading.md`

---

### Exercício 3: Triggers (Intermediário)

**Objetivo**: Trabalhar com diferentes triggers

**Descrição**:
Crie componente que demonstra diferentes triggers (@defer).

**Arquivo**: `exercises/exercise-4-3-3-triggers.md`

---

### Exercício 4: Caso de Uso Completo (Avançado)

**Objetivo**: Aplicar deferrable views em caso real

**Descrição**:
Crie aplicação que usa deferrable views para otimizar performance.

**Arquivo**: `exercises/exercise-4-3-4-caso-uso-completo.md`

---

## Referências Externas

### Documentação Oficial

- **[Deferrable Views](https://angular.io/guide/defer)**: Guia completo
- **[@defer](https://angular.io/api/core/defer)**: Documentação @defer

---

## Resumo

### Principais Conceitos

- @defer carrega componentes sob demanda
- @placeholder melhora percepção de performance
- @loading e @error melhoram feedback
- Triggers controlam quando carregar
- Deferrable views melhoram performance significativamente

### Pontos-Chave para Lembrar

- Use @defer para componentes pesados
- Sempre forneça @placeholder
- Use triggers apropriados
- Trate erros com @error
- Otimize baseado em casos de uso

### Próximos Passos

- Próxima aula: Profiling e Otimização
- Praticar deferrable views em aplicações
- Explorar triggers avançados

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

**Aula Anterior**: [Aula 4.2: Lazy Loading e Code Splitting](./lesson-4-2-lazy-loading.md)  
**Próxima Aula**: [Aula 4.4: Profiling e Otimização](./lesson-4-4-profiling.md)  
**Voltar ao Módulo**: [Módulo 4: Performance e Otimização](../modules/module-4-performance-otimizacao.md)

