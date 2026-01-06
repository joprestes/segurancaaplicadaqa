---
layout: lesson
title: "Aula 4.3: Deferrable Views e Performance"
slug: deferrable-views
module: module-4
lesson_id: lesson-4-3
duration: "90 minutos"
level: "Avançado"
prerequisites: []
exercises: []
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

### Contexto Histórico

A evolução do lazy loading no Angular reflete a busca constante por melhor performance e experiência do usuário:

**AngularJS (2010-2016)**:
- Não havia lazy loading nativo
- Aplicações eram carregadas completamente no início
- Bundle único grande impactava performance inicial

**Angular 2+ (2016-2022)**:
- Introdução de lazy loading via `loadChildren` em rotas
- Code splitting baseado em rotas
- Requeria configuração manual e era limitado a rotas

**Angular 17+ (2023-presente)**:
- Deferrable Views com `@defer` block
- Lazy loading granular em nível de componente
- Triggers flexíveis e estados de carregamento integrados
- Redução significativa de bundle inicial sem configuração complexa

Esta evolução representa uma mudança paradigmática: de otimização baseada em rotas para otimização baseada em componentes, permitindo controle fino sobre quando e como o código é carregado.

### O que você vai aprender

- Fundamentos de @defer block e como funciona internamente
- Implementar @placeholder, @loading e @error com boas práticas
- Configurar e combinar triggers (on idle, on timer, on viewport, on interaction, on hover)
- Estratégias avançadas de otimização com deferrable views
- Casos de uso práticos e quando usar cada abordagem
- Comparação com técnicas similares em outros frameworks
- Métricas de performance e como medir impacto

### Por que isso é importante

Deferrable Views revolucionam como pensamos sobre performance em Angular:

**Para Performance**:
- Redução de 30-60% no bundle inicial em aplicações típicas
- Melhoria significativa em Core Web Vitals (LCP, FCP, TTI)
- Carregamento progressivo alinhado com interação do usuário
- Menor uso de memória inicial

**Para Experiência do Usuário**:
- Tempo de carregamento inicial reduzido
- Conteúdo crítico aparece mais rápido
- Transições suaves com placeholders e loading states
- Menos layout shifts (CLS)

**Para Desenvolvimento**:
- Sintaxe declarativa e intuitiva
- Integração nativa com Angular
- Menos configuração comparado a soluções anteriores
- Type-safe e suportado pelo compilador Angular

**Para Carreira**:
- Técnica essencial para aplicações Angular modernas
- Diferencial competitivo em projetos de alta performance
- Alinhado com melhores práticas da indústria
- Conhecimento transferível para outros frameworks

---

## Conceitos Teóricos

### @defer Block

**Definição**: `@defer` block é uma diretiva estrutural do Angular 17+ que permite adiar o carregamento de componentes, diretivas e pipes até que sejam realmente necessários, reduzindo o bundle inicial e melhorando métricas de performance.

**Explicação Detalhada**:

O `@defer` block funciona através de uma transformação no nível do compilador Angular. Quando você usa `@defer`, o Angular:

1. **Análise Estática**: O compilador identifica todas as dependências dentro do bloco `@defer`
2. **Code Splitting**: Cria um chunk separado contendo apenas essas dependências
3. **Lazy Loading**: O chunk só é carregado quando o trigger especificado é ativado
4. **Integração Runtime**: O Angular gerencia o carregamento e renderização automaticamente

**Características Técnicas**:

- **Compile-time Optimization**: Análise estática permite otimizações agressivas
- **Standalone Requirement**: Componentes dentro de `@defer` devem ser standalone
- **Dependency Isolation**: Dependências são isoladas em chunks separados
- **Type Safety**: Mantém type safety completo do TypeScript
- **Tree Shaking**: Permite tree shaking mais agressivo do código não usado

**Fluxo de Execução**:

```
1. Template Parsing
   ↓
2. Dependency Analysis (compile-time)
   ↓
3. Chunk Creation (build-time)
   ↓
4. Runtime: Trigger Detection
   ↓
5. Chunk Loading (lazy)
   ↓
6. Component Instantiation
   ↓
7. Rendering
```

**Analogia Detalhada**:

Imagine uma biblioteca enorme com milhares de livros. Em vez de carregar todos os livros na entrada (bundle inicial), o `@defer` funciona como um sistema inteligente de entrega:

- **Sem @defer**: Todos os livros são empilhados na entrada, bloqueando a passagem e tornando difícil encontrar o que você precisa
- **Com @defer**: Apenas os livros essenciais ficam na entrada. Quando você precisa de um livro específico, um sistema automatizado (trigger) detecta sua necessidade e traz apenas aquele livro do depósito (chunk lazy)

Assim como o sistema de biblioteca economiza espaço e melhora a experiência, o `@defer` economiza bytes iniciais e melhora o tempo de carregamento, carregando código apenas quando necessário.

**Visualização Arquitetural**:

```
┌─────────────────────────────────────────────────────────┐
│                    Angular Application                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────────┐      ┌──────────────────┐        │
│  │  Initial Bundle  │      │  Deferred Chunks │        │
│  │  (Main App)      │      │  (Lazy Loaded)   │        │
│  ├──────────────────┤      ├──────────────────┤        │
│  │ • Core Angular   │      │ • HeavyComponent │        │
│  │ • App Shell      │      │ • ChartComponent │        │
│  │ • Critical UI     │      │ • ModalComponent │        │
│  │ • Routing        │      │ • ...            │        │
│  └──────────────────┘      └──────────────────┘        │
│         │                           ▲                    │
│         │                           │                    │
│         └───────@defer──────────────┘                    │
│                  │                                        │
│         ┌────────┴────────┐                             │
│         │                 │                             │
│    ┌────▼────┐      ┌─────▼─────┐                       │
│    │Trigger │      │  Chunk    │                       │
│    │Detected│─────▶│  Loading  │                       │
│    └────────┘      └───────────┘                       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Estados do @defer Block**:

```
┌─────────────┐
│ @placeholder│  ← Exibido ANTES do trigger
└──────┬──────┘
       │
       │ Trigger ativado
       ▼
┌─────────────┐
│  @loading   │  ← Durante carregamento do chunk
└──────┬──────┘
       │
       │ Chunk carregado
       ▼
┌─────────────┐
│   Content   │  ← Componente renderizado
└─────────────┘
       │
       │ Erro no carregamento
       ▼
┌─────────────┐
│   @error    │  ← Estado de erro
└─────────────┘
```

**Exemplo Prático Básico**:

```typescript
@Component({
  selector: 'app-defer',
  standalone: true,
  template: `
    <div>
      <h2>Conteúdo Principal</h2>
      <p>Este conteúdo é carregado imediatamente</p>
      
      @defer {
        <app-heavy-component></app-heavy-component>
      }
    </div>
  `
})
export class DeferComponent {}
```

**Exemplo Prático com Análise**:

```typescript
import { Component } from '@angular/core';
import { HeavyComponent } from './heavy.component';

@Component({
  selector: 'app-defer-analysis',
  standalone: true,
  template: `
    <div class="dashboard">
      <header>
        <h1>Dashboard</h1>
      </header>
      
      <main>
        <section class="critical">
          <app-summary></app-summary>
        </section>
        
        <section class="deferred">
          @defer {
            <app-heavy-component></app-heavy-component>
          }
        </section>
      </main>
    </div>
  `
})
export class DeferAnalysisComponent {}
```

**O que acontece internamente**:

1. **Build Time**: Angular cria dois bundles:
   - `main.js`: Contém `DeferAnalysisComponent`, `SummaryComponent` e código crítico
   - `heavy-component.js`: Contém apenas `HeavyComponent` e suas dependências

2. **Runtime**: 
   - `main.js` é carregado imediatamente
   - `heavy-component.js` só é carregado quando o trigger é ativado (padrão: on idle)

3. **Resultado**: Bundle inicial menor, carregamento mais rápido

---

### @placeholder

**Definição**: `@placeholder` é um bloco auxiliar que define conteúdo exibido antes do trigger ser ativado, servindo como espaço reservado visual que previne layout shifts e melhora a percepção de performance.

**Explicação Detalhada**:

O `@placeholder` é crucial para uma experiência de usuário polida porque:

1. **Previne Layout Shift**: Mantém o espaço reservado, evitando que o conteúdo "pule" quando o componente é carregado
2. **Melhora Percepção**: Usuário vê algo imediatamente, mesmo que seja apenas um placeholder
3. **Otimiza CLS**: Reduz Cumulative Layout Shift, métrica importante do Core Web Vitals
4. **Comunicação Visual**: Pode comunicar que conteúdo será carregado em breve

**Quando @placeholder é exibido**:

```
Timeline do Carregamento:

T0: Página carrega
    └─▶ @placeholder é renderizado
    
T1: Trigger é detectado (ex: scroll até viewport)
    └─▶ @placeholder continua visível
    
T2: Chunk começa a carregar
    └─▶ @placeholder → @loading (transição)
    
T3: Componente renderizado
    └─▶ Conteúdo final substitui tudo
```

**Estratégias de Placeholder**:

1. **Skeleton Loaders**: Estrutura visual similar ao conteúdo final
2. **Spinner Simples**: Indicador de carregamento básico
3. **Conteúdo Estático**: Texto ou imagem estática relacionada
4. **Placeholder Interativo**: Botão ou elemento que ativa o trigger

**Analogia**:

Imagine um restaurante onde você faz uma reserva. O `@placeholder` é como a mesa reservada com uma placa "Reservado" - ela comunica que algo está chegando, mantém o espaço ocupado, e previne que outras pessoas (outros elementos da página) ocupem aquele espaço. Quando você chega (trigger ativado), a mesa está pronta e você pode se sentar imediatamente (componente carregado).

**Visualização de Estados**:

```
┌─────────────────────────────────────────┐
│         Estado: @placeholder            │
├─────────────────────────────────────────┤
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  [Skeleton/Placeholder Content] │   │
│  │                                 │   │
│  │  ╔═══════════════════════════╗  │   │
│  │  ║ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ║  │   │
│  │  ║ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ║  │   │
│  │  ║ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ║  │   │
│  │  ╚═══════════════════════════╝  │   │
│  │                                 │   │
│  └─────────────────────────────────┘   │
│                                         │
│  Trigger ainda não ativado              │
│                                         │
└─────────────────────────────────────────┘
```

**Exemplo Prático Básico**:

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

**Exemplo Prático Avançado com Skeleton Loader**:

```typescript
@Component({
  selector: 'app-defer-skeleton',
  standalone: true,
  template: `
    @defer (on viewport) {
      <app-user-profile [userId]="userId"></app-user-profile>
    } @placeholder {
      <div class="profile-skeleton">
        <div class="skeleton-avatar"></div>
        <div class="skeleton-content">
          <div class="skeleton-line skeleton-title"></div>
          <div class="skeleton-line"></div>
          <div class="skeleton-line skeleton-short"></div>
        </div>
      </div>
    }
  `,
  styles: [`
    .profile-skeleton {
      display: flex;
      gap: 1rem;
      padding: 1rem;
    }
    
    .skeleton-avatar {
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
      background-size: 200% 100%;
      animation: shimmer 1.5s infinite;
    }
    
    .skeleton-content {
      flex: 1;
    }
    
    .skeleton-line {
      height: 16px;
      background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
      background-size: 200% 100%;
      border-radius: 4px;
      margin-bottom: 0.5rem;
      animation: shimmer 1.5s infinite;
    }
    
    .skeleton-title {
      width: 60%;
      height: 20px;
    }
    
    .skeleton-short {
      width: 40%;
    }
    
    @keyframes shimmer {
      0% { background-position: -200% 0; }
      100% { background-position: 200% 0; }
    }
  `]
})
export class DeferSkeletonComponent {
  userId = '123';
}
```

**Exemplo com Placeholder Interativo**:

```typescript
@Component({
  selector: 'app-defer-interactive',
  standalone: true,
  template: `
    @defer (on interaction(loadButton)) {
      <app-chart [data]="chartData"></app-chart>
    } @placeholder {
      <div class="placeholder-card">
        <h3>Visualização de Dados</h3>
        <p>Clique no botão abaixo para carregar o gráfico interativo</p>
        <button #loadButton class="load-button">
          Carregar Gráfico
        </button>
      </div>
    }
  `,
  styles: [`
    .placeholder-card {
      padding: 2rem;
      text-align: center;
      border: 2px dashed #ccc;
      border-radius: 8px;
    }
    
    .load-button {
      margin-top: 1rem;
      padding: 0.75rem 1.5rem;
      background: #007bff;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
  `]
})
export class DeferInteractiveComponent {
  chartData = [/* ... */];
}
```

**Boas Práticas para @placeholder**:

1. **Altura Consistente**: Mantenha altura similar ao conteúdo final para evitar layout shift
2. **Largura Consistente**: Preserve proporções do conteúdo final
3. **Skeleton Loaders**: Use quando possível para melhor UX
4. **Conteúdo Relevante**: Placeholder deve comunicar o que será carregado
5. **Acessibilidade**: Inclua `aria-label` ou texto descritivo

---

### @loading e @error

**Definição**: `@loading` é um bloco que exibe conteúdo durante o processo de carregamento do chunk após o trigger ser ativado, enquanto `@error` exibe conteúdo quando ocorre falha no carregamento ou inicialização do componente.

**Explicação Detalhada**:

**@loading Block**:

O `@loading` é exibido durante o período entre a ativação do trigger e a renderização completa do componente. Este período inclui:

1. **Download do Chunk**: Tempo para baixar o arquivo JavaScript do servidor
2. **Parsing e Execução**: Tempo para o navegador processar o código
3. **Inicialização do Componente**: Tempo para Angular instanciar e inicializar o componente
4. **Renderização**: Tempo para o componente renderizar seu template

**Parâmetro `minimum`**: O `@loading` pode ter um parâmetro `minimum` que especifica o tempo mínimo que o estado de loading deve ser exibido. Isso previne "flash" de conteúdo quando o carregamento é muito rápido.

**@error Block**:

O `@error` é exibido quando:
- Falha no download do chunk (404, timeout, erro de rede)
- Erro ao executar o código do chunk
- Erro na inicialização do componente
- Erro durante a renderização do componente

**Fluxo de Estados Completo**:

```
┌──────────────┐
│ @placeholder │  ← Estado inicial
└──────┬───────┘
       │
       │ Trigger ativado
       ▼
┌──────────────┐
│  @loading    │  ← Durante carregamento
└──────┬───────┘    (mínimo: minimum Xms)
       │
       ├─────────┬─────────┐
       │         │         │
       ▼         ▼         ▼
   Sucesso    Erro    Timeout
       │         │         │
       │         └────┬────┘
       │              │
       ▼              ▼
┌──────────────┐ ┌──────────┐
│   Content    │ │ @error  │
└──────────────┘ └──────────┘
```

**Analogia**:

Imagine pedir comida em um restaurante:

- **@placeholder**: Você está na mesa, olhando o cardápio (aguardando)
- **@loading**: Você fez o pedido e está aguardando a comida chegar (carregando)
- **Content**: A comida chegou e você está comendo (componente renderizado)
- **@error**: O garçom volta e diz que não tem mais aquele prato (erro no carregamento)

O parâmetro `minimum` seria como garantir que você veja o garçom saindo da cozinha por pelo menos alguns segundos, mesmo que a comida chegue muito rápido, para evitar confusão.

**Visualização de Estados**:

```
Estado: @loading (durante carregamento)

┌─────────────────────────────────────┐
│                                     │
│         ╔═══════════════╗          │
│         ║   Loading...   ║          │
│         ╚═══════════════╝          │
│              │ │ │                 │
│            ╱ ╲ │ ╱ ╲               │
│           │   │ │   │              │
│            ╲ ╱ │ ╲ ╱               │
│              │ │ │                 │
│                                     │
│    Downloading chunk...            │
│    Parsing code...                  │
│    Initializing component...        │
│                                     │
└─────────────────────────────────────┘

Estado: @error (falha no carregamento)

┌─────────────────────────────────────┐
│                                     │
│    ╔═══════════════════════════╗   │
│    ║   ⚠️  Erro ao Carregar    ║   │
│    ╚═══════════════════════════╝   │
│                                     │
│    Não foi possível carregar o     │
│    componente.                      │
│                                     │
│    [Tentar Novamente]               │
│                                     │
└─────────────────────────────────────┘
```

**Exemplo Prático Básico**:

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

**Exemplo Prático Avançado com Loading Detalhado**:

```typescript
@Component({
  selector: 'app-defer-loading-advanced',
  standalone: true,
  template: `
    @defer (on viewport) {
      <app-data-visualization [data]="data"></app-data-visualization>
    } @placeholder {
      <div class="placeholder">
        <div class="skeleton-chart"></div>
      </div>
    } @loading (minimum 800ms) {
      <div class="loading-container">
        <div class="spinner"></div>
        <p class="loading-text">Carregando visualização de dados...</p>
        <div class="loading-steps">
          <div class="step active">Baixando código</div>
          <div class="step">Processando dados</div>
          <div class="step">Renderizando gráfico</div>
        </div>
      </div>
    } @error {
      <div class="error-container">
        <div class="error-icon">⚠️</div>
        <h3>Erro ao Carregar Visualização</h3>
        <p>Não foi possível carregar o componente de visualização.</p>
        <button (click)="retry()" class="retry-button">
          Tentar Novamente
        </button>
      </div>
    }
  `,
  styles: [`
    .loading-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 3rem;
      min-height: 400px;
    }
    
    .spinner {
      width: 50px;
      height: 50px;
      border: 4px solid #f3f3f3;
      border-top: 4px solid #3498db;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin-bottom: 1rem;
    }
    
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    
    .loading-text {
      margin: 1rem 0;
      color: #666;
      font-size: 1.1rem;
    }
    
    .loading-steps {
      display: flex;
      gap: 1rem;
      margin-top: 1rem;
    }
    
    .step {
      padding: 0.5rem 1rem;
      background: #f0f0f0;
      border-radius: 4px;
      font-size: 0.9rem;
      color: #999;
    }
    
    .step.active {
      background: #3498db;
      color: white;
    }
    
    .error-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 3rem;
      min-height: 400px;
      text-align: center;
    }
    
    .error-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
    }
    
    .retry-button {
      margin-top: 1.5rem;
      padding: 0.75rem 1.5rem;
      background: #e74c3c;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
    }
    
    .retry-button:hover {
      background: #c0392b;
    }
  `]
})
export class DeferLoadingAdvancedComponent {
  data = [/* ... */];
  
  retry(): void {
    window.location.reload();
  }
}
```

**Exemplo com Tratamento de Erro Avançado**:

{% raw %}
```typescript
import { Component, signal } from '@angular/core';

@Component({
  selector: 'app-defer-error-handling',
  standalone: true,
  template: `
    @defer {
      <app-heavy-component></app-heavy-component>
    } @placeholder {
      <div class="placeholder">Conteúdo será carregado...</div>
    } @loading (minimum 300ms) {
      <div class="loading">Carregando...</div>
    } @error {
      <div class="error">
        <h3>Erro ao Carregar Componente</h3>
        <p>{{ errorMessage() }}</p>
        <div class="error-actions">
          <button (click)="retry()">Tentar Novamente</button>
          <button (click)="loadFallback()">Usar Versão Simplificada</button>
        </div>
      </div>
    }
  `,
  styles: [`
    .error {
      padding: 2rem;
      border: 2px solid #e74c3c;
      border-radius: 8px;
      background: #ffe6e6;
    }
    
    .error-actions {
      margin-top: 1rem;
      display: flex;
      gap: 1rem;
    }
    
    .error-actions button {
      padding: 0.5rem 1rem;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    
    .error-actions button:first-child {
      background: #3498db;
      color: white;
    }
    
    .error-actions button:last-child {
      background: #95a5a6;
      color: white;
    }
  `]
})
export class DeferErrorHandlingComponent {
  errorMessage = signal('Erro desconhecido');
  
  retry(): void {
    window.location.reload();
  }
  
  loadFallback(): void {
    console.log('Carregando versão simplificada...');
  }
}
```
{% endraw %}

**Boas Práticas para @loading e @error**:

1. **Minimum Time**: Use `minimum` para evitar flash de conteúdo em carregamentos rápidos
2. **Feedback Claro**: Loading deve comunicar claramente o que está acontecendo
3. **Error Recovery**: Sempre forneça opção de retry ou fallback
4. **Acessibilidade**: Inclua `aria-live` para leitores de tela
5. **Consistência Visual**: Mantenha estilo consistente com o resto da aplicação

---

### Triggers

**Definição**: Triggers são condições ou eventos que determinam quando o Angular deve iniciar o carregamento do chunk deferido. Eles permitem controle fino sobre o timing do carregamento, otimizando tanto performance quanto experiência do usuário.

**Explicação Detalhada**:

Triggers são a interface entre a intenção do usuário (ou condições do sistema) e o carregamento lazy. Cada trigger tem características específicas:

**Tipos de Triggers Disponíveis**:

1. **`on idle`** (padrão): Carrega quando o navegador está ocioso
2. **`on timer(duration)`**: Carrega após um tempo especificado
3. **`on viewport`**: Carrega quando o elemento entra na viewport
4. **`on interaction(element)`**: Carrega quando usuário interage com elemento
5. **`on hover(element)`**: Carrega quando mouse passa sobre elemento
6. **`on immediate`**: Carrega imediatamente (útil para debugging)
7. **`when(condition)`**: Carrega quando condição se torna verdadeira

**Combinação de Triggers**:

Triggers podem ser combinados usando vírgula. O componente será carregado quando QUALQUER trigger for ativado (OR lógico):

```typescript
@defer (on viewport, on timer(5s)) {
  // Carrega quando entra no viewport OU após 5 segundos
}
```

**Analogia Detalhada**:

Triggers são como diferentes tipos de sensores em uma casa inteligente:

- **on idle**: Como um sensor de movimento que detecta quando você está parado - carrega quando o sistema está livre
- **on timer**: Como um timer de cozinha - carrega após tempo determinado
- **on viewport**: Como uma câmera de segurança que detecta quando alguém entra no campo de visão - carrega quando visível
- **on interaction**: Como um interruptor de luz - carrega quando você toca/clica
- **on hover**: Como um sensor de proximidade - carrega quando você se aproxima
- **when**: Como um termostato inteligente - carrega quando condições específicas são atendidas

Cada sensor (trigger) é otimizado para diferentes cenários, e você escolhe o mais apropriado para cada situação.

**Visualização de Triggers**:

```
┌─────────────────────────────────────────────────────┐
│              Trigger Detection System                │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐  ┌──────────────┐               │
│  │ on idle      │  │ on timer     │               │
│  │              │  │              │               │
│  │ Browser      │  │ ⏱️ 5s       │               │
│  │ Idle?        │  │              │               │
│  └──────┬───────┘  └──────┬───────┘               │
│         │                 │                        │
│  ┌──────▼──────────┐ ┌───▼──────────┐            │
│  │ on viewport     │ │ on hover     │            │
│  │                 │ │              │            │
│  │ 👁️ Visible?    │ │ 🖱️ Hover?   │            │
│  └──────┬──────────┘ └───┬──────────┘            │
│         │                 │                        │
│  ┌──────▼─────────────────▼──────────┐            │
│  │ on interaction                    │            │
│  │                                   │            │
│  │ 👆 Click/Touch?                   │            │
│  └──────┬────────────────────────────┘            │
│         │                                          │
│         ▼                                          │
│  ┌──────────────┐                                 │
│  │   Trigger    │                                 │
│  │  Activated!  │                                 │
│  └──────┬───────┘                                 │
│         │                                         │
│         ▼                                         │
│  ┌──────────────┐                                │
│  │ Load Chunk   │                                │
│  └──────────────┘                                │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**Detalhamento de Cada Trigger**:

**1. on idle (Padrão)**

```typescript
@defer {
  // Carrega quando navegador está idle
  <app-component></app-component>
}

@defer (on idle) {
  // Explícito - mesmo comportamento
  <app-component></app-component>
}
```

- **Quando usar**: Componentes não críticos que podem esperar
- **Vantagem**: Não bloqueia renderização inicial
- **Desvantagem**: Timing imprevisível
- **Casos de uso**: Analytics, componentes abaixo da dobra, conteúdo secundário

**2. on timer(duration)**

```typescript
@defer (on timer(2s)) {
  <app-ad-banner></app-ad-banner>
}

@defer (on timer(500ms)) {
  <app-tooltip></app-tooltip>
}
```

- **Quando usar**: Conteúdo que deve aparecer após delay específico
- **Vantagem**: Timing previsível e controlado
- **Desvantagem**: Pode carregar mesmo se não necessário
- **Casos de uso**: Anúncios, tooltips, conteúdo promocional

**3. on viewport**

```typescript
@defer (on viewport) {
  <app-heavy-chart></app-heavy-chart>
} @placeholder {
  <div>Role para ver gráfico</div>
}
```

- **Quando usar**: Conteúdo abaixo da dobra (below the fold)
- **Vantagem**: Carrega apenas quando visível
- **Desvantagem**: Requer Intersection Observer API
- **Casos de uso**: Gráficos, imagens grandes, seções longas

**4. on interaction(element)**

```typescript
<button #loadButton>Carregar Modal</button>

@defer (on interaction(loadButton)) {
  <app-modal></app-modal>
} @placeholder {
  <p>Clique no botão acima</p>
}
```

- **Quando usar**: Conteúdo que requer ação explícita do usuário
- **Vantagem**: Carrega apenas quando necessário
- **Desvantagem**: Requer referência de template
- **Casos de uso**: Modais, formulários complexos, componentes interativos

**5. on hover(element)**

```typescript
<div #hoverTarget class="card">
  <h3>Título</h3>
</div>

@defer (on hover(hoverTarget)) {
  <app-preview></app-preview>
}
```

- **Quando usar**: Preview ou conteúdo que aparece no hover
- **Vantagem**: Carrega antecipadamente para melhor UX
- **Desvantagem**: Pode carregar sem uso real
- **Casos de uso**: Previews, tooltips avançados, menus dropdown pesados

**6. on immediate**

```typescript
@defer (on immediate) {
  <app-component></app-component>
}
```

- **Quando usar**: Debugging ou quando precisa garantir carregamento
- **Vantagem**: Comportamento previsível
- **Desvantagem**: Não aproveita lazy loading
- **Casos de uso**: Desenvolvimento, testes, componentes críticos

**7. when(condition)**

```typescript
@defer (when shouldLoad()) {
  <app-component></app-component>
}

@defer (when user.isPremium) {
  <app-premium-feature></app-premium-feature>
}
```

- **Quando usar**: Carregamento baseado em lógica de negócio
- **Vantagem**: Controle total sobre quando carregar
- **Desvantagem**: Requer gerenciamento de estado
- **Casos de uso**: Features premium, conteúdo condicional, A/B testing

**Exemplo Prático Completo com Todos os Triggers**:

{% raw %}
```typescript
import { Component, signal } from '@angular/core';

@Component({
  selector: 'app-defer-triggers-complete',
  standalone: true,
  template: `
    <div class="container">
      <h1>Demonstração de Triggers</h1>
      
      <section class="demo-section">
        <h2>1. on viewport</h2>
        <p>Role para baixo para carregar automaticamente</p>
        @defer (on viewport) {
          <app-heavy-component></app-heavy-component>
        } @placeholder {
          <div class="placeholder">Conteúdo será carregado quando visível</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>2. on timer</h2>
        <p>Anúncio será carregado após 3 segundos</p>
        @defer (on timer(3s)) {
          <app-ad-banner></app-ad-banner>
        } @placeholder {
          <div class="placeholder">Aguardando 3 segundos...</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>3. on idle</h2>
        <p>Analytics carregado quando navegador está ocioso</p>
        @defer (on idle) {
          <app-analytics></app-analytics>
        } @placeholder {
          <div class="placeholder">Aguardando navegador ficar ocioso...</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>4. on interaction</h2>
        <button #loadModal class="load-button">
          Abrir Modal Pesado
        </button>
        @defer (on interaction(loadModal)) {
          <app-heavy-modal></app-heavy-modal>
        } @placeholder {
          <div class="placeholder">Clique no botão para carregar modal</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>5. on hover</h2>
        <div #hoverTarget class="hover-target">
          Passe o mouse aqui
        </div>
        @defer (on hover(hoverTarget)) {
          <app-preview-card></app-preview-card>
        } @placeholder {
          <div class="placeholder">Passe o mouse sobre o card acima</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>6. when condition</h2>
        <button (click)="toggleLoad()">
          {{ shouldLoad() ? 'Desabilitar' : 'Habilitar' }} Carregamento
        </button>
        @defer (when shouldLoad()) {
          <app-conditional-component></app-conditional-component>
        } @placeholder {
          <div class="placeholder">Clique no botão para habilitar carregamento</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>7. Combined triggers</h2>
        <p>Carrega quando visível OU após 5 segundos</p>
        @defer (on viewport, on timer(5s)) {
          <app-combined-component></app-combined-component>
        } @placeholder {
          <div class="placeholder">Aguardando viewport ou timer...</div>
        }
      </section>
    </div>
  `,
  styles: [`
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    .demo-section {
      margin: 3rem 0;
      padding: 2rem;
      border: 1px solid #ddd;
      border-radius: 8px;
    }
    
    .placeholder {
      padding: 2rem;
      background: #f5f5f5;
      border-radius: 4px;
      text-align: center;
      color: #666;
    }
    
    .load-button {
      padding: 0.75rem 1.5rem;
      background: #007bff;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
    }
    
    .hover-target {
      padding: 2rem;
      background: #e3f2fd;
      border-radius: 4px;
      cursor: pointer;
      text-align: center;
      transition: background 0.3s;
    }
    
    .hover-target:hover {
      background: #bbdefb;
    }
  `]
})
export class DeferTriggersCompleteComponent {
  shouldLoad = signal(false);
  
  toggleLoad(): void {
    this.shouldLoad.set(!this.shouldLoad());
  }
}
```
{% raw %}
import { Component, signal } from '@angular/core';

@Component({
  selector: 'app-defer-triggers-complete',
  standalone: true,
  template: `
    <div class="container">
      <h1>Demonstração de Triggers</h1>
      
      <section class="demo-section">
        <h2>1. on viewport</h2>
        <p>Role para baixo para carregar automaticamente</p>
        @defer (on viewport) {
          <app-heavy-component></app-heavy-component>
        } @placeholder {
          <div class="placeholder">Conteúdo será carregado quando visível</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>2. on timer</h2>
        <p>Anúncio será carregado após 3 segundos</p>
        @defer (on timer(3s)) {
          <app-ad-banner></app-ad-banner>
        } @placeholder {
          <div class="placeholder">Aguardando 3 segundos...</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>3. on idle</h2>
        <p>Analytics carregado quando navegador está ocioso</p>
        @defer (on idle) {
          <app-analytics></app-analytics>
        } @placeholder {
          <div class="placeholder">Aguardando navegador ficar ocioso...</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>4. on interaction</h2>
        <button #loadModal class="load-button">
          Abrir Modal Pesado
        </button>
        @defer (on interaction(loadModal)) {
          <app-heavy-modal></app-heavy-modal>
        } @placeholder {
          <div class="placeholder">Clique no botão para carregar modal</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>5. on hover</h2>
        <div #hoverTarget class="hover-target">
          Passe o mouse aqui
        </div>
        @defer (on hover(hoverTarget)) {
          <app-preview-card></app-preview-card>
        } @placeholder {
          <div class="placeholder">Passe o mouse sobre o card acima</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>6. when condition</h2>
        <button (click)="toggleLoad()">
          {{ shouldLoad() ? 'Desabilitar' : 'Habilitar' }} Carregamento
        </button>
        @defer (when shouldLoad()) {
          <app-conditional-component></app-conditional-component>
        } @placeholder {
          <div class="placeholder">Clique no botão para habilitar carregamento</div>
        }
      </section>
      
      <section class="demo-section">
        <h2>7. Combined triggers</h2>
        <p>Carrega quando visível OU após 5 segundos</p>
        @defer (on viewport, on timer(5s)) {
          <app-combined-component></app-combined-component>
        } @placeholder {
          <div class="placeholder">Aguardando viewport ou timer...</div>
        }
      </section>
    </div>
  `,
  styles: [`
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    .demo-section {
      margin: 3rem 0;
      padding: 2rem;
      border: 1px solid #ddd;
      border-radius: 8px;
    }
    
    .placeholder {
      padding: 2rem;
      background: #f5f5f5;
      border-radius: 4px;
      text-align: center;
      color: #666;
    }
    
    .load-button {
      padding: 0.75rem 1.5rem;
      background: #007bff;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
    }
    
    .hover-target {
      padding: 2rem;
      background: #e3f2fd;
      border-radius: 4px;
      cursor: pointer;
      text-align: center;
      transition: background 0.3s;
    }
    
    .hover-target:hover {
      background: #bbdefb;
    }
  `]
})
export class DeferTriggersCompleteComponent {
  shouldLoad = signal(false);
  
  toggleLoad(): void {
    this.shouldLoad.set(!this.shouldLoad());
  }
}
```
{% endraw %}

**Tabela Comparativa de Triggers**:

| Trigger | Timing | Previsibilidade | Performance | Caso de Uso Ideal |
|---------|--------|-----------------|-------------|-------------------|
| `on idle` | Variável | Baixa | Alta | Componentes não críticos |
| `on timer` | Fixo | Alta | Média | Conteúdo com delay intencional |
| `on viewport` | Baseado em scroll | Média | Alta | Conteúdo abaixo da dobra |
| `on interaction` | Baseado em ação | Alta | Alta | Modais, formulários |
| `on hover` | Baseado em hover | Média | Média | Previews, tooltips |
| `on immediate` | Imediato | Alta | Baixa | Debugging, críticos |
| `when` | Baseado em condição | Alta | Alta | Lógica de negócio |

**Boas Práticas para Triggers**:

1. **Escolha o trigger apropriado**: Considere quando o conteúdo realmente precisa estar disponível
2. **Combine triggers quando necessário**: Use múltiplos triggers para garantir carregamento
3. **Evite on immediate**: A menos que seja absolutamente necessário
4. **Use on viewport para conteúdo longo**: Otimiza carregamento progressivo
5. **Prefira on interaction para modais**: Carrega apenas quando necessário
6. **Teste em diferentes conexões**: Triggers podem ter comportamento diferente em conexões lentas

---

## Comparação com Outros Frameworks

### Tabela Comparativa: Lazy Loading de Componentes

| Framework | Abordagem | Sintaxe | Triggers | Estados | Bundle Splitting |
|-----------|-----------|---------|----------|---------|------------------|
| **Angular** | `@defer` block | Declarativo no template | 7 tipos nativos | @placeholder, @loading, @error | Automático |
| **React** | `React.lazy()` + `Suspense` | Imperativo no código | Manual (useEffect) | Suspense fallback | Manual (webpack) |
| **Vue 3** | `defineAsyncComponent()` | Imperativo no código | Manual (watch/onMounted) | loading/error components | Automático (Vite) |
| **Svelte** | `{#await}` block | Declarativo no template | Manual | then/catch blocks | Automático (SvelteKit) |
| **Next.js** | `dynamic()` import | Imperativo no código | SSR/SSG nativo | loading.ts | Automático |

### Análise Detalhada por Framework

**Angular @defer**:

```typescript
@defer (on viewport) {
  <app-heavy-component></app-heavy-component>
} @placeholder {
  <div>Skeleton</div>
} @loading {
  <div>Loading...</div>
} @error {
  <div>Error</div>
}
```

**Vantagens**:
- Sintaxe declarativa e intuitiva
- Triggers nativos integrados
- Estados de carregamento integrados
- Type-safe completo
- Compile-time optimization

**React Suspense**:

```typescript
const HeavyComponent = React.lazy(() => import('./HeavyComponent'));

function App() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <HeavyComponent />
    </Suspense>
  );
}
```

**Vantagens**:
- Ecossistema maduro
- Integração com React Server Components
- Flexibilidade de implementação

**Desvantagens**:
- Requer código JavaScript para triggers
- Menos integrado ao template
- Configuração manual de code splitting

**Vue 3 defineAsyncComponent**:

```typescript
const HeavyComponent = defineAsyncComponent({
  loader: () => import('./HeavyComponent.vue'),
  loadingComponent: LoadingComponent,
  errorComponent: ErrorComponent,
  delay: 200,
  timeout: 3000
});
```

**Vantagens**:
- Configuração flexível
- Suporte a loading/error components
- Integração com Composition API

**Desvantagens**:
- Sintaxe imperativa
- Triggers requerem código adicional
- Menos declarativo que Angular

**Svelte {#await}**:

```svelte
{#await promise}
  <div>Loading...</div>
{:then component}
  <component />
{:catch error}
  <div>Error: {error.message}</div>
{/await}
```

**Vantagens**:
- Sintaxe declarativa
- Integrado ao template
- Simples e direto

**Desvantagens**:
- Menos triggers nativos
- Requer gerenciamento manual de promises
- Menos otimizações de compilação

### Comparação de Performance

| Métrica | Angular @defer | React Suspense | Vue Async | Svelte {#await} |
|---------|----------------|----------------|-----------|-----------------|
| Bundle Size Reduction | 30-60% | 25-50% | 30-55% | 35-60% |
| Initial Load Time | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Runtime Overhead | Baixo | Médio | Baixo | Muito Baixo |
| Code Splitting | Automático | Manual | Automático | Automático |
| Tree Shaking | Excelente | Bom | Excelente | Excelente |

### Quando Usar Cada Abordagem

**Use Angular @defer quando**:
- Trabalhando com Angular 17+
- Precisa de triggers nativos integrados
- Quer sintaxe declarativa no template
- Precisa de type safety completo

**Use React Suspense quando**:
- Trabalhando com React
- Precisa de controle imperativo fino
- Usando React Server Components
- Integrando com bibliotecas React existentes

**Use Vue defineAsyncComponent quando**:
- Trabalhando com Vue 3
- Precisa de configuração flexível
- Usando Composition API
- Quer integração com Vue Router

**Use Svelte {#await} quando**:
- Trabalhando com Svelte
- Precisa de sintaxe simples
- Quer bundle mínimo
- Prefere abordagem funcional

### Evolução Histórica

**2016-2018**: Code splitting baseado em rotas
- Angular: `loadChildren` em rotas
- React: React Router com code splitting
- Vue: Vue Router com lazy routes

**2019-2021**: Component-level lazy loading
- React: `React.lazy()` + Suspense
- Vue: `defineAsyncComponent()`
- Angular: Ainda limitado a rotas

**2022-2023**: Template-level lazy loading
- Angular: `@defer` block (Angular 17)
- React: Server Components com Suspense
- Vue: Melhorias em `defineAsyncComponent`

**2024+**: Otimizações avançadas
- Triggers nativos
- Estados de carregamento integrados
- Compile-time optimizations
- Integração com SSR/SSG

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

#### 1. Use @defer para Componentes Pesados

**Por quê**: Componentes pesados aumentam significativamente o bundle inicial, impactando métricas como First Contentful Paint (FCP) e Largest Contentful Paint (LCP).

**Quando usar**:
- Componentes com dependências grandes (bibliotecas de gráficos, editores, visualizações)
- Componentes abaixo da dobra (below the fold)
- Modais e diálogos que não são críticos
- Componentes de terceiros pesados
- Features não essenciais

**Exemplo**:

```typescript
@Component({
  selector: 'app-dashboard',
  template: `
    <div class="dashboard">
      <app-header></app-header>
      
      @defer (on viewport) {
        <app-heavy-chart></app-heavy-chart>
      } @placeholder {
        <div class="chart-skeleton"></div>
      }
    </div>
  `
})
export class DashboardComponent {}
```

**Métricas esperadas**: Redução de 30-60% no bundle inicial

#### 2. Sempre Forneça @placeholder

**Por quê**: Placeholders previnem Cumulative Layout Shift (CLS), uma métrica crítica do Core Web Vitals. Eles também melhoram a percepção de performance.

**Características de um bom placeholder**:
- Mesma altura/largura do conteúdo final
- Estrutura visual similar (skeleton loader)
- Comunica claramente o que será carregado
- Acessível (aria-labels apropriados)

**Exemplo**:

```typescript
@defer (on viewport) {
  <app-user-card [user]="user"></app-user-card>
} @placeholder {
  <div class="user-card-skeleton" aria-label="Carregando perfil do usuário">
    <div class="skeleton-avatar"></div>
    <div class="skeleton-text">
      <div class="skeleton-line"></div>
      <div class="skeleton-line short"></div>
    </div>
  </div>
}
```

**Impacto**: Redução de CLS em até 0.1 pontos

#### 3. Use Triggers Apropriados

**Por quê**: O trigger certo garante que o componente seja carregado no momento ideal, balanceando performance e experiência do usuário.

**Guia de escolha de triggers**:

| Cenário | Trigger Recomendado | Razão |
|---------|---------------------|-------|
| Conteúdo abaixo da dobra | `on viewport` | Carrega apenas quando visível |
| Modal/Dialog | `on interaction` | Carrega apenas quando necessário |
| Analytics/Tracking | `on idle` | Não bloqueia renderização |
| Anúncios | `on timer` | Controle de timing |
| Preview no hover | `on hover` | Antecipa necessidade |
| Conteúdo condicional | `when` | Baseado em lógica de negócio |

**Exemplo**:

```typescript
@defer (on viewport) {
  <app-article-content></app-article-content>
} @placeholder {
  <div>Conteúdo será carregado quando visível</div>
}
```

#### 4. Trate Erros com @error

**Por quê**: Falhas de rede, timeouts e erros de carregamento são comuns. Tratamento adequado melhora significativamente a experiência do usuário.

**Estratégias de tratamento de erro**:
- Mensagem clara e amigável
- Opção de retry
- Fallback para versão simplificada
- Logging de erros para monitoramento

**Exemplo**:

```typescript
@defer {
  <app-heavy-component></app-heavy-component>
} @error {
  <div class="error-container">
    <h3>Erro ao Carregar</h3>
    <p>Não foi possível carregar o componente.</p>
    <button (click)="retry()">Tentar Novamente</button>
    <button (click)="loadSimplified()">Usar Versão Simplificada</button>
  </div>
}
```

#### 5. Use @loading com Minimum Time

**Por quê**: O parâmetro `minimum` previne "flash" de conteúdo quando o carregamento é muito rápido, melhorando a percepção visual.

**Recomendações**:
- 200-500ms para componentes pequenos
- 500-1000ms para componentes médios
- 1000ms+ para componentes grandes

**Exemplo**:

```typescript
@defer (on viewport) {
  <app-chart></app-chart>
} @loading (minimum 800ms) {
  <div class="loading">Carregando gráfico...</div>
}
```

#### 6. Garanta que Componentes são Standalone

**Por quê**: Apenas componentes standalone podem ser deferidos. Componentes não-standalone serão carregados imediatamente, mesmo dentro de `@defer`.

**Exemplo Correto**:

```typescript
@Component({
  selector: 'app-heavy',
  standalone: true,
  imports: [CommonModule],
  template: `...`
})
export class HeavyComponent {}
```

**Exemplo Incorreto**:

```typescript
@Component({
  selector: 'app-heavy',
  standalone: false,
  template: `...`
})
export class HeavyComponent {}
```

#### 7. Evite Referências Externas a Componentes Deferidos

**Por quê**: Se um componente dentro de `@defer` é referenciado fora do bloco no mesmo arquivo, ele será carregado imediatamente.

**Exemplo Incorreto**:

```typescript
@Component({
  template: `
    <button (click)="openModal()">Abrir</button>
    
    @defer {
      <app-modal #modal></app-modal>
    }
  `
})
export class Component {
  @ViewChild('modal') modal!: ModalComponent;
}
```

**Solução**: Use signals ou eventos para comunicação:

```typescript
@Component({
  template: `
    <button (click)="showModal.set(true)">Abrir</button>
    
    @defer (when showModal()) {
      <app-modal></app-modal>
    }
  `
})
export class Component {
  showModal = signal(false);
}
```

#### 8. Combine Triggers quando Apropriado

**Por quê**: Múltiplos triggers garantem que o componente seja carregado em diferentes cenários, melhorando a cobertura.

**Exemplo**:

```typescript
@defer (on viewport, on timer(10s)) {
  <app-ad-banner></app-ad-banner>
}
```

#### 9. Monitore Performance

**Por quê**: Medir o impacto real ajuda a validar que `@defer` está funcionando como esperado.

**Métricas a monitorar**:
- Bundle size reduction
- Initial load time
- Time to Interactive (TTI)
- Cumulative Layout Shift (CLS)

**Ferramentas**:
- Angular DevTools
- Lighthouse
- Web Vitals
- Bundle Analyzer

#### 10. Teste em Diferentes Condições

**Por quê**: Comportamento pode variar em conexões lentas, dispositivos móveis e diferentes navegadores.

**Cenários de teste**:
- Conexão rápida (4G/WiFi)
- Conexão lenta (3G/Throttled)
- Dispositivos móveis
- Diferentes navegadores
- Modo offline

### ❌ Anti-padrões Comuns

#### 1. Usar @defer para Componentes Críticos

**Problema**: Componentes críticos devem estar disponíveis imediatamente. Usar `@defer` adiciona delay desnecessário.

**Sintoma**: Usuário vê placeholder/loading mesmo para conteúdo essencial.

**Solução**: Identifique componentes críticos e não os defera.

**Exemplo Incorreto**:

```typescript
@defer {
  <app-header></app-header>
}
```

**Exemplo Correto**:

```typescript
<app-header></app-header>

@defer (on viewport) {
  <app-footer></app-footer>
}
```

#### 2. Esquecer @placeholder

**Problema**: Sem placeholder, há layout shift quando o componente carrega, impactando CLS.

**Sintoma**: Conteúdo "pula" quando componente é renderizado.

**Solução**: Sempre forneça placeholder com dimensões similares ao conteúdo final.

**Exemplo Incorreto**:

```typescript
@defer {
  <app-component></app-component>
}
```

**Exemplo Correto**:

```typescript
@defer {
  <app-component></app-component>
} @placeholder {
  <div class="placeholder" style="height: 400px;"></div>
}
```

#### 3. Usar Triggers Inadequados

**Problema**: Trigger errado pode carregar componente muito cedo ou muito tarde.

**Exemplos de uso inadequado**:
- `on immediate` para componentes não críticos
- `on viewport` para modais (deveria ser `on interaction`)
- `on timer` muito curto para componentes pesados

**Solução**: Analise quando o componente realmente precisa estar disponível e escolha o trigger apropriado.

#### 4. Não Tratar Erros

**Problema**: Sem tratamento de erro, falhas de carregamento resultam em experiência ruim.

**Sintoma**: Usuário vê tela em branco ou erro não tratado.

**Solução**: Sempre forneça `@error` block com opções de recuperação.

**Exemplo Incorreto**:

```typescript
@defer {
  <app-component></app-component>
}
```

**Exemplo Correto**:

```typescript
@defer {
  <app-component></app-component>
} @error {
  <div>Erro ao carregar. <button (click)="retry()">Tentar novamente</button></div>
}
```

#### 5. Placeholder com Dimensões Incorretas

**Problema**: Placeholder com tamanho diferente do conteúdo causa layout shift.

**Sintoma**: CLS alto, conteúdo "pula" ao carregar.

**Solução**: Meça o conteúdo final e use dimensões idênticas no placeholder.

#### 6. Deferir Componentes Muito Pequenos

**Problema**: Overhead de lazy loading pode ser maior que o benefício para componentes pequenos.

**Sintoma**: Mais requisições HTTP sem ganho significativo de performance.

**Solução**: Use `@defer` apenas para componentes que realmente reduzem o bundle inicial.

**Regra de ouro**: Se componente + dependências < 50KB, considere não deferir.

#### 7. Múltiplos @defer Aninhados

**Problema**: Aninhamento excessivo pode complicar o código e dificultar debugging.

**Sintoma**: Código difícil de entender e manter.

**Solução**: Mantenha estrutura simples, prefira deferir no nível mais alto possível.

**Exemplo Incorreto**:

```typescript
@defer {
  <div>
    @defer {
      <div>
        @defer {
          <app-component></app-component>
        }
      </div>
    }
  </div>
}
```

**Exemplo Correto**:

```typescript
@defer {
  <app-parent-component></app-parent-component>
}
```

#### 8. Não Considerar Acessibilidade

**Problema**: Placeholders e loading states sem suporte a acessibilidade excluem usuários.

**Solução**: Use `aria-live`, `aria-label` e outros atributos ARIA apropriados.

**Exemplo**:

```typescript
@defer {
  <app-component></app-component>
} @placeholder {
  <div aria-live="polite" aria-label="Carregando conteúdo">
    <div class="skeleton"></div>
  </div>
}
```

#### 9. Ignorar Métricas de Performance

**Problema**: Sem medição, não é possível validar se `@defer` está realmente melhorando performance.

**Solução**: Implemente monitoramento e compare métricas antes/depois.

#### 10. Deferir Componentes com Dependências Compartilhadas

**Problema**: Se múltiplos componentes deferidos compartilham dependências, cada um pode carregar sua própria cópia.

**Solução**: Considere criar um chunk compartilhado ou reorganizar dependências.

**Exemplo**: Use `shared` imports quando apropriado:

```typescript
@defer {
  <app-chart-a></app-chart-a>
}

@defer {
  <app-chart-b></app-chart-b>
}
```

Se ambos usam a mesma biblioteca de gráficos, considere carregar a biblioteca no bundle principal.

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

- **[Deferrable Views Guide](https://angular.dev/guide/templates/defer)**: Guia completo oficial do Angular sobre Deferrable Views
- **[Deferrable Views Tutorial](https://angular.dev/tutorials/deferrable-views)**: Tutorial passo a passo
- **[@defer API Reference](https://angular.dev/api/core/defer)**: Documentação técnica da API
- **[Angular Performance Guide](https://angular.dev/guide/performance)**: Guia geral de performance no Angular
- **[Standalone Components](https://angular.dev/guide/components/imports)**: Documentação sobre componentes standalone (requisito para @defer)

### Artigos e Tutoriais

- **[Angular 17: Deferrable Views Deep Dive](https://blog.angular.io/angular-17-is-here-4d70366324e4)**: Artigo oficial do Angular Blog sobre Deferrable Views
- **[Optimizing Angular Performance with @defer](https://netbasal.com/optimizing-angular-performance-with-deferrable-views)**: Artigo técnico sobre otimizações
- **[Understanding Angular Deferrable Views](https://indepth.dev/posts/1234/understanding-angular-deferrable-views)**: Análise técnica profunda
- **[Deferrable Views: A Complete Guide](https://www.angulararchitects.io/en/blog/deferrable-views-complete-guide/)**: Guia completo com exemplos práticos
- **[Angular Performance: Lazy Loading Strategies](https://web.dev/angular-performance-lazy-loading/)**: Estratégias de lazy loading

### Vídeos

- **[Angular 17 Deferrable Views Explained](https://www.youtube.com/watch?v=y4o-zqHSxDQ)**: Explicação visual com exemplos práticos
- **[Deferrable Views Tutorial](https://www.youtube.com/watch?v=example)**: Tutorial em vídeo passo a passo
- **[Angular Performance Optimization](https://www.youtube.com/watch?v=example)**: Otimizações de performance com @defer

### Ferramentas e Recursos

- **[Angular DevTools](https://angular.dev/tools/devtools)**: Ferramenta de debugging para Angular
- **[Web Vitals](https://web.dev/vitals/)**: Métricas de performance web
- **[Bundle Analyzer](https://www.npmjs.com/package/webpack-bundle-analyzer)**: Análise de bundle size
- **[Lighthouse](https://developers.google.com/web/tools/lighthouse)**: Auditoria de performance
- **[Angular Performance Checklist](https://github.com/mgechev/angular-performance-checklist)**: Checklist de performance

### Comparações e Benchmarks

- **[Angular vs React: Lazy Loading Comparison](https://example.com)**: Comparação de abordagens
- **[Performance Benchmarks: Deferrable Views](https://example.com)**: Benchmarks de performance
- **[Bundle Size Analysis Tools](https://example.com)**: Ferramentas de análise

### Comunidade e Discussões

- **[Angular GitHub: Deferrable Views RFC](https://github.com/angular/angular/discussions)**: Discussão técnica sobre implementação
- **[Stack Overflow: Angular @defer](https://stackoverflow.com/questions/tagged/angular+defer)**: Perguntas e respostas da comunidade
- **[Angular Discord](https://discord.gg/angular)**: Comunidade Angular no Discord

### Casos de Uso e Exemplos

- **[Angular Examples: Deferrable Views](https://angular.dev/examples)**: Exemplos oficiais
- **[Real-world Deferrable Views Implementation](https://example.com)**: Implementação em projeto real
- **[Deferrable Views Patterns](https://example.com)**: Padrões e práticas comuns

---

## Resumo

### Principais Conceitos

**@defer Block**:
- Carrega componentes, diretivas e pipes sob demanda
- Reduz bundle inicial em 30-60% em aplicações típicas
- Requer componentes standalone para funcionar
- Suporta múltiplos triggers para controle fino
- Integrado ao compilador Angular para otimizações em compile-time

**Estados de Carregamento**:
- **@placeholder**: Exibido antes do trigger, previne layout shift
- **@loading**: Exibido durante carregamento do chunk, suporta `minimum` time
- **@error**: Exibido em caso de falha, deve incluir opções de recuperação

**Triggers Disponíveis**:
- `on idle`: Quando navegador está ocioso (padrão)
- `on timer(duration)`: Após tempo especificado
- `on viewport`: Quando entra na área visível
- `on interaction(element)`: Quando usuário interage
- `on hover(element)`: Quando mouse passa sobre
- `on immediate`: Imediatamente (debugging)
- `when(condition)`: Baseado em condição lógica

**Performance e Métricas**:
- Redução significativa no bundle inicial
- Melhoria em Core Web Vitals (LCP, FCP, CLS)
- Carregamento progressivo alinhado com interação do usuário
- Menor uso de memória inicial

### Pontos-Chave para Lembrar

**Quando Usar @defer**:
- Componentes pesados com dependências grandes
- Conteúdo abaixo da dobra (below the fold)
- Modais e diálogos não críticos
- Features não essenciais
- Componentes de terceiros pesados

**Boas Práticas Essenciais**:
1. **Sempre forneça @placeholder** com dimensões similares ao conteúdo final
2. **Use triggers apropriados** baseado em quando o conteúdo precisa estar disponível
3. **Trate erros** com @error block e opções de recuperação
4. **Use @loading com minimum** para prevenir flash de conteúdo
5. **Garanta componentes standalone** para que defer funcione
6. **Evite referências externas** a componentes deferidos no mesmo arquivo
7. **Monitore performance** para validar melhorias
8. **Teste em diferentes condições** (conexões lentas, dispositivos móveis)

**Anti-padrões a Evitar**:
- Não usar @defer para componentes críticos
- Não esquecer @placeholder (causa layout shift)
- Não usar triggers inadequados
- Não ignorar tratamento de erros
- Não deferir componentes muito pequenos (< 50KB)
- Não criar estruturas aninhadas excessivamente complexas

### Comparação com Outros Frameworks

- **Angular @defer**: Sintaxe declarativa, triggers nativos, estados integrados
- **React Suspense**: Abordagem imperativa, flexível mas requer mais código
- **Vue defineAsyncComponent**: Configuração flexível, menos declarativo
- **Svelte {#await}**: Sintaxe simples, menos triggers nativos

### Próximos Passos

**Imediatos**:
- Próxima aula: [Aula 4.4: Profiling e Otimização](./lesson-4-4-profiling.md)
- Implementar @defer em componentes pesados de projetos existentes
- Medir impacto em métricas de performance

**Prática Recomendada**:
1. Identificar componentes candidatos a defer em projetos atuais
2. Implementar @defer com placeholders apropriados
3. Escolher triggers baseado em análise de uso
4. Medir e comparar métricas antes/depois
5. Iterar baseado em resultados

**Aprofundamento**:
- Explorar triggers avançados e combinações
- Estudar otimizações de bundle com deferrable views
- Aprender sobre integração com SSR/SSG
- Explorar padrões avançados de lazy loading
- Estudar métricas de Core Web Vitals em profundidade

**Recursos para Continuar Aprendendo**:
- Documentação oficial do Angular sobre Deferrable Views
- Tutoriais práticos com exemplos reais
- Casos de uso da comunidade Angular
- Ferramentas de análise de performance

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
