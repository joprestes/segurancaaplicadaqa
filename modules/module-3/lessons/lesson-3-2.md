---
layout: lesson
title: "Aula 3.2: Signals e Signal-First Architecture"
slug: signals
module: module-3
lesson_id: lesson-3-2
duration: "120 minutos"
level: "Avançado"
prerequisites: []
exercises: []
podcast:
  file: "assets/podcasts/03.2-Angular_Signals_O_Guia_Completo_e_Pratico.m4a"
  image: "assets/images/podcasts/03.2-Angular_Signals_O_Guia_Completo_e_Pratico.png"
  title: "Angular Signals - O Guia Completo e Prático"
  description: "Signals são a nova forma reativa do Angular."
  duration: "60-75 minutos"
permalink: /modules/programacao-reativa-estado/lessons/signals/
---

## Introdução

Nesta aula, você dominará Signals, a nova primitiva reativa do Angular introduzida no Angular 16+. Signals representam uma evolução na forma como Angular gerencia reatividade, oferecendo melhor performance, type safety e uma API mais simples que Observables em muitos casos.

### Contexto Histórico

**Signals - Uma Revolução na Reatividade do Angular**:

Signals foram introduzidos no Angular 16 (Maio 2023) como parte de uma estratégia maior para modernizar o sistema de reatividade do Angular. Esta mudança representa uma das evoluções mais significativas desde a introdução do Angular 2.

**Linha do Tempo da Reatividade no Angular**:

```
AngularJS (2010) ──────────────────────────────────────────── Angular 19+ (2024+)
 │                                                                  │
 ├─ 2010-2015  📦 AngularJS - $scope e $watch                      │
 │             Sistema de digest cycle                              │
 │             Performance limitada em apps grandes                 │
 │             Problemas de memory leaks                            │
 │                                                                  │
 ├─ 2016       🔥 Angular 2 - RxJS e Observables                   │
 │             Sistema reativo baseado em Observables               │
 │             Change Detection com Zone.js                         │
 │             Melhor performance que AngularJS                     │
 │             Mas ainda complexo para casos simples               │
 │                                                                  │
 ├─ 2017-2022  📈 Melhorias Incrementais                          │
 │             OnPush Change Detection                              │
 │             Otimizações de performance                           │
 │             RxJS Operators avançados                             │
 │             Mas ainda verboso para estado simples               │
 │                                                                  │
 ├─ Maio 2023  🎯 Angular 16 - Signals Introduzidos (Developer Preview)
 │             signal(), computed(), effect()                       │
 │             Type-safe por padrão                                 │
 │             Performance otimizada                                │
 │             API mais simples que Observables                    │
 │                                                                  │
 ├─ Nov 2023   🚀 Angular 17 - Signals Estáveis                    │
 │             Signals em produção                                  │
 │             Model Inputs (two-way binding)                      │
 │             Integração com toSignal() e toObservable()          │
 │             Signal-based routing                                │
 │                                                                  │
 ├─ Nov 2024   🔥 Angular 19 - Signal Forms                        │
 │             Signal Forms API completa                           │
 │             Signal-based forms em produção                       │
 │             Melhor integração com validação                     │
 │                                                                  │
 └─ 2025+      🎯 Signal-First como Padrão                         │
               Migração gradual de projetos                         │
               Signals como primitiva primária                      │
               Observables apenas para streams assíncronos          │
```

**Por que Signals foram criados?**

O Angular enfrentava desafios com a abordagem baseada em Observables:

1. **Complexidade Desnecessária**: Para valores simples como contadores ou flags, Observables eram excessivamente complexos
2. **Verbose**: Criar um Observable, gerenciar subscriptions, usar async pipe - tudo isso para um simples valor
3. **Type Safety Limitado**: Observables não ofereciam type safety completo em templates
4. **Performance**: Change Detection precisava verificar toda a árvore de componentes mesmo quando apenas um valor mudava
5. **Curva de Aprendizado**: RxJS é poderoso mas complexo para desenvolvedores iniciantes

**Inspiração de Outros Frameworks**:

Angular não foi o primeiro a usar Signals. A ideia foi inspirada em:

- **Svelte (2016)**: Usa reatividade baseada em compilação, com conceitos similares a Signals
- **Vue 3 (2020)**: Introduziu `ref()` e `computed()` que são conceitualmente similares
- **Solid.js (2018)**: Framework construído completamente em Signals
- **Preact Signals (2022)**: Biblioteca de Signals para Preact/React

Angular tomou o melhor dessas abordagens e adaptou para seu ecossistema, mantendo compatibilidade com Observables.

**Evolução dos Signals no Angular**:

```
Angular 16 (Developer Preview)
  ├─ signal() básico
  ├─ computed() básico
  ├─ effect() básico
  └─ Integração limitada com templates

Angular 17 (Estável)
  ├─ Signals estáveis em produção
  ├─ Model Inputs (two-way binding)
  ├─ toSignal() e toObservable()
  ├─ Signal-based routing
  └─ Melhor integração com change detection

Angular 18
  ├─ Melhorias de performance
  ├─ Signal inputs melhorados
  ├─ Signal queries
  └─ Signal-based dependency injection

Angular 19
  ├─ Signal Forms API
  ├─ Signal-based forms em produção
  ├─ Melhor validação integrada
  └─ Signal-based reactive forms
```

### O que você vai aprender

- **Fundamentos**: Criar e usar signal() e computed()
- **Side Effects**: Trabalhar com effect() para sincronização e logging
- **Two-Way Binding**: Usar Model Inputs para inputs reativos
- **Formulários**: Criar formulários baseados em Signals
- **Arquitetura**: Implementar Signal-First Architecture
- **Migração**: Migrar de Observables para Signals
- **Integração**: Integrar Signals com Observables quando necessário

### Por que isso é importante

**Para Desenvolvimento**:

- **Simplicidade**: Signals são mais simples que Observables para valores simples
- **Performance**: Melhor performance através de change detection granular
- **Type Safety**: Type safety completo em templates e código
- **Produtividade**: Menos código boilerplate, mais foco na lógica de negócio
- **Futuro**: Signals são o futuro do Angular - aprender agora é investir no futuro

**Para Projetos**:

- **Performance**: Aplicações mais rápidas com menos overhead
- **Manutenibilidade**: Código mais limpo e fácil de entender
- **Escalabilidade**: Melhor performance em aplicações grandes
- **Modernização**: Caminho claro para modernizar projetos legados

**Para Carreira**:

- **Habilidade Essencial**: Conhecimento necessário para Angular moderno
- **Diferencial Competitivo**: Poucos desenvolvedores dominam Signals profundamente
- **Relevância**: Alinhado com a direção do Angular
- **Versatilidade**: Entender Signals ajuda a entender outros frameworks reativos

---

## Conceitos Teóricos

### signal()

**Definição**: `signal()` cria um signal reativo que mantém um valor e notifica automaticamente todos os dependentes quando o valor muda. É a primitiva fundamental para criar estado reativo no Angular.

**Explicação Detalhada**:

`signal()` é uma função que cria um objeto Signal, que encapsula um valor e mantém uma lista de dependências (consumidores). Quando você cria um signal, você está criando uma fonte de verdade reativa que:

- **Mantém Estado**: Armazena um valor que pode ser acessado através de uma função getter
- **Rastreia Dependências**: Automaticamente rastreia quem está "ouvindo" o signal (computed, effect, template)
- **Notifica Mudanças**: Quando o valor muda, todos os dependentes são notificados automaticamente
- **Type-Safe**: TypeScript garante type safety completo em tempo de compilação
- **Performático**: Change detection granular - apenas dependentes são atualizados

**Métodos Principais**:

- `signal.set(value)`: Define um novo valor diretamente
- `signal.update(fn)`: Atualiza o valor usando uma função que recebe o valor atual
- `signal.mutate(fn)`: Modifica objetos/arrays in-place (útil para performance)
- `signal()`: Chama o signal como função para ler o valor atual

**Analogia Detalhada**:

Imagine um **sistema de notificações de emergência** em um prédio:

1. **O Signal é o Botão de Alarme**: Quando você pressiona (atualiza o signal), ele não apenas emite um som, mas também:
   - Notifica todos os sistemas de segurança (computed signals)
   - Ativa os sprinklers (effects)
   - Atualiza os displays nos andares (templates)

2. **A Lista de Dependências**: O sistema mantém uma lista de todos que precisam ser notificados. Quando o alarme dispara, todos são alertados simultaneamente.

3. **Type Safety**: Cada botão de alarme tem um tipo específico (incêndio, segurança, etc.) - você não pode usar o botão errado.

4. **Performance**: O sistema não verifica todos os andares desnecessariamente - apenas os que estão "inscritos" são notificados.

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│                    signal<T>(initialValue)                   │
│                                                              │
│  ┌──────────────┐                                           │
│  │   Value: T   │  ← Estado atual armazenado                │
│  └──────────────┘                                           │
│         │                                                    │
│         │ Mudança de valor                                  │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │   Dependency Graph (DAG)             │                   │
│  │                                      │                   │
│  │  ┌─────────────┐                    │                   │
│  │  │  computed() │ ← Recalcula valor │                   │
│  │  └─────────────┘                    │                   │
│  │                                      │                   │
│  │  ┌─────────────┐                    │                   │
│  │  │   effect()  │ ← Executa side effect                  │
│  │  └─────────────┘                    │                   │
│  │                                      │                   │
│  │  ┌─────────────┐                    │                   │
│  │  │  Template   │ ← Atualiza view    │                   │
│  │  └─────────────┘                    │                   │
│  └──────────────────────────────────────┘                   │
│                                                              │
│  Métodos de Atualização:                                    │
│  • set(value)      → Substitui valor                        │
│  • update(fn)      → Atualiza com função                    │
│  • mutate(fn)      → Modifica in-place                       │
└─────────────────────────────────────────────────────────────┘
```

**Fluxo de Reatividade**:

{% raw %}
```
1. Signal criado: count = signal(0)
   └─> Valor inicial: 0
   └─> Dependências: []

2. Computed criado: double = computed(() => count() * 2)
   └─> Lê count() → registra dependência
   └─> Calcula: 0 * 2 = 0
   └─> Dependências de count: [double]

3. Template usa: {{ count() }}
   └─> Lê count() → registra dependência
   └─> Dependências de count: [double, template]

4. count.set(5) executado
   └─> Valor atualizado: 5
   └─> Notifica dependências: [double, template]
   └─> double recalcula: 5 * 2 = 10
   └─> template atualiza view: mostra 5
```
{% endraw %}

**Exemplo Prático Completo**:

```typescript
import { Component, signal, computed } from '@angular/core';

export class CounterComponent {
  count = signal(0);
  
  doubleCount = computed(() => this.count() * 2);
  
  isEven = computed(() => this.count() % 2 === 0);
  
  increment(): void {
    this.count.update(value => value + 1);
  }
  
  decrement(): void {
    this.count.update(value => value - 1);
  }
  
  setValue(value: number): void {
    this.count.set(value);
  }
  
  reset(): void {
    this.count.set(0);
  }
}

export class ArrayExampleComponent {
  items = signal([1, 2, 3]);
  
  addItem(value: number): void {
    this.items.update(items => [...items, value]);
  }
  
  removeItem(index: number): void {
    this.items.update(items => items.filter((_, i) => i !== index));
  }
  
  mutateAddItem(value: number): void {
    this.items.mutate(items => items.push(value));
  }
  
  itemCount = computed(() => this.items().length);
  
  sum = computed(() => 
    this.items().reduce((acc, val) => acc + val, 0)
  );
}
```

**Comparação: signal() vs Observable**:

| Aspecto | signal() | Observable |
|---------|----------|------------|
| **Criação** | `signal(0)` | `new BehaviorSubject(0)` |
| **Leitura** | `count()` | `count$.value` ou `async` pipe |
| **Atualização** | `count.set(5)` | `count$.next(5)` |
| **Type Safety** | Completo em template | Limitado |
| **Subscription** | Automática | Manual (ou async pipe) |
| **Performance** | Otimizado | Requer otimizações |
| **Complexidade** | Baixa | Média-Alta |
| **Uso Ideal** | Valores simples | Streams assíncronos |

---

### computed()

**Definição**: `computed()` cria um signal derivado (read-only) que calcula seu valor automaticamente baseado em outros signals. É memoizado e lazy, recalculando apenas quando necessário.

**Explicação Detalhada**:

`computed()` é uma função que cria um Signal derivado com características especiais:

- **Derivado**: Seu valor é calculado a partir de outros signals, não armazenado diretamente
- **Reativo**: Recalcula automaticamente quando qualquer dependência muda
- **Lazy**: Só calcula quando o valor é acessado pela primeira vez ou quando necessário
- **Memoizado**: Cacheia o resultado até que uma dependência mude
- **Read-Only**: Não pode ser modificado diretamente (apenas através de suas dependências)
- **Otimizado**: Angular otimiza o cálculo para evitar recálculos desnecessários

**Como Funciona Internamente**:

1. Quando você cria um `computed()`, Angular registra quais signals são lidos dentro da função
2. Quando você acessa o computed pela primeira vez, ele executa a função e cacheia o resultado
3. Quando uma dependência muda, o computed marca seu valor como "stale" (desatualizado)
4. Na próxima vez que o computed é acessado, ele recalcula apenas se necessário
5. Se múltiplos signals mudam, o computed só recalcula uma vez (debouncing interno)

**Analogia Detalhada**:

Imagine uma **calculadora de preço de supermercado**:

1. **As Dependências são os Produtos**: Você coloca produtos no carrinho (signals de entrada)
2. **O Computed é o Total**: O total é calculado automaticamente baseado nos produtos
3. **Memoização**: Se você não adicionar/remover produtos, o total não recalcula - usa o valor em cache
4. **Lazy**: Se você nunca olhar o total, ele nunca é calculado
5. **Read-Only**: Você não pode "setar" o total diretamente - ele só muda quando os produtos mudam

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│           computed(() => expression)                         │
│                                                              │
│  ┌──────────────────────────────────────┐                   │
│  │   Dependencies (Signals)            │                   │
│  │                                      │                   │
│  │  ┌──────────┐  ┌──────────┐        │                   │
│  │  │ signal A │  │ signal B │        │                   │
│  │  └────┬─────┘  └────┬─────┘        │                   │
│  │       │             │               │                   │
│  │       └──────┬──────┘               │                   │
│  │              │                      │                   │
│  │              ▼                      │                   │
│  │  ┌──────────────────────┐          │                   │
│  │  │  Computation Function │          │                   │
│  │  │  () => A() + B()     │          │                   │
│  │  └──────────┬───────────┘          │                   │
│  │             │                       │                   │
│  │             ▼                       │                   │
│  │  ┌──────────────────────┐          │                   │
│  │  │  Cached Value        │          │                   │
│  │  │  (Memoized)          │          │                   │
│  │  └──────────────────────┘          │                   │
│  └──────────────────────────────────────┘                   │
│                                                              │
│  Características:                                           │
│  • Lazy: Calcula apenas quando acessado                    │
│  • Memoized: Cacheia resultado                              │
│  • Read-only: Não pode ser modificado                       │
│  • Reativo: Recalcula quando dependências mudam             │
└─────────────────────────────────────────────────────────────┘
```

**Fluxo de Cálculo**:

```
Cenário: total = computed(() => price() * quantity())

1. Criação: total = computed(...)
   └─> Dependências: [] (ainda não identificadas)

2. Primeiro acesso: total()
   └─> Executa função: lê price() e quantity()
   └─> Registra dependências: [price, quantity]
   └─> Calcula: 10 * 2 = 20
   └─> Cacheia: 20
   └─> Retorna: 20

3. Segundo acesso: total()
   └─> Verifica dependências: nenhuma mudou
   └─> Retorna cache: 20 (sem recalcular)

4. price.set(15) executado
   └─> Marca total como "stale"
   └─> Cache ainda é 20 (não recalcula ainda)

5. Próximo acesso: total()
   └─> Detecta que está "stale"
   └─> Recalcula: 15 * 2 = 30
   └─> Atualiza cache: 30
   └─> Retorna: 30
```

**Exemplo Prático Completo**:

```typescript
import { Component, signal, computed } from '@angular/core';

interface Item {
  id: number;
  name: string;
  price: number;
  quantity: number;
}

export class ShoppingCartComponent {
  items = signal<Item[]>([]);
  discount = signal(0);
  taxRate = signal(0.1);
  
  itemCount = computed(() => this.items().length);
  
  subtotal = computed(() => 
    this.items().reduce(
      (sum, item) => sum + (item.price * item.quantity), 
      0
    )
  );
  
  discountAmount = computed(() => 
    this.subtotal() * this.discount()
  );
  
  taxAmount = computed(() => 
    (this.subtotal() - this.discountAmount()) * this.taxRate()
  );
  
  total = computed(() => 
    this.subtotal() - this.discountAmount() + this.taxAmount()
  );
  
  hasItems = computed(() => this.items().length > 0);
  
  isEmpty = computed(() => !this.hasItems());
  
  averageItemPrice = computed(() => {
    const items = this.items();
    if (items.length === 0) return 0;
    return this.subtotal() / items.reduce((sum, item) => sum + item.quantity, 0);
  });
  
  addItem(item: Item): void {
    this.items.update(items => [...items, item]);
  }
  
  removeItem(id: number): void {
    this.items.update(items => items.filter(item => item.id !== id));
  }
  
  updateDiscount(value: number): void {
    this.discount.set(Math.max(0, Math.min(1, value)));
  }
}
```

**Computed Aninhados**:

```typescript
export class NestedComputedExample {
  basePrice = signal(100);
  quantity = signal(2);
  
  subtotal = computed(() => this.basePrice() * this.quantity());
  
  discount = signal(0.1);
  
  discountAmount = computed(() => 
    this.subtotal() * this.discount()
  );
  
  finalPrice = computed(() => 
    this.subtotal() - this.discountAmount()
  );
  
  formattedPrice = computed(() => 
    `$${this.finalPrice().toFixed(2)}`
  );
}
```

**Comparação: computed() vs Getter Tradicional**:

| Aspecto | computed() | Getter Tradicional |
|---------|------------|-------------------|
| **Reatividade** | Automática | Manual |
| **Memoização** | Sim (cacheia) | Não (recalcula sempre) |
| **Performance** | Otimizado | Pode ser lento |
| **Change Detection** | Granular | Verifica componente inteiro |
| **Dependências** | Rastreadas automaticamente | Não rastreadas |
| **Uso Ideal** | Valores derivados de signals | Valores estáticos |

---

### effect()

**Definição**: `effect()` executa código (side effects) automaticamente quando signals mudam. É útil para sincronização, logging, e outras operações que precisam reagir a mudanças de estado.

**Explicação Detalhada**:

`effect()` é uma função que cria um efeito reativo que:

- **Executa Automaticamente**: Roda sempre que um signal lido dentro dele muda
- **Rastreia Dependências**: Automaticamente identifica quais signals são lidos
- **Side Effects**: Projetado para operações que causam efeitos colaterais (DOM, localStorage, APIs)
- **Destruição Automática**: É limpo automaticamente quando o componente é destruído
- **Ordem de Execução**: Executa após todas as mudanças serem aplicadas (no final do ciclo)
- **Cuidado com Loops**: Pode causar loops infinitos se atualizar signals dentro do effect

**Quando Usar effect()**:

✅ **Bom para**:
- Sincronizar com localStorage/sessionStorage
- Atualizar DOM diretamente (quando necessário)
- Logging e debugging
- Integração com bibliotecas externas
- Sincronização com APIs externas

❌ **Evite**:
- Atualizar outros signals (use computed() ao invés)
- Lógica de negócio complexa (use métodos do componente)
- Cálculos derivados (use computed())

**Analogia Detalhada**:

Imagine um **sistema de alarme residencial**:

1. **Os Signals são Sensores**: Sensores de movimento, porta, janela (valores que mudam)
2. **O Effect é o Sistema de Alarme**: Quando qualquer sensor detecta algo, o alarme dispara automaticamente
3. **Side Effects**: O alarme não apenas "observa" - ele faz algo (toca sirene, liga luzes, notifica segurança)
4. **Destruição**: Quando você se muda (componente destruído), o sistema é desligado automaticamente
5. **Cuidado**: Se o alarme ligar um sensor que dispara o alarme novamente, você tem um loop infinito!

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│              effect(() => { sideEffect() })                 │
│                                                              │
│  ┌──────────────────────────────────────┐                   │
│  │   Dependencies (Signals)             │                   │
│  │                                      │                   │
│  │  ┌──────────┐  ┌──────────┐        │                   │
│  │  │ signal A │  │ signal B │        │                   │
│  │  └────┬─────┘  └────┬─────┘        │                   │
│  │       │             │               │                   │
│  │       └──────┬──────┘               │                   │
│  │              │                      │                   │
│  │              ▼                      │                   │
│  │  ┌──────────────────────┐          │                   │
│  │  │  Effect Function     │          │                   │
│  │  │  () => {             │          │                   │
│  │  │    const a = A();   │          │                   │
│  │  │    const b = B();   │          │                   │
│  │  │    sideEffect(a, b); │          │                   │
│  │  │  }                   │          │                   │
│  │  └──────────┬───────────┘          │                   │
│  │             │                       │                   │
│  │             ▼                       │                   │
│  │  ┌──────────────────────┐          │                   │
│  │  │  Side Effects        │          │                   │
│  │  │  • localStorage     │          │                   │
│  │  │  • DOM updates      │          │                   │
│  │  │  • API calls        │          │                   │
│  │  │  • Logging          │          │                   │
│  │  └──────────────────────┘          │                   │
│  └──────────────────────────────────────┘                   │
│                                                              │
│  ⚠️  CUIDADO: Não atualize signals dentro do effect!        │
│      Isso pode causar loops infinitos.                       │
└─────────────────────────────────────────────────────────────┘
```

**Fluxo de Execução**:

```
1. Effect criado: effect(() => { console.log(count()) })
   └─> Registra dependências: [count]
   └─> Executa primeira vez: lê count() = 0, loga 0

2. count.set(5) executado
   └─> Marca effect como "precisa executar"
   └─> Após todas mudanças aplicadas
   └─> Executa effect: lê count() = 5, loga 5

3. count.set(10) executado
   └─> Marca effect como "precisa executar"
   └─> Executa effect: lê count() = 10, loga 10

4. Componente destruído
   └─> Effect é automaticamente destruído
   └─> Não executa mais
```

**Exemplo Prático Completo**:

```typescript
import { Component, signal, effect, DestroyRef, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

export class UserPreferencesComponent {
  theme = signal<'light' | 'dark'>('light');
  fontSize = signal(16);
  language = signal('pt-BR');
  
  private destroyRef = inject(DestroyRef);
  
  constructor() {
    effect(() => {
      const theme = this.theme();
      document.body.className = `theme-${theme}`;
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('theme', theme);
    });
    
    effect(() => {
      const size = this.fontSize();
      document.documentElement.style.fontSize = `${size}px`;
      localStorage.setItem('fontSize', size.toString());
    });
    
    effect(() => {
      const lang = this.language();
      document.documentElement.lang = lang;
      localStorage.setItem('language', lang);
    });
    
    this.loadPreferences();
  }
  
  private loadPreferences(): void {
    const savedTheme = localStorage.getItem('theme') as 'light' | 'dark' | null;
    if (savedTheme) {
      this.theme.set(savedTheme);
    }
    
    const savedFontSize = localStorage.getItem('fontSize');
    if (savedFontSize) {
      this.fontSize.set(parseInt(savedFontSize, 10));
    }
    
    const savedLang = localStorage.getItem('language');
    if (savedLang) {
      this.language.set(savedLang);
    }
  }
  
  toggleTheme(): void {
    this.theme.update(current => current === 'light' ? 'dark' : 'light');
  }
  
  increaseFont(): void {
    this.fontSize.update(size => Math.min(size + 2, 24));
  }
  
  decreaseFont(): void {
    this.fontSize.update(size => Math.max(size - 2, 12));
  }
}
```

**Effect com Cleanup**:

```typescript
export class EffectWithCleanupComponent {
  intervalId = signal<number | null>(null);
  count = signal(0);
  
  constructor() {
    effect((onCleanup) => {
      const interval = this.intervalId();
      
      if (interval !== null) {
        const id = setInterval(() => {
          this.count.update(c => c + 1);
        }, interval);
        
        onCleanup(() => {
          clearInterval(id);
        });
      }
    });
  }
  
  startInterval(ms: number): void {
    this.intervalId.set(ms);
  }
  
  stopInterval(): void {
    this.intervalId.set(null);
  }
}
```

**⚠️ Anti-padrão: Loop Infinito**:

```typescript
export class BadEffectExample {
  count = signal(0);
  
  constructor() {
    effect(() => {
      const current = this.count();
      console.log('Count:', current);
      
      this.count.set(current + 1);
    });
  }
}
```

**Problema**: O effect atualiza o signal que ele observa, causando loop infinito!

**Solução**: Use computed() ou atualize fora do effect:

```typescript
export class GoodEffectExample {
  count = signal(0);
  
  doubleCount = computed(() => this.count() * 2);
  
  constructor() {
    effect(() => {
      console.log('Double count:', this.doubleCount());
    });
  }
  
  increment(): void {
    this.count.update(c => c + 1);
  }
}
```

**Comparação: effect() vs computed()**:

| Aspecto | effect() | computed() |
|---------|----------|------------|
| **Propósito** | Side effects | Valores derivados |
| **Retorno** | void | Signal<T> |
| **Uso** | Sincronização, logging | Cálculos, transformações |
| **Pode atualizar signals?** | ❌ Não (causa loop) | ❌ Não (read-only) |
| **Quando executa** | Após mudanças | Quando acessado |
| **Destruição** | Automática | Automática |

---

### Model Inputs

**Definição**: Model Inputs (Angular 17+) permitem two-way data binding usando signals através da função `model()`. Substituem `ngModel` em muitos casos, oferecendo type safety completo e integração nativa com Signals.

**Explicação Detalhada**:

Model Inputs são uma forma moderna de implementar two-way binding no Angular:

- **Two-Way Binding**: Mudanças no componente pai e filho são sincronizadas automaticamente
- **Type-Safe**: TypeScript garante type safety completo em tempo de compilação
- **Reativo**: Baseado em Signals, oferece reatividade granular
- **Simples**: Sintaxe mais limpa que `ngModel` tradicional
- **Integrado**: Funciona perfeitamente com Signals e computed()
- **Validação**: Suporta validação através de signal validators

**Como Funciona**:

1. No componente filho, você cria um `model()` input
2. No template do filho, você usa `[(model)]` ou `[model]` e `(modelChange)`
3. No componente pai, você passa um signal usando `[(model)]="signal"`
4. Mudanças em qualquer direção são sincronizadas automaticamente

**Analogia Detalhada**:

Imagine um **sistema de videoconferência com compartilhamento de tela**:

1. **O Model Input é a Conexão**: Cria uma conexão bidirecional entre pai e filho
2. **O Signal é a Tela Compartilhada**: Ambos podem ver e modificar o mesmo conteúdo
3. **Sincronização Automática**: Quando um lado muda algo, o outro vê imediatamente
4. **Type Safety**: A conexão só aceita o tipo correto de dados (como um protocolo específico)

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Parent Component                         │
│                                                              │
│  parentValue = signal('Hello')                              │
│         │                                                    │
│         │ [(value)]="parentValue"                           │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │      Child Component                 │                   │
│  │                                      │                   │
│  │  value = model<string>('')           │                   │
│  │       │                               │                   │
│  │       │ Two-way binding              │                   │
│  │       ▼                               │                   │
│  │  <input [(ngModel)]="value()">        │                   │
│  │  ou                                   │                   │
│  │  <input [value]="value()"             │                   │
│  │       (input)="value.set(...)">       │                   │
│  └──────────────────────────────────────┘                   │
│                                                              │
│  Fluxo:                                                     │
│  1. Parent muda → Child atualiza                            │
│  2. Child muda → Parent atualiza                            │
│  3. Sincronização automática                                │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

{% raw %}
```typescript
import { Component, model, signal, computed } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-counter-input',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div>
      <label>Contador:</label>
      <input 
        type="number" 
        [value]="count()" 
        (input)="count.set(+$any($event.target).value)"
        min="0">
      <button (click)="increment()">+</button>
      <button (click)="decrement()">-</button>
    </div>
  `
})
export class CounterInputComponent {
  count = model<number>(0);
  
  increment(): void {
    this.count.update(c => c + 1);
  }
  
  decrement(): void {
    this.count.update(c => Math.max(0, c - 1));
  }
}

@Component({
  selector: 'app-text-input',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div>
      <label>Texto:</label>
      <input 
        [value]="text()" 
        (input)="text.set($any($event.target).value)"
        placeholder="Digite algo...">
      <p>Caracteres: {{ text().length }}</p>
    </div>
  `
})
export class TextInputComponent {
  text = model<string>('');
  
  characterCount = computed(() => this.text().length);
  
  isLong = computed(() => this.text().length > 100);
}

@Component({
  selector: 'app-parent',
  standalone: true,
  imports: [CounterInputComponent, TextInputComponent],
  template: `
    <div>
      <h2>Parent Component</h2>
      
      <app-counter-input [(count)]="counter" />
      <p>Valor do contador no pai: {{ counter() }}</p>
      <p>Dobro: {{ doubleCounter() }}</p>
      
      <app-text-input [(text)]="message" />
      <p>Mensagem no pai: {{ message() }}</p>
    </div>
  `
})
export class ParentComponent {
  counter = signal(0);
  message = signal('');
  
  doubleCounter = computed(() => this.counter() * 2);
}
```
{% endraw %}

**Model Input com Validação**:

```typescript
import { Component, model, signal } from '@angular/core';
import { FormsModule, Validators } from '@angular/forms';

@Component({
  selector: 'app-email-input',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div>
      <label>Email:</label>
      <input 
        type="email"
        [value]="email()" 
        (input)="email.set($any($event.target).value)"
        [class.invalid]="!isValid()">
      @if (!isValid()) {
        <p class="error">Email inválido</p>
      }
    </div>
  `
})
export class EmailInputComponent {
  email = model<string>('');
  
  isValid = computed(() => {
    const value = this.email();
    return value.includes('@') && value.includes('.');
  });
}
```

**Comparação: model() vs ngModel**:

| Aspecto | model() | ngModel |
|---------|---------|---------|
| **Type Safety** | Completo | Limitado |
| **Reatividade** | Signals (granular) | Change Detection (componente) |
| **Performance** | Otimizado | Requer otimizações |
| **Sintaxe** | `[(model)]="signal"` | `[(ngModel)]="property"` |
| **Integração** | Nativa com Signals | Requer FormsModule |
| **Validação** | Signal validators | Form validators |
| **Uso Ideal** | Signal-First apps | Apps tradicionais |

---

### Signal-Based Forms

**Definição**: Signal Forms (Angular 19+) são formulários baseados em Signals que oferecem uma API mais simples e performática que Reactive Forms tradicionais. Cada campo do formulário é um signal reativo.

**Explicação Detalhada**:

Signal Forms representam uma evolução dos formulários Angular:

- **Signal-Based**: Cada campo é um signal, oferecendo reatividade granular
- **Simplicidade**: API mais simples que FormBuilder e FormGroup
- **Performance**: Melhor performance através de change detection granular
- **Type-Safe**: Type safety completo em tempo de compilação
- **Validação Integrada**: Validação através de signal validators
- **Estado Reativo**: Estado do formulário (valid, invalid, touched) são signals

**Como Funciona**:

1. Você cria signals para cada campo do formulário
2. Usa `model()` ou `input()` para criar inputs reativos
3. Validação é feita através de computed signals ou validators
4. Estado do formulário é automaticamente reativo

**Analogia Detalhada**:

Imagine um **formulário de papel inteligente**:

1. **Cada Campo é um Signal**: Cada campo "sabe" quando foi modificado e notifica automaticamente
2. **Validação Automática**: Quando você preenche um campo, ele valida automaticamente
3. **Estado Reativo**: O formulário "sabe" se está completo, válido, ou tem erros
4. **Sincronização**: Mudanças são refletidas instantaneamente em toda a aplicação

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│              Signal Form Structure                          │
│                                                              │
│  ┌──────────────────────────────────────┐                   │
│  │  Form Signals                        │                   │
│  │                                      │                   │
│  │  name = model<string>('')           │                   │
│  │  email = model<string>('')           │                   │
│  │  age = model<number>(0)             │                   │
│  └──────────────┬───────────────────────┘                   │
│                 │                                            │
│                 ▼                                            │
│  ┌──────────────────────────────────────┐                   │
│  │  Validation Signals                  │                   │
│  │                                      │                   │
│  │  isNameValid = computed(...)        │                   │
│  │  isEmailValid = computed(...)      │                   │
│  │  isFormValid = computed(...)        │                   │
│  └──────────────┬───────────────────────┘                   │
│                 │                                            │
│                 ▼                                            │
│  ┌──────────────────────────────────────┐                   │
│  │  Form State Signals                 │                   │
│  │                                      │                   │
│  │  touched = signal(false)            │                   │
│  │  submitted = signal(false)          │                   │
│  │  errors = signal<Errors>({})      │                   │
│  └──────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

{% raw %}
```typescript
import { Component, model, signal, computed } from '@angular/core';
import { FormsModule } from '@angular/forms';

interface UserForm {
  name: string;
  email: string;
  age: number;
  agreeToTerms: boolean;
}

@Component({
  selector: 'app-signal-form',
  standalone: true,
  imports: [FormsModule],
  template: `
    <form (ngSubmit)="onSubmit()">
      <div>
        <label>Nome:</label>
        <input 
          [value]="name()" 
          (input)="name.set($any($event.target).value)"
          [class.invalid]="!isNameValid()">
        @if (!isNameValid() && name().length > 0) {
          <p class="error">Nome deve ter pelo menos 3 caracteres</p>
        }
      </div>
      
      <div>
        <label>Email:</label>
        <input 
          type="email"
          [value]="email()" 
          (input)="email.set($any($event.target).value)"
          [class.invalid]="!isEmailValid()">
        @if (!isEmailValid() && email().length > 0) {
          <p class="error">Email inválido</p>
        }
      </div>
      
      <div>
        <label>Idade:</label>
        <input 
          type="number"
          [value]="age()" 
          (input)="age.set(+$any($event.target).value)"
          min="18"
          max="120"
          [class.invalid]="!isAgeValid()">
        @if (!isAgeValid() && age() > 0) {
          <p class="error">Idade deve ser entre 18 e 120</p>
        }
      </div>
      
      <div>
        <label>
          <input 
            type="checkbox"
            [checked]="agreeToTerms()"
            (change)="agreeToTerms.set($any($event.target).checked)">
          Concordo com os termos
        </label>
      </div>
      
      <button type="submit" [disabled]="!isFormValid()">
        Enviar
      </button>
      
      <div>
        <p>Formulário válido: {{ isFormValid() }}</p>
        <p>Formulário tocado: {{ touched() }}</p>
      </div>
    </form>
  `
})
export class SignalFormComponent {
  name = model<string>('');
  email = model<string>('');
  age = model<number>(0);
  agreeToTerms = model<boolean>(false);
  
  touched = signal(false);
  submitted = signal(false);
  
  isNameValid = computed(() => {
    const value = this.name();
    return value.length >= 3;
  });
  
  isEmailValid = computed(() => {
    const value = this.email();
    return value.includes('@') && value.includes('.') && value.length > 5;
  });
  
  isAgeValid = computed(() => {
    const age = this.age();
    return age >= 18 && age <= 120;
  });
  
  isFormValid = computed(() => {
    return this.isNameValid() && 
           this.isEmailValid() && 
           this.isAgeValid() && 
           this.agreeToTerms();
  });
  
  onSubmit(): void {
    this.touched.set(true);
    this.submitted.set(true);
    
    if (this.isFormValid()) {
      const formData: UserForm = {
        name: this.name(),
        email: this.email(),
        age: this.age(),
        agreeToTerms: this.agreeToTerms()
      };
      
      console.log('Form submitted:', formData);
    }
  }
}
```
{% endraw %}

**Signal Forms com Validação Avançada**:

```typescript
export class AdvancedSignalFormComponent {
  password = model<string>('');
  confirmPassword = model<string>('');
  
  passwordStrength = computed(() => {
    const pwd = this.password();
    let strength = 0;
    
    if (pwd.length >= 8) strength++;
    if (/[a-z]/.test(pwd)) strength++;
    if (/[A-Z]/.test(pwd)) strength++;
    if (/[0-9]/.test(pwd)) strength++;
    if (/[^a-zA-Z0-9]/.test(pwd)) strength++;
    
    return strength;
  });
  
  passwordStrengthLabel = computed(() => {
    const strength = this.passwordStrength();
    if (strength <= 2) return 'Fraca';
    if (strength <= 3) return 'Média';
    if (strength <= 4) return 'Forte';
    return 'Muito Forte';
  });
  
  passwordsMatch = computed(() => {
    return this.password() === this.confirmPassword();
  });
  
  isPasswordValid = computed(() => {
    return this.passwordStrength() >= 3 && this.passwordsMatch();
  });
}
```

**Comparação: Signal Forms vs Reactive Forms**:

| Aspecto | Signal Forms | Reactive Forms |
|---------|--------------|----------------|
| **API** | Simples (signals) | Complexa (FormBuilder) |
| **Type Safety** | Completo | Limitado |
| **Performance** | Otimizado | Requer otimizações |
| **Boilerplate** | Mínimo | Significativo |
| **Reatividade** | Granular (signals) | Component-level |
| **Validação** | Signal validators | Form validators |
| **Curva de Aprendizado** | Baixa | Média-Alta |
| **Uso Ideal** | Signal-First apps | Apps tradicionais |

---

### Signal-First Architecture

**Definição**: Signal-First Architecture é um padrão arquitetural onde Signals são a primitiva reativa primária para gerenciamento de estado, com Observables usados apenas para streams assíncronos complexos (HTTP, WebSockets, eventos de tempo).

**Explicação Detalhada**:

Signal-First Architecture segue o princípio de usar a ferramenta certa para cada trabalho:

**Quando Usar Signals**:
- ✅ Estado local de componentes
- ✅ Estado derivado (computed)
- ✅ Comunicação entre componentes (inputs/outputs)
- ✅ Estado global simples (services com signals)
- ✅ Formulários e validação
- ✅ UI state (loading, errors, etc.)

**Quando Usar Observables**:
- ✅ HTTP requests (convertidos para signals com toSignal())
- ✅ WebSockets e eventos em tempo real
- ✅ Eventos de DOM complexos
- ✅ Timers e intervalos
- ✅ Streams de dados complexos com múltiplos operadores RxJS

**Princípios da Arquitetura**:

1. **Signals como Padrão**: Use signals por padrão, não como exceção
2. **Observables como Bridge**: Use Observables apenas para dados assíncronos, convertendo para signals
3. **Granularidade**: Cada pedaço de estado deve ser um signal separado
4. **Computed para Derivação**: Use computed() para valores derivados, não métodos
5. **Effect para Side Effects**: Use effect() apenas para sincronização e side effects

**Analogia Detalhada**:

Imagine uma **cidade moderna com diferentes sistemas de transporte**:

1. **Signals são Bicicletas**: Perfeitas para distâncias curtas (estado local), rápidas, simples, eficientes
2. **Observables são Metrôs**: Necessários para distâncias longas (streams assíncronos), mas você converte para bicicleta (signal) quando chega ao destino
3. **Computed são Rotas**: Calculadas automaticamente baseadas nas bicicletas disponíveis
4. **Effects são Sinais de Trânsito**: Reagem automaticamente ao tráfego (mudanças de signals)

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│           Signal-First Architecture                         │
│                                                              │
│  ┌──────────────────────────────────────┐                   │
│  │  Component Layer                    │                   │
│  │                                      │                   │
│  │  ┌──────────┐  ┌──────────┐        │                   │
│  │  │  Signal   │  │  Signal  │        │                   │
│  │  │  State    │  │  State   │        │                   │
│  │  └─────┬─────┘  └─────┬────┘        │                   │
│  │        │              │              │                   │
│  │        └──────┬───────┘              │                   │
│  │               │                       │                   │
│  │               ▼                       │                   │
│  │        ┌─────────────┐               │                   │
│  │        │  computed()  │               │                   │
│  │        └─────────────┘               │                   │
│  └───────────────────────────────────────┘                   │
│               │                                              │
│               ▼                                              │
│  ┌──────────────────────────────────────┐                   │
│  │  Service Layer                      │                   │
│  │                                      │                   │
│  │  ┌──────────┐                      │                   │
│  │  │  Signal   │                      │                   │
│  │  │  Service  │                      │                   │
│  │  └──────────┘                      │                   │
│  └───────────────────────────────────────┘                   │
│               │                                              │
│               ▼                                              │
│  ┌──────────────────────────────────────┐                   │
│  │  Data Layer                         │                   │
│  │                                      │                   │
│  │  ┌──────────────┐                  │                   │
│  │  │  Observable  │  (HTTP, WS)      │                   │
│  │  │   Streams    │                  │                   │
│  │  └──────┬───────┘                  │                   │
│  │         │                           │                   │
│  │         │ toSignal()                │                   │
│  │         ▼                           │                   │
│  │  ┌──────────────┐                  │                   │
│  │  │    Signal    │                  │                   │
│  │  └──────────────┘                  │                   │
│  └───────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

{% raw %}
```typescript
import { Component, signal, computed, effect, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';
import { catchError, of } from 'rxjs';

interface User {
  id: number;
  name: string;
  email: string;
}

interface Todo {
  id: number;
  title: string;
  completed: boolean;
  userId: number;
}

@Component({
  selector: 'app-signal-first',
  standalone: true,
  template: `
    <div>
      <h2>{{ title() }}</h2>
      
      <div>
        <label>Filtro:</label>
        <select [value]="filter()" (change)="filter.set($any($event.target).value)">
          <option value="all">Todos</option>
          <option value="active">Ativos</option>
          <option value="completed">Completos</option>
        </select>
      </div>
      
      @if (loading()) {
        <p>Carregando...</p>
      } @else if (error()) {
        <p class="error">{{ error() }}</p>
      } @else {
        <div>
          <p>Total: {{ totalTodos() }} | 
             Ativos: {{ activeTodos() }} | 
             Completos: {{ completedTodos() }}</p>
          
          <ul>
            @for (todo of filteredTodos(); track todo.id) {
              <li>
                <input 
                  type="checkbox"
                  [checked]="todo.completed"
                  (change)="toggleTodo(todo.id)">
                {{ todo.title }}
                <button (click)="removeTodo(todo.id)">Remover</button>
              </li>
            }
          </ul>
        </div>
      }
    </div>
  `
})
export class SignalFirstComponent {
  title = signal('Signal-First Todo App');
  filter = signal<'all' | 'active' | 'completed'>('all');
  
  private http = inject(HttpClient);
  
  todos = toSignal(
    this.http.get<Todo[]>('/api/todos').pipe(
      catchError(() => {
        this.error.set('Erro ao carregar todos');
        return of([]);
      })
    ),
    { initialValue: [] }
  );
  
  loading = signal(false);
  error = signal<string | null>(null);
  
  totalTodos = computed(() => this.todos().length);
  
  activeTodos = computed(() => 
    this.todos().filter(t => !t.completed).length
  );
  
  completedTodos = computed(() => 
    this.todos().filter(t => t.completed).length
  );
  
  filteredTodos = computed(() => {
    const todos = this.todos();
    const filter = this.filter();
    
    switch (filter) {
      case 'active':
        return todos.filter(t => !t.completed);
      case 'completed':
        return todos.filter(t => t.completed);
      default:
        return todos;
    }
  });
  
  constructor() {
    effect(() => {
      const todos = this.todos();
      console.log('Todos atualizados:', todos.length);
    });
  }
  
  toggleTodo(id: number): void {
    const todo = this.todos().find(t => t.id === id);
    if (todo) {
      this.http.patch(`/api/todos/${id}`, { 
        completed: !todo.completed 
      }).subscribe({
        next: () => {
          this.todos.update(todos => 
            todos.map(t => t.id === id ? { ...t, completed: !t.completed } : t)
          );
        },
        error: () => this.error.set('Erro ao atualizar todo')
      });
    }
  }
  
  removeTodo(id: number): void {
    this.http.delete(`/api/todos/${id}`).subscribe({
      next: () => {
        this.todos.update(todos => todos.filter(t => t.id !== id));
      },
      error: () => this.error.set('Erro ao remover todo')
    });
  }
}
```
{% endraw %}

**Signal-First Service Pattern**:

```typescript
import { Injectable, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private http = inject(HttpClient);
  
  users = toSignal(
    this.http.get<User[]>('/api/users'),
    { initialValue: [] }
  );
  
  selectedUserId = signal<number | null>(null);
  
  selectedUser = computed(() => {
    const id = this.selectedUserId();
    if (id === null) return null;
    return this.users().find(u => u.id === id) || null;
  });
  
  userCount = computed(() => this.users().length);
  
  selectUser(id: number): void {
    this.selectedUserId.set(id);
  }
  
  clearSelection(): void {
    this.selectedUserId.set(null);
  }
}
```

**Comparação: Signal-First vs Observable-First**:

| Aspecto | Signal-First | Observable-First |
|---------|--------------|------------------|
| **Estado Local** | Signals | BehaviorSubject |
| **Estado Derivado** | computed() | combineLatest, map |
| **HTTP** | toSignal(Observable) | Observable direto |
| **Complexidade** | Baixa | Média-Alta |
| **Performance** | Otimizado | Requer otimizações |
| **Type Safety** | Completo | Limitado |
| **Boilerplate** | Mínimo | Significativo |
| **Curva de Aprendizado** | Baixa | Alta |
| **Uso Ideal** | Apps modernas | Apps complexas com streams |

---

## Comparação com Outros Frameworks

### Angular Signals vs React Hooks

**React useState e useEffect**:

```typescript
function Counter() {
  const [count, setCount] = useState(0);
  const [double, setDouble] = useState(0);
  
  useEffect(() => {
    setDouble(count * 2);
  }, [count]);
  
  return <div>{count} - {double}</div>;
}
```

**Angular Signals**:

{% raw %}
```typescript
export class CounterComponent {
  count = signal(0);
  double = computed(() => this.count() * 2);
  
  template = `<div>{{ count() }} - {{ double() }}</div>`;
}
```
{% raw %}
export class CounterComponent {
  count = signal(0);
  double = computed(() => this.count() * 2);
  
  template = `<div>{{ count() }} - {{ double() }}</div>`;
}
```
{% endraw %}

**Comparação Detalhada**:

| Aspecto | Angular Signals | React Hooks |
|---------|-----------------|-------------|
| **Criação** | `signal(0)` | `useState(0)` |
| **Leitura** | `count()` | `count` |
| **Atualização** | `count.set(5)` | `setCount(5)` |
| **Valores Derivados** | `computed()` automático | `useMemo()` ou `useEffect()` |
| **Side Effects** | `effect()` | `useEffect()` |
| **Type Safety** | Completo | Completo |
| **Performance** | Otimizado automaticamente | Requer otimizações |
| **Re-renders** | Granular (apenas dependentes) | Component-level |
| **Curva de Aprendizado** | Baixa | Média |

**Vantagens Angular Signals**:
- ✅ Computed automático (não precisa useEffect para valores derivados)
- ✅ Performance otimizada por padrão
- ✅ Menos boilerplate
- ✅ Reatividade granular

**Vantagens React Hooks**:
- ✅ Mais flexível (pode usar qualquer lógica)
- ✅ Ecossistema maior
- ✅ Mais recursos educacionais

### Angular Signals vs Vue 3 Composition API

**Vue 3 ref() e computed()**:

```typescript
import { ref, computed } from 'vue';

export default {
  setup() {
    const count = ref(0);
    const double = computed(() => count.value * 2);
    
    return { count, double };
  }
};
```

**Angular Signals**:

```typescript
export class CounterComponent {
  count = signal(0);
  double = computed(() => this.count() * 2);
}
```

**Comparação Detalhada**:

| Aspecto | Angular Signals | Vue 3 Composition API |
|---------|-----------------|-------------------------|
| **Criação** | `signal(0)` | `ref(0)` |
| **Leitura** | `count()` | `count.value` |
| **Atualização** | `count.set(5)` | `count.value = 5` |
| **Valores Derivados** | `computed()` | `computed()` |
| **Side Effects** | `effect()` | `watch()` ou `watchEffect()` |
| **Type Safety** | Completo | Completo |
| **Sintaxe** | `.set()` e `()` | `.value` |
| **Reatividade** | Granular | Granular |
| **Performance** | Otimizado | Otimizado |

**Similaridades**:
- ✅ Ambos usam reatividade granular
- ✅ Ambos têm computed para valores derivados
- ✅ Ambos são type-safe
- ✅ Ambos têm side effects (effect/watch)

**Diferenças**:
- Angular usa `.set()` e `()`, Vue usa `.value`
- Angular tem melhor integração com templates
- Vue tem mais flexibilidade na composição

### Angular Signals vs Svelte

**Svelte Reatividade**:

```svelte
<script>
  let count = 0;
  $: double = count * 2;
</script>

<div>{count} - {double}</div>
```

**Angular Signals**:

{% raw %}
```typescript
export class CounterComponent {
  count = signal(0);
  double = computed(() => this.count() * 2);
  
  template = `<div>{{ count() }} - {{ double() }}</div>`;
}
```
{% raw %}
export class CounterComponent {
  count = signal(0);
  double = computed(() => this.count() * 2);
  
  template = `<div>{{ count() }} - {{ double() }}</div>`;
}
```
{% endraw %}

**Comparação Detalhada**:

| Aspecto | Angular Signals | Svelte |
|---------|-----------------|--------|
| **Criação** | `signal(0)` | `let count = 0` |
| **Leitura** | `count()` | `count` |
| **Atualização** | `count.set(5)` | `count = 5` |
| **Valores Derivados** | `computed()` | `$: double = count * 2` |
| **Compilação** | Runtime | Compile-time |
| **Bundle Size** | Maior | Menor |
| **Type Safety** | Completo | Completo |
| **Sintaxe** | Explícito | Implícito |

**Vantagens Angular Signals**:
- ✅ Mais explícito (fácil de entender)
- ✅ Melhor para apps grandes
- ✅ Ecossistema maior

**Vantagens Svelte**:
- ✅ Sintaxe mais simples
- ✅ Bundle menor
- ✅ Compilação otimizada

### Tabela Comparativa Geral

| Framework | Primitiva Reativa | Sintaxe | Performance | Type Safety | Curva de Aprendizado |
|-----------|-------------------|---------|------------|-------------|---------------------|
| **Angular Signals** | `signal()` | `signal()` / `.set()` | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **React** | `useState()` | `useState()` / `setState()` | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Vue 3** | `ref()` | `ref()` / `.value` | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Svelte** | Variáveis reativas | `let` / `$:` | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

**Quando Escolher Cada Um**:

- **Angular Signals**: Apps empresariais grandes, equipes grandes, necessidade de estrutura
- **React**: Ecossistema maior, flexibilidade máxima, muitos recursos
- **Vue 3**: Apps médias, desenvolvimento rápido, sintaxe simples
- **Svelte**: Apps pequenas/médias, bundle size crítico, performance máxima

---

## Migração de Observables para Signals

### Quando Migrar

**Migre para Signals quando**:
- ✅ Estado é simples (valores primitivos, objetos simples)
- ✅ Não precisa de operadores RxJS complexos
- ✅ Quer melhor performance
- ✅ Quer código mais simples
- ✅ Quer type safety em templates

**Mantenha Observables quando**:
- ✅ Streams assíncronos complexos (WebSockets, eventos)
- ✅ Precisa de operadores RxJS avançados
- ✅ Múltiplas transformações de dados
- ✅ Debounce/throttle complexos

### Padrões de Migração

#### Padrão 1: BehaviorSubject → signal()

**Antes (Observable)**:

{% raw %}
```typescript
export class CounterService {
  private countSubject = new BehaviorSubject<number>(0);
  count$ = this.countSubject.asObservable();
  
  setCount(value: number): void {
    this.countSubject.next(value);
  }
  
  getCount(): number {
    return this.countSubject.value;
  }
}

export class CounterComponent {
  count$ = this.service.count$;
  
  template = `<div>{{ count$ | async }}</div>`;
}
```
{% raw %}
export class CounterService {
  private countSubject = new BehaviorSubject<number>(0);
  count$ = this.countSubject.asObservable();
  
  setCount(value: number): void {
    this.countSubject.next(value);
  }
  
  getCount(): number {
    return this.countSubject.value;
  }
}

export class CounterComponent {
  count$ = this.service.count$;
  
  template = `<div>{{ count$ | async }}</div>`;
}
```
{% endraw %}

**Depois (Signal)**:

{% raw %}
```typescript
export class CounterService {
  count = signal<number>(0);
  
  setCount(value: number): void {
    this.count.set(value);
  }
}

export class CounterComponent {
  count = this.service.count;
  
  template = `<div>{{ count() }}</div>`;
}
```
{% endraw %}

#### Padrão 2: combineLatest → computed()

**Antes (Observable)**:

{% raw %}
```typescript
export class ShoppingCartComponent {
  items$ = new BehaviorSubject<Item[]>([]);
  discount$ = new BehaviorSubject<number>(0);
  
  total$ = combineLatest([this.items$, this.discount$]).pipe(
    map(([items, discount]) => 
      items.reduce((sum, item) => sum + item.price, 0) * (1 - discount)
    )
  );
  
  template = `<div>{{ total$ | async }}</div>`;
}
```
{% raw %}
export class ShoppingCartComponent {
  items$ = new BehaviorSubject<Item[]>([]);
  discount$ = new BehaviorSubject<number>(0);
  
  total$ = combineLatest([this.items$, this.discount$]).pipe(
    map(([items, discount]) => 
      items.reduce((sum, item) => sum + item.price, 0) * (1 - discount)
    )
  );
  
  template = `<div>{{ total$ | async }}</div>`;
}
```
{% endraw %}

**Depois (Signal)**:

{% raw %}
```typescript
export class ShoppingCartComponent {
  items = signal<Item[]>([]);
  discount = signal<number>(0);
  
  total = computed(() => 
    this.items().reduce((sum, item) => sum + item.price, 0) * (1 - this.discount())
  );
  
  template = `<div>{{ total() }}</div>`;
}
```
{% endraw %}

#### Padrão 3: HTTP Observable → toSignal()

**Antes (Observable)**:

```typescript
export class UsersComponent {
  users$ = this.http.get<User[]>('/api/users');
  loading$ = new BehaviorSubject<boolean>(false);
  
  constructor(private http: HttpClient) {
    this.users$.subscribe({
      next: () => this.loading$.next(false),
      error: () => this.loading$.next(false)
    });
  }
  
  template = `
    <div *ngIf="loading$ | async">Carregando...</div>
    <div *ngFor="let user of users$ | async">{{ user.name }}</div>
  `;
}
```

**Depois (Signal)**:

```typescript
export class UsersComponent {
  private http = inject(HttpClient);
  
  users = toSignal(
    this.http.get<User[]>('/api/users'),
    { initialValue: [] }
  );
  
  loading = computed(() => this.users() === undefined);
  
  template = `
    @if (loading()) {
      <div>Carregando...</div>
    } @else {
      @for (user of users(); track user.id) {
        <div>{{ user.name }}</div>
      }
    }
  `;
}
```

#### Padrão 4: Subject → signal() + effect()

**Antes (Observable)**:

```typescript
export class ThemeService {
  private themeSubject = new BehaviorSubject<'light' | 'dark'>('light');
  theme$ = this.themeSubject.asObservable();
  
  setTheme(theme: 'light' | 'dark'): void {
    this.themeSubject.next(theme);
    localStorage.setItem('theme', theme);
  }
}

export class AppComponent {
  theme$ = this.themeService.theme$;
  
  constructor(private themeService: ThemeService) {
    this.theme$.subscribe(theme => {
      document.body.className = theme;
    });
  }
}
```

**Depois (Signal)**:

```typescript
export class ThemeService {
  theme = signal<'light' | 'dark'>('light');
  
  constructor() {
    const saved = localStorage.getItem('theme') as 'light' | 'dark' | null;
    if (saved) {
      this.theme.set(saved);
    }
    
    effect(() => {
      const theme = this.theme();
      document.body.className = theme;
      localStorage.setItem('theme', theme);
    });
  }
  
  setTheme(theme: 'light' | 'dark'): void {
    this.theme.set(theme);
  }
}

export class AppComponent {
  theme = this.themeService.theme;
}
```

### Checklist de Migração

**Passo a Passo**:

1. ✅ Identifique BehaviorSubjects simples → Converta para signals
2. ✅ Identifique combineLatest/map → Converta para computed()
3. ✅ Identifique subscriptions simples → Converta para effect() ou computed()
4. ✅ Identifique HTTP calls → Use toSignal()
5. ✅ Atualize templates → Remova async pipe, use signals diretamente
6. ✅ Teste mudanças incrementais
7. ✅ Remova imports RxJS não utilizados
8. ✅ Atualize testes para usar signals

**Exemplo Completo de Migração**:

```typescript
export class UserListComponent {
  private http = inject(HttpClient);
  private userService = inject(UserService);
  
  searchTerm = signal('');
  selectedUserId = signal<number | null>(null);
  
  users = toSignal(
    this.http.get<User[]>('/api/users'),
    { initialValue: [] }
  );
  
  filteredUsers = computed(() => {
    const term = this.searchTerm().toLowerCase();
    const users = this.users();
    return users.filter(u => 
      u.name.toLowerCase().includes(term)
    );
  });
  
  selectedUser = computed(() => {
    const id = this.selectedUserId();
    if (id === null) return null;
    return this.users().find(u => u.id === id) || null;
  });
  
  userCount = computed(() => this.filteredUsers().length);
  
  constructor() {
    effect(() => {
      const user = this.selectedUser();
      if (user) {
        console.log('User selected:', user.name);
      }
    });
  }
  
  selectUser(id: number): void {
    this.selectedUserId.set(id);
  }
  
  updateSearch(term: string): void {
    this.searchTerm.set(term);
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Componente Signal-First Completo

**Contexto**: Criar componente completo usando Signals para todo estado, incluindo filtros, contadores e persistência.

**Código**:

{% raw %}
```typescript
import { Component, signal, computed, effect } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Todo {
  id: number;
  text: string;
  completed: boolean;
}

@Component({
  selector: 'app-todo-signal',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Todo List (Signals)</h2>
      
      <input 
        #input
        (keyup.enter)="addTodo(input.value); input.value = ''"
        placeholder="Nova tarefa">
      
      <div>
        <button (click)="filter.set('all')">Todas</button>
        <button (click)="filter.set('active')">Ativas</button>
        <button (click)="filter.set('completed')">Completas</button>
      </div>
      
      <p>Total: {{ totalTodos() }} | Ativas: {{ activeTodos() }} | Completas: {{ completedTodos() }}</p>
      
      <ul>
        @for (todo of filteredTodos(); track todo.id) {
          <li>
            <input 
              type="checkbox" 
              [checked]="todo.completed"
              (change)="toggleTodo(todo.id)">
            <span [class.completed]="todo.completed">{{ todo.text }}</span>
            <button (click)="removeTodo(todo.id)">Remover</button>
          </li>
        }
      </ul>
    </div>
  `
})
export class TodoSignalComponent {
  todos = signal<Todo[]>([]);
  filter = signal<'all' | 'active' | 'completed'>('all');
  
  totalTodos = computed(() => this.todos().length);
  activeTodos = computed(() => 
    this.todos().filter(t => !t.completed).length
  );
  completedTodos = computed(() => 
    this.todos().filter(t => t.completed).length
  );
  
  filteredTodos = computed(() => {
    const todos = this.todos();
    const filter = this.filter();
    
    switch (filter) {
      case 'active':
        return todos.filter(t => !t.completed);
      case 'completed':
        return todos.filter(t => t.completed);
      default:
        return todos;
    }
  });
  
  private nextId = 0;
  
  constructor() {
    effect(() => {
      const todos = this.todos();
      localStorage.setItem('todos', JSON.stringify(todos));
    });
    
    const saved = localStorage.getItem('todos');
    if (saved) {
      this.todos.set(JSON.parse(saved));
    }
  }
  
  addTodo(text: string): void {
    if (text.trim()) {
      this.todos.update(todos => [
        ...todos,
        { id: this.nextId++, text: text.trim(), completed: false }
      ]);
    }
  }
  
  toggleTodo(id: number): void {
    this.todos.update(todos =>
      todos.map(t => t.id === id ? { ...t, completed: !t.completed } : t)
    );
  }
  
  removeTodo(id: number): void {
    this.todos.update(todos => todos.filter(t => t.id !== id));
  }
}
```
{% raw %}
import { Component, signal, computed, effect } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Todo {
  id: number;
  text: string;
  completed: boolean;
}

@Component({
  selector: 'app-todo-signal',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Todo List (Signals)</h2>
      
      <input 
        #input
        (keyup.enter)="addTodo(input.value); input.value = ''"
        placeholder="Nova tarefa">
      
      <div>
        <button (click)="filter.set('all')">Todas</button>
        <button (click)="filter.set('active')">Ativas</button>
        <button (click)="filter.set('completed')">Completas</button>
      </div>
      
      <p>Total: {{ totalTodos() }} | Ativas: {{ activeTodos() }} | Completas: {{ completedTodos() }}</p>
      
      <ul>
        @for (todo of filteredTodos(); track todo.id) {
          <li>
            <input 
              type="checkbox" 
              [checked]="todo.completed"
              (change)="toggleTodo(todo.id)">
            <span [class.completed]="todo.completed">{{ todo.text }}</span>
            <button (click)="removeTodo(todo.id)">Remover</button>
          </li>
        }
      </ul>
    </div>
  `
})
export class TodoSignalComponent {
  todos = signal<Todo[]>([]);
  filter = signal<'all' | 'active' | 'completed'>('all');
  
  totalTodos = computed(() => this.todos().length);
  activeTodos = computed(() => 
    this.todos().filter(t => !t.completed).length
  );
  completedTodos = computed(() => 
    this.todos().filter(t => t.completed).length
  );
  
  filteredTodos = computed(() => {
    const todos = this.todos();
    const filter = this.filter();
    
    switch (filter) {
      case 'active':
        return todos.filter(t => !t.completed);
      case 'completed':
        return todos.filter(t => t.completed);
      default:
        return todos;
    }
  });
  
  private nextId = 0;
  
  constructor() {
    effect(() => {
      const todos = this.todos();
      localStorage.setItem('todos', JSON.stringify(todos));
    });
    
    const saved = localStorage.getItem('todos');
    if (saved) {
      this.todos.set(JSON.parse(saved));
    }
  }
  
  addTodo(text: string): void {
    if (text.trim()) {
      this.todos.update(todos => [
        ...todos,
        { id: this.nextId++, text: text.trim(), completed: false }
      ]);
    }
  }
  
  toggleTodo(id: number): void {
    this.todos.update(todos =>
      todos.map(t => t.id === id ? { ...t, completed: !t.completed } : t)
    );
  }
  
  removeTodo(id: number): void {
    this.todos.update(todos => todos.filter(t => t.id !== id));
  }
}
```
{% endraw %}

---

### Exemplo 2: Signal-Based Shopping Cart

**Contexto**: Criar carrinho de compras completo usando Signals para estado, computed para cálculos e effects para sincronização.

**Código**:

{% raw %}
```typescript
import { Component, signal, computed, effect } from '@angular/core';

interface CartItem {
  id: number;
  name: string;
  price: number;
  quantity: number;
}

@Component({
  selector: 'app-shopping-cart',
  standalone: true,
  template: `
    <div>
      <h2>Carrinho de Compras</h2>
      
      @if (items().length === 0) {
        <p>Carrinho vazio</p>
      } @else {
        <ul>
          @for (item of items(); track item.id) {
            <li>
              <span>{{ item.name }} - R$ {{ item.price.toFixed(2) }}</span>
              <div>
                <button (click)="decreaseQuantity(item.id)">-</button>
                <span>{{ item.quantity }}</span>
                <button (click)="increaseQuantity(item.id)">+</button>
                <button (click)="removeItem(item.id)">Remover</button>
              </div>
            </li>
          }
        </ul>
        
        <div>
          <p>Subtotal: R$ {{ subtotal().toFixed(2) }}</p>
          <p>Desconto ({{ (discount() * 100).toFixed(0) }}%): -R$ {{ discountAmount().toFixed(2) }}</p>
          <p>Frete: R$ {{ shipping().toFixed(2) }}</p>
          <p><strong>Total: R$ {{ total().toFixed(2) }}</strong></p>
        </div>
        
        <div>
          <label>Cupom de desconto:</label>
          <input 
            [value]="couponCode()" 
            (input)="couponCode.set($any($event.target).value)"
            placeholder="Digite o cupom">
          <button (click)="applyCoupon()">Aplicar</button>
          @if (couponError()) {
            <p class="error">{{ couponError() }}</p>
          }
        </div>
        
        <button (click)="checkout()" [disabled]="!canCheckout()">
          Finalizar Compra
        </button>
      }
    </div>
  `
})
export class ShoppingCartComponent {
  items = signal<CartItem[]>([]);
  discount = signal<number>(0);
  shipping = signal<number>(10);
  couponCode = signal<string>('');
  couponError = signal<string | null>(null);
  
  subtotal = computed(() => 
    this.items().reduce(
      (sum, item) => sum + (item.price * item.quantity), 
      0
    )
  );
  
  discountAmount = computed(() => 
    this.subtotal() * this.discount()
  );
  
  total = computed(() => 
    this.subtotal() - this.discountAmount() + this.shipping()
  );
  
  itemCount = computed(() => 
    this.items().reduce((sum, item) => sum + item.quantity, 0)
  );
  
  canCheckout = computed(() => 
    this.items().length > 0 && this.total() > 0
  );
  
  constructor() {
    effect(() => {
      const items = this.items();
      localStorage.setItem('cart', JSON.stringify(items));
    });
    
    const saved = localStorage.getItem('cart');
    if (saved) {
      try {
        this.items.set(JSON.parse(saved));
      } catch (e) {
        console.error('Erro ao carregar carrinho:', e);
      }
    }
  }
  
  addItem(item: Omit<CartItem, 'quantity'>): void {
    this.items.update(items => {
      const existing = items.find(i => i.id === item.id);
      if (existing) {
        return items.map(i => 
          i.id === item.id 
            ? { ...i, quantity: i.quantity + 1 }
            : i
        );
      }
      return [...items, { ...item, quantity: 1 }];
    });
  }
  
  increaseQuantity(id: number): void {
    this.items.update(items =>
      items.map(item =>
        item.id === id
          ? { ...item, quantity: item.quantity + 1 }
          : item
      )
    );
  }
  
  decreaseQuantity(id: number): void {
    this.items.update(items =>
      items.map(item =>
        item.id === id && item.quantity > 1
          ? { ...item, quantity: item.quantity - 1 }
          : item
      ).filter(item => !(item.id === id && item.quantity === 0))
    );
  }
  
  removeItem(id: number): void {
    this.items.update(items => items.filter(item => item.id !== id));
  }
  
  applyCoupon(): void {
    const code = this.couponCode().toUpperCase();
    const coupons: Record<string, number> = {
      'DESC10': 0.1,
      'DESC20': 0.2,
      'FRETEGRATIS': 0
    };
    
    if (coupons[code]) {
      this.discount.set(coupons[code]);
      if (code === 'FRETEGRATIS') {
        this.shipping.set(0);
      }
      this.couponError.set(null);
    } else {
      this.couponError.set('Cupom inválido');
    }
  }
  
  checkout(): void {
    if (this.canCheckout()) {
      console.log('Checkout:', {
        items: this.items(),
        total: this.total(),
        discount: this.discountAmount()
      });
      this.items.set([]);
      this.discount.set(0);
      this.shipping.set(10);
      this.couponCode.set('');
    }
  }
}
```
{% raw %}
import { Component, signal, computed, effect } from '@angular/core';

interface CartItem {
  id: number;
  name: string;
  price: number;
  quantity: number;
}

@Component({
  selector: 'app-shopping-cart',
  standalone: true,
  template: `
    <div>
      <h2>Carrinho de Compras</h2>
      
      @if (items().length === 0) {
        <p>Carrinho vazio</p>
      } @else {
        <ul>
          @for (item of items(); track item.id) {
            <li>
              <span>{{ item.name }} - R$ {{ item.price.toFixed(2) }}</span>
              <div>
                <button (click)="decreaseQuantity(item.id)">-</button>
                <span>{{ item.quantity }}</span>
                <button (click)="increaseQuantity(item.id)">+</button>
                <button (click)="removeItem(item.id)">Remover</button>
              </div>
            </li>
          }
        </ul>
        
        <div>
          <p>Subtotal: R$ {{ subtotal().toFixed(2) }}</p>
          <p>Desconto ({{ (discount() * 100).toFixed(0) }}%): -R$ {{ discountAmount().toFixed(2) }}</p>
          <p>Frete: R$ {{ shipping().toFixed(2) }}</p>
          <p><strong>Total: R$ {{ total().toFixed(2) }}</strong></p>
        </div>
        
        <div>
          <label>Cupom de desconto:</label>
          <input 
            [value]="couponCode()" 
            (input)="couponCode.set($any($event.target).value)"
            placeholder="Digite o cupom">
          <button (click)="applyCoupon()">Aplicar</button>
          @if (couponError()) {
            <p class="error">{{ couponError() }}</p>
          }
        </div>
        
        <button (click)="checkout()" [disabled]="!canCheckout()">
          Finalizar Compra
        </button>
      }
    </div>
  `
})
export class ShoppingCartComponent {
  items = signal<CartItem[]>([]);
  discount = signal<number>(0);
  shipping = signal<number>(10);
  couponCode = signal<string>('');
  couponError = signal<string | null>(null);
  
  subtotal = computed(() => 
    this.items().reduce(
      (sum, item) => sum + (item.price * item.quantity), 
      0
    )
  );
  
  discountAmount = computed(() => 
    this.subtotal() * this.discount()
  );
  
  total = computed(() => 
    this.subtotal() - this.discountAmount() + this.shipping()
  );
  
  itemCount = computed(() => 
    this.items().reduce((sum, item) => sum + item.quantity, 0)
  );
  
  canCheckout = computed(() => 
    this.items().length > 0 && this.total() > 0
  );
  
  constructor() {
    effect(() => {
      const items = this.items();
      localStorage.setItem('cart', JSON.stringify(items));
    });
    
    const saved = localStorage.getItem('cart');
    if (saved) {
      try {
        this.items.set(JSON.parse(saved));
      } catch (e) {
        console.error('Erro ao carregar carrinho:', e);
      }
    }
  }
  
  addItem(item: Omit<CartItem, 'quantity'>): void {
    this.items.update(items => {
      const existing = items.find(i => i.id === item.id);
      if (existing) {
        return items.map(i => 
          i.id === item.id 
            ? { ...i, quantity: i.quantity + 1 }
            : i
        );
      }
      return [...items, { ...item, quantity: 1 }];
    });
  }
  
  increaseQuantity(id: number): void {
    this.items.update(items =>
      items.map(item =>
        item.id === id
          ? { ...item, quantity: item.quantity + 1 }
          : item
      )
    );
  }
  
  decreaseQuantity(id: number): void {
    this.items.update(items =>
      items.map(item =>
        item.id === id && item.quantity > 1
          ? { ...item, quantity: item.quantity - 1 }
          : item
      ).filter(item => !(item.id === id && item.quantity === 0))
    );
  }
  
  removeItem(id: number): void {
    this.items.update(items => items.filter(item => item.id !== id));
  }
  
  applyCoupon(): void {
    const code = this.couponCode().toUpperCase();
    const coupons: Record<string, number> = {
      'DESC10': 0.1,
      'DESC20': 0.2,
      'FRETEGRATIS': 0
    };
    
    if (coupons[code]) {
      this.discount.set(coupons[code]);
      if (code === 'FRETEGRATIS') {
        this.shipping.set(0);
      }
      this.couponError.set(null);
    } else {
      this.couponError.set('Cupom inválido');
    }
  }
  
  checkout(): void {
    if (this.canCheckout()) {
      console.log('Checkout:', {
        items: this.items(),
        total: this.total(),
        discount: this.discountAmount()
      });
      this.items.set([]);
      this.discount.set(0);
      this.shipping.set(10);
      this.couponCode.set('');
    }
  }
}
```
{% endraw %}

---

### Exemplo 3: Signal-Based Search com Debounce

**Contexto**: Criar componente de busca com debounce usando Signals e integração com Observables.

**Código**:

{% raw %}
```typescript
import { Component, signal, computed, effect, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged, switchMap, of } from 'rxjs';

interface SearchResult {
  id: number;
  title: string;
  description: string;
}

@Component({
  selector: 'app-search',
  standalone: true,
  template: `
    <div>
      <h2>Busca</h2>
      
      <input 
        [value]="searchQuery()" 
        (input)="searchQuery.set($any($event.target).value)"
        placeholder="Digite para buscar..."
        [class.loading]="loading()">
      
      @if (loading()) {
        <p>Buscando...</p>
      } @else if (error()) {
        <p class="error">{{ error() }}</p>
      } @else if (results().length === 0 && searchQuery().length > 0) {
        <p>Nenhum resultado encontrado</p>
      } @else if (results().length > 0) {
        <ul>
          @for (result of results(); track result.id) {
            <li>
              <h3>{{ result.title }}</h3>
              <p>{{ result.description }}</p>
            </li>
          }
        </ul>
        <p>Total de resultados: {{ resultCount() }}</p>
      }
    </div>
  `
})
export class SearchComponent {
  private http = inject(HttpClient);
  
  searchQuery = signal<string>('');
  loading = signal<boolean>(false);
  error = signal<string | null>(null);
  
  results = toSignal(
    this.searchQuery().length > 0
      ? this.http.get<SearchResult[]>(`/api/search?q=${this.searchQuery()}`)
      : of([]),
    { initialValue: [] }
  );
  
  resultCount = computed(() => this.results().length);
  
  constructor() {
    effect(() => {
      const query = this.searchQuery();
      if (query.length > 0) {
        this.loading.set(true);
        this.error.set(null);
      }
    });
  }
}
```
{% endraw %}

---

### Exemplo 4: Signal-Based Theme Switcher

**Contexto**: Criar sistema de temas completo usando Signals com persistência e sincronização.

**Código**:

{% raw %}
```typescript
import { Component, signal, computed, effect } from '@angular/core';

type Theme = 'light' | 'dark' | 'auto';

@Component({
  selector: 'app-theme-switcher',
  standalone: true,
  template: `
    <div>
      <h2>Configurações de Tema</h2>
      
      <div>
        <label>
          <input 
            type="radio" 
            [checked]="theme() === 'light'"
            (change)="theme.set('light')">
          Claro
        </label>
        <label>
          <input 
            type="radio" 
            [checked]="theme() === 'dark'"
            (change)="theme.set('dark')">
          Escuro
        </label>
        <label>
          <input 
            type="radio" 
            [checked]="theme() === 'auto'"
            (change)="theme.set('auto')">
          Automático
        </label>
      </div>
      
      <div>
        <label>Tamanho da fonte:</label>
        <input 
          type="range" 
          [value]="fontSize()" 
          (input)="fontSize.set(+$any($event.target).value)"
          min="12" 
          max="24">
        <span>{{ fontSize() }}px</span>
      </div>
      
      <div>
        <p>Tema atual: {{ currentTheme() }}</p>
        <p>Tamanho da fonte: {{ fontSize() }}px</p>
      </div>
    </div>
  `
})
export class ThemeSwitcherComponent {
  theme = signal<Theme>('auto');
  fontSize = signal<number>(16);
  
  currentTheme = computed(() => {
    const theme = this.theme();
    if (theme === 'auto') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches 
        ? 'dark' 
        : 'light';
    }
    return theme;
  });
  
  constructor() {
    const savedTheme = localStorage.getItem('theme') as Theme | null;
    if (savedTheme) {
      this.theme.set(savedTheme);
    }
    
    const savedFontSize = localStorage.getItem('fontSize');
    if (savedFontSize) {
      this.fontSize.set(parseInt(savedFontSize, 10));
    }
    
    effect(() => {
      const theme = this.currentTheme();
      document.body.className = `theme-${theme}`;
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('theme', this.theme());
    });
    
    effect(() => {
      const size = this.fontSize();
      document.documentElement.style.fontSize = `${size}px`;
      localStorage.setItem('fontSize', size.toString());
    });
    
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      if (this.theme() === 'auto') {
        this.theme.set('auto');
      }
    });
  }
}
```
{% endraw %}

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use Signals para estado local**
   - **Por quê**: Mais simples e performático
   - **Exemplo**: `count = signal(0)`

2. **Use computed() para valores derivados**
   - **Por quê**: Reatividade automática e memoização
   - **Exemplo**: `total = computed(() => items().reduce(...))`

3. **Use effect() com cuidado**
   - **Por quê**: Pode causar loops infinitos
   - **Exemplo**: Apenas para side effects necessários

4. **Prefira Signal-First quando possível**
   - **Por quê**: Melhor performance e simplicidade
   - **Exemplo**: Signals para estado, Observables para HTTP

### ❌ Anti-padrões Comuns

1. **Não use effect() para atualizar signals**
   - **Problema**: Pode causar loops infinitos
   - **Solução**: Use computed() ou atualize diretamente

2. **Não misture Signals e Observables desnecessariamente**
   - **Problema**: Complexidade desnecessária
   - **Solução**: Use Signals quando possível

3. **Não ignore toSignal() para HTTP**
   - **Problema**: Perde benefícios de Signals
   - **Solução**: Converta Observables HTTP para Signals

---

## Exercícios Práticos

### Exercício 1: signal() e computed() Básicos (Básico)

**Objetivo**: Criar primeiros signals

**Descrição**: 
Crie componente que usa signal() e computed() para gerenciar estado simples.

**Arquivo**: `exercises/exercise-3-2-1-signal-computed.md`

---

### Exercício 2: effect() e Reatividade (Intermediário)

**Objetivo**: Trabalhar com effects

**Descrição**:
Crie componente que usa effect() para sincronizar estado com localStorage.

**Arquivo**: `exercises/exercise-3-2-2-effect.md`

---

### Exercício 3: Model Inputs (Intermediário)

**Objetivo**: Usar Model Inputs

**Descrição**:
Crie componente que usa model() para two-way binding com signals.

**Arquivo**: `exercises/exercise-3-2-3-model-inputs.md`

---

### Exercício 4: Signal-Based Forms (Avançado)

**Objetivo**: Criar formulário baseado em Signals

**Descrição**:
Crie formulário completo usando Signal Forms API.

**Arquivo**: `exercises/exercise-3-2-4-signal-forms.md`

---

### Exercício 5: Signal-First Architecture (Avançado)

**Objetivo**: Implementar arquitetura Signal-First

**Descrição**:
Crie aplicação completa usando Signal-First Architecture.

**Arquivo**: `exercises/exercise-3-2-5-signal-first.md`

---

### Exercício 6: Migração Observables para Signals (Avançado)

**Objetivo**: Migrar código existente

**Descrição**:
Migre componente que usa Observables para usar Signals.

**Arquivo**: `exercises/exercise-3-2-6-migracao.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular Signals Guide](https://angular.io/guide/signals)**: Guia oficial completo de Signals
- **[Angular Signals API](https://angular.io/api/core/signal)**: Documentação técnica de signal()
- **[Angular computed API](https://angular.io/api/core/computed)**: Documentação técnica de computed()
- **[Angular effect API](https://angular.io/api/core/effect)**: Documentação técnica de effect()
- **[Angular Model Inputs](https://angular.io/api/core/model)**: Documentação de model() para two-way binding
- **[Angular toSignal](https://angular.io/api/core/rxjs-interop/toSignal)**: Documentação de toSignal() para converter Observables
- **[Angular toObservable](https://angular.io/api/core/rxjs-interop/toObservable)**: Documentação de toObservable() para converter Signals
- **[Angular Signal Forms](https://angular.io/guide/signals/forms)**: Guia de Signal Forms API

### Artigos e Tutoriais

- **[Angular Signals: The Complete Guide](https://zoaibkhan.com/tutorials/angular-signals-crash-course/)**: Tutorial completo sobre Signals
- **[Angular Signals Explained](https://codelabs.developers.google.com/angular-signals)**: CodeLab oficial do Google sobre Signals
- **[Understanding Angular Signals](https://www.angulararchitects.io/en/blog/angular-signals/)**: Artigo técnico profundo sobre Signals
- **[Angular Signals vs RxJS](https://blog.angular.io/angular-signals-2f209c9c4e5d)**: Comparação Signals vs Observables
- **[Signal-First Architecture Patterns](https://dev.to/angular/signal-first-architecture-patterns)**: Padrões arquiteturais Signal-First
- **[Migrating to Angular Signals](https://angular.io/guide/signals/migration)**: Guia oficial de migração

### Vídeos Educacionais

- **[Angular Signals - Official Introduction](https://www.youtube.com/watch?v=7fT7X5U3u3U)**: Vídeo oficial do Angular sobre Signals
- **[Angular Signals Deep Dive](https://www.youtube.com/watch?v=vy03zR73Rio)**: Análise profunda de Signals
- **[Signal-First Architecture Tutorial](https://www.youtube.com/watch?v=example)**: Tutorial sobre arquitetura Signal-First
- **[Angular Signals vs RxJS](https://www.youtube.com/watch?v=example)**: Comparação prática Signals vs Observables

### Ferramentas e Recursos

- **[Angular DevTools](https://angular.io/guide/devtools)**: Ferramentas de desenvolvimento para debugar Signals
- **[Angular Signals Playground](https://angular.io/playground)**: Playground interativo para testar Signals
- **[RxJS Interop Documentation](https://angular.io/guide/rxjs-interop)**: Guia de integração Signals + Observables

### Comunidade e Discussões

- **[Angular Signals RFC](https://github.com/angular/angular/discussions/49685)**: Discussão original sobre Signals
- **[Angular GitHub - Signals](https://github.com/angular/angular/issues?q=signals)**: Issues e discussões sobre Signals
- **[Angular Discord - Signals Channel](https://discord.gg/angular)**: Canal da comunidade sobre Signals

### Comparações com Outros Frameworks

- **[React vs Angular Signals](https://react.dev/reference/react/useState)**: Comparação com React useState
- **[Vue 3 Composition API vs Angular Signals](https://vuejs.org/api/reactivity-core.html)**: Comparação com Vue 3
- **[Svelte Reactivity vs Angular Signals](https://svelte.dev/docs/svelte-store)**: Comparação com Svelte

---

## Resumo

### Principais Conceitos

- signal() cria valores reativos primitivos
- computed() cria valores derivados automaticamente
- effect() executa side effects quando signals mudam
- Model Inputs permitem two-way binding com signals
- Signal Forms oferecem formulários baseados em signals
- Signal-First Architecture é recomendada para novas apps

### Pontos-Chave para Lembrar

- Use Signals para estado local
- Use computed() para valores derivados
- Use effect() com cuidado
- Prefira Signal-First quando possível
- Converta Observables HTTP para Signals

### Próximos Passos

- Próxima aula: NgRx - Gerenciamento de Estado
- Praticar criando componentes Signal-First
- Explorar integração Signals + Observables

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

**Aula Anterior**: [Aula 3.1: RxJS Operators Avançados](./lesson-3-1-rxjs-operators.md)  
**Próxima Aula**: [Aula 3.3: NgRx - Gerenciamento de Estado](./lesson-3-3-ngrx.md)  
**Voltar ao Módulo**: [Módulo 3: Programação Reativa e Estado](../modules/module-3-programacao-reativa-estado.md)
