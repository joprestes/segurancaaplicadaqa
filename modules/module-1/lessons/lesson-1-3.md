---
layout: lesson
title: "Aula 1.3: Componentes Standalone e Templates"
slug: componentes-standalone
module: module-1
lesson_id: lesson-1-3
duration: "120 minutos"
level: "Intermediário"
prerequisites: []
exercises: []
podcast:
  file: "assets/podcasts/01.3e4-Fundacao_Angular_Tipagem_Encapsulamento_e_Generics.m4a"
  image: "assets/images/podcasts/01.3e4-Fundacao_Angular_Tipagem_Encapsulamento_e_Generics.png"
  title: "Componentes Standalone, Templates, Data Binding e Diretivas Modernas"
  description: "Mergulhe profundamente nos componentes standalone do Angular."
  duration: "60-75 minutos"
permalink: /modules/fundamentos-acelerados/lessons/componentes-standalone/
---

## Introdução

Nesta aula, você aprenderá a criar componentes standalone do Angular, trabalhar com templates avançados e entender o ciclo de vida dos componentes. Standalone Components são o futuro do Angular e representam uma mudança arquitetural significativa que simplifica o desenvolvimento e melhora a experiência do desenvolvedor.

### Contexto Histórico dos Standalone Components

Standalone Components foram uma das mudanças mais significativas na arquitetura do Angular desde sua criação. Esta feature representa uma evolução natural do framework em direção a uma arquitetura mais simples e moderna.

**Linha do Tempo da Evolução**:

```
Angular 2 (2016) ──────────────────────────────────────────── Angular 17+ (2023+)
 │                                                                  │
 ├─ 2016    📦 NgModules introduzidos                              │
 │          Sistema de módulos obrigatório                        │
 │          Declarações, imports, exports                         │
 │                                                                  │
 ├─ 2017-2020 📈 NgModules se tornam padrão                       │
 │          Complexidade crescente                                │
 │          Necessidade de módulos para tudo                     │
 │                                                                  │
 ├─ Jun 2022 🚀 Angular 14 - Standalone Components (experimental) │
 │          Primeira versão experimental                          │
 │          Permite componentes sem NgModule                     │
 │                                                                  │
 ├─ Nov 2022 ⚡ Angular 15 - Standalone estável                    │
 │          API estável                                           │
 │          Suporte completo                                      │
 │                                                                  │
 ├─ Mai 2023 🔥 Angular 16 - Melhorias e otimizações              │
 │          Performance melhorada                                 │
 │          Migração facilitada                                   │
 │                                                                  │
 └─ Nov 2023 🎯 Angular 17 - Standalone como padrão               │
            CLI gera standalone por padrão                        │
            Documentação atualizada                               │
            Futuro do Angular                                     │
```

**Por que Standalone Components foram criados?**

O sistema de NgModules, embora poderoso, introduzia complexidade desnecessária em muitos casos:

1. **Boilerplate Excessivo**: Cada componente precisava de um módulo dedicado ou ser declarado em um módulo compartilhado
2. **Dificuldade de Reutilização**: Componentes eram acoplados aos módulos onde eram declarados
3. **Lazy Loading Complexo**: Configurar lazy loading com NgModules era verboso
4. **Barreira de Entrada**: Novos desenvolvedores precisavam entender NgModules antes de criar componentes simples
5. **Comparação com Frameworks Modernos**: React e Vue não requerem módulos, tornando Angular menos atraente

**Adoção e Impacto**:

- **Angular 14**: Introdução experimental - comunidade testa e fornece feedback
- **Angular 15**: Estabilização - API final definida, migração começa
- **Angular 16**: Otimizações - performance melhorada, ferramentas de migração
- **Angular 17**: Padrão - novo padrão recomendado, CLI atualizado

**Benefícios Imediatos**:

- **Redução de Código**: Menos arquivos, menos boilerplate
- **Melhor Performance**: Bundle size reduzido, tree-shaking melhorado
- **Desenvolvimento Mais Rápido**: Menos configuração, mais produtividade
- **Migração Gradual**: Projetos existentes podem migrar incrementalmente

### O que você vai aprender

- **Anatomia de um Componente Angular**: Estrutura completa e responsabilidades
- **Standalone Components**: Criação e uso de componentes independentes
- **SCAM Pattern**: Padrão de migração e organização
- **Templates e Sintaxe**: Interpolação, binding, diretivas avançadas
- **ViewEncapsulation**: Isolamento e controle de estilos
- **Ciclo de Vida dos Componentes**: Hooks e quando usar cada um
- **Projeção de Conteúdo**: `ng-content` e slots dinâmicos
- **Comunicação entre Componentes**: `@Input`, `@Output`, EventEmitters
- **Change Detection**: Estratégias e otimização

### Por que isso é importante

**Para Desenvolvimento**:
- **Simplicidade Arquitetural**: Menos arquivos para gerenciar, código mais limpo
- **Produtividade**: Desenvolvimento mais rápido sem configuração excessiva
- **Reutilização**: Componentes verdadeiramente portáteis e independentes
- **Manutenibilidade**: Código mais fácil de entender e modificar

**Para Projetos**:
- **Performance**: Bundle size reduzido, tree-shaking melhorado
- **Escalabilidade**: Arquitetura que escala melhor com projetos grandes
- **Migração**: Caminho claro para modernizar projetos legados
- **Futuro**: Alinhado com a direção do Angular

**Para Carreira**:
- **Padrão Moderno**: Habilidade essencial para Angular moderno
- **Diferencial Competitivo**: Conhecimento de arquitetura atualizada
- **Base Sólida**: Fundamentos para conceitos avançados
- **Relevância**: Angular continua evoluindo nesta direção

---

## Conceitos Teóricos

### Anatomia de um Componente Angular

**Definição**: Um componente Angular é uma classe TypeScript decorada com `@Component` que controla uma parte da interface do usuário (view).

**Explicação Detalhada**:

Um componente Angular consiste em três partes principais:

1. **Classe TypeScript**: Contém a lógica do componente
2. **Template HTML**: Define a estrutura visual
3. **Estilos CSS**: Define a aparência

**Analogia**:

Um componente é como uma célula do corpo humano:
- A **classe** é o núcleo (controle e lógica)
- O **template** é a membrana (interface externa)
- Os **estilos** são as características visuais (cor, forma)

**Visualização**:

```
┌─────────────────────────────────────┐
│      Componente Angular             │
├─────────────────────────────────────┤
│                                     │
│  ┌───────────────────────────────┐  │
│  │  Classe TypeScript            │  │
│  │  @Component({...})            │  │
│  │  export class MyComponent {}  │  │
│  └───────────────────────────────┘  │
│           │                         │
│           ├─── Template HTML        │
│           │    (Estrutura)          │
│           │                         │
│           └─── Estilos CSS          │
│                (Aparência)          │
└─────────────────────────────────────┘
```

**Exemplo Prático**:

```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-user-card',
  templateUrl: './user-card.component.html',
  styleUrls: ['./user-card.component.css']
})
export class UserCardComponent {
  userName: string = 'João Silva';
  userEmail: string = 'joao@example.com';
  
  greet(): string {
    return `Olá, ${this.userName}!`;
  }
}
```

---

### Standalone Components

**Definição**: Standalone Components são componentes Angular que não precisam ser declarados em um NgModule. Eles são auto-suficientes e podem importar diretamente suas dependências (diretivas, pipes, outros componentes), eliminando a necessidade de módulos intermediários.

**Explicação Detalhada**:

Standalone Components foram introduzidos no Angular 14 (experimental) e se tornaram estáveis no Angular 15, sendo o padrão recomendado desde o Angular 17. Eles representam uma mudança paradigmática na arquitetura Angular:

**Características Principais**:

1. **Independência**: Não requerem NgModule para funcionar
2. **Auto-suficiência**: Declaram suas próprias dependências via `imports`
3. **Portabilidade**: Podem ser facilmente movidos entre projetos
4. **Lazy Loading Simplificado**: Roteamento direto sem módulos
5. **Tree-shaking Melhorado**: Apenas código usado é incluído no bundle

**Como Funciona**:

Quando você marca um componente como `standalone: true`, o Angular:
- Não procura por um NgModule que declare o componente
- Permite que o componente importe diretamente o que precisa
- Torna o componente disponível para importação direta em outros lugares
- Habilita lazy loading direto via roteamento

**Analogia Detalhada**:

Standalone Components são como **apartamentos autossuficientes** em um condomínio moderno:

- **NgModules (Antigo)**: Eram como prédios antigos onde você precisava:
  - Se registrar no síndico (declarar no módulo)
  - Depender de serviços compartilhados do prédio (imports do módulo)
  - Seguir regras rígidas do condomínio (estrutura de módulos)
  - Não podia se mudar facilmente (acoplamento ao módulo)

- **Standalone Components (Novo)**: São como apartamentos modernos onde você:
  - Tem sua própria entrada independente (não precisa de módulo)
  - Contrata seus próprios serviços diretamente (imports no componente)
  - Pode se mudar facilmente (portabilidade total)
  - É auto-suficiente mas pode compartilhar recursos (importar outros componentes)

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│              NgModule Approach (Antigo)                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐                                       │
│  │  ProductModule  │                                       │
│  ├──────────────────┤                                       │
│  │ declarations:    │                                       │
│  │  - ProductCard   │  ← Componente preso ao módulo        │
│  │                  │                                       │
│  │ imports:         │                                       │
│  │  - CommonModule  │                                       │
│  │  - FormsModule   │                                       │
│  │                  │                                       │
│  │ exports:         │                                       │
│  │  - ProductCard   │  ← Precisa exportar para usar        │
│  └──────────────────┘                                       │
│           │                                                  │
│           │ Import necessário                                │
│           ▼                                                  │
│  ┌──────────────────┐                                       │
│  │  AppModule       │                                       │
│  │  imports: [       │                                       │
│  │    ProductModule  │  ← Importa módulo inteiro            │
│  │  ]                │                                       │
│  └──────────────────┘                                       │
│                                                              │
│  Problemas:                                                  │
│  • Múltiplos arquivos                                       │
│  • Boilerplate excessivo                                    │
│  • Acoplamento ao módulo                                    │
│  • Difícil reutilização                                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│           Standalone Component Approach (Novo)              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────┐                  │
│  │  ProductCardComponent               │                  │
│  ├──────────────────────────────────────┤                  │
│  │  @Component({                        │                  │
│  │    standalone: true,                │  ← Auto-suficiente│
│  │    imports: [                        │                  │
│  │      CommonModule,                   │  ← Dependências   │
│  │      FormsModule                     │     diretas       │
│  │    ]                                 │                  │
│  │  })                                  │                  │
│  └──────────────────────────────────────┘                  │
│           │                                                  │
│           │ Import direto                                    │
│           ▼                                                  │
│  ┌──────────────────────────────────────┐                  │
│  │  AppComponent                        │                  │
│  │  imports: [                          │                  │
│  │    ProductCardComponent              │  ← Import direto │
│  │  ]                                    │                  │
│  └──────────────────────────────────────┘                  │
│                                                              │
│  Benefícios:                                                 │
│  • Arquivo único                                            │
│  • Sem boilerplate                                          │
│  • Desacoplado                                              │
│  • Fácil reutilização                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Fluxo de Dependências:

Standalone Component
     │
     ├─→ imports: [CommonModule]     ← Importa diretamente
     ├─→ imports: [FormsModule]      ← Sem módulo intermediário
     ├─→ imports: [OtherComponent]  ← Pode importar outros standalone
     └─→ imports: [Pipe, Directive]  ← Qualquer dependência necessária
```

**Exemplo Prático Completo**:

```typescript
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CurrencyPipe } from '@angular/common';

interface Product {
  id: number;
  name: string;
  price: number;
  inStock: boolean;
}

@Component({
  selector: 'app-product-card',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    CurrencyPipe
  ],
  templateUrl: './product-card.component.html',
  styleUrls: ['./product-card.component.css']
})
export class ProductCardComponent {
  @Input() product!: Product;
  @Output() addToCart = new EventEmitter<Product>();

  onAddToCart(): void {
    if (this.product.inStock) {
      this.addToCart.emit(this.product);
    }
  }
}

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule, ProductCardComponent],
  template: `
    <div class="product-list">
      <app-product-card
        *ngFor="let product of products"
        [product]="product"
        (addToCart)="handleAddToCart($event)">
      </app-product-card>
    </div>
  `
})
export class ProductListComponent {
  products: Product[] = [];

  handleAddToCart(product: Product): void {
    console.log('Added to cart:', product);
  }
}
```

**Lazy Loading com Standalone**:

```typescript
const routes: Routes = [
  {
    path: 'products',
    loadComponent: () => import('./product-list.component')
      .then(m => m.ProductListComponent)
  }
];
```

**Migração de NgModule para Standalone**:

```typescript
// Antes (NgModule)
@NgModule({
  declarations: [ProductCardComponent],
  imports: [CommonModule],
  exports: [ProductCardComponent]
})
export class ProductCardModule {}

// Depois (Standalone)
@Component({
  selector: 'app-product-card',
  standalone: true,
  imports: [CommonModule]
})
export class ProductCardComponent {}
```

---

### SCAM Pattern

**Definição**: SCAM (Single Component Angular Module) é um padrão onde cada componente tem seu próprio módulo NgModule, mesmo quando usando standalone components.

**Explicação Detalhada**:

SCAM Pattern é útil para:
- Migração gradual de NgModules para Standalone
- Organização de código
- Isolamento de dependências
- Facilita testes

**Analogia**:

SCAM é como ter um quarto separado para cada pessoa na casa. Cada quarto tem suas próprias coisas, mas ainda faz parte da casa maior.

**Exemplo Prático**:

```typescript
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ProductCardComponent } from './product-card.component';

@NgModule({
  declarations: [ProductCardComponent],
  imports: [CommonModule],
  exports: [ProductCardComponent]
})
export class ProductCardModule {}
```

---

### Templates e Sintaxe

**Definição**: Templates são HTML com sintaxe especial do Angular que permite interpolação, binding e diretivas.

**Explicação Detalhada**:

Templates Angular suportam:
- **Interpolação**: `{{ expression }}`
- **Property Binding**: `[property]="value"`
- **Event Binding**: `(event)="handler()"`
- **Two-Way Binding**: `[(ngModel)]="value"`
- **Diretivas**: `*ngIf`, `*ngFor`, etc.

**Analogia**:

Um template é como um formulário preenchível:
- O HTML é o formulário em branco
- A sintaxe Angular são as instruções de como preencher
- Os dados do componente preenchem os campos

**Visualização**:

```
Template HTML                  Component Class
┌──────────────────────┐           ┌───────────────────┐
│ <h1>{{title}}</h1>   │  ←──────  │ title = "Hello"   │
│ <button              │           │                   │
│  (click)="do()">     │  ←──────  │ do() { ... }      │
│ </button>            │           └───────────────────┘
└──────────────────────┘
```

**Exemplo Prático**:

{% raw %}
```html
<div class="product-card">
  <h2>{{ product.name }}</h2>
  <p class="price">{{ product.price | currency }}</p>
  <button 
    [disabled]="!product.inStock"
    (click)="addToCart()">
    Adicionar ao Carrinho
  </button>
  <img [src]="product.imageUrl" [alt]="product.name">
</div>
```
{% raw %}
<div class="product-card">
  <h2>{{ product.name }}</h2>
  <p class="price">{{ product.price | currency }}</p>
  <button 
    [disabled]="!product.inStock"
    (click)="addToCart()">
    Adicionar ao Carrinho
  </button>
  <img [src]="product.imageUrl" [alt]="product.name">
</div>
```
{% endraw %}

---

### ViewEncapsulation

**Definição**: ViewEncapsulation controla como os estilos CSS são aplicados e isolados em componentes.

**Explicação Detalhada**:

Angular oferece três modos de encapsulação:

1. **Emulated** (padrão): Estilos são isolados usando atributos únicos
2. **None**: Estilos são globais, sem isolamento
3. **ShadowDom**: Usa Shadow DOM nativo do navegador

**Analogia**:

ViewEncapsulation é como diferentes tipos de isolamento:
- **Emulated**: Como ter um quarto com paredes que bloqueiam som
- **None**: Como estar em um espaço aberto
- **ShadowDom**: Como ter um quarto completamente isolado

**Exemplo Prático**:

```typescript
import { Component, ViewEncapsulation } from '@angular/core';

@Component({
  selector: 'app-styled',
  templateUrl: './styled.component.html',
  styleUrls: ['./styled.component.css'],
  encapsulation: ViewEncapsulation.Emulated
})
export class StyledComponent {}
```

---

### Ciclo de Vida dos Componentes

**Definição**: O ciclo de vida de um componente Angular consiste em uma série de hooks (métodos) que são chamados pelo framework em momentos específicos da existência do componente, desde sua criação até sua destruição. Esses hooks permitem que você execute código em momentos críticos do ciclo de vida.

**Explicação Detalhada**:

O ciclo de vida de um componente segue uma ordem específica e previsível:

**Fase 1: Criação e Inicialização**

1. **constructor()**: Chamado quando o componente é instanciado
   - Executado antes de qualquer hook
   - Use apenas para injeção de dependências
   - Não acesse `@Input()` aqui (ainda não inicializado)

2. **ngOnChanges(changes: SimpleChanges)**: Chamado quando propriedades `@Input()` mudam
   - Executado antes de `ngOnInit()` na primeira vez
   - Recebe objeto com valores anteriores e atuais
   - Não é chamado se não houver `@Input()` ou se referência do objeto não mudar

3. **ngOnInit()**: Chamado uma vez após primeira inicialização
   - Ideal para lógica de inicialização
   - Acesso seguro a `@Input()` e dependências injetadas
   - Melhor lugar para chamadas HTTP e setup inicial

**Fase 2: Verificação e Atualização**

4. **ngDoCheck()**: Chamado durante cada ciclo de detecção de mudanças
   - Use com cuidado - pode impactar performance
   - Útil para detecção customizada de mudanças
   - Geralmente usado com `ChangeDetectorRef`

5. **ngAfterContentInit()**: Chamado após conteúdo projetado (`ng-content`) ser inicializado
   - Executado uma vez após primeira verificação de conteúdo
   - Acesso seguro a `@ContentChild()` e `@ContentChildren()`

6. **ngAfterContentChecked()**: Chamado após cada verificação de conteúdo projetado
   - Executado após cada `ngDoCheck()`
   - Use com cuidado devido à frequência

7. **ngAfterViewInit()**: Chamado após view do componente e views filhas serem inicializadas
   - Executado uma vez após primeira renderização
   - Acesso seguro a `@ViewChild()` e `@ViewChildren()`
   - Ideal para manipulação de DOM

8. **ngAfterViewChecked()**: Chamado após cada verificação de view
   - Executado após cada `ngAfterContentChecked()`
   - Use com extrema cautela - pode causar loops infinitos

**Fase 3: Destruição**

9. **ngOnDestroy()**: Chamado antes do componente ser destruído
   - Última chance de limpar recursos
   - **CRÍTICO**: Sempre limpe subscriptions, timers, event listeners
   - Previne memory leaks

**Analogia Detalhada**:

O ciclo de vida é como a **jornada de uma árvore**:

- **constructor()**: Semente plantada no solo (instanciação)
- **ngOnChanges()**: Primeira chuva que ativa a semente (inputs recebidos)
- **ngOnInit()**: Broto emergindo do solo (inicialização completa)
- **ngDoCheck()**: Processo contínuo de crescimento (detecção de mudanças)
- **ngAfterContentInit()**: Folhas aparecendo (conteúdo projetado pronto)
- **ngAfterViewInit()**: Árvore completamente formada (view renderizada)
- **ngAfterViewChecked()**: Monitoramento contínuo do crescimento (verificações periódicas)
- **ngOnDestroy()**: Árvore sendo cortada - limpeza do terreno (destruição e limpeza)

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│              Component Lifecycle Timeline                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Fase 1: Criação                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                                                       │  │
│  │  1. constructor()                                     │  │
│  │     ↓                                                 │  │
│  │  2. ngOnChanges()  (se houver @Input)               │  │
│  │     ↓                                                 │  │
│  │  3. ngOnInit()      ← Inicialização principal        │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  Fase 2: Verificação e Atualização                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                                                       │  │
│  │  4. ngDoCheck()                                       │  │
│  │     ↓                                                 │  │
│  │  5. ngAfterContentInit()  (primeira vez)            │  │
│  │     ↓                                                 │  │
│  │  6. ngAfterContentChecked()                           │  │
│  │     ↓                                                 │  │
│  │  7. ngAfterViewInit()     ← View pronta              │  │
│  │     ↓                                                 │  │
│  │  8. ngAfterViewChecked()                              │  │
│  │                                                       │  │
│  │  [Loop: 4→6→8 se houver mudanças]                    │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  Fase 3: Destruição                                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                                                       │  │
│  │  9. ngOnDestroy()    ← Limpeza obrigatória         │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Ordem de Execução Detalhada:

Primeira Renderização:
constructor() 
  → ngOnChanges() (se @Input presente)
  → ngOnInit()
  → ngDoCheck()
  → ngAfterContentInit()
  → ngAfterContentChecked()
  → ngAfterViewInit()
  → ngAfterViewChecked()

Mudanças Subsequentes:
ngOnChanges() (se @Input mudou)
  → ngDoCheck()
  → ngAfterContentChecked()
  → ngAfterViewChecked()

Destruição:
ngOnDestroy()
```

**Exemplo Prático Completo**:

```typescript
import {
  Component,
  OnInit,
  OnDestroy,
  OnChanges,
  AfterViewInit,
  AfterContentInit,
  SimpleChanges,
  Input,
  ViewChild,
  ContentChild,
  ChangeDetectorRef
} from '@angular/core';
import { Subscription, interval } from 'rxjs';

@Component({
  selector: 'app-lifecycle-demo',
  standalone: true,
  template: `
    <div>
      <h2>{{ title }}</h2>
      <p>Counter: {{ counter }}</p>
      <p>Input Value: {{ inputValue }}</p>
      <ng-content></ng-content>
    </div>
  `
})
export class LifecycleDemoComponent
  implements OnInit, OnDestroy, OnChanges, AfterViewInit, AfterContentInit {
  
  @Input() inputValue: number = 0;
  @Input() title: string = 'Lifecycle Demo';
  
  counter: number = 0;
  private subscription?: Subscription;

  constructor(private cdr: ChangeDetectorRef) {
    console.log('1. Constructor called');
  }

  ngOnChanges(changes: SimpleChanges): void {
    console.log('2. ngOnChanges called', changes);
    if (changes['inputValue'] && !changes['inputValue'].firstChange) {
      console.log(`Input value changed from ${changes['inputValue'].previousValue} to ${changes['inputValue'].currentValue}`);
    }
  }

  ngOnInit(): void {
    console.log('3. ngOnInit called');
    this.subscription = interval(1000).subscribe(() => {
      this.counter++;
    });
  }

  ngAfterContentInit(): void {
    console.log('4. ngAfterContentInit called');
  }

  ngAfterViewInit(): void {
    console.log('5. ngAfterViewInit called');
  }

  ngOnDestroy(): void {
    console.log('6. ngOnDestroy called');
    this.subscription?.unsubscribe();
  }
}
```

**Quando Usar Cada Hook**:

| Hook | Quando Usar | Quando NÃO Usar |
|------|------------|-----------------|
| `constructor` | Injeção de dependências | Lógica de inicialização |
| `ngOnInit` | Setup inicial, chamadas HTTP | Acesso a ViewChild |
| `ngOnChanges` | Reagir a mudanças de `@Input` | Lógica complexa (use setters) |
| `ngDoCheck` | Detecção customizada de mudanças | Lógica pesada (performance) |
| `ngAfterViewInit` | Manipulação de DOM, ViewChild | Setup inicial |
| `ngOnDestroy` | Limpeza de recursos | Sempre necessário! |

**Exemplo Prático**:

```typescript
import { Component, OnInit, OnDestroy, OnChanges, SimpleChanges, Input } from '@angular/core';

@Component({
  selector: 'app-lifecycle-demo',
  standalone: true,
  template: '<p>{{ message }}</p>'
})
export class LifecycleDemoComponent implements OnInit, OnDestroy, OnChanges {
  @Input() userId: number = 0;
  message: string = '';

  constructor() {
    console.log('Constructor called');
  }

  ngOnChanges(changes: SimpleChanges): void {
    console.log('ngOnChanges called', changes);
    if (changes['userId']) {
      this.message = `User ID changed to ${this.userId}`;
    }
  }

  ngOnInit(): void {
    console.log('ngOnInit called');
    this.message = 'Component initialized';
  }

  ngOnDestroy(): void {
    console.log('ngOnDestroy called');
  }
}
```

---

### Projeção de Conteúdo (ng-content)

**Definição**: Projeção de conteúdo permite inserir conteúdo HTML externo dentro de um componente.

**Explicação Detalhada**:

`ng-content` permite:
- Inserir conteúdo dinâmico
- Criar componentes wrapper reutilizáveis
- Passar HTML complexo para componentes filhos

**Analogia**:

Projeção de conteúdo é como uma caixa de correio:
- O componente é a caixa
- `ng-content` é a abertura onde você coloca as cartas (conteúdo)
- O conteúdo vem de fora e é projetado dentro

**Visualização**:

```
Componente Pai                  Componente Filho
┌─────────────────┐            ┌─────────────────────┐
│ <app-card>      │            │ <div class="card">  │
│   <h1>Title</h1>│  ────────→ │   <ng-content>      │
│ </app-card>     │            │   </ng-content>     │
└─────────────────┘            │ </div>              │
                               └─────────────────────┘
```

**Exemplo Prático**:

```typescript
card.component.ts
@Component({
  selector: 'app-card',
  standalone: true,
  template: `
    <div class="card">
      <div class="card-header">
        <ng-content select="[slot=header]"></ng-content>
      </div>
      <div class="card-body">
        <ng-content></ng-content>
      </div>
      <div class="card-footer">
        <ng-content select="[slot=footer]"></ng-content>
      </div>
    </div>
  `
})
export class CardComponent {}
```

```html
app.component.html
<app-card>
  <h1 slot="header">Título do Card</h1>
  <p>Conteúdo principal do card</p>
  <button slot="footer">Ação</button>
</app-card>
```

---

## Comparação com Outras Abordagens

### Standalone Components vs NgModules

**Tabela Comparativa Detalhada**:

| Aspecto | NgModules | Standalone Components |
|---------|-----------|----------------------|
| **Arquivos Necessários** | Componente + Módulo (2 arquivos) | Apenas Componente (1 arquivo) |
| **Boilerplate** | Alto (declarations, imports, exports) | Mínimo (apenas imports) |
| **Declaração** | Em NgModule | No próprio componente |
| **Reutilização** | Dependente do módulo | Totalmente independente |
| **Lazy Loading** | Via módulo | Direto no componente |
| **Tree-shaking** | Bom | Excelente |
| **Bundle Size** | Maior (módulos completos) | Menor (apenas usado) |
| **Curva de Aprendizado** | Mais alta | Mais baixa |
| **Migração** | N/A (padrão antigo) | Fácil (incremental) |
| **Performance** | Boa | Melhor |
| **Manutenibilidade** | Média | Alta |
| **Portabilidade** | Baixa | Alta |
| **Compatibilidade** | Angular 2-17 | Angular 14+ |

**Quando Usar Cada Abordagem**:

**Use NgModules quando**:
- Trabalhando com projeto legado que ainda não migrou
- Precisa de configuração complexa de providers compartilhados
- Usando bibliotecas antigas que não suportam standalone
- Migração incremental (pode coexistir)

**Use Standalone Components quando**:
- Criando novos projetos (Angular 17+)
- Desenvolvendo novos componentes
- Priorizando simplicidade e performance
- Querendo melhor tree-shaking
- Facilitando reutilização entre projetos

**Visualização Comparativa**:

```
┌─────────────────────────────────────────────────────────────┐
│          NgModule Approach (Complexidade)                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  product-card.component.ts                                  │
│  product-card.component.html                                 │
│  product-card.component.css                                 │
│  product-card.module.ts      ← Arquivo extra necessário    │
│                                                              │
│  product-card.module.ts:                                     │
│  ┌─────────────────────────────┐                          │
│  │ @NgModule({                  │                          │
│  │   declarations: [            │                          │
│  │     ProductCardComponent     │                          │
│  │   ],                         │                          │
│  │   imports: [                │                          │
│  │     CommonModule             │                          │
│  │   ],                         │                          │
│  │   exports: [                │                          │
│  │     ProductCardComponent     │                          │
│  │   ]                          │                          │
│  │ })                           │                          │
│  └─────────────────────────────┘                          │
│                                                              │
│  Total: 4 arquivos                                           │
│  Linhas de código: ~30+ (boilerplate)                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│        Standalone Component Approach (Simplicidade)         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  product-card.component.ts                                  │
│  product-card.component.html                                 │
│  product-card.component.css                                 │
│                                                              │
│  product-card.component.ts:                                 │
│  ┌─────────────────────────────┐                          │
│  │ @Component({                │                          │
│  │   standalone: true,         │                          │
│  │   imports: [                │                          │
│  │     CommonModule             │                          │
│  │   ]                          │                          │
│  │ })                           │                          │
│  └─────────────────────────────┘                          │
│                                                              │
│  Total: 3 arquivos                                           │
│  Linhas de código: ~10 (mínimo necessário)                │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Redução: 25% menos arquivos, 66% menos boilerplate
```

### Angular vs React vs Vue: Abordagem de Componentes

**Comparação entre Frameworks**:

| Aspecto | Angular (Standalone) | React | Vue 3 |
|---------|---------------------|-------|-------|
| **Sistema de Módulos** | Opcional (Standalone) | Não tem | Não tem |
| **Organização** | Arquivos separados | JSX inline ou separado | SFC (Single File Component) |
| **Template Syntax** | HTML + Diretivas | JSX (JavaScript) | Template HTML |
| **TypeScript** | Nativo | Opcional | Opcional |
| **Dependency Injection** | Nativo (DI) | Context API / Props | Provide/Inject |
| **Lifecycle Hooks** | 9 hooks principais | useEffect, etc. | onMounted, etc. |
| **State Management** | Services + Signals | Redux, Zustand | Pinia, Vuex |
| **Bundle Size** | Médio-Grande | Pequeno-Médio | Pequeno |
| **Curva de Aprendizado** | Moderada-Alta | Baixa-Moderada | Baixa |
| **Performance** | Excelente | Excelente | Excelente |
| **Ecosystem** | Maduro e completo | Enorme | Crescente |

**Estrutura de Componente Comparativa**:

```typescript
// Angular Standalone Component
@Component({
  selector: 'app-product',
  standalone: true,
  imports: [CommonModule],
  template: '<div>{{ product.name }}</div>'
})
export class ProductComponent {
  @Input() product!: Product;
}

// React Component
function ProductComponent({ product }: { product: Product }) {
  return <div>{product.name}</div>;
}

// Vue 3 Component
<template>
  <div>{{ product.name }}</div>
</template>
<script setup lang="ts">
defineProps<{ product: Product }>();
</script>
```

**Vantagens de Cada Abordagem**:

**Angular Standalone**:
- ✅ TypeScript nativo e type-safe
- ✅ DI integrado e poderoso
- ✅ Estrutura clara e organizada
- ✅ Ferramentas completas (CLI, DevTools)
- ✅ Padrões bem definidos

**React**:
- ✅ Flexibilidade máxima
- ✅ Ecossistema enorme
- ✅ JSX intuitivo
- ✅ Hooks poderosos
- ✅ Grande comunidade

**Vue 3**:
- ✅ Sintaxe simples e intuitiva
- ✅ Performance excelente
- ✅ Composition API poderosa
- ✅ Curva de aprendizado suave
- ✅ Documentação excelente

---

## Exemplos Práticos Completos

### Exemplo 1: Componente Standalone Completo

**Contexto**: Criar um componente de card de produto standalone completo.

**Código**:

{% raw %}
```typescript
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Product {
  id: number;
  name: string;
  price: number;
  imageUrl: string;
  inStock: boolean;
}

@Component({
  selector: 'app-product-card',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="product-card" [class.out-of-stock]="!product.inStock">
      <img [src]="product.imageUrl" [alt]="product.name">
      <h3>{{ product.name }}</h3>
      <p class="price">{{ product.price | currency:'BRL' }}</p>
      <button 
        [disabled]="!product.inStock"
        (click)="onAddToCart()">
        {{ product.inStock ? 'Adicionar ao Carrinho' : 'Indisponível' }}
      </button>
    </div>
  `,
  styles: [`
    .product-card {
      border: 1px solid #ddd;
      border-radius: 8px;
      padding: 16px;
      max-width: 300px;
    }
    .out-of-stock {
      opacity: 0.6;
    }
  `]
})
export class ProductCardComponent {
  @Input() product!: Product;
  @Output() addToCart = new EventEmitter<Product>();

  onAddToCart(): void {
    this.addToCart.emit(this.product);
  }
}
```
{% raw %}
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Product {
  id: number;
  name: string;
  price: number;
  imageUrl: string;
  inStock: boolean;
}

@Component({
  selector: 'app-product-card',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="product-card" [class.out-of-stock]="!product.inStock">
      <img [src]="product.imageUrl" [alt]="product.name">
      <h3>{{ product.name }}</h3>
      <p class="price">{{ product.price | currency:'BRL' }}</p>
      <button 
        [disabled]="!product.inStock"
        (click)="onAddToCart()">
        {{ product.inStock ? 'Adicionar ao Carrinho' : 'Indisponível' }}
      </button>
    </div>
  `,
  styles: [`
    .product-card {
      border: 1px solid #ddd;
      border-radius: 8px;
      padding: 16px;
      max-width: 300px;
    }
    .out-of-stock {
      opacity: 0.6;
    }
  `]
})
export class ProductCardComponent {
  @Input() product!: Product;
  @Output() addToCart = new EventEmitter<Product>();

  onAddToCart(): void {
    this.addToCart.emit(this.product);
  }
}
```
{% endraw %}

**Explicação**:

1. Componente standalone com `standalone: true`
2. Importa `CommonModule` para diretivas comuns
3. Usa `@Input` para receber dados
4. Usa `@Output` para emitir eventos
5. Template inline com binding e diretivas
6. Estilos encapsulados inline

---

### Exemplo 2: Componente com Ciclo de Vida

**Contexto**: Criar componente que demonstra hooks do ciclo de vida.

**Código**:

```typescript
import { Component, OnInit, OnDestroy, Input } from '@angular/core';
import { interval, Subscription } from 'rxjs';

@Component({
  selector: 'app-timer',
  standalone: true,
  template: `
    <div class="timer">
      <h2>Timer: {{ seconds }}s</h2>
      <p>Status: {{ status }}</p>
    </div>
  `
})
export class TimerComponent implements OnInit, OnDestroy {
  @Input() initialSeconds: number = 0;
  seconds: number = 0;
  status: string = 'Inicializando...';
  private subscription?: Subscription;

  ngOnInit(): void {
    this.seconds = this.initialSeconds;
    this.status = 'Rodando';
    
    this.subscription = interval(1000).subscribe(() => {
      this.seconds++;
    });
  }

  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
    this.status = 'Parado';
  }
}
```

**Explicação**:

1. Implementa `OnInit` e `OnDestroy`
2. `ngOnInit` inicializa timer
3. `ngOnDestroy` limpa subscription
4. Previne memory leaks

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Sempre use Standalone Components em novos projetos**
   - **Por quê**: Simplifica arquitetura, reduz boilerplate, melhora performance e é o padrão moderno do Angular
   - **Exemplo Bom**:
```
     @Component({
       selector: 'app-product',
       standalone: true,
       imports: [CommonModule],
       templateUrl: './product.component.html'
     })
     export class ProductComponent {}
```
   - **Exemplo Ruim**:
```
     @Component({
       selector: 'app-product',
       templateUrl: './product.component.html'
     })
     export class ProductComponent {}
     // Precisa ser declarado em NgModule
```
   - **Benefícios**: Menos arquivos, código mais limpo, melhor tree-shaking

2. **Use ViewEncapsulation.Emulated (padrão)**
   - **Por quê**: Isola estilos sem complexidade do Shadow DOM, funciona em todos os navegadores
   - **Exemplo Bom**:
```
     @Component({
       encapsulation: ViewEncapsulation.Emulated
     })
```
   - **Quando usar None**: Apenas quando realmente precisa de estilos globais
   - **Quando usar ShadowDom**: Apenas quando precisa isolamento completo e suporta navegadores modernos

3. **Limpe subscriptions em ngOnDestroy**
   - **Por quê**: Previne memory leaks, especialmente crítico com observables e timers
   - **Exemplo Bom**:
```
     export class TimerComponent implements OnDestroy {
       private subscription = new Subscription();
       
       ngOnInit() {
         this.subscription.add(
           interval(1000).subscribe(() => { /* ... */ })
         );
       }
       
       ngOnDestroy() {
         this.subscription.unsubscribe();
       }
     }
```
   - **Exemplo Ruim**:
```
     ngOnInit() {
       interval(1000).subscribe(() => { /* ... */ });
       // Sem unsubscribe - memory leak!
     }
```
   - **Alternativa**: Use `takeUntilDestroyed()` (Angular 16+)

4. **Use ng-content para componentes wrapper**
   - **Por quê**: Cria componentes reutilizáveis e flexíveis, permite composição
   - **Exemplo Bom**:
```
     @Component({
       template: `
         <div class="card">
           <ng-content select="[slot=header]"></ng-content>
           <ng-content></ng-content>
           <ng-content select="[slot=footer]"></ng-content>
         </div>
       `
     })
     export class CardComponent {}
```
   - **Benefícios**: Flexibilidade, reutilização, composição

5. **Use ChangeDetectionStrategy.OnPush para performance**
   - **Por quê**: Reduz verificações de mudanças, melhora performance significativamente
   - **Exemplo Bom**:
```
     @Component({
       changeDetection: ChangeDetectionStrategy.OnPush,
       // ...
     })
```
   - **Quando usar**: Componentes que recebem dados via `@Input` ou signals
   - **Benefícios**: Menos ciclos de detecção, melhor performance

6. **Organize imports de forma clara**
   - **Por quê**: Facilita manutenção e leitura do código
   - **Exemplo Bom**:
```
     imports: [
       CommonModule,
       FormsModule,
       ProductCardComponent,
       CurrencyPipe
     ]
```
   - **Padrão**: Agrupe por tipo (módulos, componentes, pipes)

7. **Use inject() ao invés de constructor DI quando possível**
   - **Por quê**: Mais limpo, funciona em funções, melhor para testes
   - **Exemplo Bom**:
```
     export class ProductComponent {
       private productService = inject(ProductService);
     }
```
   - **Exemplo Ruim**:
```
     constructor(private productService: ProductService) {}
```
   - **Nota**: `inject()` só funciona em contexto de injeção

8. **Mantenha templates simples**
   - **Por quê**: Facilita manutenção, testes e debugging
   - **Exemplo Bom**:
```
     <div *ngIf="isLoading">Carregando...</div>
     <div *ngIf="!isLoading">{{ product.name }}</div>
```
   - **Exemplo Ruim**:
{% raw %}
```
     <div>{{ isLoading ? 'Carregando...' : product.name }}</div>
     <!-- Lógica complexa no template -->
```
{% endraw %}
   - **Regra**: Se a lógica tem mais de uma linha, mova para método

9. **Use interfaces para @Input e @Output**
   - **Por quê**: Type safety, documentação, melhor autocomplete
   - **Exemplo Bom**:
```
     interface ProductInput {
       id: number;
       name: string;
     }
     
     @Input() product!: ProductInput;
     @Output() selected = new EventEmitter<ProductInput>();
```
   - **Benefícios**: Type checking, documentação inline

10. **Separe lógica complexa em serviços**
    - **Por quê**: Componentes devem ser focados em apresentação
    - **Exemplo Bom**:
```
      export class ProductComponent {
        private productService = inject(ProductService);
        
        loadProduct(id: number) {
          this.productService.getProduct(id).subscribe(/* ... */);
        }
      }
```
    - **Regra**: Se método tem mais de 10 linhas, considere mover para serviço

### ❌ Anti-padrões Comuns

1. **Não esqueça de limpar recursos em ngOnDestroy**
   - **Problema**: Memory leaks, performance degradada, bugs difíceis de rastrear
   - **Exemplo Ruim**:
```
     ngOnInit() {
       this.timer = setInterval(() => {
         this.counter++;
       }, 1000);
       // Nunca limpa - memory leak!
     }
```
   - **Solução**: Sempre limpe em `ngOnDestroy`
   - **Exemplo Correto**:
```
     ngOnDestroy() {
       if (this.timer) {
         clearInterval(this.timer);
       }
     }
```
   - **Impacto**: Aplicação pode travar após uso prolongado

2. **Não use NgModules desnecessariamente**
   - **Problema**: Complexidade desnecessária, mais arquivos, pior performance
   - **Exemplo Ruim**:
```
     @NgModule({
       declarations: [SimpleComponent],
       imports: [CommonModule],
       exports: [SimpleComponent]
     })
     export class SimpleComponentModule {}
```
   - **Solução**: Use Standalone Components
   - **Exemplo Correto**:
```
     @Component({
       standalone: true,
       imports: [CommonModule]
     })
     export class SimpleComponent {}
```
   - **Impacto**: Código mais complexo, difícil manutenção

3. **Não misture lógica complexa no template**
   - **Problema**: Dificulta manutenção, testes e debugging
   - **Exemplo Ruim**:
{% raw %}
```
     <div>{{ users.filter(u => u.active).map(u => u.name).join(', ') }}</div>
```
{% endraw %}
   - **Solução**: Mova lógica para método ou getter
   - **Exemplo Correto**:
```
     get activeUserNames(): string {
       return this.users
         .filter(u => u.active)
         .map(u => u.name)
         .join(', ');
     }
```
```
     <div>{{ activeUserNames }}</div>
```
   - **Impacto**: Templates difíceis de ler e manter

4. **Não use any em @Input e @Output**
   - **Problema**: Perde type safety, erros em runtime
   - **Exemplo Ruim**:
```
     @Input() data: any;
     @Output() event = new EventEmitter<any>();
```
   - **Solução**: Use interfaces ou tipos específicos
   - **Exemplo Correto**:
```
     interface ProductData {
       id: number;
       name: string;
     }
     
     @Input() data!: ProductData;
     @Output() event = new EventEmitter<ProductData>();
```
   - **Impacto**: Bugs difíceis de detectar, perda de autocomplete

5. **Não ignore erros de compilação do Angular**
   - **Problema**: Pode causar bugs em runtime, comportamento inesperado
   - **Exemplo Ruim**:
```
     // @ts-ignore
     this.undefinedProperty.value;
```
   - **Solução**: Corrija os tipos ou use type guards
   - **Impacto**: Aplicação pode quebrar em produção

6. **Não crie componentes muito grandes**
   - **Problema**: Difícil manutenção, testes complexos, baixa reutilização
   - **Exemplo Ruim**: Componente com 500+ linhas, múltiplas responsabilidades
   - **Solução**: Divida em componentes menores e focados
   - **Regra**: Se componente tem mais de 200 linhas, considere dividir
   - **Impacto**: Código difícil de entender e modificar

7. **Não use ViewChild sem verificação**
   - **Problema**: Pode ser undefined, causa erros em runtime
   - **Exemplo Ruim**:
```
     @ViewChild('element') element!: ElementRef;
     
     ngAfterViewInit() {
       this.element.nativeElement.focus(); // Pode ser undefined!
     }
```
   - **Solução**: Use verificação ou optional chaining
   - **Exemplo Correto**:
```
     ngAfterViewInit() {
       this.element?.nativeElement?.focus();
     }
```
   - **Impacto**: Aplicação pode quebrar se elemento não existir

---

## Exercícios Práticos

### Exercício 1: Criar Primeiro Componente Standalone (Básico)

**Objetivo**: Criar componente standalone básico

**Descrição**: 
Crie um componente `WelcomeComponent` standalone que exibe uma mensagem de boas-vindas. O componente deve ter título, subtítulo e botão.

**Arquivo**: `exercises/exercise-1-3-1-componente-standalone.md`

---

### Exercício 2: Componente com Input e Output (Básico)

**Objetivo**: Criar componente com comunicação

**Descrição**:
Crie um componente `ButtonComponent` que recebe texto via `@Input` e emite evento via `@Output` quando clicado.

**Arquivo**: `exercises/exercise-1-3-2-input-output.md`

---

### Exercício 3: Componente com Template Avançado (Intermediário)

**Objetivo**: Trabalhar com templates complexos

**Descrição**:
Crie um componente `UserProfileComponent` que exibe perfil de usuário com interpolação, property binding, event binding e diretivas.

**Arquivo**: `exercises/exercise-1-3-3-template-avancado.md`

---

### Exercício 4: ViewEncapsulation e Estilos (Intermediário)

**Objetivo**: Entender encapsulação de estilos

**Descrição**:
Crie três versões do mesmo componente com diferentes ViewEncapsulation (Emulated, None, ShadowDom) e observe as diferenças.

**Arquivo**: `exercises/exercise-1-3-4-view-encapsulation.md`

---

### Exercício 5: Ciclo de Vida Completo (Avançado)

**Objetivo**: Implementar hooks do ciclo de vida

**Descrição**:
Crie um componente que demonstra todos os principais hooks do ciclo de vida com logs no console.

**Arquivo**: `exercises/exercise-1-3-5-ciclo-vida.md`

---

### Exercício 6: Projeção de Conteúdo (Avançado)

**Objetivo**: Usar ng-content para projeção

**Descrição**:
Crie um componente `CardComponent` que usa `ng-content` com múltiplos slots (header, body, footer).

**Arquivo**: `exercises/exercise-1-3-6-projecao-conteudo.md`

---

## Referências Externas

### Documentação Oficial

#### Componentes e Arquitetura

- **[Angular Components Overview](https://angular.io/guide/component-overview)**: Guia oficial completo sobre componentes Angular
- **[Standalone Components](https://angular.io/guide/standalone-components)**: Documentação oficial de Standalone Components
- **[Component Interaction](https://angular.io/guide/component-interaction)**: Como componentes se comunicam
- **[Component Styles](https://angular.io/guide/component-styles)**: Guia sobre estilos de componentes

#### Ciclo de Vida e Hooks

- **[Lifecycle Hooks](https://angular.io/guide/lifecycle-hooks)**: Documentação completa dos hooks do ciclo de vida
- **[OnChanges](https://angular.io/api/core/OnChanges)**: API reference de OnChanges
- **[OnInit and OnDestroy](https://angular.io/api/core/OnInit)**: Hooks de inicialização e destruição

#### ViewEncapsulation e Estilos

- **[ViewEncapsulation API](https://angular.io/api/core/ViewEncapsulation)**: Documentação de encapsulação de estilos
- **[Component Styles Guide](https://angular.io/guide/component-styles)**: Guia sobre estilos e encapsulação

#### Migração e Padrões

- **[Migrating to Standalone](https://angular.io/guide/standalone-components#migrating-existing-libraries)**: Guia de migração para Standalone Components
- **[SCAM Pattern](https://angular.io/guide/standalone-components#migrating-existing-libraries)**: Padrão Single Component Angular Module

### Artigos e Tutoriais

#### Guias Completos

- **[Angular Standalone Components - Complete Guide](https://angular.io/guide/standalone-components)**: Guia completo oficial
- **[Understanding Angular Standalone Components](https://www.angular.io/guide/standalone-components)**: Explicação detalhada do conceito

#### Artigos Técnicos

- **[Angular Standalone Components Best Practices](https://angular.io/guide/standalone-components)**: Melhores práticas
- **[Component Lifecycle Deep Dive](https://angular.io/guide/lifecycle-hooks)**: Análise profunda do ciclo de vida
- **[ViewEncapsulation Explained](https://angular.io/api/core/ViewEncapsulation)**: Explicação detalhada de encapsulação

#### Tutoriais Práticos

- **[Creating Your First Standalone Component](https://angular.io/guide/standalone-components)**: Tutorial passo a passo
- **[Migrating from NgModules to Standalone](https://angular.io/guide/standalone-components#migrating-existing-libraries)**: Guia de migração prática

### Vídeos e Cursos

#### Canais Oficiais

- **[Angular Official YouTube](https://www.youtube.com/@angular)**: Canal oficial do Angular
- **[Angular University](https://www.youtube.com/results?search_query=angular+standalone+components)**: Tutoriais sobre Standalone Components

#### Playlists Recomendadas

- **Angular Standalone Components**: Playlist dedicada ao tema
- **Angular Component Lifecycle**: Tutoriais sobre ciclo de vida
- **Angular Best Practices**: Padrões e práticas recomendadas

### Ferramentas e Recursos

#### IDEs e Editores

- **[VS Code Angular Extension](https://marketplace.visualstudio.com/items?itemName=Angular.ng-template)**: Extensão oficial para VS Code
- **[WebStorm Angular Support](https://www.jetbrains.com/help/webstorm/angular.html)**: Suporte Angular no WebStorm

#### Ferramentas de Desenvolvimento

- **[Angular DevTools](https://angular.io/guide/devtools)**: Ferramentas de desenvolvimento do Angular
- **[Angular CLI](https://angular.io/cli)**: CLI oficial para criar e gerenciar projetos

#### Ferramentas Online

- **[StackBlitz Angular](https://stackblitz.com/edit/angular)**: Editor online para Angular
- **[Angular Playground](https://angular.io/guide/standalone-components)**: Ambiente de testes online

### Comunidade e Suporte

#### Fóruns e Comunidades

- **[Angular GitHub](https://github.com/angular/angular)**: Repositório oficial e issues
- **[Stack Overflow - Angular](https://stackoverflow.com/questions/tagged/angular)**: Perguntas e respostas da comunidade
- **[Angular Discord](https://discord.gg/angular)**: Comunidade Discord do Angular
- **[r/Angular](https://www.reddit.com/r/Angular/)**: Subreddit do Angular

#### Newsletters e Blogs

- **[Angular Blog](https://blog.angular.io/)**: Blog oficial do Angular
- **[Angular Weekly](https://www.angular.io/)**: Newsletter semanal sobre Angular

### Livros Recomendados

- **"Angular: The Complete Guide"** por Maximilian Schwarzmüller: Guia completo incluindo Standalone Components
- **"Angular Best Practices"** por various authors: Padrões e práticas recomendadas
- **"Pro Angular"** por Adam Freeman: Guia avançado sobre Angular

### Cheat Sheets

- **[Angular Component Cheat Sheet](https://angular.io/guide/cheatsheet)**: Referência rápida oficial
- **[Standalone Components Quick Reference](https://angular.io/guide/standalone-components)**: Referência rápida de Standalone Components

---

## Resumo

### Principais Conceitos

- **Componentes Angular**: Classes TypeScript decoradas com `@Component` que controlam partes da UI
- **Standalone Components**: Componentes auto-suficientes que não requerem NgModules (padrão desde Angular 17)
- **Anatomia de Componente**: Classe TypeScript (lógica) + Template HTML (estrutura) + Estilos CSS (aparência)
{% raw %}
- **Templates e Sintaxe**: Interpolação `{{ }}`, Property Binding `[]`, Event Binding `()`, Two-way Binding `[()]`
{% endraw %}
- **ViewEncapsulation**: Controla isolamento de estilos (Emulated padrão, None, ShadowDom)
- **Ciclo de Vida**: 9 hooks principais desde criação até destruição (constructor → ngOnInit → ngOnDestroy)
- **Projeção de Conteúdo**: `ng-content` permite inserir HTML externo em componentes
- **SCAM Pattern**: Padrão de migração gradual de NgModules para Standalone

### Pontos-Chave para Lembrar

- **Standalone First**: Sempre use `standalone: true` em novos componentes (padrão Angular 17+)
- **Limpeza Obrigatória**: Sempre limpe recursos em `ngOnDestroy` (subscriptions, timers, listeners)
- **Composição com ng-content**: Use `ng-content` para criar componentes wrapper reutilizáveis
- **ViewEncapsulation**: Emulated é padrão e recomendado para maioria dos casos
- **Templates Simples**: Mantenha templates simples, mova lógica complexa para métodos
- **Change Detection**: Use `OnPush` para melhor performance quando possível
- **Type Safety**: Use interfaces para `@Input` e `@Output`, evite `any`
- **Organização**: Separe lógica complexa em serviços, mantenha componentes focados em apresentação
- **Migração Gradual**: Standalone e NgModules podem coexistir durante migração

### Comparações Importantes

- **Standalone vs NgModules**: Standalone reduz boilerplate, melhora performance e facilita reutilização
- **Angular vs React/Vue**: Angular oferece estrutura mais rígida, TypeScript nativo e DI integrado
- **ViewEncapsulation**: Emulated (padrão) vs None (global) vs ShadowDom (isolamento completo)

### Próximos Passos

- **Próxima Aula**: Data Binding e Diretivas Modernas
- **Prática Recomendada**:
  - Criar componentes standalone do zero
  - Implementar ciclo de vida completo com todos os hooks
  - Praticar projeção de conteúdo com múltiplos slots
  - Migrar componente NgModule para Standalone
  - Implementar ChangeDetectionStrategy.OnPush
- **Aprofundamento**:
  - Explorar lazy loading com Standalone Components
  - Estudar padrões avançados de comunicação entre componentes
  - Aprender sobre Signals e reatividade moderna
  - Praticar testes unitários de componentes standalone

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

**Aula Anterior**: [Aula 1.2: TypeScript Essencial](./lesson-1-2-typescript-essencial.md)  
**Próxima Aula**: [Aula 1.4: Data Binding e Diretivas Modernas](./lesson-1-4-data-binding.md)  
**Voltar ao Módulo**: [Módulo 1: Fundamentos Acelerados](../modules/module-1-fundamentos-acelerados.md)
