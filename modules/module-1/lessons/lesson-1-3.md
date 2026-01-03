---
layout: lesson
title: "Aula 1.3: Componentes Standalone e Templates"
slug: componentes-standalone
module: module-1
lesson_id: lesson-1-3
duration: "120 minutos"
level: "Básico"
prerequisites: 
  - "lesson-1-2"
exercises:
  - 
  - "lesson-1-3-exercise-1"
  - "lesson-1-3-exercise-2"
  - "lesson-1-3-exercise-3"
  - "lesson-1-3-exercise-4"
  - "lesson-1-3-exercise-5"
  - "lesson-1-3-exercise-6"
podcast:
  file: "assets/podcasts/01.3e4-Fundação_Angular_Tipagem_Encapsulamento_e_Generics.m4a"
  title: "Componentes Standalone, Templates, Data Binding e Diretivas Modernas"
  description: "Mergulhe profundamente nos componentes standalone do Angular."
  duration: "60-75 minutos"
---

## Introdução

Nesta aula, você aprenderá a criar componentes standalone do Angular, trabalhar com templates avançados e entender o ciclo de vida dos componentes. Standalone Components são o futuro do Angular e representam uma mudança arquitetural significativa.

### O que você vai aprender

- Anatomia de um componente Angular
- Standalone Components (Angular 17+)
- SCAM Pattern (Single Component Angular Module)
- Templates e sintaxe de templates
- ViewEncapsulation e estilos
- Ciclo de vida dos componentes
- Projeção de conteúdo (ng-content)

### Por que isso é importante

Componentes são o coração do Angular. Entender como criar componentes standalone eficientes e trabalhar com templates é fundamental para construir aplicações modernas. Standalone Components simplificam a arquitetura e são o padrão recomendado para novos projetos.

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

**Definição**: Standalone Components são componentes que não precisam ser declarados em um NgModule. Eles podem ser importados diretamente e são auto-suficientes.

**Explicação Detalhada**:

Standalone Components foram introduzidos no Angular 14 e se tornaram padrão no Angular 17+. Eles simplificam a arquitetura porque:

- Não requerem NgModules
- Podem importar diretamente dependências
- Facilitam lazy loading
- Reduzem boilerplate

**Analogia**:

Standalone Components são como apartamentos autossuficientes:
- **NgModules** eram como prédios onde você precisava se registrar
- **Standalone Components** são apartamentos que têm tudo que precisam e podem funcionar independentemente

**Visualização**:

```
NgModule (Antigo)              Standalone (Novo)
┌──────────────────┐            ┌─────────────────┐
│ @NgModule({      │            │ @Component({    │
│   declarations:  │            │   standalone:   │
│     [Comp]       │            │   true,         │
│   imports: [...] │            │   imports: [...]│
│ })               │            │ })              │
└──────────────────┘            └─────────────────┘
```

**Exemplo Prático**:

```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-product-card',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './product-card.component.html',
  styleUrls: ['./product-card.component.css']
})
export class ProductCardComponent {
  product = {
    name: 'Notebook',
    price: 2500,
    inStock: true
  };
}
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

**Definição**: O ciclo de vida de um componente são os hooks que Angular chama em momentos específicos da existência do componente.

**Explicação Detalhada**:

Principais hooks do ciclo de vida:

1. **ngOnChanges**: Quando propriedades de entrada mudam
2. **ngOnInit**: Após primeira inicialização
3. **ngDoCheck**: Durante cada verificação de mudanças
4. **ngAfterContentInit**: Após conteúdo projetado inicializado
5. **ngAfterContentChecked**: Após cada verificação de conteúdo
6. **ngAfterViewInit**: Após view inicializada
7. **ngAfterViewChecked**: Após cada verificação de view
8. **ngOnDestroy**: Antes do componente ser destruído

**Analogia**:

O ciclo de vida é como a vida de uma pessoa:
- **ngOnInit**: Nascimento
- **ngOnChanges**: Crescimento e mudanças
- **ngAfterViewInit**: Primeira vez vendo o mundo
- **ngOnDestroy**: Morte

**Visualização**:

```
Criação  →  Inicialização     →     Mudanças  →  Destruição
   │               │                    │           │
   │               │                    │           │
   ├─ constructor()│                    │           │
   │               │                    │           │
   ├───────────────┼─ ngOnInit()        │           │
   │               │                    │           │
   │               ├─ ngOnChanges()     │           │
   │               │                    │           │
   │               ├─ ngAfterViewInit() │           │
   │               │                    │           │
   │               │                    └─ ngOnDestroy()
```

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
{% raw %}
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
{% endraw %}
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
{% raw %}
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
{% endraw %}
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

{% raw %}
```typescript
import { Component, OnInit, OnDestroy, Input } from '@angular/core';
import { interval, Subscription } from 'rxjs';

@Component({
  selector: 'app-timer',
  standalone: true,
{% raw %}
  template: `
    <div class="timer">
      <h2>Timer: {{ seconds }}s</h2>
      <p>Status: {{ status }}</p>
    </div>
  `
{% endraw %}
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
{% endraw %}

**Explicação**:

1. Implementa `OnInit` e `OnDestroy`
2. `ngOnInit` inicializa timer
3. `ngOnDestroy` limpa subscription
4. Previne memory leaks

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Sempre use Standalone Components em novos projetos**
   - **Por quê**: Simplifica arquitetura e é o padrão moderno
   - **Exemplo**: `standalone: true` em `@Component`

2. **Use ViewEncapsulation.Emulated (padrão)**
   - **Por quê**: Isola estilos sem complexidade do Shadow DOM
   - **Exemplo**: Deixe padrão ou configure explicitamente

3. **Limpe subscriptions em ngOnDestroy**
   - **Por quê**: Previne memory leaks
   - **Exemplo**: `this.subscription?.unsubscribe()`

4. **Use ng-content para componentes wrapper**
   - **Por quê**: Cria componentes reutilizáveis e flexíveis
   - **Exemplo**: Componentes de card, modal, etc.

### ❌ Anti-padrões Comuns

1. **Não esqueça de limpar recursos em ngOnDestroy**
   - **Problema**: Pode causar memory leaks
   - **Solução**: Sempre unsubscribe de observables

2. **Não use NgModules desnecessariamente**
   - **Problema**: Adiciona complexidade sem benefício
   - **Solução**: Use Standalone Components

3. **Não misture lógica complexa no template**
   - **Problema**: Dificulta manutenção e testes
   - **Solução**: Mova lógica para métodos na classe

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

- **[Angular Components](https://angular.io/guide/component-overview)**: Guia oficial de componentes
- **[Standalone Components](https://angular.io/guide/standalone-components)**: Documentação de Standalone Components
- **[Component Lifecycle](https://angular.io/guide/lifecycle-hooks)**: Hooks do ciclo de vida
- **[ViewEncapsulation](https://angular.io/api/core/ViewEncapsulation)**: Documentação de encapsulação

### Artigos e Tutoriais

- **[Standalone Components Guide](https://angular.io/guide/standalone-components)**: Guia completo
- **[SCAM Pattern](https://angular.io/guide/standalone-components#migrating-existing-libraries)**: Padrão SCAM

---

## Resumo

### Principais Conceitos

- Componentes são classes TypeScript com decorator `@Component`
- Standalone Components são o padrão moderno do Angular
- Templates usam sintaxe especial do Angular para binding
- ViewEncapsulation controla isolamento de estilos
- Ciclo de vida oferece hooks para diferentes momentos
- Projeção de conteúdo permite inserir HTML externo

### Pontos-Chave para Lembrar

- Sempre use `standalone: true` em novos componentes
- Limpe recursos em `ngOnDestroy` para evitar memory leaks
- Use `ng-content` para componentes wrapper reutilizáveis
- ViewEncapsulation.Emulated é o padrão recomendado
- Templates devem ser simples, lógica complexa na classe

### Próximos Passos

- Próxima aula: Data Binding e Diretivas Modernas
- Praticar criando componentes standalone
- Explorar diferentes padrões de template

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

