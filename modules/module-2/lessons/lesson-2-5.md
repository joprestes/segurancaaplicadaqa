---
layout: lesson
title: "Aula 2.5: Comunicação entre Componentes"
slug: comunicacao-componentes
module: module-2
lesson_id: lesson-2-5
duration: "60 minutos"
level: "Intermediário"
prerequisites: 
  - "lesson-2-4"
exercises:
  - 
  - "lesson-2-5-exercise-1"
  - "lesson-2-5-exercise-2"
  - "lesson-2-5-exercise-3"
  - "lesson-2-5-exercise-4"
podcast:
  file: "assets/podcasts/02.5-Comunicação_entre_Componentes_Input_Output_ViewChild.m4a"
  title: "Comunicação entre Componentes - Input, Output, ViewChild"
  description: "Domine todos os padrões de comunicação entre componentes no Angular."
  duration: "45-60 minutos"
---

## Introdução

Nesta aula, você dominará todas as formas de comunicação entre componentes no Angular. Comunicação eficiente entre componentes é essencial para criar aplicações bem estruturadas e manuteníveis. Você aprenderá desde comunicação pai-filho básica até padrões avançados como Master/Detail.

### O que você vai aprender

- Usar @Input() e @Output() para comunicação pai-filho
- Trabalhar com ViewChild e ContentChild
- Usar Template Reference Variables
- Implementar comunicação via serviços
- Aplicar padrões Smart/Dumb Components
- Criar padrão Master/Detail

### Por que isso é importante

Componentes precisam se comunicar para criar aplicações funcionais. Entender diferentes formas de comunicação permite escolher a melhor abordagem para cada situação, criando código mais limpo e manutenível.

---

## Conceitos Teóricos

### @Input() e @Output()

**Definição**: `@Input()` permite passar dados do componente pai para o filho, e `@Output()` permite que o filho emita eventos para o pai.

**Explicação Detalhada**:

@Input():
- Passa dados do pai para o filho
- Pode ter valores padrão
- Suporta setters para lógica customizada
- Type-safe com TypeScript

@Output():
- Emite eventos do filho para o pai
- Usa EventEmitter
- Permite passar dados no evento
- Pai escuta via event binding

**Analogia**:

@Input() é como receber uma carta (dados) do correio. @Output() é como enviar uma carta de volta (evento) para o remetente.

**Visualização**:

```
Parent Component          Child Component
┌──────────────┐         ┌──────────────┐
│              │  @Input │              │
│   [data]  ───┼─────────→│  @Input()    │
│              │         │              │
│              │  @Output│              │
│   (event) ←──┼─────────│  @Output()   │
└──────────────┘         └──────────────┘
```

**Exemplo Prático**:

```typescript
import { Component, Input, Output, EventEmitter } from '@angular/core';

@Component({
  selector: 'app-child',
  standalone: true,
{% raw %}
  template: `
    <div>
      <h3>{{ title }}</h3>
      <p>{{ message }}</p>
      <button (click)="onClick()">Clique aqui</button>
    </div>
  `
{% endraw %}
})
export class ChildComponent {
  @Input() title: string = 'Título Padrão';
  @Input() message: string = '';
  
  @Output() buttonClick = new EventEmitter<string>();
  
  onClick(): void {
    this.buttonClick.emit('Botão foi clicado!');
  }
}

@Component({
  selector: 'app-parent',
  standalone: true,
  imports: [ChildComponent],
{% raw %}
  template: `
    <app-child 
      [title]="childTitle"
      [message]="childMessage"
      (buttonClick)="handleClick($event)">
    </app-child>
  `
{% endraw %}
})
export class ParentComponent {
  childTitle = 'Título do Filho';
  childMessage = 'Mensagem do pai';
  
  handleClick(message: string): void {
    console.log(message);
  }
}
```

---

### ViewChild e ViewChildren

**Definição**: `ViewChild` e `ViewChildren` permitem acessar componentes filhos diretamente no template do componente pai.

**Explicação Detalhada**:

ViewChild:
- Acessa primeiro componente filho
- Retorna ElementRef, Component ou Directive
- Disponível após ngAfterViewInit
- Pode usar template reference variable

ViewChildren:
- Acessa todos componentes filhos
- Retorna QueryList
- Permite iterar sobre filhos
- Reativo a mudanças

**Analogia**:

ViewChild é como ter uma referência direta a um filho específico. Você pode chamá-lo diretamente ao invés de esperar que ele te chame.

**Exemplo Prático**:

```typescript
import { Component, ViewChild, ViewChildren, QueryList, AfterViewInit } from '@angular/core';
import { ChildComponent } from './child.component';

@Component({
  selector: 'app-parent',
  standalone: true,
  imports: [ChildComponent],
{% raw %}
  template: `
    <div>
      <app-child #firstChild></app-child>
      <app-child #secondChild></app-child>
      <button (click)="callChildMethod()">Chamar Método do Filho</button>
    </div>
  `
{% endraw %}
})
export class ParentComponent implements AfterViewInit {
  @ViewChild('firstChild') firstChild!: ChildComponent;
  @ViewChild(ChildComponent) firstChildComponent!: ChildComponent;
  
  @ViewChildren(ChildComponent) children!: QueryList<ChildComponent>;
  
  ngAfterViewInit(): void {
    console.log('First child:', this.firstChild);
    console.log('All children:', this.children.toArray());
  }
  
  callChildMethod(): void {
    this.firstChild.someMethod();
    this.children.forEach(child => child.someMethod());
  }
}
```

---

### ContentChild e ContentChildren

**Definição**: `ContentChild` e `ContentChildren` permitem acessar conteúdo projetado via `ng-content`.

**Explicação Detalhada**:

ContentChild:
- Acessa primeiro conteúdo projetado
- Disponível após ngAfterContentInit
- Útil para componentes wrapper

ContentChildren:
- Acessa todo conteúdo projetado
- Retorna QueryList
- Reativo a mudanças

**Analogia**:

ContentChild é como acessar conteúdo que foi "inserido" no seu componente através de ng-content, como se fosse um slot.

**Exemplo Prático**:

```typescript
import { Component, ContentChild, ContentChildren, QueryList, AfterContentInit } from '@angular/core';

@Component({
  selector: 'app-card-header',
  standalone: true,
{% raw %}
  template: `<ng-content></ng-content>`
})
export class CardHeaderComponent {}

@Component({
  selector: 'app-card',
  standalone: true,
  imports: [CardHeaderComponent],
  template: `
    <div class="card">
      <ng-content select="app-card-header"></ng-content>
      <div class="card-body">
        <ng-content></ng-content>
      </div>
    </div>
  `
{% endraw %}
})
export class CardComponent implements AfterContentInit {
  @ContentChild(CardHeaderComponent) header!: CardHeaderComponent;
  @ContentChildren(CardHeaderComponent) headers!: QueryList<CardHeaderComponent>;
  
  ngAfterContentInit(): void {
    console.log('Header:', this.header);
  }
}
```

---

### Template Reference Variables

**Definição**: Template Reference Variables permitem criar referências a elementos ou componentes no template.

**Explicação Detalhada**:

Template Reference Variables:
- Criadas com `#variableName`
- Acessíveis no template
- Podem referenciar elementos DOM, componentes ou diretivas
- Úteis com ViewChild

**Analogia**:

Template Reference Variables são como dar um nome a algo no template para poder referenciá-lo depois.

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-example',
  standalone: true,
{% raw %}
  template: `
    <input #inputRef type="text" (input)="onInput(inputRef.value)">
    <button (click)="inputRef.focus()">Focar Input</button>
    <app-child #childRef></app-child>
    <button (click)="childRef.someMethod()">Chamar Filho</button>
  `
{% endraw %}
})
export class ExampleComponent {
  onInput(value: string): void {
    console.log('Input value:', value);
  }
}
```

---

### Comunicação via Serviços

**Definição**: Serviços podem ser usados para comunicação entre componentes que não têm relação pai-filho direta.

**Explicação Detalhada**:

Comunicação via serviços:
- Útil para componentes irmãos
- Usa Subject ou BehaviorSubject
- Permite comunicação assíncrona
- Centraliza lógica de comunicação

**Analogia**:

Comunicação via serviços é como usar um sistema de correio central. Componentes enviam e recebem mensagens através de um serviço compartilhado.

**Exemplo Prático**:

{% raw %}
```typescript
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class MessageService {
  private message$ = new BehaviorSubject<string>('');
  
  sendMessage(message: string): void {
    this.message$.next(message);
  }
  
  getMessage(): Observable<string> {
    return this.message$.asObservable();
  }
}

@Component({
  selector: 'app-sender',
  standalone: true,
  template: `
    <input #input type="text">
    <button (click)="send(input.value)">Enviar</button>
  `
{% endraw %}
})
export class SenderComponent {
  constructor(private messageService: MessageService) {}
  
  send(message: string): void {
    this.messageService.sendMessage(message);
  }
}

@Component({
  selector: 'app-receiver',
  standalone: true,
{% raw %}
  template: `<p>{{ message }}</p>`
})
export class ReceiverComponent implements OnInit, OnDestroy {
  message: string = '';
  private subscription?: Subscription;
  
  constructor(private messageService: MessageService) {}
  
  ngOnInit(): void {
    this.subscription = this.messageService.getMessage().subscribe(
      message => this.message = message
    );
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }
}
{% endraw %}
```

---

### Smart e Dumb Components

**Definição**: Padrão de arquitetura onde Smart Components (Container) gerenciam lógica e estado, e Dumb Components (Presentational) apenas exibem dados.

**Explicação Detalhada**:

Smart Components:
- Gerenciam estado e lógica
- Fazem chamadas HTTP
- Passam dados para Dumb Components
- Escutam eventos de Dumb Components

Dumb Components:
- Apenas exibem dados
- Recebem dados via @Input
- Emitem eventos via @Output
- Fáceis de testar e reutilizar

**Analogia**:

Smart Components são como gerentes que tomam decisões e gerenciam recursos. Dumb Components são como funcionários que apenas executam tarefas específicas.

**Visualização**:

```
Smart Component (Container)
┌─────────────────────────┐
│ - Estado                │
│ - Lógica de Negócio     │
│ - HTTP Calls            │
│                         │
│  ┌──────────────────┐   │
│  │ Dumb Component   │   │
│  │ - Apenas UI      │   │
│  │ - @Input/@Output │   │
│  └──────────────────┘   │
└─────────────────────────┘
```

**Exemplo Prático**:

{% raw %}
```typescript
@Component({
  selector: 'app-product-list-smart',
  standalone: true,
  imports: [ProductListDumbComponent],
  template: `
    <app-product-list-dumb
      [products]="products$ | async"
      [loading]="loading"
      (productSelected)="onProductSelected($event)"
      (refresh)="loadProducts()">
    </app-product-list-dumb>
  `
{% endraw %}
})
export class ProductListSmartComponent implements OnInit {
  products$ = new BehaviorSubject<Product[]>([]);
  loading = false;
  
  constructor(private productService: ProductService) {}
  
  ngOnInit(): void {
    this.loadProducts();
  }
  
  loadProducts(): void {
    this.loading = true;
    this.productService.getProducts().subscribe({
      next: (products) => {
        this.products$.next(products);
        this.loading = false;
      }
    });
  }
  
  onProductSelected(product: Product): void {
    console.log('Selected:', product);
  }
}

@Component({
  selector: 'app-product-list-dumb',
  standalone: true,
{% raw %}
  template: `
    @if (loading) {
      <p>Carregando...</p>
    } @else {
      <ul>
        @for (product of products; track product.id) {
          <li (click)="selectProduct(product)">
            {{ product.name }}
          </li>
        }
      </ul>
      <button (click)="refresh.emit()">Atualizar</button>
    }
  `
{% endraw %}
})
export class ProductListDumbComponent {
  @Input() products: Product[] = [];
  @Input() loading: boolean = false;
  @Output() productSelected = new EventEmitter<Product>();
  @Output() refresh = new EventEmitter<void>();
  
  selectProduct(product: Product): void {
    this.productSelected.emit(product);
  }
}
```

---

### Padrão Master/Detail

**Definição**: Padrão onde um componente Master exibe lista e um componente Detail exibe detalhes do item selecionado.

**Explicação Detalhada**:

Master/Detail:
- Master exibe lista de itens
- Detail exibe detalhes do item selecionado
- Comunicação via serviço ou eventos
- Útil para interfaces complexas

**Analogia**:

Master/Detail é como uma lista de contatos (Master) e detalhes do contato selecionado (Detail). Quando você clica em um contato, os detalhes aparecem.

**Exemplo Prático**:

{% raw %}
```typescript
@Injectable({
  providedIn: 'root'
})
export class SelectionService {
  private selectedItem$ = new BehaviorSubject<any>(null);
  
  selectItem(item: any): void {
    this.selectedItem$.next(item);
  }
  
  getSelectedItem(): Observable<any> {
    return this.selectedItem$.asObservable();
  }
}

@Component({
  selector: 'app-master',
  standalone: true,
  template: `
    <ul>
      @for (item of items; track item.id) {
        <li (click)="selectItem(item)" [class.selected]="item.id === selectedId">
          {{ item.name }}
        </li>
      }
    </ul>
  `
{% endraw %}
})
export class MasterComponent {
  items: Item[] = [];
  selectedId: number | null = null;
  
  constructor(private selectionService: SelectionService) {}
  
  selectItem(item: Item): void {
    this.selectedId = item.id;
    this.selectionService.selectItem(item);
  }
}

@Component({
  selector: 'app-detail',
  standalone: true,
{% raw %}
  template: `
    @if (selectedItem) {
      <h2>{{ selectedItem.name }}</h2>
      <p>{{ selectedItem.description }}</p>
    } @else {
      <p>Selecione um item</p>
    }
  `
{% endraw %}
})
export class DetailComponent implements OnInit, OnDestroy {
  selectedItem: Item | null = null;
  private subscription?: Subscription;
  
  constructor(private selectionService: SelectionService) {}
  
  ngOnInit(): void {
    this.subscription = this.selectionService.getSelectedItem().subscribe(
      item => this.selectedItem = item
    );
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Comunicação Completa

**Contexto**: Criar sistema de comunicação completo usando todas as técnicas.

**Código**:

```typescript
@Component({
  selector: 'app-parent',
  standalone: true,
  imports: [ChildComponent],
{% raw %}
  template: `
    <app-child 
      [data]="parentData"
      (dataChange)="handleDataChange($event)">
    </app-child>
    <p>Dados recebidos: {{ receivedData }}</p>
  `
{% endraw %}
})
export class ParentComponent {
  parentData = 'Dados do pai';
  receivedData: string = '';
  
  handleDataChange(data: string): void {
    this.receivedData = data;
  }
}

@Component({
  selector: 'app-child',
  standalone: true,
{% raw %}
  template: `
    <div>
      <p>Dados recebidos: {{ data }}</p>
      <input [(ngModel)]="inputValue">
      <button (click)="sendData()">Enviar</button>
    </div>
  `
{% endraw %}
})
export class ChildComponent {
  @Input() data: string = '';
  @Output() dataChange = new EventEmitter<string>();
  inputValue: string = '';
  
  sendData(): void {
    this.dataChange.emit(this.inputValue);
  }
}
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use @Input/@Output para comunicação pai-filho**
   - **Por quê**: Simples e direto
   - **Exemplo**: `@Input() data`, `@Output() change`

2. **Use serviços para componentes irmãos**
   - **Por quê**: Evita prop drilling
   - **Exemplo**: BehaviorSubject em serviço

3. **Separe Smart e Dumb Components**
   - **Por quê**: Melhor testabilidade e reutilização
   - **Exemplo**: Container e Presentational

4. **Use ViewChild apenas quando necessário**
   - **Por quê**: Cria acoplamento
   - **Exemplo**: Quando precisa chamar método do filho

### ❌ Anti-padrões Comuns

1. **Não use ViewChild para comunicação simples**
   - **Problema**: Cria acoplamento desnecessário
   - **Solução**: Use @Input/@Output

2. **Não faça prop drilling excessivo**
   - **Problema**: Código difícil de manter
   - **Solução**: Use serviços ou state management

3. **Não misture lógica e apresentação**
   - **Problema**: Componentes difíceis de testar
   - **Solução**: Separe Smart e Dumb Components

---

## Exercícios Práticos

### Exercício 1: @Input e @Output Básicos (Básico)

**Objetivo**: Criar comunicação pai-filho básica

**Descrição**: 
Crie componente filho que recebe dados via @Input e emite eventos via @Output.

**Arquivo**: `exercises/exercise-2-5-1-input-output.md`

---

### Exercício 2: ViewChild e ContentChild (Intermediário)

**Objetivo**: Trabalhar com ViewChild e ContentChild

**Descrição**:
Crie componente que usa ViewChild para acessar filho e ContentChild para conteúdo projetado.

**Arquivo**: `exercises/exercise-2-5-2-viewchild-contentchild.md`

---

### Exercício 3: Comunicação via Serviços (Intermediário)

**Objetivo**: Implementar comunicação entre componentes irmãos

**Descrição**:
Crie serviço que permite comunicação entre componentes que não têm relação direta.

**Arquivo**: `exercises/exercise-2-5-3-comunicacao-servicos.md`

---

### Exercício 4: Padrão Master/Detail Completo (Avançado)

**Objetivo**: Criar padrão Master/Detail completo

**Descrição**:
Crie aplicação Master/Detail completa usando todas as técnicas de comunicação aprendidas.

**Arquivo**: `exercises/exercise-2-5-4-master-detail.md`

---

## Referências Externas

### Documentação Oficial

- **[Component Interaction](https://angular.io/guide/component-interaction)**: Guia oficial
- **[ViewChild](https://angular.io/api/core/ViewChild)**: Documentação ViewChild
- **[Input/Output](https://angular.io/api/core/Input)**: Documentação @Input/@Output

---

## Resumo

### Principais Conceitos

- @Input() passa dados do pai para o filho
- @Output() emite eventos do filho para o pai
- ViewChild acessa componentes filhos
- ContentChild acessa conteúdo projetado
- Serviços permitem comunicação entre componentes irmãos
- Smart/Dumb Components separam lógica e apresentação
- Master/Detail é padrão comum para listas e detalhes

### Pontos-Chave para Lembrar

- Use @Input/@Output para comunicação pai-filho
- Use serviços para componentes irmãos
- Separe Smart e Dumb Components
- ViewChild apenas quando necessário
- Escolha a técnica apropriada para cada situação

### Próximos Passos

- Próximo módulo: Programação Reativa e Estado
- Praticar criando componentes comunicativos
- Explorar padrões avançados de comunicação

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

**Aula Anterior**: [Aula 2.4: HTTP Client e Interceptors](./lesson-2-4-http-client.md)  
**Próxima Aula**: [Aula 3.1: RxJS e Programação Reativa](../modules/module-3-programacao-reativa-estado.md)  
**Voltar ao Módulo**: [Módulo 2: Desenvolvimento Intermediário](../modules/module-2-desenvolvimento-intermediario.md)

