---
layout: lesson
title: "Aula 1.4: Data Binding e Diretivas Modernas"
slug: data-binding
module: module-1
lesson_id: lesson-1-4
duration: "120 minutos"
level: "Básico"
prerequisites: 
  - "lesson-1-3"
exercises:
  - 
  - "lesson-1-4-exercise-1"
  - "lesson-1-4-exercise-2"
  - "lesson-1-4-exercise-3"
  - "lesson-1-4-exercise-4"
  - "lesson-1-4-exercise-5"
  - "lesson-1-4-exercise-6"
  - "lesson-1-4-exercise-7"
podcast:
  file: "assets/podcasts/01.3e4-Fundacao_Angular_Tipagem_Encapsulamento_e_Generics.m4a"
  image: "assets/images/podcasts/01.3e4-Fundacao_Angular_Tipagem_Encapsulamento_e_Generics.png"
  title: "Componentes Standalone, Templates, Data Binding e Diretivas Modernas"
  description: "Mergulhe profundamente nos componentes standalone do Angular."
  duration: "60-75 minutos"
permalink: /modules/fundamentos-acelerados/lessons/data-binding/
---

## Introdução

Nesta aula, você dominará todas as formas de data binding do Angular e aprenderá a usar diretivas modernas de forma eficiente. Data binding é o coração da comunicação entre componente e template no Angular.

### O que você vai aprender

- Interpolação e suas variações
- Property Binding avançado
- Event Binding e manipulação de eventos
- Two-Way Data Binding com ngModel
- Binding de classes e estilos dinâmicos
- Diretivas estruturais (*ngIf, *ngFor, *ngSwitch)
- Diretivas de atributo ([ngClass], [ngStyle])
- Criação de diretivas customizadas

### Por que isso é importante

Data binding é fundamental no Angular. Sem entender completamente como dados fluem entre componente e template, você não conseguirá criar aplicações interativas eficientes. Diretivas são ferramentas poderosas para manipular o DOM de forma declarativa.

---

## Conceitos Teóricos

{% raw %}
### Interpolação ({{ }})
{% endraw %}

**Definição**: Interpolação é a forma mais simples de exibir dados do componente no template usando a sintaxe `{{ expression }}`.

**Explicação Detalhada**:

Interpolação converte expressões em strings e as exibe no template. Suporta:
- Variáveis simples: `{{ name }}`
{% raw %}
- Expressões: `{{ 1 + 1 }}`
- Chamadas de método: `{{ getFullName() }}`
{% endraw %}
- Propriedades aninhadas: `{{ user.address.city }}`

**Analogia**:

{% raw %}
Interpolação é como preencher um formulário em branco. O template é o formulário, e `{{ }}` são os campos que serão preenchidos com dados do componente.
{% endraw %}

**Visualização**:

{% raw %}
```
Component                    Template
┌────────────────┐            ┌─────────────┐
│ name = "João"  │  ────────→ │ {{ name }}  │
│ age = 30       │  ────────→ │ {{ age }}   │
└────────────────┘            └─────────────┘
                              ↓
                          "João"
                          "30"
```
{% endraw %}

**Exemplo Prático**:

export class UserComponent {
  userName: string = 'João Silva';
  userAge: number = 30;
  isActive: boolean = true;
  
  getDisplayName(): string {
    return `${this.userName} (${this.userAge})`;
  }
}
```typescript
export class UserComponent {
  userName: string = 'João Silva';
  userAge: number = 30;
  isActive: boolean = true;
  
  getDisplayName(): string {
    return `${this.userName} (${this.userAge})`;
  }
}
```

{% raw %}
<h1>{{ userName }}</h1>
<p>Idade: {{ userAge }}</p>
<p>Status: {{ isActive ? 'Ativo' : 'Inativo' }}</p>
<p>{{ getDisplayName() }}</p>
```html
<h1>{{ userName }}</h1>
<p>Idade: {{ userAge }}</p>
<p>Status: {{ isActive ? 'Ativo' : 'Inativo' }}</p>
<p>{{ getDisplayName() }}</p>
```
{% endraw %}

---

### Property Binding ([property])

**Definição**: Property Binding permite definir propriedades de elementos HTML ou diretivas usando a sintaxe `[property]="expression"`.

**Explicação Detalhada**:

Property binding é unidirecional (componente → template) e é usado para:
- Propriedades HTML: `[src]`, `[href]`, `[disabled]`
- Propriedades de componentes: `[user]`, `[config]`
- Propriedades de diretivas: `[ngClass]`, `[ngStyle]`

**Analogia**:

Property binding é como configurar um aparelho. Você define as configurações (propriedades) e o aparelho funciona de acordo com essas configurações.

**Visualização**:

Component                    Template
┌─────────────┐            ┌─────────────┐
│ imageUrl    │  ────────→ │ [src]="..." │
│ isDisabled  │  ────────→ │ [disabled]  │
└─────────────┘            └─────────────┘
```
Component                    Template
┌─────────────┐            ┌─────────────┐
│ imageUrl    │  ────────→ │ [src]="..." │
│ isDisabled  │  ────────→ │ [disabled]  │
└─────────────┘            └─────────────┘
```

**Exemplo Prático**:

export class ImageComponent {
  imageUrl: string = 'https://example.com/image.jpg';
  isDisabled: boolean = false;
  buttonText: string = 'Clique aqui';
}
```typescript
export class ImageComponent {
  imageUrl: string = 'https://example.com/image.jpg';
  isDisabled: boolean = false;
  buttonText: string = 'Clique aqui';
}
```

<img [src]="imageUrl" [alt]="buttonText">
<button [disabled]="isDisabled">{{ buttonText }}</button>
<input [value]="buttonText" [readonly]="isDisabled">
```html
<img [src]="imageUrl" [alt]="buttonText">
<button [disabled]="isDisabled">{{ buttonText }}</button>
<input [value]="buttonText" [readonly]="isDisabled">
```

---

### Event Binding ((event))

**Definição**: Event Binding permite responder a eventos do DOM usando a sintaxe `(event)="handler()"`.

**Explicação Detalhada**:

Event binding é unidirecional (template → componente) e captura eventos como:
- Eventos do mouse: `(click)`, `(mouseenter)`, `(mouseleave)`
- Eventos do teclado: `(keyup)`, `(keydown)`, `(keypress)`
- Eventos de formulário: `(submit)`, `(change)`, `(input)`
- Eventos customizados: `(customEvent)`

**Analogia**:

Event binding é como instalar um botão de emergência. Quando alguém pressiona o botão (evento), uma ação é executada (handler).

**Visualização**:

Template                    Component
┌─────────────┐            ┌─────────────┐
│ (click)     │  ────────→ │ onClick()   │
│ (keyup)     │  ────────→ │ onKeyUp()   │
└─────────────┘            └─────────────┘
```
Template                    Component
┌─────────────┐            ┌─────────────┐
│ (click)     │  ────────→ │ onClick()   │
│ (keyup)     │  ────────→ │ onKeyUp()   │
└─────────────┘            └─────────────┘
```

**Exemplo Prático**:

export class ButtonComponent {
  clickCount: number = 0;
  
  onClick(): void {
    this.clickCount++;
    console.log('Botão clicado!');
  }
  
  onKeyUp(event: KeyboardEvent): void {
    console.log('Tecla pressionada:', event.key);
  }
  
  onMouseEnter(): void {
    console.log('Mouse entrou');
  }
}
```typescript
export class ButtonComponent {
  clickCount: number = 0;
  
  onClick(): void {
    this.clickCount++;
    console.log('Botão clicado!');
  }
  
  onKeyUp(event: KeyboardEvent): void {
    console.log('Tecla pressionada:', event.key);
  }
  
  onMouseEnter(): void {
    console.log('Mouse entrou');
  }
}
```

<button (click)="onClick()">Clique aqui</button>
<input (keyup)="onKeyUp($event)" placeholder="Digite algo">
<div (mouseenter)="onMouseEnter()">Passe o mouse</div>
<p>Cliques: {{ clickCount }}</p>
```html
<button (click)="onClick()">Clique aqui</button>
<input (keyup)="onKeyUp($event)" placeholder="Digite algo">
<div (mouseenter)="onMouseEnter()">Passe o mouse</div>
<p>Cliques: {{ clickCount }}</p>
```

---

### Two-Way Data Binding ([(ngModel)])

**Definição**: Two-Way Data Binding combina property binding e event binding para criar comunicação bidirecional usando `[(ngModel)]="property"`.

**Explicação Detalhada**:

Two-way binding é uma combinação de:
- Property binding: `[ngModel]="property"`
- Event binding: `(ngModelChange)="property = $event"`

Isso cria sincronização automática entre template e componente.

**Analogia**:

Two-way binding é como um espelho mágico que reflete e modifica simultaneamente. Quando você muda algo no template, o componente atualiza, e vice-versa.

**Visualização**:

Component  ←──────────────→  Template
┌─────────┐                ┌─────────────┐
│ name    │  ←───────────→ │ [(ngModel)] │
└─────────┘                └─────────────┘
```
Component  ←──────────────→  Template
┌─────────┐                ┌─────────────┐
│ name    │  ←───────────→ │ [(ngModel)] │
└─────────┘                └─────────────┘
```

**Exemplo Prático**:

import { FormsModule } from '@angular/forms';

export class FormComponent {
  userName: string = '';
  userEmail: string = '';
  isSubscribed: boolean = false;
}
```typescript
import { FormsModule } from '@angular/forms';

export class FormComponent {
  userName: string = '';
  userEmail: string = '';
  isSubscribed: boolean = false;
}
```

<input [(ngModel)]="userName" placeholder="Nome">
<input [(ngModel)]="userEmail" placeholder="Email">
<input type="checkbox" [(ngModel)]="isSubscribed"> Inscrever-se

<p>Nome: {{ userName }}</p>
<p>Email: {{ userEmail }}</p>
<p>Inscrito: {{ isSubscribed }}</p>
```html
<input [(ngModel)]="userName" placeholder="Nome">
<input [(ngModel)]="userEmail" placeholder="Email">
<input type="checkbox" [(ngModel)]="isSubscribed"> Inscrever-se

<p>Nome: {{ userName }}</p>
<p>Email: {{ userEmail }}</p>
<p>Inscrito: {{ isSubscribed }}</p>
```

---

### Binding de Classes e Estilos

**Definição**: Angular oferece formas especiais de binding para classes CSS e estilos inline usando `[ngClass]` e `[ngStyle]`.

**Explicação Detalhada**:

**ngClass** aceita:
- String: `[ngClass]="'class1 class2'"`
- Array: `[ngClass]="['class1', 'class2']"`
- Object: `[ngClass]="{active: isActive, disabled: isDisabled}"`

**ngStyle** aceita:
- Object: `[ngStyle]="{color: textColor, fontSize: fontSize + 'px'}"`

**Analogia**:

Binding de classes é como trocar de roupa dinamicamente. Você pode adicionar ou remover roupas (classes) baseado em condições.

**Exemplo Prático**:

export class StyledComponent {
  isActive: boolean = true;
  isDisabled: boolean = false;
  textColor: string = 'blue';
  fontSize: number = 16;
  
  getClasses(): {[key: string]: boolean} {
    return {
      'active': this.isActive,
      'disabled': this.isDisabled,
      'highlight': this.isActive && !this.isDisabled
    };
  }
}
```typescript
export class StyledComponent {
  isActive: boolean = true;
  isDisabled: boolean = false;
  textColor: string = 'blue';
  fontSize: number = 16;
  
  getClasses(): {[key: string]: boolean} {
    return {
      'active': this.isActive,
      'disabled': this.isDisabled,
      'highlight': this.isActive && !this.isDisabled
    };
  }
}
```

<div [ngClass]="getClasses()">Conteúdo</div>
<div [ngClass]="{'active': isActive, 'error': !isActive}">Status</div>
<div [ngStyle]="{'color': textColor, 'font-size': fontSize + 'px'}">Texto</div>
<div [style.color]="textColor" [style.font-size.px]="fontSize">Texto 2</div>
```html
<div [ngClass]="getClasses()">Conteúdo</div>
<div [ngClass]="{'active': isActive, 'error': !isActive}">Status</div>
<div [ngStyle]="{'color': textColor, 'font-size': fontSize + 'px'}">Texto</div>
<div [style.color]="textColor" [style.font-size.px]="fontSize">Texto 2</div>
```

---

### Diretivas Estruturais

**Definição**: Diretivas estruturais modificam a estrutura do DOM adicionando, removendo ou manipulando elementos usando `*` prefix.

**Explicação Detalhada**:

Principais diretivas estruturais:

1. **\*ngIf**: Adiciona/remove elementos baseado em condição
2. **\*ngFor**: Repete elementos para cada item em uma lista
3. **\*ngSwitch**: Seleciona um elemento de múltiplas opções

**Analogia**:

Diretivas estruturais são como instruções de construção. `*ngIf` decide se constrói ou não, `*ngFor` constrói múltiplas cópias, `*ngSwitch` escolhe qual construir.

**Visualização**:

*ngIf                    *ngFor
┌─────────┐            ┌─────────┐
│ if true │  → Exibe   │ for item│  → Repete
│ if false│  → Remove  │ in list │     elemento
└─────────┘            └─────────┘
```
*ngIf                    *ngFor
┌─────────┐            ┌─────────┐
│ if true │  → Exibe   │ for item│  → Repete
│ if false│  → Remove  │ in list │     elemento
└─────────┘            └─────────┘
```

**Exemplo Prático**:

export class ListComponent {
  items: string[] = ['Item 1', 'Item 2', 'Item 3'];
  showList: boolean = true;
  selectedValue: string = 'option1';
}
```typescript
export class ListComponent {
  items: string[] = ['Item 1', 'Item 2', 'Item 3'];
  showList: boolean = true;
  selectedValue: string = 'option1';
}
```

{% raw %}
<div *ngIf="showList">
  <ul>
    <li *ngFor="let item of items; let i = index">
      {{ i + 1 }}. {{ item }}
    </li>
  </ul>
</div>

<div [ngSwitch]="selectedValue">
  <p *ngSwitchCase="'option1'">Opção 1 selecionada</p>
  <p *ngSwitchCase="'option2'">Opção 2 selecionada</p>
  <p *ngSwitchDefault>Nenhuma opção selecionada</p>
</div>
{% endraw %}
{% raw %}
```html
<div *ngIf="showList">
  <ul>
    <li *ngFor="let item of items; let i = index">
      {{ i + 1 }}. {{ item }}
    </li>
  </ul>
</div>

<div [ngSwitch]="selectedValue">
  <p *ngSwitchCase="'option1'">Opção 1 selecionada</p>
  <p *ngSwitchCase="'option2'">Opção 2 selecionada</p>
  <p *ngSwitchDefault>Nenhuma opção selecionada</p>
</div>
```
{% endraw %}

---

### Diretivas de Atributo

**Definição**: Diretivas de atributo modificam a aparência ou comportamento de elementos existentes sem alterar a estrutura do DOM.

**Explicação Detalhada**:

Diretivas de atributo principais:

1. **[ngClass]**: Adiciona/remove classes CSS dinamicamente
2. **[ngStyle]**: Aplica estilos inline dinamicamente
3. **[ngModel]**: Two-way binding para formulários

**Exemplo Prático**:

export class AttributeDirectiveComponent {
  isHighlighted: boolean = false;
  currentColor: string = 'blue';
  
  toggleHighlight(): void {
    this.isHighlighted = !this.isHighlighted;
  }
}
```typescript
export class AttributeDirectiveComponent {
  isHighlighted: boolean = false;
  currentColor: string = 'blue';
  
  toggleHighlight(): void {
    this.isHighlighted = !this.isHighlighted;
  }
}
```

<div 
  [ngClass]="{'highlight': isHighlighted, 'active': true}"
  [ngStyle]="{'background-color': currentColor}">
  Conteúdo estilizado
</div>
```html
<div 
  [ngClass]="{'highlight': isHighlighted, 'active': true}"
  [ngStyle]="{'background-color': currentColor}">
  Conteúdo estilizado
</div>
```

---

### Criando Diretivas Customizadas

**Definição**: Você pode criar suas próprias diretivas para adicionar comportamento customizado a elementos.

**Explicação Detalhada**:

Diretivas customizadas podem:
- Modificar aparência com `@HostBinding`
- Responder a eventos com `@HostListener`
- Receber dados com `@Input`
- Acessar elemento com `ElementRef`

**Analogia**:

Diretivas customizadas são como extensões personalizadas. Você cria ferramentas específicas para suas necessidades.

**Exemplo Prático**:

import { Directive, HostBinding, HostListener, Input } from '@angular/core';

@Directive({
  selector: '[appHighlight]',
  standalone: true
})
export class HighlightDirective {
  @Input() appHighlight: string = 'yellow';
  @Input() defaultColor: string = 'transparent';
  
  @HostBinding('style.backgroundColor') backgroundColor: string = '';
  
  ngOnInit(): void {
    this.backgroundColor = this.defaultColor;
  }
  
  @HostListener('mouseenter') onMouseEnter(): void {
    this.backgroundColor = this.appHighlight;
  }
  
  @HostListener('mouseleave') onMouseLeave(): void {
    this.backgroundColor = this.defaultColor;
  }
}
```typescript
import { Directive, HostBinding, HostListener, Input } from '@angular/core';

@Directive({
  selector: '[appHighlight]',
  standalone: true
})
export class HighlightDirective {
  @Input() appHighlight: string = 'yellow';
  @Input() defaultColor: string = 'transparent';
  
  @HostBinding('style.backgroundColor') backgroundColor: string = '';
  
  ngOnInit(): void {
    this.backgroundColor = this.defaultColor;
  }
  
  @HostListener('mouseenter') onMouseEnter(): void {
    this.backgroundColor = this.appHighlight;
  }
  
  @HostListener('mouseleave') onMouseLeave(): void {
    this.backgroundColor = this.defaultColor;
  }
}
```

<p [appHighlight]="'yellow'" [defaultColor]="'lightblue'">
  Passe o mouse sobre mim
</p>
```html
<p [appHighlight]="'yellow'" [defaultColor]="'lightblue'">
  Passe o mouse sobre mim
</p>
```

---

## Exemplos Práticos Completos

### Exemplo 1: Formulário com Two-Way Binding

**Contexto**: Criar formulário completo com validação e two-way binding.

**Código**:

{% raw %}
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

interface User {
  name: string;
  email: string;
  age: number;
  subscribe: boolean;
}

@Component({
  selector: 'app-user-form',
  standalone: true,
  imports: [FormsModule, CommonModule],
  template: `
    <form (ngSubmit)="onSubmit()">
      <div>
        <label>Nome:</label>
        <input [(ngModel)]="user.name" name="name" required>
      </div>
      
      <div>
        <label>Email:</label>
        <input [(ngModel)]="user.email" type="email" name="email" required>
      </div>
      
      <div>
        <label>Idade:</label>
        <input [(ngModel)]="user.age" type="number" name="age" min="18">
      </div>
      
      <div>
        <label>
          <input type="checkbox" [(ngModel)]="user.subscribe" name="subscribe">
          Receber newsletter
        </label>
      </div>
      
      <button type="submit" [disabled]="!isValid()">Enviar</button>
    </form>
    
    <div *ngIf="submitted">
      <h3>Dados enviados:</h3>
      <pre>{{ user | json }}</pre>
    </div>
  `
})
export class UserFormComponent {
  user: User = {
    name: '',
    email: '',
    age: 18,
    subscribe: false
  };
  
  submitted: boolean = false;
  
  isValid(): boolean {
    return this.user.name.length > 0 && 
           this.user.email.includes('@') && 
           this.user.age >= 18;
  }
  
  onSubmit(): void {
    this.submitted = true;
    console.log('Formulário enviado:', this.user);
  }
}
```typescript
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

interface User {
  name: string;
  email: string;
  age: number;
  subscribe: boolean;
}

@Component({
  selector: 'app-user-form',
  standalone: true,
  imports: [FormsModule, CommonModule],
  template: `
    <form (ngSubmit)="onSubmit()">
      <div>
        <label>Nome:</label>
        <input [(ngModel)]="user.name" name="name" required>
      </div>
      
      <div>
        <label>Email:</label>
        <input [(ngModel)]="user.email" type="email" name="email" required>
      </div>
      
      <div>
        <label>Idade:</label>
        <input [(ngModel)]="user.age" type="number" name="age" min="18">
      </div>
      
      <div>
        <label>
          <input type="checkbox" [(ngModel)]="user.subscribe" name="subscribe">
          Receber newsletter
        </label>
      </div>
      
      <button type="submit" [disabled]="!isValid()">Enviar</button>
    </form>
    
    <div *ngIf="submitted">
      <h3>Dados enviados:</h3>
      <pre>{{ user | json }}</pre>
    </div>
  `
})
export class UserFormComponent {
  user: User = {
    name: '',
    email: '',
    age: 18,
    subscribe: false
  };
  
  submitted: boolean = false;
  
  isValid(): boolean {
    return this.user.name.length > 0 && 
           this.user.email.includes('@') && 
           this.user.age >= 18;
  }
  
  onSubmit(): void {
    this.submitted = true;
    console.log('Formulário enviado:', this.user);
  }
}
```
{% endraw %}

---

### Exemplo 2: Lista Interativa com Diretivas

**Contexto**: Criar lista interativa com filtros e ações.

**Código**:

{% raw %}
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Task {
  id: number;
  title: string;
  completed: boolean;
  priority: 'low' | 'medium' | 'high';
}

@Component({
  selector: 'app-task-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="task-list">
      <input 
        [(ngModel)]="searchTerm" 
        placeholder="Buscar tarefas..."
        (input)="filterTasks()">
      
      <div class="filters">
        <button 
          *ngFor="let filter of filters"
          [class.active]="activeFilter === filter"
          (click)="setFilter(filter)">
          {{ filter }}
        </button>
      </div>
      
      <ul>
        <li 
          *ngFor="let task of filteredTasks; trackBy: trackByTaskId"
          [ngClass]="{
            'completed': task.completed,
            'high-priority': task.priority === 'high',
            'medium-priority': task.priority === 'medium',
            'low-priority': task.priority === 'low'
          }"
          (click)="toggleTask(task.id)">
          <span>{{ task.title }}</span>
          <span [ngSwitch]="task.priority">
            <span *ngSwitchCase="'high'" class="badge high">Alta</span>
            <span *ngSwitchCase="'medium'" class="badge medium">Média</span>
            <span *ngSwitchDefault class="badge low">Baixa</span>
          </span>
        </li>
      </ul>
      
      <p *ngIf="filteredTasks.length === 0">Nenhuma tarefa encontrada</p>
    </div>
  `
})
export class TaskListComponent {
  tasks: Task[] = [
    { id: 1, title: 'Tarefa 1', completed: false, priority: 'high' },
    { id: 2, title: 'Tarefa 2', completed: true, priority: 'medium' },
    { id: 3, title: 'Tarefa 3', completed: false, priority: 'low' }
  ];
  
  filteredTasks: Task[] = [];
  searchTerm: string = '';
  activeFilter: string = 'all';
  filters: string[] = ['all', 'active', 'completed'];
  
  ngOnInit(): void {
    this.filterTasks();
  }
  
  filterTasks(): void {
    let filtered = this.tasks;
    
    if (this.searchTerm) {
      filtered = filtered.filter(t => 
        t.title.toLowerCase().includes(this.searchTerm.toLowerCase())
      );
    }
    
    if (this.activeFilter === 'active') {
      filtered = filtered.filter(t => !t.completed);
    } else if (this.activeFilter === 'completed') {
      filtered = filtered.filter(t => t.completed);
    }
    
    this.filteredTasks = filtered;
  }
  
  setFilter(filter: string): void {
    this.activeFilter = filter;
    this.filterTasks();
  }
  
  toggleTask(id: number): void {
    const task = this.tasks.find(t => t.id === id);
    if (task) {
      task.completed = !task.completed;
      this.filterTasks();
    }
  }
  
  trackByTaskId(index: number, task: Task): number {
    return task.id;
  }
}
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Task {
  id: number;
  title: string;
  completed: boolean;
  priority: 'low' | 'medium' | 'high';
}

@Component({
  selector: 'app-task-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="task-list">
      <input 
        [(ngModel)]="searchTerm" 
        placeholder="Buscar tarefas..."
        (input)="filterTasks()">
      
      <div class="filters">
        <button 
          *ngFor="let filter of filters"
          [class.active]="activeFilter === filter"
          (click)="setFilter(filter)">
          {{ filter }}
        </button>
      </div>
      
      <ul>
        <li 
          *ngFor="let task of filteredTasks; trackBy: trackByTaskId"
          [ngClass]="{
            'completed': task.completed,
            'high-priority': task.priority === 'high',
            'medium-priority': task.priority === 'medium',
            'low-priority': task.priority === 'low'
          }"
          (click)="toggleTask(task.id)">
          <span>{{ task.title }}</span>
          <span [ngSwitch]="task.priority">
            <span *ngSwitchCase="'high'" class="badge high">Alta</span>
            <span *ngSwitchCase="'medium'" class="badge medium">Média</span>
            <span *ngSwitchDefault class="badge low">Baixa</span>
          </span>
        </li>
      </ul>
      
      <p *ngIf="filteredTasks.length === 0">Nenhuma tarefa encontrada</p>
    </div>
  `
})
export class TaskListComponent {
  tasks: Task[] = [
    { id: 1, title: 'Tarefa 1', completed: false, priority: 'high' },
    { id: 2, title: 'Tarefa 2', completed: true, priority: 'medium' },
    { id: 3, title: 'Tarefa 3', completed: false, priority: 'low' }
  ];
  
  filteredTasks: Task[] = [];
  searchTerm: string = '';
  activeFilter: string = 'all';
  filters: string[] = ['all', 'active', 'completed'];
  
  ngOnInit(): void {
    this.filterTasks();
  }
  
  filterTasks(): void {
    let filtered = this.tasks;
    
    if (this.searchTerm) {
      filtered = filtered.filter(t => 
        t.title.toLowerCase().includes(this.searchTerm.toLowerCase())
      );
    }
    
    if (this.activeFilter === 'active') {
      filtered = filtered.filter(t => !t.completed);
    } else if (this.activeFilter === 'completed') {
      filtered = filtered.filter(t => t.completed);
    }
    
    this.filteredTasks = filtered;
  }
  
  setFilter(filter: string): void {
    this.activeFilter = filter;
    this.filterTasks();
  }
  
  toggleTask(id: number): void {
    const task = this.tasks.find(t => t.id === id);
    if (task) {
      task.completed = !task.completed;
      this.filterTasks();
    }
  }
  
  trackByTaskId(index: number, task: Task): number {
    return task.id;
  }
}
```
{% endraw %}

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use trackBy com *ngFor**
   - **Por quê**: Melhora performance ao evitar re-renderizações desnecessárias
   - **Exemplo**: `*ngFor="let item of items; trackBy: trackById"`

2. **Evite lógica complexa no template**
   - **Por quê**: Dificulta manutenção e testes
   - **Exemplo**: Mova lógica para métodos ou getters

3. **Use property binding para propriedades boolean**
   - **Por quê**: Mais claro e type-safe
   - **Exemplo**: `[disabled]="isDisabled"` ao invés de `disabled="{{isDisabled}}"`

4. **Combine diretivas quando necessário**
   - **Por quê**: Cria comportamentos complexos de forma declarativa
   - **Exemplo**: `*ngFor` com `*ngIf` em elementos diferentes

### ❌ Anti-padrões Comuns

1. **Não use interpolação para propriedades boolean**
   - **Problema**: Converte para string "true"/"false"
   - **Solução**: Use property binding `[disabled]="isDisabled"`

2. **Não esqueça trackBy em listas grandes**
   - **Problema**: Performance ruim com muitas iterações
   - **Solução**: Sempre use `trackBy` em `*ngFor`

3. **Não misture *ngIf e *ngFor no mesmo elemento**
   - **Problema**: Angular não permite
   - **Solução**: Use `<ng-container>` ou elementos separados

---

## Exercícios Práticos

### Exercício 1: Formulário com Two-Way Binding (Básico)

**Objetivo**: Criar formulário usando two-way binding

**Descrição**: 
Crie um formulário de contato com campos nome, email e mensagem usando `[(ngModel)]`. Exiba os dados em tempo real abaixo do formulário.

**Arquivo**: `exercises/exercise-1-4-1-two-way-binding.md`

---

### Exercício 2: Lista com *ngFor e Filtros (Básico)

**Objetivo**: Trabalhar com diretivas estruturais

**Descrição**:
Crie uma lista de produtos usando `*ngFor` com filtros por categoria. Use `trackBy` para otimização.

**Arquivo**: `exercises/exercise-1-4-2-ngfor-filtros.md`

---

### Exercício 3: Classes Dinâmicas com ngClass (Intermediário)

**Objetivo**: Aplicar classes CSS dinamicamente

**Descrição**:
Crie um componente de status que muda classes CSS baseado em diferentes estados (ativo, inativo, pendente, erro).

**Arquivo**: `exercises/exercise-1-4-3-ngclass-dinamico.md`

---

### Exercício 4: Estilos Dinâmicos com ngStyle (Intermediário)

**Objetivo**: Aplicar estilos inline dinamicamente

**Descrição**:
Crie um seletor de cores que aplica estilos dinamicamente usando `[ngStyle]`. Permita escolher cor de fundo, texto e tamanho da fonte.

**Arquivo**: `exercises/exercise-1-4-4-ngstyle-dinamico.md`

---

### Exercício 5: Diretiva Customizada Highlight (Avançado)

**Objetivo**: Criar diretiva customizada

**Descrição**:
Crie uma diretiva `appHighlight` que muda cor de fundo ao passar o mouse. A diretiva deve aceitar cor via `@Input`.

**Arquivo**: `exercises/exercise-1-4-5-diretiva-customizada.md`

---

### Exercício 6: Componente Interativo Completo (Avançado)

**Objetivo**: Combinar todas as técnicas aprendidas

**Descrição**:
Crie um componente de dashboard que usa interpolação, property binding, event binding, two-way binding, diretivas estruturais e de atributo.

**Arquivo**: `exercises/exercise-1-4-6-componente-interativo.md`

---

### Exercício 7: Formulário Avançado com Validação Visual (Avançado)

**Objetivo**: Aplicar validação visual com binding

**Descrição**:
Crie formulário com validação que muda classes e estilos baseado no estado de validação dos campos (válido, inválido, touched, dirty).

**Arquivo**: `exercises/exercise-1-4-7-validacao-visual.md`

---

## Referências Externas

### Documentação Oficial

- **[Template Syntax](https://angular.io/guide/template-syntax)**: Guia completo de sintaxe de templates
- **[Property Binding](https://angular.io/guide/property-binding)**: Documentação de property binding
- **[Event Binding](https://angular.io/guide/event-binding)**: Documentação de event binding
- **[Two-Way Binding](https://angular.io/guide/two-way-binding)**: Documentação de two-way binding
- **[Structural Directives](https://angular.io/guide/structural-directives)**: Diretivas estruturais
- **[Attribute Directives](https://angular.io/guide/attribute-directives)**: Diretivas de atributo

---

## Resumo

### Principais Conceitos

- Interpolação exibe dados do componente no template
- Property binding define propriedades de elementos
- Event binding responde a eventos do DOM
- Two-way binding sincroniza template e componente
- Diretivas estruturais modificam estrutura do DOM
- Diretivas de atributo modificam aparência/comportamento
- Diretivas customizadas adicionam comportamento específico

### Pontos-Chave para Lembrar

- Use `trackBy` em `*ngFor` para melhor performance
- Evite lógica complexa no template
- Two-way binding requer `FormsModule`
- Diretivas customizadas são poderosas para reutilização
- Combine diferentes tipos de binding para criar UIs interativas

### Próximos Passos

- Próxima aula: Control Flow e Pipes
- Praticar criando componentes interativos
- Explorar diretivas customizadas avançadas

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

**Aula Anterior**: [Aula 1.3: Componentes Standalone e Templates](./lesson-1-3-componentes-standalone.md)  
**Próxima Aula**: [Aula 1.5: Control Flow e Pipes](./lesson-1-5-control-flow-pipes.md)  
**Voltar ao Módulo**: [Módulo 1: Fundamentos Acelerados](../modules/module-1-fundamentos-acelerados.md)

