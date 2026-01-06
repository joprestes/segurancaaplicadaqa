---
layout: lesson
title: "Aula 1.4: Data Binding e Diretivas Modernas"
slug: data-binding
module: module-1
lesson_id: lesson-1-4
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
permalink: /modules/fundamentos-acelerados/lessons/data-binding/
---

## Introdução

Nesta aula, você dominará todas as formas de data binding do Angular e aprenderá a usar diretivas modernas de forma eficiente. Data binding é o coração da comunicação entre componente e template no Angular, permitindo criar interfaces de usuário dinâmicas e interativas.

### Contexto Histórico do Data Binding

Data binding é um dos conceitos mais fundamentais do Angular desde sua primeira versão. A evolução do data binding reflete a evolução do próprio framework:

**Linha do Tempo da Evolução**:

{% raw %}
```
AngularJS (2010) ──────────────────────────────────────────── Angular 17+ (2023+)
 │                                                                  │
 ├─ 2010    📦 AngularJS - Two-way binding por padrão             │
 │          {{ }} interpolation                                    │
 │          ng-model para two-way                                  │
 │          Performance limitada                                    │
 │                                                                  │
 ├─ 2016    🚀 Angular 2 - One-way binding por padrão             │
 │          [property] e (event)                                   │
 │          [(ngModel)] para two-way                              │
 │          Melhor performance                                     │
 │                                                                  │
 ├─ 2017-2020 📈 Melhorias incrementais                           │
 │          Otimizações de change detection                        │
 │          Novas diretivas estruturais                            │
 │          Performance melhorada                                  │
 │                                                                  │
 ├─ 2023    🔥 Angular 17 - Control Flow (@if, @for)              │
 │          Sintaxe moderna                                        │
 │          Melhor performance                                     │
 │          Type safety melhorado                                  │
 │                                                                  │
 └─ 2024    🎯 Angular 18+ - Signals integration                   │
            Reatividade moderna                                    │
            Performance otimizada                                  │
```
{% endraw %}

**Por que Data Binding é Essencial?**

Data binding elimina a necessidade de manipulação manual do DOM, que era comum em jQuery e JavaScript vanilla:

- **Antes (jQuery)**: Manipulação manual do DOM, código verboso, difícil manutenção
- **Com Angular**: Declarativo, type-safe, reativo, fácil manutenção

**Evolução dos Padrões**:

1. **AngularJS**: Two-way binding por padrão (conveniente mas lento)
2. **Angular 2+**: One-way binding por padrão (mais rápido, mais controle)
3. **Angular Moderno**: Combinação inteligente com signals e control flow

### O que você vai aprender

{% raw %}
- **Interpolação**: Exibir dados do componente no template (`{{ }}`)
{% endraw %}
- **Property Binding**: Definir propriedades dinamicamente (`[property]`)
- **Event Binding**: Responder a eventos do DOM (`(event)`)
- **Two-Way Data Binding**: Sincronização bidirecional (`[(ngModel)]`)
- **Binding de Classes**: Classes CSS dinâmicas (`[ngClass]`, `[class]`)
- **Binding de Estilos**: Estilos inline dinâmicos (`[ngStyle]`, `[style]`)
- **Diretivas Estruturais**: Modificar estrutura do DOM (`*ngIf`, `*ngFor`, `*ngSwitch`)
- **Diretivas de Atributo**: Modificar aparência/comportamento (`[ngClass]`, `[ngStyle]`)
- **Diretivas Customizadas**: Criar suas próprias diretivas
- **Control Flow Moderno**: Sintaxe `@if`, `@for`, `@switch` (Angular 17+)

### Por que isso é importante

**Para Desenvolvimento**:
- **Produtividade**: Código mais rápido de escrever e manter
- **Type Safety**: TypeScript garante tipos corretos em compile-time
- **Reatividade**: Mudanças automáticas na UI quando dados mudam
- **Declarativo**: Código mais legível e fácil de entender

**Para Projetos**:
- **Performance**: Change detection otimizado
- **Manutenibilidade**: Código organizado e previsível
- **Escalabilidade**: Padrões consistentes em projetos grandes
- **Testabilidade**: Fácil de testar com binding explícito

**Para Carreira**:
- **Fundamental**: Base para todo desenvolvimento Angular
- **Diferencial**: Entendimento profundo de data binding
- **Relevância**: Conceito usado em todos os projetos Angular
- **Base Sólida**: Necessário para conceitos avançados

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
Interpolação é como preencher um formulário em branco. O template é o formulário, e `{{ }}` são os campos que serão preenchidos com dados do componente. Assim como um formulário físico tem campos em branco que você preenche com informações, o template tem expressões `{{ }}` que são automaticamente preenchidas com valores do componente quando a página é renderizada.
{% endraw %}

**Como Funciona Internamente**:

{% raw %}
O Angular avalia a expressão dentro de `{{ }}` durante cada ciclo de change detection. Se o valor mudar, o DOM é atualizado automaticamente. Isso é feito de forma eficiente usando o mecanismo de detecção de mudanças do Angular.
{% endraw %}

**Visualização**:

```
Component                    Angular Engine              Template
┌────────────────┐            ┌──────────────┐            ┌─────────────┐
│ name = "João"  │  ────────→ │   Evaluate   │  ────────→ │ {{ name }}  │
│ age = 30       │            │   Expression  │            │ {{ age }}   │
│                │            │              │            │             │
│ Change:        │            │  Change      │            │   Update    │
│ name = "Maria" │  ────────→ │  Detection   │  ────────→ │   DOM       │
└────────────────┘            └──────────────┘            └─────────────┘
                              ↓
                          "João" → "Maria"
                          "30" (unchanged)
```

**Fluxo de Execução**:

{% raw %}
1. Angular compila o template e identifica expressões `{{ }}`
{% endraw %}
2. Durante change detection, avalia cada expressão
3. Compara valor anterior com valor atual
4. Se diferente, atualiza o DOM apenas naquele ponto específico
5. Otimização: apenas elementos que mudaram são atualizados

**Exemplo Prático**:

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
```html
<h1>{{ userName }}</h1>
<p>Idade: {{ userAge }}</p>
<p>Status: {{ isActive ? 'Ativo' : 'Inativo' }}</p>
<p>{{ getDisplayName() }}</p>
```
{% raw %}
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

Property binding é como configurar um aparelho eletrônico. Você define as configurações (propriedades) e o aparelho funciona de acordo com essas configurações. Assim como você ajusta o volume, brilho e outras configurações de uma TV usando o controle remoto, o property binding permite "configurar" elementos HTML dinamicamente através de valores do componente.

**Diferença entre Interpolação e Property Binding**:

- **Interpolação**: Usada para conteúdo de texto (`{{ value }}`)
- **Property Binding**: Usada para propriedades HTML (`[property]="value"`)

**Por que usar Property Binding ao invés de Interpolação para propriedades?**

```html
<!-- ❌ Ruim: Interpolação para propriedades -->
<img src="{{ imageUrl }}">

<!-- ✅ Bom: Property Binding -->
<img [src]="imageUrl">
```

Property binding é mais seguro e eficiente porque:
- Type safety: TypeScript valida o tipo da propriedade
- Performance: Angular otimiza melhor property bindings
- Funciona corretamente com valores boolean/null/undefined

**Visualização**:

```
Component                    Angular Binding              Template Element
┌─────────────┐            ┌──────────────┐            ┌─────────────┐
│ imageUrl    │  ────────→ │   Property   │  ────────→ │ <img        │
│ = "url.jpg" │            │   Binding    │            │  [src]="..."│
│             │            │              │            │             │
│ isDisabled  │  ────────→ │   Evaluate   │  ────────→ │ <button     │
│ = true      │            │   Boolean    │            │  [disabled] │
└─────────────┘            └──────────────┘            └─────────────┘
                              ↓
                          DOM Update:
                          img.src = "url.jpg"
                          button.disabled = true
```

**Casos de Uso Comuns**:

- Propriedades HTML: `[src]`, `[href]`, `[disabled]`, `[hidden]`
- Propriedades de componentes filhos: `[user]="currentUser"`
- Propriedades de diretivas: `[ngClass]`, `[ngStyle]`
- Propriedades customizadas: `[data-*]` attributes

**Exemplo Prático**:

```typescript
export class ImageComponent {
  imageUrl: string = 'https://example.com/image.jpg';
  isDisabled: boolean = false;
  buttonText: string = 'Clique aqui';
}
```

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

Event binding é como instalar um botão de emergência conectado a um sistema de alarme. Quando alguém pressiona o botão (evento no template), o sistema detecta a ação e executa uma resposta programada (handler no componente). Assim como diferentes botões podem acionar diferentes alarmes, diferentes eventos podem chamar diferentes métodos do componente.

**Como Funciona o Event Binding**:

1. Angular registra listeners de eventos no elemento DOM
2. Quando evento ocorre, Angular executa a expressão do handler
3. O objeto `$event` contém informações do evento original
4. Método do componente é executado no contexto do componente

**Visualização**:

```
User Action                Template                    Angular Event         Component
┌─────────────┐            ┌─────────────┐            ┌──────────────┐      ┌─────────────┐
│ Click Button│  ────────→ │ (click)     │  ────────→ │   Capture    │ ───→ │ onClick()   │
│             │            │ ="onClick()"│            │   Event      │      │ {           │
│ Type Key    │  ────────→ │ (keyup)     │  ────────→ │   Execute    │ ───→ │   logic...  │
│             │            │ ="onKeyUp($event)"        │   Handler    │      │ }           │
└─────────────┘            └─────────────┘            └──────────────┘      └─────────────┘
                              ↑
                          Event Object
                          ($event)
```

**Acesso ao Objeto de Evento**:

O objeto `$event` contém informações detalhadas sobre o evento:

```typescript
onKeyUp(event: KeyboardEvent): void {
  console.log('Key:', event.key);
  console.log('Code:', event.code);
  console.log('Target:', event.target);
}
```

**Tipos de Eventos Disponíveis**:

- **Mouse Events**: `click`, `dblclick`, `mouseenter`, `mouseleave`, `mousemove`
- **Keyboard Events**: `keydown`, `keyup`, `keypress`
- **Form Events**: `submit`, `change`, `input`, `focus`, `blur`
- **Custom Events**: Eventos emitidos por componentes filhos

**Exemplo Prático**:

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

Two-way binding é como um espelho mágico bidirecional que reflete e modifica simultaneamente. Quando você muda algo no template (como digitar em um input), o componente atualiza automaticamente. E quando o componente muda o valor (como receber dados de uma API), o template atualiza automaticamente. É como ter duas pessoas conversando em tempo real - qualquer mudança de um lado é imediatamente refletida no outro.

**Como Funciona Internamente**:

Two-way binding `[(ngModel)]` é uma sintaxe especial que combina:
- Property binding: `[ngModel]="property"` (componente → template)
- Event binding: `(ngModelChange)="property = $event"` (template → componente)

Angular expande `[(ngModel)]="name"` para:
```html
[ngModel]="name" (ngModelChange)="name = $event"
```

**Visualização Detalhada**:

```
                    Two-Way Data Binding Flow
                    
Component                    Angular Engine              Template
┌─────────────┐            ┌──────────────┐            ┌─────────────┐
│ name = ""   │  ────────→ │ Property     │  ────────→ │ [(ngModel)] │
│             │            │ Binding      │            │ ="name"     │
│             │            │              │            │             │
│ User types: │            │              │            │ User Input  │
│ "João"      │  ←──────── │ Event        │  ←──────── │ "João"      │
│             │            │ Binding      │            │             │
│             │            │              │            │             │
│ API updates:│            │              │            │             │
│ name = "Maria"│ ────────→ │ Property     │  ────────→ │ Auto Update │
└─────────────┘            │ Binding      │            │ "Maria"     │
                           └──────────────┘            └─────────────┘
                           
                    Sincronização Automática
                    Component ↔ Template
```

**Quando Usar Two-Way Binding**:

✅ **Use quando**:
- Formulários simples com inputs básicos
- Precisa sincronização bidirecional automática
- Trabalhando com `FormsModule` (template-driven forms)

❌ **Evite quando**:
- Formulários complexos (use reactive forms)
- Performance crítica (one-way é mais rápido)
- Precisa validação avançada (use FormBuilder)

**Exemplo Prático**:

```typescript
import { FormsModule } from '@angular/forms';

export class FormComponent {
  userName: string = '';
  userEmail: string = '';
  isSubscribed: boolean = false;
}
```

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

```html
<div [ngClass]="getClasses()">Conteúdo</div>
<div [ngClass]="{'active': isActive, 'error': !isActive}">Status</div>
<div [ngStyle]="{'color': textColor, 'font-size': fontSize + 'px'}">Texto</div>
<div [style.color]="textColor" [style.font-size.px]="fontSize">Texto 2</div>
```

---

### Diretivas Estruturais

**Definição**: Diretivas estruturais modificam a estrutura do DOM adicionando, removendo ou manipulando elementos usando `*` prefix. Elas são diferentes de diretivas de atributo porque alteram a estrutura do DOM, não apenas propriedades de elementos existentes.

**Explicação Detalhada**:

Principais diretivas estruturais:

1. **\*ngIf**: Adiciona/remove elementos baseado em condição booleana
2. **\*ngFor**: Repete elementos para cada item em uma lista/array
3. **\*ngSwitch**: Seleciona um elemento de múltiplas opções baseado em valor

**Como Funciona o Asterisco (`*`)**:

O `*` é uma sintaxe especial do Angular. Quando você escreve `*ngIf="condition"`, Angular expande para:

```html
<!-- Sintaxe curta -->
<div *ngIf="show">Conteúdo</div>

<!-- O que Angular realmente cria -->
<ng-template [ngIf]="show">
  <div>Conteúdo</div>
</ng-template>
```

O `*` é um açúcar sintático que cria um `<ng-template>` automaticamente.

**Analogia**:

Diretivas estruturais são como instruções de construção para um arquiteto. `*ngIf` é como dizer "construa este cômodo apenas se a condição for verdadeira". `*ngFor` é como dizer "construa este mesmo cômodo múltiplas vezes, uma para cada item da lista". `*ngSwitch` é como dizer "construa apenas um destes cômodos específicos baseado no valor da variável".

**Visualização Detalhada**:

```
*ngIf Flow:
┌─────────────┐
│ condition   │
│ = true      │  ────────→  DOM: <div>Conteúdo</div>
└─────────────┘
┌─────────────┐
│ condition   │
│ = false     │  ────────→  DOM: (elemento removido)
└─────────────┘

*ngFor Flow:
┌─────────────┐
│ items =     │
│ ['A','B','C']│  ────────→  DOM:
└─────────────┘              <div>Item A</div>
                            <div>Item B</div>
                            <div>Item C</div>

*ngSwitch Flow:
┌─────────────┐
│ value =     │
│ "option1"   │  ────────→  DOM: <div>Opção 1</div>
└─────────────┘              (outras opções não renderizadas)
```

**Performance com Diretivas Estruturais**:

- **\*ngIf**: Remove elemento do DOM completamente (não apenas esconde)
- **\*ngFor**: Use `trackBy` para otimizar re-renderizações
- **\*ngSwitch**: Mais eficiente que múltiplos `*ngIf` aninhados

**Exemplo Prático**:

```typescript
export class ListComponent {
  items: string[] = ['Item 1', 'Item 2', 'Item 3'];
  showList: boolean = true;
  selectedValue: string = 'option1';
}
```

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

```typescript
export class AttributeDirectiveComponent {
  isHighlighted: boolean = false;
  currentColor: string = 'blue';
  
  toggleHighlight(): void {
    this.isHighlighted = !this.isHighlighted;
  }
}
```

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
```
{% endraw %}

---

### Exemplo 2: Lista Interativa com Diretivas

**Contexto**: Criar lista interativa com filtros e ações.

**Código**:

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

---

### Control Flow Moderno (Angular 17+)

**Definição**: Angular 17 introduziu sintaxe moderna para control flow usando `@if`, `@for`, `@switch` ao invés das diretivas estruturais tradicionais `*ngIf`, `*ngFor`, `*ngSwitch`.

**Explicação Detalhada**:

A nova sintaxe de control flow oferece:
- **Melhor Type Safety**: TypeScript pode inferir tipos melhor
- **Melhor Performance**: Compilador otimiza melhor
- **Sintaxe Mais Limpa**: Mais legível e menos verbosa
- **Built-in**: Não precisa importar `CommonModule`

**Comparação: Sintaxe Antiga vs Moderna**:

{% raw %}
```html
<!-- ❌ Sintaxe Antiga (Angular < 17) -->
<div *ngIf="user">
  <p>{{ user.name }}</p>
</div>
<div *ngIf="!user">
  <p>Nenhum usuário</p>
</div>

<ul>
  <li *ngFor="let item of items; let i = index; trackBy: trackById">
    {{ i + 1 }}. {{ item.name }}
  </li>
</ul>

<div [ngSwitch]="status">
  <p *ngSwitchCase="'active'">Ativo</p>
  <p *ngSwitchCase="'inactive'">Inativo</p>
  <p *ngSwitchDefault>Desconhecido</p>
</div>

<!-- ✅ Sintaxe Moderna (Angular 17+) -->
@if (user) {
  <p>{{ user.name }}</p>
} @else {
  <p>Nenhum usuário</p>
}

<ul>
  @for (item of items; track item.id) {
    <li>{{ $index + 1 }}. {{ item.name }}</li>
  }
</ul>

@switch (status) {
  @case ('active') {
    <p>Ativo</p>
  }
  @case ('inactive') {
    <p>Inativo</p>
  }
  @default {
    <p>Desconhecido</p>
  }
}
```
{% raw %}
<!-- ❌ Sintaxe Antiga (Angular < 17) -->
<div *ngIf="user">
  <p>{{ user.name }}</p>
</div>
<div *ngIf="!user">
  <p>Nenhum usuário</p>
</div>

<ul>
  <li *ngFor="let item of items; let i = index; trackBy: trackById">
    {{ i + 1 }}. {{ item.name }}
  </li>
</ul>

<div [ngSwitch]="status">
  <p *ngSwitchCase="'active'">Ativo</p>
  <p *ngSwitchCase="'inactive'">Inativo</p>
  <p *ngSwitchDefault>Desconhecido</p>
</div>

<!-- ✅ Sintaxe Moderna (Angular 17+) -->
@if (user) {
  <p>{{ user.name }}</p>
} @else {
  <p>Nenhum usuário</p>
}

<ul>
  @for (item of items; track item.id) {
    <li>{{ $index + 1 }}. {{ item.name }}</li>
  }
</ul>

@switch (status) {
  @case ('active') {
    <p>Ativo</p>
  }
  @case ('inactive') {
    <p>Inativo</p>
  }
  @default {
    <p>Desconhecido</p>
  }
}
```
{% endraw %}

**Vantagens da Sintaxe Moderna**:

1. **Type Safety Melhorado**:
```
   // Angular infere que 'user' não é null dentro do bloco @if
   @if (user) {
     <p>{{ user.name }}</p>  // TypeScript sabe que user existe aqui
   }
```

2. **Performance**:
   - Compilador pode otimizar melhor
   - Menos overhead de runtime
   - Melhor tree-shaking

3. **Sintaxe Mais Limpa**:
   - Não precisa de `*` prefix
   - Não precisa de `ng-container` para combinar diretivas
   - Mais parecido com JavaScript/TypeScript nativo

**Migração de Sintaxe Antiga para Moderna**:

```typescript
// Antes (Angular < 17)
@Component({
  imports: [CommonModule]  // Necessário para *ngIf, *ngFor
})

// Depois (Angular 17+)
@Component({
  // Não precisa importar CommonModule para @if, @for, @switch
})
```

**Quando Usar Cada Sintaxe**:

- **Use Sintaxe Moderna (@if, @for, @switch)** quando:
  - Projeto Angular 17+
  - Quer melhor type safety
  - Quer melhor performance
  - Código novo

- **Use Sintaxe Antiga (*ngIf, *ngFor, *ngSwitch)** quando:
  - Projeto Angular < 17
  - Migrando gradualmente
  - Precisa compatibilidade com código legado

**Exemplo Prático Completo**:

```typescript
import { Component } from '@angular/core';

interface Task {
  id: number;
  title: string;
  completed: boolean;
  priority: 'low' | 'medium' | 'high';
}

@Component({
  selector: 'app-task-list-modern',
  standalone: true,
  template: `
    <div class="task-list">
      @if (tasks.length === 0) {
        <p>Nenhuma tarefa encontrada</p>
      } @else {
        <ul>
          @for (task of tasks; track task.id) {
            <li [class.completed]="task.completed">
              <span>{{ task.title }}</span>
              @switch (task.priority) {
                @case ('high') {
                  <span class="badge high">Alta</span>
                }
                @case ('medium') {
                  <span class="badge medium">Média</span>
                }
                @case ('low') {
                  <span class="badge low">Baixa</span>
                }
              }
            </li>
          }
        </ul>
      }
    </div>
  `
})
export class TaskListModernComponent {
  tasks: Task[] = [
    { id: 1, title: 'Tarefa 1', completed: false, priority: 'high' },
    { id: 2, title: 'Tarefa 2', completed: true, priority: 'medium' }
  ];
}
```

---

## Comparação com Outras Abordagens

### Angular vs React vs Vue vs Svelte: Data Binding

**Tabela Comparativa Completa**:

| Aspecto | Angular | React | Vue | Svelte |
|---------|---------|-------|-----|--------|
| **Interpolação** | `{{ value }}` | `{value}` | `{{ value }}` | `{value}` |
| **Property Binding** | `[prop]="value"` | `prop={value}` | `:prop="value"` | `prop={value}` |
| **Event Binding** | `(click)="handler()"` | `onClick={handler}` | `@click="handler"` | `on:click={handler}` |
| **Two-Way Binding** | `[(ngModel)]` | Controlled components | `v-model` | `bind:value` |
| **Classes Dinâmicas** | `[ngClass]` ou `[class]` | `className={...}` | `:class` | `class:active={condition}` |
{% raw %}
| **Estilos Dinâmicos** | `[ngStyle]` ou `[style]` | `style={{...}}` | `:style` | `style:color={value}` |
{% endraw %}
| **Diretivas Estruturais** | `*ngIf`, `*ngFor` ou `@if`, `@for` | `{condition && <div>}` | `v-if`, `v-for` | `{#if}`, `{#each}` |
| **Type Safety** | Nativo (TypeScript) | Opcional (TS/Flow) | Opcional (TypeScript) | Nativo (TypeScript) |
| **Change Detection** | Zone.js ou Signals | Virtual DOM diff | Reactive Proxy | Compile-time |
| **Performance** | Boa (com OnPush) | Excelente | Excelente | Excelente |
| **Bundle Size** | Grande (~500KB) | Médio (~130KB) | Pequeno (~34KB) | Muito Pequeno (~10KB) |
| **Curva de Aprendizado** | Alta | Média | Baixa | Baixa |
| **Comunidade** | Grande | Muito Grande | Grande | Crescendo |

**Análise Detalhada por Framework**:

**Angular**:
- ✅ Type safety nativo e forte
- ✅ Padrões consistentes e opinativos
- ✅ Excelente para projetos grandes e complexos
- ❌ Curva de aprendizado mais íngreme
- ❌ Bundle size maior

**React**:
- ✅ Ecossistema enorme e maduro
- ✅ Flexibilidade máxima
- ✅ Virtual DOM eficiente
- ❌ Requer mais decisões arquiteturais
- ❌ Type safety opcional

**Vue**:
- ✅ Curva de aprendizado suave
- ✅ Sintaxe intuitiva
- ✅ Performance excelente
- ❌ Ecossistema menor que React
- ❌ Menos padrões estabelecidos

**Svelte**:
- ✅ Bundle size mínimo
- ✅ Performance excelente (compile-time)
- ✅ Sintaxe muito limpa
- ❌ Ecossistema menor
- ❌ Menos recursos de terceiros

**Exemplos Comparativos Detalhados**:

```typescript
// ========== INTERPOLAÇÃO ==========

// Angular
<h1>{{ userName }}</h1>
<p>Idade: {{ userAge }}</p>

// React
<h1>{userName}</h1>
<p>Idade: {userAge}</p>

// Vue
<h1>{{ userName }}</h1>
<p>Idade: {{ userAge }}</p>

// Svelte
<h1>{userName}</h1>
<p>Idade: {userAge}</p>

// ========== PROPERTY BINDING ==========

// Angular
<img [src]="imageUrl" [alt]="imageAlt">
<button [disabled]="isDisabled">Clique</button>

// React
<img src={imageUrl} alt={imageAlt} />
<button disabled={isDisabled}>Clique</button>

// Vue
<img :src="imageUrl" :alt="imageAlt">
<button :disabled="isDisabled">Clique</button>

// Svelte
<img src={imageUrl} alt={imageAlt}>
<button disabled={isDisabled}>Clique</button>

// ========== EVENT BINDING ==========

// Angular
<button (click)="onClick()">Clique</button>
<input (keyup)="onKeyUp($event)">

// React
<button onClick={onClick}>Clique</button>
<input onKeyUp={onKeyUp} />

// Vue
<button @click="onClick">Clique</button>
<input @keyup="onKeyUp">

// Svelte
<button on:click={onClick}>Clique</button>
<input on:keyup={onKeyUp}>

// ========== TWO-WAY BINDING ==========

// Angular
<input [(ngModel)]="userName">
<p>{{ userName }}</p>

// React (Controlled Component)
<input value={userName} onChange={(e) => setUserName(e.target.value)} />
<p>{userName}</p>

// Vue
<input v-model="userName">
<p>{{ userName }}</p>

// Svelte
<input bind:value={userName}>
<p>{userName}</p>

// ========== CLASSES DINÂMICAS ==========

// Angular
<div [class.active]="isActive" [class.disabled]="isDisabled">
  Conteúdo
</div>
<div [ngClass]="{'active': isActive, 'error': hasError}">
  Conteúdo
</div>

// React
<div className={`base ${isActive ? 'active' : ''} ${isDisabled ? 'disabled' : ''}`}>
  Conteúdo
</div>
<div className={classNames({active: isActive, error: hasError})}>
  Conteúdo
</div>

// Vue
<div :class="{active: isActive, disabled: isDisabled}">
  Conteúdo
</div>

// Svelte
<div class:active={isActive} class:disabled={isDisabled}>
  Conteúdo
</div>

// ========== CONDICIONAIS ==========

// Angular (Antigo)
<div *ngIf="isVisible">Conteúdo</div>

// Angular (Moderno - 17+)
@if (isVisible) {
  <div>Conteúdo</div>
}

// React
{isVisible && <div>Conteúdo</div>}

// Vue
<div v-if="isVisible">Conteúdo</div>

// Svelte
{#if isVisible}
  <div>Conteúdo</div>
{/if}

// ========== LOOPS ==========

// Angular (Antigo)
<ul>
  <li *ngFor="let item of items; trackBy: trackById">
    {{ item.name }}
  </li>
</ul>

// Angular (Moderno - 17+)
<ul>
  @for (item of items; track item.id) {
    <li>{{ item.name }}</li>
  }
</ul>

// React
<ul>
  {items.map(item => (
    <li key={item.id}>{item.name}</li>
  ))}
</ul>

// Vue
<ul>
  <li v-for="item in items" :key="item.id">
    {{ item.name }}
  </li>
</ul>

// Svelte
<ul>
  {#each items as item (item.id)}
    <li>{item.name}</li>
  {/each}
</ul>
```

### Data Binding: Unidirecional vs Bidirecional

**Comparação de Abordagens**:

| Tipo | Angular | Quando Usar |
|------|---------|-------------|
{% raw %}
| **One-Way (Component → Template)** | `{{ }}`, `[property]` | Padrão, mais performático |
{% endraw %}
| **One-Way (Template → Component)** | `(event)` | Interações do usuário |
| **Two-Way** | `[(ngModel)]` | Formulários simples |
| **Two-Way Custom** | `[(custom)]` | Componentes customizados |

---

## Performance e Otimização

### Como Angular Otimiza Data Binding

Angular usa várias estratégias para otimizar data binding:

1. **Change Detection Strategy**:
   - **Default**: Verifica todos os componentes a cada evento
   - **OnPush**: Verifica apenas quando `@Input()` muda ou eventos ocorrem
   - **OnPush com Signals**: Verifica apenas quando signals mudam

2. **Expression Evaluation**:
   - Expressões são avaliadas apenas quando necessário
   - Angular compara valores anteriores com atuais
   - DOM é atualizado apenas quando valores mudam

3. **TrackBy Function**:
   - Identifica itens em listas de forma eficiente
   - Evita re-renderizações desnecessárias
   - Essencial para listas grandes

### Diagrama de Fluxo de Change Detection

```
Event Occurs (click, HTTP, timer)
         │
         ↓
┌────────────────────┐
│ Zone.js Detects    │
│ Event              │
└────────────────────┘
         │
         ↓
┌────────────────────┐
│ Angular Triggers   │
│ Change Detection   │
└────────────────────┘
         │
         ↓
┌────────────────────┐
│ Check Components   │
│ (Default: All)     │
│ (OnPush: Changed)  │
└────────────────────┘
         │
         ↓
┌────────────────────┐
│ Evaluate Bindings │
│ Compare Values     │
└────────────────────┘
         │
         ↓
┌────────────────────┐
│ Update DOM         │
│ (Only Changed)     │
└────────────────────┘
```

### Otimizações Práticas

**1. Use OnPush Change Detection**:

```typescript
@Component({
  selector: 'app-user-card',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>{{ user.name }}</div>
  `
})
export class UserCardComponent {
  @Input() user!: User;
}
```

**2. Use TrackBy em Listas**:

```typescript
trackByUserId(index: number, user: User): number {
  return user.id;
}
```

```html
<div *ngFor="let user of users; trackBy: trackByUserId">
  {{ user.name }}
</div>
```

**3. Evite Funções no Template**:

{% raw %}
```typescript
// ❌ Ruim: Função é chamada a cada change detection
{{ getFullName() }}

// ✅ Bom: Getter é cacheado ou computed property
{{ fullName }}
```
{% endraw %}

**4. Use Async Pipe para Observables**:

{% raw %}
```typescript
// ✅ Bom: Async pipe gerencia subscription
{{ data$ | async }}

// ❌ Ruim: Subscription manual
ngOnInit() {
  this.data$.subscribe(data => this.data = data);
}
```
{% raw %}
// ✅ Bom: Async pipe gerencia subscription
{{ data$ | async }}

// ❌ Ruim: Subscription manual
ngOnInit() {
  this.data$.subscribe(data => this.data = data);
}
```
{% endraw %}

**5. Use Signals para Reatividade Moderna**:

```typescript
import { signal, computed } from '@angular/core';

export class UserComponent {
  users = signal<User[]>([]);
  activeUsers = computed(() => 
    this.users().filter(u => u.active)
  );
}
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use trackBy com *ngFor**
   - **Por quê**: Melhora performance ao evitar re-renderizações desnecessárias
   - **Exemplo Bom**:
```
     trackById(index: number, item: Item): number {
       return item.id;
     }
```
```
     <div *ngFor="let item of items; trackBy: trackById">
```
   - **Exemplo Ruim**: `*ngFor="let item of items"` (sem trackBy)
   - **Benefícios**: Performance melhorada, menos re-renderizações

2. **Evite lógica complexa no template**
   - **Por quê**: Dificulta manutenção, testes e debugging
   - **Exemplo Bom**:
```
     get displayName(): string {
       return `${this.firstName} ${this.lastName}`.trim();
     }
```
```
     <p>{{ displayName }}</p>
```
{% raw %}
   - **Exemplo Ruim**: `{{ firstName + ' ' + lastName }}` (lógica no template)
{% endraw %}
   - **Benefícios**: Código mais testável, fácil manutenção

3. **Use property binding para propriedades boolean**
   - **Por quê**: Mais claro, type-safe, evita conversão para string
   - **Exemplo Bom**: `[disabled]="isDisabled"`
   - **Exemplo Ruim**: `disabled="{{isDisabled}}"` (converte para string)
   - **Benefícios**: Type safety, comportamento correto

4. **Use sintaxe moderna quando disponível (Angular 17+)**
   - **Por quê**: Melhor performance, type safety, sintaxe mais limpa
   - **Exemplo Bom**: `@if`, `@for`, `@switch` (Angular 17+)
   - **Exemplo Antigo**: `*ngIf`, `*ngFor`, `*ngSwitch`
   - **Benefícios**: Performance melhorada, type safety

5. **Combine diretivas usando ng-container**
   - **Por quê**: Permite combinar diretivas sem criar elementos extras
   - **Exemplo Bom**:
```
     <ng-container *ngIf="showList">
       <div *ngFor="let item of items">{{ item }}</div>
     </ng-container>
```
   - **Exemplo Ruim**: Tentar usar `*ngIf` e `*ngFor` no mesmo elemento
   - **Benefícios**: DOM mais limpo, sem elementos desnecessários

6. **Use getters para computações derivadas**
   - **Por quê**: Cache automático, código mais limpo
   - **Exemplo Bom**:
```
     get filteredItems(): Item[] {
       return this.items.filter(item => item.active);
     }
```
   - **Benefícios**: Código mais legível, fácil de testar

7. **Prefira [class] e [style] sobre [ngClass] e [ngStyle] quando simples**
   - **Por quê**: Mais performático, sintaxe mais direta
   - **Exemplo Bom**: `[class.active]="isActive"` ou `[style.color]="textColor"`
   - **Exemplo Alternativo**: `[ngClass]="{'active': isActive}"` (quando complexo)
   - **Benefícios**: Melhor performance, código mais direto

8. **Use OnPush change detection com binding**
   - **Por quê**: Melhora significativa de performance
   - **Exemplo**: 
```
     @Component({
       changeDetection: ChangeDetectionStrategy.OnPush
     })
```
   - **Benefícios**: Menos ciclos de detecção, melhor performance
   - **Quando usar**: Componentes que recebem dados via `@Input()` ou signals

9. **Use sintaxe moderna de control flow quando possível**
   - **Por quê**: Melhor type safety, performance e legibilidade
   - **Exemplo Bom**: `@if`, `@for`, `@switch` (Angular 17+)
   - **Exemplo Antigo**: `*ngIf`, `*ngFor`, `*ngSwitch`
   - **Benefícios**: Type safety melhorado, código mais limpo

10. **Evite mutações diretas em listas com *ngFor**
    - **Por quê**: Angular pode não detectar mudanças corretamente
    - **Exemplo Bom**:
```
      this.items = [...this.items, newItem];  // Nova referência
```
    - **Exemplo Ruim**: `this.items.push(newItem);` (mutação direta)
    - **Benefícios**: Change detection funciona corretamente

11. **Use async pipe para observables**
    - **Por quê**: Gerencia subscription automaticamente, evita memory leaks
{% raw %}
    - **Exemplo Bom**: `{{ data$ | async }}`
{% endraw %}
    - **Exemplo Ruim**: Subscription manual no componente
    - **Benefícios**: Menos código, sem memory leaks

12. **Separe lógica de apresentação do template**
    - **Por quê**: Facilita testes e manutenção
    - **Exemplo Bom**: Métodos simples no componente, lógica complexa em services
    - **Exemplo Ruim**: Lógica complexa diretamente no template
    - **Benefícios**: Código mais testável e manutenível

### ❌ Anti-padrões Comuns

1. **Não use interpolação para propriedades boolean**
   - **Problema**: Converte para string "true"/"false", não funciona corretamente
   - **Exemplo Ruim**: `disabled="{{isDisabled}}"` → `disabled="true"` (sempre desabilitado!)
   - **Solução**: Use property binding `[disabled]="isDisabled"`
   - **Impacto**: Bugs difíceis de detectar, comportamento incorreto

2. **Não esqueça trackBy em listas grandes**
   - **Problema**: Performance ruim, re-renderizações desnecessárias
   - **Exemplo Ruim**: `*ngFor="let item of items"` (sem trackBy)
   - **Solução**: Sempre use `trackBy` em `*ngFor`
   - **Impacto**: Performance degradada, UI lenta

3. **Não misture *ngIf e *ngFor no mesmo elemento**
   - **Problema**: Angular não permite, erro de compilação
   - **Exemplo Ruim**: `<div *ngIf="show" *ngFor="let item of items">`
   - **Solução**: Use `<ng-container>` ou elementos separados
   - **Impacto**: Código não compila

4. **Não use métodos no template para cálculos pesados**
   - **Problema**: Método é chamado a cada ciclo de change detection
{% raw %}
   - **Exemplo Ruim**: `{{ calculateTotal() }}` (chamado múltiplas vezes)
{% endraw %}
   - **Solução**: Use getters ou computed properties
   - **Impacto**: Performance ruim, aplicação lenta

5. **Não use two-way binding desnecessariamente**
   - **Problema**: Pode causar loops infinitos, performance ruim
   - **Exemplo Ruim**: `[(ngModel)]` em todos os inputs quando one-way é suficiente
   - **Solução**: Use one-way binding quando possível
   - **Impacto**: Performance degradada, bugs potenciais

6. **Não ignore o $event em event binding quando necessário**
   - **Problema**: Perde informações importantes do evento
   - **Exemplo Ruim**: `(keyup)="handleKeyUp()"` (sem acesso à tecla)
   - **Solução**: `(keyup)="handleKeyUp($event)"`
   - **Impacto**: Funcionalidade limitada, bugs

7. **Não use interpolação para propriedades HTML**
   - **Problema**: Não funciona corretamente, perde type safety
   - **Exemplo Ruim**: `<img src="{{imageUrl}}">`
   - **Solução**: Use property binding `[src]="imageUrl"`
   - **Impacto**: Pode não funcionar, perde type safety

8. **Não esqueça o name attribute com ngModel**
   - **Problema**: ngModel requer name attribute para funcionar corretamente
   - **Exemplo Ruim**: `<input [(ngModel)]="name">` (sem name)
   - **Solução**: `<input [(ngModel)]="name" name="name">`
   - **Impacto**: Two-way binding pode não funcionar

9. **Não use two-way binding com objetos complexos sem cuidado**
   - **Problema**: Pode causar referências compartilhadas inesperadas
   - **Exemplo Ruim**: `[(ngModel)]="user.address"` (objeto aninhado)
   - **Solução**: Use reactive forms ou crie objetos separados
   - **Impacto**: Mutação acidental de dados compartilhados

10. **Não ignore o ChangeDetectorRef quando necessário**
    - **Problema**: Com OnPush, mudanças podem não ser detectadas
    - **Exemplo Ruim**: Usar OnPush mas não marcar mudanças manualmente quando necessário
    - **Solução**: Use `this.cdr.markForCheck()` quando atualizar dados externamente
    - **Impacto**: UI não atualiza quando deveria

11. **Não use *ngFor sem trackBy em listas grandes**
    - **Problema**: Performance degradada, re-renderizações desnecessárias
    - **Exemplo Ruim**: `*ngFor="let item of items"` (sem trackBy)
    - **Solução**: Sempre use `trackBy` com identificador único
    - **Impacto**: UI lenta, especialmente em listas grandes

12. **Não misture sintaxe antiga e moderna no mesmo componente**
    - **Problema**: Código inconsistente, confusão
    - **Exemplo Ruim**: Misturar `*ngIf` e `@if` no mesmo template
    - **Solução**: Escolha uma sintaxe e seja consistente
    - **Impacto**: Código difícil de manter, confusão para desenvolvedores

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
- **[Control Flow](https://angular.io/guide/control-flow)**: Sintaxe moderna de control flow (@if, @for, @switch)
- **[Built-in Directives](https://angular.io/api/common#directives)**: Lista completa de diretivas built-in

### Artigos e Tutoriais

- **[Angular Data Binding: Complete Guide](https://www.bacancytechnology.com/blog/angular-data-binding)**: Guia completo sobre data binding
- **[Angular Performance: OnPush Change Detection](https://angular.io/guide/change-detection)**: Otimização de performance com OnPush
- **[Angular Control Flow: Migration Guide](https://angular.io/guide/control-flow)**: Guia de migração para sintaxe moderna
- **[Understanding Angular Change Detection](https://blog.angular-university.io/how-does-angular-2-change-detection-work/)**: Artigo técnico sobre change detection

### Vídeos

- **[Angular Data Binding Tutorial](https://www.youtube.com/watch?v=Y4CMZoFM7Ts)**: Tutorial completo sobre data binding
- **[Angular Two-Way Binding Explained](https://www.youtube.com/watch?v=6wUCBJ-2Dew)**: Explicação detalhada de two-way binding
- **[Angular Control Flow: @if, @for, @switch](https://www.youtube.com/results?search_query=angular+control+flow)**: Vídeos sobre sintaxe moderna

### Ferramentas

- **[Angular DevTools](https://angular.io/guide/devtools)**: Ferramentas de desenvolvimento para debug
- **[Angular Language Service](https://angular.io/guide/language-service)**: Type safety e autocomplete melhorados
- **[Angular CLI](https://angular.io/cli)**: Ferramenta de linha de comando para desenvolvimento

### Recursos Adicionais

- **[Angular Style Guide](https://angular.io/guide/styleguide)**: Guia de estilo oficial do Angular
- **[Angular Best Practices](https://angular.io/guide/best-practices)**: Melhores práticas recomendadas
- **[Angular Performance Checklist](https://angular.io/guide/performance)**: Checklist de otimização de performance

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
- Prefira sintaxe moderna (`@if`, `@for`) quando possível (Angular 17+)
- Use `OnPush` change detection para melhor performance
- Property binding é mais seguro que interpolação para propriedades HTML
- Event binding sempre passa `$event` quando necessário
- Two-way binding é açúcar sintático para property + event binding

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
