---
layout: lesson
title: "Aula 1.5: Control Flow e Pipes"
slug: control-flow-pipes
module: module-1
lesson_id: lesson-1-5
duration: "90 minutos"
level: "Básico"
prerequisites: 
  - "lesson-1-4"
exercises:
  - 
  - "lesson-1-5-exercise-1"
  - "lesson-1-5-exercise-2"
  - "lesson-1-5-exercise-3"
  - "lesson-1-5-exercise-4"
  - "lesson-1-5-exercise-5"
---

## Introdução

Nesta aula, você aprenderá sobre Control Flow moderno do Angular (Angular 17+) e Pipes para transformação de dados. Control Flow substitui as diretivas estruturais tradicionais com sintaxe mais moderna e performática, enquanto Pipes permitem transformar dados para exibição.

### O que você vai aprender

- Control Flow moderno (@if, @for, @switch)
- Migração de diretivas estruturais para Control Flow
- Pipes embutidos do Angular
- Criação de pipes customizados
- Pure vs Impure pipes
- Performance de pipes

### Por que isso é importante

Control Flow é o futuro do Angular e oferece melhor performance e sintaxe mais limpa. Pipes são essenciais para formatação de dados e criação de código reutilizável. Dominar ambos é crucial para desenvolvimento Angular moderno.

---

## Conceitos Teóricos

### Control Flow Moderno (@if, @for, @switch)

**Definição**: Control Flow é a nova sintaxe do Angular 17+ que substitui diretivas estruturais (*ngIf, *ngFor, *ngSwitch) com sintaxe mais moderna e performática.

**Explicação Detalhada**:

Control Flow oferece:
- **@if/@else**: Substitui *ngIf com sintaxe mais clara
- **@for**: Substitui *ngFor com melhor performance nativa
- **@switch**: Substitui *ngSwitch com sintaxe mais limpa

Vantagens sobre diretivas estruturais:
- Melhor performance (compilação mais eficiente)
- Sintaxe mais limpa e legível
- Type safety melhorado
- Menos boilerplate

**Analogia**:

Control Flow é como uma linguagem de programação moderna comparada a uma antiga. Faz a mesma coisa, mas de forma mais eficiente e fácil de entender.

**Visualização**:

```
Diretivas Estruturais (Antigo)    Control Flow (Novo)
┌─────────────────────┐          ┌─────────────────────┐
│ *ngIf="condition"   │          │ @if (condition) {   │
│ *ngFor="let item"   │          │ @for (item of list) │
│ *ngSwitch="value"   │          │ @switch (value) {   │
└─────────────────────┘          └─────────────────────┘
```

**Exemplo Prático**:

```typescript
export class ControlFlowComponent {
  isLoggedIn: boolean = true;
  items: string[] = ['Item 1', 'Item 2', 'Item 3'];
  status: 'active' | 'pending' | 'inactive' = 'active';
}
```

```html
@if (isLoggedIn) {
  <p>Bem-vindo!</p>
} @else {
  <p>Por favor, faça login</p>
}

@for (item of items; track item) {
  <div>{{ item }}</div>
} @empty {
  <p>Nenhum item encontrado</p>
}

@switch (status) {
  @case ('active') {
    <span>Ativo</span>
  }
  @case ('pending') {
    <span>Pendente</span>
  }
  @default {
    <span>Inativo</span>
  }
}
```

---

### @if e @else

**Definição**: `@if` é a nova sintaxe para renderização condicional que substitui `*ngIf`.

**Explicação Detalhada**:

Sintaxe `@if`:
- `@if (condition) { ... }`: Renderiza se condição verdadeira
- `@else { ... }`: Bloco alternativo
- `@else if (condition) { ... }`: Condições adicionais

**Analogia**:

`@if` é como uma porta que só abre se você tiver a chave certa (condição verdadeira). Se não tiver, pode usar a porta dos fundos (`@else`).

**Exemplo Prático**:

```html
@if (user) {
  <div class="user-profile">
    <h2>{{ user.name }}</h2>
    <p>{{ user.email }}</p>
  </div>
} @else if (loading) {
  <p>Carregando...</p>
} @else {
  <p>Usuário não encontrado</p>
}
```

---

### @for com trackBy

**Definição**: `@for` é a nova sintaxe para iteração que substitui `*ngFor` com melhor performance nativa.

**Explicação Detalhada**:

Sintaxe `@for`:
- `@for (item of items; track item.id) { ... }`: Itera com tracking
- `@empty { ... }`: Bloco quando lista vazia
- Tracking é obrigatório e integrado

Vantagens:
- Performance melhor que *ngFor
- Tracking integrado (não precisa de função separada)
- Sintaxe mais clara

**Analogia**:

`@for` é como uma linha de produção moderna. Cada item tem um código de barras (track) que permite rastrear eficientemente, ao invés de contar manualmente.

**Exemplo Prático**:

{% raw %}
```html
@for (product of products; track product.id) {
  <div class="product-card">
    <h3>{{ product.name }}</h3>
    <p>{{ product.price | currency }}</p>
  </div>
} @empty {
  <p>Nenhum produto disponível</p>
}
```
{% endraw %}

---

### @switch

**Definição**: `@switch` é a nova sintaxe para seleção múltipla que substitui `*ngSwitch`.

**Explicação Detalhada**:

Sintaxe `@switch`:
- `@switch (value) { ... }`: Inicia switch
- `@case (option) { ... }`: Caso específico
- `@default { ... }`: Caso padrão

**Analogia**:

`@switch` é como um seletor de canais de TV. Você escolhe um número (caso) e vê o canal correspondente.

**Exemplo Prático**:

```html
@switch (userRole) {
  @case ('admin') {
    <button>Gerenciar Usuários</button>
    <button>Configurações</button>
  }
  @case ('editor') {
    <button>Criar Conteúdo</button>
  }
  @default {
    <button>Ver Conteúdo</button>
  }
}
```

---

### Pipes Embutidos

{% raw %}
**Definição**: Pipes são funções que transformam dados para exibição no template usando a sintaxe `{{ value | pipe }}`.
{% endraw %}

**Explicação Detalhada**:

Pipes embutidos principais:
{% raw %}
- **DatePipe**: Formata datas (`{{ date | date:'short' }}`)
{% endraw %}
{% raw %}
- **CurrencyPipe**: Formata moedas (`{{ price | currency:'BRL' }}`)
{% endraw %}
{% raw %}
- **DecimalPipe**: Formata números (`{{ number | number:'1.2-2' }}`)
{% endraw %}
{% raw %}
- **PercentPipe**: Formata percentuais (`{{ ratio | percent }}`)
{% endraw %}
- **AsyncPipe**: Subscribe automaticamente em Observables
- **UpperCasePipe / LowerCasePipe**: Transforma texto
- **JsonPipe**: Converte para JSON (útil para debug)

**Analogia**:

Pipes são como filtros de água. Você coloca água suja (dados brutos) e sai água limpa (dados formatados). Cada pipe é um tipo diferente de filtro.

**Visualização**:

```
Dados Brutos          Pipe              Dados Formatados
┌──────────┐         ┌──────────┐         ┌──────────────┐
│ 1234.56  │  ────→  │currenc   │  ────→  │ R$ 1.234,56  │
│ new Date │  ────→  │ date     │  ────→  │ 03/01/2026   │
│ 0.75     │  ────→  │percent   │  ────→  │ 75%          │
└──────────┘         └──────────┘         └──────────────┘
```

**Exemplo Prático**:

```typescript
export class PipesComponent {
  price: number = 1234.56;
  date: Date = new Date();
  percentage: number = 0.75;
  userName: string = 'joão silva';
  userData: any = { name: 'João', age: 30 };
}
```

{% raw %}
```html
<p>Preço: {{ price | currency:'BRL':'symbol':'1.2-2' }}</p>
<p>Data: {{ date | date:'dd/MM/yyyy' }}</p>
<p>Percentual: {{ percentage | percent:'1.0-2' }}</p>
<p>Nome: {{ userName | titlecase }}</p>
<p>Debug: {{ userData | json }}</p>
```
{% endraw %}

---

### Pipes Customizados

**Definição**: Você pode criar seus próprios pipes para transformações específicas de dados.

**Explicação Detalhada**:

Pipes customizados são criados com:
- Decorator `@Pipe`
- Método `transform(value, ...args)` obrigatório
- Pode ser `pure` (padrão) ou `impure`

**Pure vs Impure**:
- **Pure**: Recalcula apenas quando entrada muda (padrão, melhor performance)
- **Impure**: Recalcula a cada change detection (use com cuidado)

**Analogia**:

Pipes customizados são como ferramentas personalizadas. Você cria uma ferramenta específica para uma tarefa que as ferramentas padrão não fazem bem.

**Exemplo Prático**:

```typescript
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'truncate',
  standalone: true
})
export class TruncatePipe implements PipeTransform {
  transform(value: string, limit: number = 20, trail: string = '...'): string {
    if (!value) return '';
    if (value.length <= limit) return value;
    return value.substring(0, limit) + trail;
  }
}

@Pipe({
  name: 'filter',
  standalone: true,
  pure: false
})
export class FilterPipe implements PipeTransform {
  transform<T>(items: T[], filterFn: (item: T) => boolean): T[] {
    if (!items || !filterFn) return items;
    return items.filter(filterFn);
  }
}
```

{% raw %}
```html
<p>{{ longText | truncate:50 }}</p>
<div *ngFor="let item of items | filter:isActive">
  {{ item.name }}
</div>
```
{% endraw %}

---

### AsyncPipe

**Definição**: AsyncPipe é um pipe especial que automaticamente faz subscribe/unsubscribe em Observables e Promises.

**Explicação Detalhada**:

AsyncPipe:
- Faz subscribe automaticamente
- Faz unsubscribe quando componente é destruído
- Previne memory leaks
- Atualiza template quando valor muda

**Analogia**:

AsyncPipe é como um assistente que monitora uma caixa de correio. Quando chega uma nova carta (novo valor), ele te avisa automaticamente e para de monitorar quando você não precisa mais.

**Exemplo Prático**:

{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { Observable, interval } from 'rxjs';
import { map } from 'rxjs/operators';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-async-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
    <p>Timer: {{ timer$ | async }}</p>
    <p>Data: {{ date$ | async | date:'medium' }}</p>
  `
{% endraw %}
})
export class AsyncDemoComponent implements OnInit {
  timer$!: Observable<number>;
  date$!: Observable<Date>;
  
  ngOnInit(): void {
    this.timer$ = interval(1000).pipe(map(() => Date.now()));
    this.date$ = interval(1000).pipe(map(() => new Date()));
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Componente com Control Flow Completo

**Contexto**: Criar componente que demonstra todos os tipos de Control Flow.

**Código**:

{% raw %}
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Task {
  id: number;
  title: string;
  completed: boolean;
  priority: 'high' | 'medium' | 'low';
}

@Component({
  selector: 'app-task-manager',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="task-manager">
      <h2>Gerenciador de Tarefas</h2>
      
      @if (tasks.length === 0) {
        <p class="empty">Nenhuma tarefa cadastrada</p>
      } @else {
        <div class="tasks">
          @for (task of tasks; track task.id) {
            <div class="task-card" [class.completed]="task.completed">
              <h3>{{ task.title }}</h3>
              
              @switch (task.priority) {
                @case ('high') {
                  <span class="priority high">Alta Prioridade</span>
                }
                @case ('medium') {
                  <span class="priority medium">Média Prioridade</span>
                }
                @default {
                  <span class="priority low">Baixa Prioridade</span>
                }
              }
              
              @if (task.completed) {
                <span class="status">✓ Concluída</span>
              } @else {
                <button (click)="completeTask(task.id)">Marcar como Concluída</button>
              }
            </div>
          }
        </div>
      }
    </div>
  `
{% endraw %}
})
export class TaskManagerComponent {
  tasks: Task[] = [
    { id: 1, title: 'Tarefa Urgente', completed: false, priority: 'high' },
    { id: 2, title: 'Tarefa Normal', completed: true, priority: 'medium' },
    { id: 3, title: 'Tarefa Baixa', completed: false, priority: 'low' }
  ];
  
  completeTask(id: number): void {
    const task = this.tasks.find(t => t.id === id);
    if (task) {
      task.completed = true;
    }
  }
}
```

---

### Exemplo 2: Pipes Customizados Avançados

**Contexto**: Criar conjunto de pipes customizados úteis.

**Código**:

```typescript
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'initials',
  standalone: true
})
export class InitialsPipe implements PipeTransform {
  transform(name: string): string {
    if (!name) return '';
    const parts = name.trim().split(' ');
    if (parts.length === 1) return parts[0][0].toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }
}

@Pipe({
  name: 'timeAgo',
  standalone: true
})
export class TimeAgoPipe implements PipeTransform {
  transform(date: Date): string {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days} dia${days > 1 ? 's' : ''} atrás`;
    if (hours > 0) return `${hours} hora${hours > 1 ? 's' : ''} atrás`;
    if (minutes > 0) return `${minutes} minuto${minutes > 1 ? 's' : ''} atrás`;
    return 'Agora mesmo';
  }
}

@Pipe({
  name: 'highlight',
  standalone: true
})
export class HighlightPipe implements PipeTransform {
  transform(text: string, search: string): string {
    if (!search || !text) return text;
    const regex = new RegExp(`(${search})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
  }
}
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use Control Flow em novos projetos**
   - **Por quê**: Melhor performance e sintaxe mais limpa
   - **Exemplo**: `@if` ao invés de `*ngIf`

2. **Sempre use track em @for**
   - **Por quê**: Melhora performance significativamente
   - **Exemplo**: `@for (item of items; track item.id)`

3. **Use AsyncPipe para Observables**
   - **Por quê**: Previne memory leaks automaticamente
{% raw %}
   - **Exemplo**: `{{ data$ | async }}`
{% endraw %}

4. **Mantenha pipes pure quando possível**
   - **Por quê**: Melhor performance
   - **Exemplo**: Evite `pure: false` a menos que necessário

### ❌ Anti-padrões Comuns

1. **Não misture Control Flow com diretivas estruturais**
   - **Problema**: Pode causar confusão e problemas de performance
   - **Solução**: Escolha um padrão e mantenha consistente

2. **Não use pipes impure desnecessariamente**
   - **Problema**: Performance ruim
   - **Solução**: Use pure pipes sempre que possível

3. **Não faça subscribe manual em Observables no template**
   - **Problema**: Memory leaks
   - **Solução**: Use AsyncPipe

---

## Exercícios Práticos

### Exercício 1: Migrar para Control Flow (Básico)

**Objetivo**: Migrar componente de diretivas estruturais para Control Flow

**Descrição**: 
Pegue um componente existente que usa *ngIf, *ngFor e *ngSwitch e migre para @if, @for e @switch.

**Arquivo**: `exercises/exercise-1-5-1-migrar-control-flow.md`

---

### Exercício 2: Lista com @for e Pipes (Básico)

**Objetivo**: Usar @for com pipes para formatação

**Descrição**:
Crie uma lista de produtos usando @for e formate preços, datas e números usando pipes embutidos.

**Arquivo**: `exercises/exercise-1-5-2-for-pipes.md`

---

### Exercício 3: Pipe Customizado Simples (Intermediário)

**Objetivo**: Criar pipe customizado básico

**Descrição**:
Crie um pipe `capitalize` que capitaliza primeira letra de cada palavra.

**Arquivo**: `exercises/exercise-1-5-3-pipe-simples.md`

---

### Exercício 4: Pipe Customizado Avançado (Avançado)

**Objetivo**: Criar pipe customizado complexo

**Descrição**:
Crie um pipe `filter` que filtra arrays baseado em função predicado. Use com cuidado (pode ser impure).

**Arquivo**: `exercises/exercise-1-5-4-pipe-avancado.md`

---

### Exercício 5: Componente Completo com Control Flow e Pipes (Avançado)

**Objetivo**: Combinar Control Flow e Pipes

**Descrição**:
Crie um componente de lista de transações financeiras que usa @for, @if, @switch, pipes embutidos e customizados para exibir dados formatados.

**Arquivo**: `exercises/exercise-1-5-5-componente-completo.md`

---

## Referências Externas

### Documentação Oficial

- **[Control Flow](https://angular.io/guide/control-flow)**: Guia oficial de Control Flow
- **[Pipes](https://angular.io/guide/pipes)**: Guia oficial de Pipes
- **[Built-in Pipes](https://angular.io/api/common#pipes)**: Lista de pipes embutidos
- **[AsyncPipe](https://angular.io/api/common/AsyncPipe)**: Documentação AsyncPipe

---

## Resumo

### Principais Conceitos

- Control Flow (@if, @for, @switch) substitui diretivas estruturais
- Pipes transformam dados para exibição
- AsyncPipe gerencia Observables automaticamente
- Pipes customizados criam transformações reutilizáveis
- Pure vs Impure afeta performance

### Pontos-Chave para Lembrar

- Use Control Flow em novos projetos
- Sempre use track em @for
- Use AsyncPipe para Observables
- Mantenha pipes pure quando possível
- Pipes são para transformação, não para lógica complexa

### Próximos Passos

- Próximo módulo: Desenvolvimento Intermediário
- Praticar migração para Control Flow
- Criar pipes customizados úteis

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

**Aula Anterior**: [Aula 1.4: Data Binding e Diretivas Modernas](./lesson-1-4-data-binding.md)  
**Próximo Módulo**: [Módulo 2: Desenvolvimento Intermediário](../modules/module-2-desenvolvimento-intermediario.md)  
**Voltar ao Módulo**: [Módulo 1: Fundamentos Acelerados](../modules/module-1-fundamentos-acelerados.md)

