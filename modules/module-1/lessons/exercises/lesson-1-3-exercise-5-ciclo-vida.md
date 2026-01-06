---
layout: exercise
title: "Exercício 1.3.5: Ciclo de Vida Completo"
slug: "ciclo-vida"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **hooks do ciclo de vida** através da **implementação de um componente que demonstra todos os principais hooks**.

Ao completar este exercício, você será capaz de:

- Implementar todos os principais lifecycle hooks
- Entender ordem de execução dos hooks
- Usar hooks para inicialização e limpeza
- Prevenir memory leaks com ngOnDestroy
- Observar ciclo de vida completo

---

## Descrição

Você precisa criar um componente `LifecycleDemoComponent` que implementa e demonstra todos os principais hooks do ciclo de vida do Angular. O componente deve registrar logs para cada hook executado.

### Contexto

Um desenvolvedor precisa entender quando cada hook é chamado e para que serve. Criar um componente demonstrativo ajuda a visualizar o ciclo completo.

### Tarefa

Crie um componente `LifecycleDemoComponent` que:

1. **Implementa interfaces**: OnInit, OnDestroy, OnChanges, AfterViewInit, AfterContentInit
2. **ngOnChanges**: Log quando `@Input` muda
3. **ngOnInit**: Log na inicialização
4. **ngDoCheck**: Log em cada verificação (opcional, use com cuidado)
5. **ngAfterContentInit**: Log após conteúdo projetado inicializado
6. **ngAfterContentChecked**: Log após verificação de conteúdo
7. **ngAfterViewInit**: Log após view inicializada
8. **ngAfterViewChecked**: Log após verificação de view
9. **ngOnDestroy**: Log e limpeza antes de destruir
10. **Template**: Exibe lista de logs em tempo real

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Todas as interfaces de lifecycle implementadas
- [ ] Cada hook registra log com timestamp
- [ ] Logs são exibidos no template
- [ ] @Input para testar ngOnChanges
- [ ] Subscription limpa em ngOnDestroy
- [ ] Componente pode ser criado e destruído

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todos os hooks são implementados corretamente
- [ ] Logs são claros e informativos
- [ ] Limpeza adequada em ngOnDestroy
- [ ] Código é bem organizado

---

## Dicas

### Dica 1: Implementar Interfaces

```typescript
import { OnInit, OnDestroy, OnChanges, AfterViewInit, AfterContentInit } from '@angular/core';

export class MyComponent implements OnInit, OnDestroy, OnChanges {
  // implementação
}
```

### Dica 2: ngOnChanges com SimpleChanges

```typescript
ngOnChanges(changes: SimpleChanges): void {
  console.log('ngOnChanges', changes);
}
```

### Dica 3: Limpar em ngOnDestroy

```typescript
private subscription?: Subscription;

ngOnDestroy(): void {
  this.subscription?.unsubscribe();
}
```

### Dica 4: Usar Array para Logs

```typescript
logs: string[] = [];

addLog(message: string): void {
  this.logs.push(`${new Date().toLocaleTimeString()}: ${message}`);
}
```

---

## Solução Esperada

### Abordagem Recomendada

**lifecycle-demo.component.ts**
```typescript
import { 
  Component, 
  Input, 
  OnInit, 
  OnDestroy, 
  OnChanges, 
  SimpleChanges,
  AfterViewInit,
  AfterContentInit,
  AfterContentChecked,
  AfterViewChecked,
  DoCheck,
  ChangeDetectorRef
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { interval, Subscription } from 'rxjs';

interface LogEntry {
  timestamp: string;
  hook: string;
  message: string;
}

@Component({
  selector: 'app-lifecycle-demo',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './lifecycle-demo.component.html',
  styleUrls: ['./lifecycle-demo.component.css']
})
export class LifecycleDemoComponent implements 
  OnInit, 
  OnDestroy, 
  OnChanges,
  AfterViewInit,
  AfterContentInit,
  AfterContentChecked,
  AfterViewChecked,
  DoCheck {
  
  @Input() userId: number = 0;
  @Input() userName: string = '';
  
  logs: LogEntry[] = [];
  private subscription?: Subscription;
  private changeCount: number = 0;

  constructor(private cdr: ChangeDetectorRef) {
    this.addLog('constructor', 'Componente instanciado');
  }

  ngOnChanges(changes: SimpleChanges): void {
    this.addLog('ngOnChanges', `Mudanças detectadas: ${Object.keys(changes).join(', ')}`);
    
    if (changes['userId']) {
      this.addLog('ngOnChanges', `userId mudou de ${changes['userId'].previousValue} para ${changes['userId'].currentValue}`);
    }
  }

  ngOnInit(): void {
    this.addLog('ngOnInit', 'Componente inicializado');
    
    this.subscription = interval(1000).subscribe(() => {
      this.addLog('ngOnInit', `Timer tick: ${new Date().toLocaleTimeString()}`);
    });
  }

  ngDoCheck(): void {
    this.changeCount++;
    if (this.changeCount % 10 === 0) {
      this.addLog('ngDoCheck', `Verificação de mudanças #${this.changeCount}`);
    }
  }

  ngAfterContentInit(): void {
    this.addLog('ngAfterContentInit', 'Conteúdo projetado inicializado');
  }

  ngAfterContentChecked(): void {
    if (this.changeCount % 5 === 0) {
      this.addLog('ngAfterContentChecked', 'Conteúdo verificado');
    }
  }

  ngAfterViewInit(): void {
    this.addLog('ngAfterViewInit', 'View inicializada');
  }

  ngAfterViewChecked(): void {
    if (this.changeCount % 5 === 0) {
      this.addLog('ngAfterViewChecked', 'View verificada');
    }
  }

  ngOnDestroy(): void {
    this.addLog('ngOnDestroy', 'Componente sendo destruído');
    this.subscription?.unsubscribe();
    this.addLog('ngOnDestroy', 'Recursos limpos');
  }

  private addLog(hook: string, message: string): void {
    const entry: LogEntry = {
      timestamp: new Date().toLocaleTimeString(),
      hook,
      message
    };
    this.logs.push(entry);
    
    if (this.logs.length > 50) {
      this.logs.shift();
    }
  }

  clearLogs(): void {
    this.logs = [];
  }

  getLogsByHook(hook: string): LogEntry[] {
    return this.logs.filter(log => log.hook === hook);
  }
}
```

**lifecycle-demo.component.html**
{% raw %}
```html
<div class="lifecycle-demo">
  <div class="demo-controls">
    <h2>Lifecycle Demo Component</h2>
    <div class="inputs">
      <label>
        User ID: 
        <input type="number" [value]="userId" (input)="userId = +$any($event.target).value">
      </label>
      <label>
        User Name: 
        <input type="text" [value]="userName" (input)="userName = $any($event.target).value">
      </label>
    </div>
    <button (click)="clearLogs()">Limpar Logs</button>
  </div>

  <div class="logs-container">
    <h3>Logs do Ciclo de Vida ({{ logs.length }})</h3>
    <div class="logs">
      <div 
        *ngFor="let log of logs; trackBy: trackByTimestamp" 
        class="log-entry"
        [class]="'log-' + log.hook">
        <span class="timestamp">{{ log.timestamp }}</span>
        <span class="hook">{{ log.hook }}</span>
        <span class="message">{{ log.message }}</span>
      </div>
    </div>
  </div>

  <div class="summary">
    <h3>Resumo por Hook</h3>
    <div class="hook-summary">
      <div *ngFor="let hook of getHooks()" class="summary-item">
        <strong>{{ hook }}:</strong> {{ getLogsByHook(hook).length }} chamadas
      </div>
    </div>
  </div>
</div>
```
{% raw %}
<div class="lifecycle-demo">
  <div class="demo-controls">
    <h2>Lifecycle Demo Component</h2>
    <div class="inputs">
      <label>
        User ID: 
        <input type="number" [value]="userId" (input)="userId = +$any($event.target).value">
      </label>
      <label>
        User Name: 
        <input type="text" [value]="userName" (input)="userName = $any($event.target).value">
      </label>
    </div>
    <button (click)="clearLogs()">Limpar Logs</button>
  </div>

  <div class="logs-container">
    <h3>Logs do Ciclo de Vida ({{ logs.length }})</h3>
    <div class="logs">
      <div 
        *ngFor="let log of logs; trackBy: trackByTimestamp" 
        class="log-entry"
        [class]="'log-' + log.hook">
        <span class="timestamp">{{ log.timestamp }}</span>
        <span class="hook">{{ log.hook }}</span>
        <span class="message">{{ log.message }}</span>
      </div>
    </div>
  </div>

  <div class="summary">
    <h3>Resumo por Hook</h3>
    <div class="hook-summary">
      <div *ngFor="let hook of getHooks()" class="summary-item">
        <strong>{{ hook }}:</strong> {{ getLogsByHook(hook).length }} chamadas
      </div>
    </div>
  </div>
</div>
```
{% endraw %}

**lifecycle-demo.component.css**
```css
.lifecycle-demo {
  max-width: 900px;
  margin: 0 auto;
  padding: 2rem;
}

.demo-controls {
  margin-bottom: 2rem;
  padding: 1rem;
  background-color: #f5f5f5;
  border-radius: 4px;
}

.inputs {
  display: flex;
  gap: 1rem;
  margin: 1rem 0;
}

.inputs label {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.logs-container {
  margin-bottom: 2rem;
}

.logs {
  max-height: 400px;
  overflow-y: auto;
  border: 1px solid #ddd;
  border-radius: 4px;
  padding: 1rem;
  background-color: #fafafa;
}

.log-entry {
  display: grid;
  grid-template-columns: 100px 150px 1fr;
  gap: 1rem;
  padding: 0.5rem;
  margin-bottom: 0.25rem;
  border-left: 3px solid #ccc;
  font-size: 0.875rem;
}

.log-constructor { border-left-color: #2196f3; }
.log-ngOnChanges { border-left-color: #4caf50; }
.log-ngOnInit { border-left-color: #ff9800; }
.log-ngDoCheck { border-left-color: #9c27b0; }
.log-ngAfterContentInit { border-left-color: #f44336; }
.log-ngAfterContentChecked { border-left-color: #00bcd4; }
.log-ngAfterViewInit { border-left-color: #795548; }
.log-ngAfterViewChecked { border-left-color: #607d8b; }
.log-ngOnDestroy { border-left-color: #e91e63; }

.timestamp {
  color: #666;
  font-weight: 500;
}

.hook {
  color: #1976d2;
  font-weight: 600;
}

.message {
  color: #333;
}

.summary {
  padding: 1rem;
  background-color: #e3f2fd;
  border-radius: 4px;
}

.hook-summary {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-top: 1rem;
}

.summary-item {
  padding: 0.5rem;
  background-color: white;
  border-radius: 4px;
}
```

**app.component.ts** (exemplo de uso)
{% raw %}
```typescript
import { Component } from '@angular/core';
import { LifecycleDemoComponent } from './lifecycle-demo/lifecycle-demo.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [LifecycleDemoComponent],
  template: `
    <button (click)="toggleDemo()">
      {{ showDemo ? 'Destruir' : 'Criar' }} Componente
    </button>
    <app-lifecycle-demo 
      *ngIf="showDemo"
      [userId]="currentUserId"
      [userName]="currentUserName">
    </app-lifecycle-demo>
  `
})
export class AppComponent {
  showDemo: boolean = true;
  currentUserId: number = 1;
  currentUserName: string = 'João';

  toggleDemo(): void {
    this.showDemo = !this.showDemo;
    if (this.showDemo) {
      this.currentUserId++;
    }
  }
}
```
{% raw %}
import { Component } from '@angular/core';
import { LifecycleDemoComponent } from './lifecycle-demo/lifecycle-demo.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [LifecycleDemoComponent],
  template: `
    <button (click)="toggleDemo()">
      {{ showDemo ? 'Destruir' : 'Criar' }} Componente
    </button>
    <app-lifecycle-demo 
      *ngIf="showDemo"
      [userId]="currentUserId"
      [userName]="currentUserName">
    </app-lifecycle-demo>
  `
})
export class AppComponent {
  showDemo: boolean = true;
  currentUserId: number = 1;
  currentUserName: string = 'João';

  toggleDemo(): void {
    this.showDemo = !this.showDemo;
    if (this.showDemo) {
      this.currentUserId++;
    }
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. Todas as interfaces de lifecycle implementadas
2. Cada hook adiciona log com timestamp
3. Logs são exibidos em tempo real no template
4. @Input permite testar ngOnChanges
5. Subscription é limpa em ngOnDestroy
6. Resumo mostra contagem por hook
7. Componente pode ser criado/destruído dinamicamente

**Decisões de Design**:

- Logs limitados a 50 para performance
- Cores diferentes por hook para visualização
- Resumo estatístico para análise
- Controles para testar diferentes cenários

---

## Testes

### Casos de Teste

**Teste 1**: Ordem de execução inicial
- **Input**: Componente criado
- **Output Esperado**: Logs devem aparecer na ordem: constructor → ngOnChanges → ngOnInit → ngAfterContentInit → ngAfterViewInit

**Teste 2**: ngOnChanges ao mudar @Input
- **Input**: Mudar `userId` ou `userName`
- **Output Esperado**: ngOnChanges deve ser chamado com mudanças

**Teste 3**: Limpeza em ngOnDestroy
- **Input**: Destruir componente
- **Output Esperado**: ngOnDestroy deve ser chamado e subscription limpa

**Teste 4**: ngDoCheck frequente
- **Input**: Componente renderizado
- **Output Esperado**: ngDoCheck deve ser chamado frequentemente (limitado no log)

**Teste 5**: Resumo de hooks
- **Input**: Componente executado por algum tempo
- **Output Esperado**: Resumo deve mostrar contagem de cada hook

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Adicionar Gráfico**: Crie gráfico visual mostrando frequência de cada hook
2. **Exportar Logs**: Adicione funcionalidade para exportar logs
3. **Filtros**: Adicione filtros para mostrar apenas hooks específicos
4. **Performance**: Meça tempo de execução de cada hook

---

## Referências Úteis

- **[Lifecycle Hooks](https://angular.io/guide/lifecycle-hooks)**: Guia completo de lifecycle hooks
- **[OnInit](https://angular.io/api/core/OnInit)**: Documentação OnInit
- **[OnDestroy](https://angular.io/api/core/OnDestroy)**: Documentação OnDestroy
- **[OnChanges](https://angular.io/api/core/OnChanges)**: Documentação OnChanges

---

## Checklist de Qualidade

Antes de considerar este exercício completo:

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

