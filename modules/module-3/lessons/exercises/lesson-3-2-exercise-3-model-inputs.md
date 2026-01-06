---
layout: exercise
title: "Exercício 3.2.3: Model Inputs"
slug: "model-inputs"
lesson_id: "lesson-3-2"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Model Inputs** através da **implementação de two-way binding usando model()**.

Ao completar este exercício, você será capaz de:

- Usar model() para two-way binding
- Criar comunicação bidirecional com signals
- Entender diferença entre input() e model()
- Implementar componentes com Model Inputs
- Trabalhar com Model Inputs em hierarquias

---

## Descrição

Você precisa criar componentes que usam model() para two-way binding entre pai e filho.

### Contexto

Uma aplicação precisa de componentes que permitem two-way binding usando signals.

### Tarefa

Crie:

1. **Child Component**: Componente filho com model()
2. **Parent Component**: Componente pai que usa model()
3. **Two-Way Binding**: Implementar binding bidirecional
4. **Hierarquia**: Demonstrar uso em múltiplos níveis

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] model() implementado no filho
- [ ] Two-way binding funciona
- [ ] Pai e filho sincronizados
- [ ] Múltiplos Model Inputs funcionam
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Binding está correto
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**counter-model.component.ts**
import { Component, model } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter-model',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="counter">
      <h3>Contador</h3>
{% raw %}
      <p>Valor: {{ count() }}</p>
{% endraw %}

      <div class="buttons">
        <button (click)="increment()">+</button>
        <button (click)="decrement()">-</button>
        <button (click)="reset()">Reset</button>
      </div>
    </div>
  `,
  styles: [`
    .counter {
      border: 1px solid #ccc;
      padding: 1rem;
      border-radius: 4px;
    }
    
    .buttons {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
    }
  `]
})
export class CounterModelComponent {
  count = model<number>(0);
  
  increment(): void {
    this.count.update(value => value + 1);
  }
  
  decrement(): void {
    this.count.update(value => value - 1);
  }
  
  reset(): void {
    this.count.set(0);
  }
}
{% raw %}
import { Component, model } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter-model',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="counter">
      <h3>Contador</h3>
{% raw %}
      <p>Valor: {{ count() }}</p>
{% endraw %}
      <div class="buttons">
        <button (click)="increment()">+</button>
        <button (click)="decrement()">-</button>
        <button (click)="reset()">Reset</button>
      </div>
    </div>
  `,
  styles: [`
    .counter {
      border: 1px solid #ccc;
      padding: 1rem;
      border-radius: 4px;
    }
    
    .buttons {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
    }
  `]
})
export class CounterModelComponent {
  count = model<number>(0);
  
  increment(): void {
    this.count.update(value => value + 1);
  }
  
  decrement(): void {
    this.count.update(value => value - 1);
  }
  
  reset(): void {
    this.count.set(0);
  }
}
{% raw %}
```typescript
import { Component, model } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter-model',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="counter">
      <h3>Contador</h3>
      <p>Valor: {{ count() }}</p>
      <div class="buttons">
        <button (click)="increment()">+</button>
        <button (click)="decrement()">-</button>
        <button (click)="reset()">Reset</button>
      </div>
    </div>
  `,
  styles: [`
    .counter {
      border: 1px solid #ccc;
      padding: 1rem;
      border-radius: 4px;
    }
    
    .buttons {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
    }
  `]
})
export class CounterModelComponent {
  count = model<number>(0);
  
  increment(): void {
    this.count.update(value => value + 1);
  }
  
  decrement(): void {
    this.count.update(value => value - 1);
  }
  
  reset(): void {
    this.count.set(0);
  }
}
```
{% endraw %}

**parent-model.component.ts**
import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CounterModelComponent } from './counter-model.component';

@Component({
  selector: 'app-parent-model',
  standalone: true,
  imports: [CommonModule, CounterModelComponent],
  template: `
    <div>
      <h2>Parent Component</h2>
{% raw %}
      <p>Valor no pai: {{ parentCount() }}</p>
{% endraw %}

      
      <app-counter-model [(count)]="parentCount"></app-counter-model>
      
      <div class="controls">
        <button (click)="setValue(10)">Definir como 10</button>
        <button (click)="setValue(0)">Resetar</button>
        <button (click)="increment()">Incrementar do Pai</button>
      </div>
    </div>
  `
})
export class ParentModelComponent {
  parentCount = signal<number>(5);
  
  setValue(value: number): void {
    this.parentCount.set(value);
  }
  
  increment(): void {
    this.parentCount.update(value => value + 1);
  }
}
{% raw %}
import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CounterModelComponent } from './counter-model.component';

@Component({
  selector: 'app-parent-model',
  standalone: true,
  imports: [CommonModule, CounterModelComponent],
  template: `
    <div>
      <h2>Parent Component</h2>
{% raw %}
      <p>Valor no pai: {{ parentCount() }}</p>
{% endraw %}
      
      <app-counter-model [(count)]="parentCount"></app-counter-model>
      
      <div class="controls">
        <button (click)="setValue(10)">Definir como 10</button>
        <button (click)="setValue(0)">Resetar</button>
        <button (click)="increment()">Incrementar do Pai</button>
      </div>
    </div>
  `
})
export class ParentModelComponent {
  parentCount = signal<number>(5);
  
  setValue(value: number): void {
    this.parentCount.set(value);
  }
  
  increment(): void {
    this.parentCount.update(value => value + 1);
  }
}
{% raw %}
```typescript
import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CounterModelComponent } from './counter-model.component';

@Component({
  selector: 'app-parent-model',
  standalone: true,
  imports: [CommonModule, CounterModelComponent],
  template: `
    <div>
      <h2>Parent Component</h2>
      <p>Valor no pai: {{ parentCount() }}</p>
      
      <app-counter-model [(count)]="parentCount"></app-counter-model>
      
      <div class="controls">
        <button (click)="setValue(10)">Definir como 10</button>
        <button (click)="setValue(0)">Resetar</button>
        <button (click)="increment()">Incrementar do Pai</button>
      </div>
    </div>
  `
})
export class ParentModelComponent {
  parentCount = signal<number>(5);
  
  setValue(value: number): void {
    this.parentCount.set(value);
  }
  
  increment(): void {
    this.parentCount.update(value => value + 1);
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. model() cria two-way binding signal
2. [(count)] sintaxe de banana-in-box funciona
3. Pai pode atualizar e filho pode atualizar
4. Sincronização automática bidirecional
5. Código simples e direto
6. Type-safe por padrão

---

## Testes

### Casos de Teste

**Teste 1**: Two-way binding funciona
- **Input**: Mudar valor no filho
- **Output Esperado**: Valor no pai atualiza

**Teste 2**: Pai atualiza filho
- **Input**: Clicar em botão do pai
- **Output Esperado**: Valor no filho atualiza

**Teste 3**: Sincronização bidirecional
- **Input**: Mudar em qualquer lugar
- **Output Esperado**: Ambos sincronizados

---

## Extensões (Opcional)

1. **Múltiplos Models**: Adicione múltiplos Model Inputs
2. **Validação**: Adicione validação ao Model Input
3. **Transformação**: Transforme valores no Model Input

---

## Referências Úteis

- **[model()](https://angular.io/api/core/model)**: Documentação model()
- **[Two-Way Binding](https://angular.io/guide/two-way-binding)**: Guia two-way binding

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

