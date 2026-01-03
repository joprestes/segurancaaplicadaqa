---
layout: exercise
title: "Exercício 2.5.1: @Input e @Output Básicos"
slug: "input-output"
lesson_id: "lesson-2-5"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **@Input e @Output básicos** através da **criação de comunicação pai-filho**.

Ao completar este exercício, você será capaz de:

- Usar @Input() para receber dados do pai
- Usar @Output() para emitir eventos para o pai
- Criar comunicação bidirecional
- Entender fluxo de dados entre componentes

---

## Descrição

Você precisa criar um componente contador que recebe valor inicial via @Input e emite mudanças via @Output.

### Contexto

Uma aplicação precisa de um componente reutilizável de contador que pode ser controlado pelo componente pai.

### Tarefa

Crie:

1. **CounterComponent**: Componente filho com @Input e @Output
2. **ParentComponent**: Componente pai que usa o contador
3. **Comunicação**: Dados fluem do pai para filho e eventos do filho para pai

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] CounterComponent criado com @Input
- [ ] @Output implementado com EventEmitter
- [ ] ParentComponent usa componente filho
- [ ] Dados passam do pai para filho
- [ ] Eventos passam do filho para pai
- [ ] Comunicação funciona corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Comunicação está clara
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**counter.component.ts**
```typescript
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="counter">
      <h3>Contador</h3>
      <p>Valor: {{ count }}</p>
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
    
    button {
      padding: 0.5rem 1rem;
    }
  `]
})
export class CounterComponent {
  @Input() initialValue: number = 0;
  @Output() valueChange = new EventEmitter<number>();
  
  count: number = 0;
  
  ngOnInit(): void {
    this.count = this.initialValue;
  }
  
  ngOnChanges(): void {
    this.count = this.initialValue;
  }
  
  increment(): void {
    this.count++;
    this.valueChange.emit(this.count);
  }
  
  decrement(): void {
    this.count--;
    this.valueChange.emit(this.count);
  }
  
  reset(): void {
    this.count = this.initialValue;
    this.valueChange.emit(this.count);
  }
}
```

**parent.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CounterComponent } from './counter.component';

@Component({
  selector: 'app-parent',
  standalone: true,
  imports: [CommonModule, CounterComponent],
  template: `
    <div>
      <h2>Componente Pai</h2>
      <p>Valor inicial: {{ initialValue }}</p>
      <p>Valor atual do contador: {{ currentValue }}</p>
      
      <app-counter 
        [initialValue]="initialValue"
        (valueChange)="onValueChange($event)">
      </app-counter>
      
      <div class="controls">
        <button (click)="setInitialValue(10)">Definir como 10</button>
        <button (click)="setInitialValue(0)">Resetar</button>
      </div>
    </div>
  `,
  styles: [`
    .controls {
      margin-top: 1rem;
      display: flex;
      gap: 0.5rem;
    }
  `]
})
export class ParentComponent {
  initialValue: number = 5;
  currentValue: number = 5;
  
  onValueChange(newValue: number): void {
    this.currentValue = newValue;
    console.log('Valor mudou para:', newValue);
  }
  
  setInitialValue(value: number): void {
    this.initialValue = value;
    this.currentValue = value;
  }
}
```

**Explicação da Solução**:

1. CounterComponent recebe initialValue via @Input
2. valueChange emite novo valor via @Output
3. ParentComponent passa dados e escuta eventos
4. ngOnChanges atualiza quando @Input muda
5. Comunicação bidirecional funciona
6. Código claro e bem estruturado

---

## Testes

### Casos de Teste

**Teste 1**: @Input funciona
- **Input**: Passar initialValue diferente
- **Output Esperado**: Contador atualiza

**Teste 2**: @Output funciona
- **Input**: Clicar em botões do contador
- **Output Esperado**: Evento emitido e capturado pelo pai

**Teste 3**: Comunicação bidirecional funciona
- **Input**: Mudar initialValue e usar contador
- **Output Esperado**: Ambos funcionam corretamente

---

## Extensões (Opcional)

1. **Two-Way Binding**: Implemente [(ngModel)] equivalente
2. **Validação**: Adicione limites mínimo e máximo
3. **Múltiplos Contadores**: Use múltiplos contadores no pai

---

## Referências Úteis

- **[Component Interaction](https://angular.io/guide/component-interaction)**: Guia oficial
- **[@Input](https://angular.io/api/core/Input)**: Documentação @Input
- **[@Output](https://angular.io/api/core/Output)**: Documentação @Output

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

