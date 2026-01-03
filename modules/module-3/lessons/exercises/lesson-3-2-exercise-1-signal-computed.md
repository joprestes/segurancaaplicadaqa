---
layout: exercise
title: "Exercício 3.2.1: signal() e computed() Básicos"
slug: "signal-computed"
lesson_id: "lesson-3-2"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **signal() e computed() básicos** através da **criação de componente que usa signals para gerenciar estado**.

Ao completar este exercício, você será capaz de:

- Criar signals básicos
- Criar computed signals
- Atualizar signals com set() e update()
- Entender reatividade automática
- Usar signals no template

---

## Descrição

Você precisa criar um componente de calculadora simples que usa signals para estado e computed para valores derivados.

### Contexto

Uma aplicação precisa entender fundamentos de Signals antes de usar recursos avançados.

### Tarefa

Crie:

1. **Signals**: Criar signals para valores de entrada
2. **Computed**: Criar computed para resultados
3. **Template**: Usar signals no template
4. **Atualização**: Atualizar signals via métodos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Signals criados para valores de entrada
- [ ] Computed signals criados para resultados
- [ ] Template usa signals corretamente
- [ ] Valores atualizam automaticamente
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Signals estão bem estruturados
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**calculator-signal.component.ts**
{% raw %}
```typescript
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-calculator-signal',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="calculator">
      <h2>Calculadora com Signals</h2>
      
      <div class="inputs">
        <input 
          type="number" 
          [value]="value1()" 
          (input)="value1.set(+$any($event.target).value)"
          placeholder="Primeiro número">
        <input 
          type="number" 
          [value]="value2()" 
          (input)="value2.set(+$any($event.target).value)"
          placeholder="Segundo número">
      </div>
      
      <div class="results">
        <p>Soma: {{ sum() }}</p>
        <p>Subtração: {{ difference() }}</p>
        <p>Multiplicação: {{ product() }}</p>
        <p>Divisão: {{ quotient() }}</p>
        <p>Média: {{ average() }}</p>
      </div>
      
      <div class="actions">
        <button (click)="reset()">Resetar</button>
        <button (click)="swap()">Trocar Valores</button>
      </div>
    </div>
  `,
  styles: [`
    .calculator {
      max-width: 400px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    .inputs {
      display: flex;
      gap: 1rem;
      margin-bottom: 1rem;
    }
    
    .inputs input {
      flex: 1;
      padding: 0.5rem;
    }
    
    .results {
      margin: 1rem 0;
    }
    
    .results p {
      padding: 0.5rem;
      background-color: #f0f0f0;
      margin-bottom: 0.5rem;
      border-radius: 4px;
    }
    
    .actions {
      display: flex;
      gap: 0.5rem;
    }
    
    button {
      flex: 1;
      padding: 0.75rem;
    }
  `]
})
export class CalculatorSignalComponent {
  value1 = signal<number>(0);
  value2 = signal<number>(0);
  
  sum = computed(() => this.value1() + this.value2());
  difference = computed(() => this.value1() - this.value2());
  product = computed(() => this.value1() * this.value2());
  quotient = computed(() => {
    const v2 = this.value2();
    return v2 !== 0 ? this.value1() / v2 : 0;
  });
  average = computed(() => (this.value1() + this.value2()) / 2);
  
  reset(): void {
    this.value1.set(0);
    this.value2.set(0);
  }
  
  swap(): void {
    const temp = this.value1();
    this.value1.set(this.value2());
    this.value2.set(temp);
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. value1 e value2 são signals básicos
2. Computed signals calculam valores derivados
3. Template usa signals com () para acessar valores
4. Atualização via set() e métodos helper
5. Reatividade automática quando valores mudam
6. Código simples e direto

---

## Testes

### Casos de Teste

**Teste 1**: Signals atualizam
- **Input**: Mudar valor1
- **Output Esperado**: Todos computed atualizam automaticamente

**Teste 2**: Computed funciona
- **Input**: Mudar ambos valores
- **Output Esperado**: Resultados recalculados

**Teste 3**: Métodos funcionam
- **Input**: Clicar em "Resetar" ou "Trocar"
- **Output Esperado**: Valores atualizados corretamente

---

## Extensões (Opcional)

1. **Mais Operações**: Adicione mais operações matemáticas
2. **Histórico**: Mantenha histórico de cálculos
3. **Validação**: Adicione validação de valores

---

## Referências Úteis

- **[signal()](https://angular.io/api/core/signal)**: Documentação signal()
- **[computed()](https://angular.io/api/core/computed)**: Documentação computed()

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

