---
layout: exercise
title: "Exercício 2.1.1: Criar Serviço Básico"
slug: "servico-basico"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **criação de serviços básicos** através da **implementação de um serviço de calculadora**.

Ao completar este exercício, você será capaz de:

- Criar serviço standalone com @Injectable
- Configurar providedIn: 'root'
- Implementar métodos no serviço
- Injetar serviço em componente
- Usar serviço no template

---

## Descrição

Você precisa criar um serviço `CalculatorService` que fornece operações matemáticas básicas e usá-lo em um componente.

### Contexto

Uma aplicação precisa de funcionalidades de cálculo que podem ser reutilizadas em múltiplos componentes. Um serviço é a solução ideal.

### Tarefa

Crie um serviço `CalculatorService` com:

1. **Métodos**: add, subtract, multiply, divide
2. **@Injectable**: Configurado com providedIn: 'root'
3. **Uso**: Injete e use em um componente
4. **Interface**: Crie componente que usa o serviço

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Serviço criado com @Injectable
- [ ] providedIn: 'root' configurado
- [ ] Métodos add, subtract, multiply, divide implementados
- [ ] Serviço injetado em componente
- [ ] Componente usa métodos do serviço
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Serviço é standalone
- [ ] Métodos são bem definidos
- [ ] Código é legível

---

## Dicas

### Dica 1: Estrutura Básica

```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class CalculatorService {
  // métodos aqui
}
```

### Dica 2: Métodos Simples

```typescript
add(a: number, b: number): number {
  return a + b;
}
```

### Dica 3: Injetar no Componente

```typescript
constructor(private calculator: CalculatorService) {}
```

---

## Solução Esperada

### Abordagem Recomendada

**calculator.service.ts**
```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class CalculatorService {
  add(a: number, b: number): number {
    return a + b;
  }
  
  subtract(a: number, b: number): number {
    return a - b;
  }
  
  multiply(a: number, b: number): number {
    return a * b;
  }
  
  divide(a: number, b: number): number {
    if (b === 0) {
      throw new Error('Division by zero is not allowed');
    }
    return a / b;
  }
  
  power(base: number, exponent: number): number {
    return Math.pow(base, exponent);
  }
  
  sqrt(value: number): number {
    if (value < 0) {
      throw new Error('Square root of negative number is not allowed');
    }
    return Math.sqrt(value);
  }
}
```

**calculator.component.ts**
{% raw %}
```typescript
import { Component } from '@angular/core';
import { CalculatorService } from './calculator.service';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-calculator',
  standalone: true,
  imports: [FormsModule, CommonModule],
  template: `
    <div class="calculator">
      <h2>Calculadora</h2>
      
      <div class="inputs">
        <input type="number" [(ngModel)]="value1" placeholder="Primeiro número">
        <input type="number" [(ngModel)]="value2" placeholder="Segundo número">
      </div>
      
      <div class="operations">
        <button (click)="calculate('add')">+</button>
        <button (click)="calculate('subtract')">-</button>
        <button (click)="calculate('multiply')">×</button>
        <button (click)="calculate('divide')">÷</button>
      </div>
      
      <div class="result" *ngIf="result !== null">
        <h3>Resultado: {{ result }}</h3>
      </div>
      
      <div class="error" *ngIf="error">
        <p>{{ error }}</p>
      </div>
    </div>
  `,
  styles: [`
{% endraw %}
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
    
    .operations {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }
    
    .operations button {
      flex: 1;
      padding: 0.75rem;
      font-size: 1.5rem;
    }
    
    .result {
      text-align: center;
      padding: 1rem;
      background-color: #e8f5e9;
      border-radius: 4px;
    }
    
    .error {
      color: #f44336;
      text-align: center;
    }
  `]
})
export class CalculatorComponent {
  value1: number = 0;
  value2: number = 0;
  result: number | null = null;
  error: string = '';
  
  constructor(private calculator: CalculatorService) {}
  
  calculate(operation: string): void {
    this.error = '';
    this.result = null;
    
    try {
      switch (operation) {
        case 'add':
          this.result = this.calculator.add(this.value1, this.value2);
          break;
        case 'subtract':
          this.result = this.calculator.subtract(this.value1, this.value2);
          break;
        case 'multiply':
          this.result = this.calculator.multiply(this.value1, this.value2);
          break;
        case 'divide':
          this.result = this.calculator.divide(this.value1, this.value2);
          break;
      }
    } catch (err) {
      this.error = err instanceof Error ? err.message : 'Erro desconhecido';
    }
  }
}
```

**Explicação da Solução**:

1. Serviço criado com `@Injectable` e `providedIn: 'root'`
2. Métodos matemáticos implementados
3. Tratamento de erros para divisão por zero
4. Serviço injetado no componente via constructor
5. Componente usa métodos do serviço
6. Interface simples e funcional

---

## Testes

### Casos de Teste

**Teste 1**: Adição funciona
- **Input**: value1=5, value2=3, operação=add
- **Output Esperado**: result=8

**Teste 2**: Divisão por zero
- **Input**: value1=10, value2=0, operação=divide
- **Output Esperado**: error="Division by zero is not allowed"

**Teste 3**: Todas operações funcionam
- **Input**: Testar todas as operações
- **Output Esperado**: Resultados corretos

---

## Extensões (Opcional)

1. **Histórico**: Adicione método para manter histórico de cálculos
2. **Memória**: Adicione funcionalidade de memória (M+, M-, MR, MC)
3. **Operações Avançadas**: Adicione mais operações (potência, raiz)

---

## Referências Úteis

- **[Angular Services](https://angular.io/guide/services)**: Guia oficial
- **[@Injectable](https://angular.io/api/core/Injectable)**: Documentação @Injectable

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

