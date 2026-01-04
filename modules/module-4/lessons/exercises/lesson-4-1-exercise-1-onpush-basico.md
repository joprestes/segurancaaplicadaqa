---
layout: exercise
title: "Exercício 4.1.1: Implementar OnPush Básico"
slug: "onpush-basico"
lesson_id: "lesson-4-1"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **OnPush strategy básica** através da **conversão de componente de Default para OnPush**.

Ao completar este exercício, você será capaz de:

- Converter componente para OnPush
- Entender diferença entre Default e OnPush
- Verificar que OnPush funciona corretamente
- Identificar quando OnPush é apropriado

---

## Descrição

Você precisa converter um componente que usa Default strategy para OnPush strategy.

### Contexto

Uma aplicação precisa melhorar performance convertendo componentes para OnPush.

### Tarefa

Crie:

1. **Componente Original**: Componente usando Default strategy
2. **Componente Convertido**: Versão usando OnPush
3. **Comparação**: Demonstre diferença
4. **Verificação**: Verifique que funciona corretamente

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente original criado
- [ ] Componente convertido para OnPush
- [ ] Funcionalidade mantida
- [ ] OnPush funciona corretamente
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] OnPush está implementado corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**counter-default.component.ts** (Original)
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter-default',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Contador (Default)</h2>
      <p>Valor: {{ count }}</p>
      <button (click)="increment()">Incrementar</button>
      <button (click)="decrement()">Decrementar</button>
    </div>
  `
})
export class CounterDefaultComponent {
  count = 0;
  
  increment(): void {
    this.count++;
  }
  
  decrement(): void {
    this.count--;
  }
}
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter-default',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Contador (Default)</h2>
      <p>Valor: {{ count }}</p>
      <button (click)="increment()">Incrementar</button>
      <button (click)="decrement()">Decrementar</button>
    </div>
  `
})
export class CounterDefaultComponent {
  count = 0;
  
  increment(): void {
    this.count++;
  }
  
  decrement(): void {
    this.count--;
  }
}
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter-default',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Contador (Default)</h2>
      <p>Valor: {{ count }}</p>
      <button (click)="increment()">Incrementar</button>
      <button (click)="decrement()">Decrementar</button>
    </div>
  `
})
export class CounterDefaultComponent {
  count = 0;
  
  increment(): void {
    this.count++;
  }
  
  decrement(): void {
    this.count--;
  }
}
```

**counter-onpush.component.ts** (Convertido)
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter-onpush',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>Contador (OnPush)</h2>
{% raw %}

      <p>Valor: {{ count() }}</p>
{% endraw %}

      <button (click)="increment()">Incrementar</button>
      <button (click)="decrement()">Decrementar</button>
    </div>
  `
})
export class CounterOnPushComponent {
  count = signal(0);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
  
  decrement(): void {
    this.count.update(v => v - 1);
  }
}
{% raw %}
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter-onpush',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>Contador (OnPush)</h2>
      <p>Valor: {{ count() }}</p>
      <button (click)="increment()">Incrementar</button>
      <button (click)="decrement()">Decrementar</button>
    </div>
  `
})
export class CounterOnPushComponent {
  count = signal(0);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
  
  decrement(): void {
    this.count.update(v => v - 1);
  }
}
```typescript
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter-onpush',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>Contador (OnPush)</h2>
      <p>Valor: {{ count() }}</p>
      <button (click)="increment()">Incrementar</button>
      <button (click)="decrement()">Decrementar</button>
    </div>
  `
})
export class CounterOnPushComponent {
  count = signal(0);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
  
  decrement(): void {
    this.count.update(v => v - 1);
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. ChangeDetectionStrategy.OnPush adicionado
2. Signal usado ao invés de propriedade simples
3. update() usado para mudanças imutáveis
4. Eventos do componente ainda disparam change detection
5. Funcionalidade mantida
6. Performance melhorada

---

## Testes

### Casos de Teste

**Teste 1**: Funcionalidade mantida
- **Input**: Clicar em botões
- **Output Esperado**: Contador funciona igual

**Teste 2**: OnPush funciona
- **Input**: Verificar change detection
- **Output Esperado**: OnPush detecta mudanças corretamente

**Teste 3**: Performance melhorada
- **Input**: Comparar performance
- **Output Esperado**: Menos verificações de change detection

---

## Extensões (Opcional)

1. **Múltiplos Componentes**: Converta múltiplos componentes
2. **Benchmark**: Compare performance real
3. **Profiling**: Use DevTools para verificar

---

## Referências Úteis

- **[OnPush](https://angular.io/api/core/ChangeDetectionStrategy)**: Documentação OnPush
- **[Change Detection](https://angular.io/guide/change-detection)**: Guia change detection

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

