---
layout: exercise
title: "Exercício 3.1.1: Observables Básicos"
slug: "observables-basicos"
lesson_id: "lesson-3-1"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Observables básicos** através da **criação de Observables simples e demonstração de subscription**.

Ao completar este exercício, você será capaz de:

- Criar Observable manualmente
- Criar Observable usando operadores de criação
- Fazer subscription e receber valores
- Entender lifecycle de Observable
- Gerenciar subscriptions

---

## Descrição

Você precisa criar diferentes tipos de Observables e demonstrar como fazer subscription e gerenciar lifecycle.

### Contexto

Uma aplicação precisa entender fundamentos de Observables antes de usar operators avançados.

### Tarefa

Crie:

1. **Observable Manual**: Criar Observable usando constructor
2. **Observable com of()**: Criar Observable com valores fixos
3. **Observable com interval()**: Criar Observable que emite valores periodicamente
4. **Subscription**: Fazer subscription e gerenciar lifecycle
5. **Componente**: Componente que demonstra uso

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Observable manual criado
- [ ] Observable com of() criado
- [ ] Observable com interval() criado
- [ ] Subscriptions funcionam
- [ ] Unsubscribe implementado
- [ ] Componente demonstra uso

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Subscriptions são gerenciadas
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**observable-demo.component.ts**
{% raw %}
```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Observable, Observer, of, interval, Subscription } from 'rxjs';

@Component({
  selector: 'app-observable-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Observables Básicos</h2>
      
      <section>
        <h3>Observable Manual</h3>
        <button (click)="startManualObservable()">Iniciar</button>
        <ul>
          @for (value of manualValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>Observable com of()</h3>
        <button (click)="startOfObservable()">Iniciar</button>
        <ul>
          @for (value of ofValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>Observable com interval()</h3>
        <button (click)="startIntervalObservable()">Iniciar</button>
        <button (click)="stopIntervalObservable()">Parar</button>
        <p>Valor atual: {{ intervalValue }}</p>
      </section>
    </div>
  `
})
export class ObservableDemoComponent implements OnInit, OnDestroy {
  manualValues: number[] = [];
  ofValues: string[] = [];
  intervalValue: number = 0;
  
  private intervalSubscription?: Subscription;
  
  ngOnInit(): void {
    console.log('Component initialized');
  }
  
  startManualObservable(): void {
    this.manualValues = [];
    
    const manualObservable = new Observable<number>((observer: Observer<number>) => {
      console.log('Manual Observable: Starting execution');
      
      observer.next(1);
      observer.next(2);
      observer.next(3);
      
      setTimeout(() => {
        observer.next(4);
        observer.complete();
        console.log('Manual Observable: Completed');
      }, 1000);
    });
    
    manualObservable.subscribe({
      next: (value) => {
        console.log('Manual Observable: Received', value);
        this.manualValues.push(value);
      },
      error: (error) => {
        console.error('Manual Observable: Error', error);
      },
      complete: () => {
        console.log('Manual Observable: Subscription completed');
      }
    });
  }
  
  startOfObservable(): void {
    this.ofValues = [];
    
    const ofObservable = of('Apple', 'Banana', 'Cherry');
    
    ofObservable.subscribe({
      next: (value) => {
        console.log('of() Observable: Received', value);
        this.ofValues.push(value);
      },
      complete: () => {
        console.log('of() Observable: Completed');
      }
    });
  }
  
  startIntervalObservable(): void {
    this.intervalValue = 0;
    
    const intervalObservable = interval(1000);
    
    this.intervalSubscription = intervalObservable.subscribe({
      next: (value) => {
        console.log('interval() Observable: Received', value);
        this.intervalValue = value;
      }
    });
  }
  
  stopIntervalObservable(): void {
    if (this.intervalSubscription) {
      this.intervalSubscription.unsubscribe();
      console.log('interval() Observable: Unsubscribed');
    }
  }
  
  ngOnDestroy(): void {
    this.stopIntervalObservable();
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. Observable manual criado com constructor
2. Observer implementado com next, error, complete
3. Observable com of() para valores fixos
4. Observable com interval() para valores periódicos
5. Subscriptions gerenciadas adequadamente
6. Unsubscribe implementado para evitar memory leaks
7. Componente demonstra todos os casos

---

## Testes

### Casos de Teste

**Teste 1**: Observable manual funciona
- **Input**: Clicar em "Iniciar" no Observable Manual
- **Output Esperado**: Valores 1, 2, 3, 4 aparecem na lista

**Teste 2**: Observable com of() funciona
- **Input**: Clicar em "Iniciar" no Observable com of()
- **Output Esperado**: Valores Apple, Banana, Cherry aparecem

**Teste 3**: Observable com interval() funciona
- **Input**: Clicar em "Iniciar" e depois "Parar"
- **Output Esperado**: Valores incrementam e param ao clicar em "Parar"

---

## Extensões (Opcional)

1. **from()**: Adicione exemplo com from() para arrays
2. **fromEvent()**: Adicione exemplo com eventos do DOM
3. **timer()**: Adicione exemplo com timer()

---

## Referências Úteis

- **[RxJS Observable](https://rxjs.dev/api/index/class/Observable)**: Documentação Observable
- **[Creation Operators](https://rxjs.dev/guide/operators#creation-operators)**: Guia operadores de criação

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

