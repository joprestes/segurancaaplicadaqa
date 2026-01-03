---
layout: exercise
title: "Exercício 3.1.5: Subjects"
slug: "subjects"
lesson_id: "lesson-3-1"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Subjects** através da **criação de serviço de comunicação usando diferentes tipos de Subjects**.

Ao completar este exercício, você será capaz de:

- Usar Subject para multicast
- Usar BehaviorSubject para estado atual
- Usar ReplaySubject para histórico
- Usar AsyncSubject para último valor
- Escolher Subject correto para cada situação

---

## Descrição

Você precisa criar um serviço de comunicação que demonstra diferentes tipos de Subjects e seus comportamentos.

### Contexto

Uma aplicação precisa de comunicação entre componentes usando diferentes estratégias de Subjects.

### Tarefa

Crie:

1. **Subject**: Comunicação básica multicast
2. **BehaviorSubject**: Estado atual compartilhado
3. **ReplaySubject**: Histórico de valores
4. **AsyncSubject**: Último valor ao completar
5. **Comparação**: Demonstre diferenças

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Subject implementado
- [ ] BehaviorSubject implementado
- [ ] ReplaySubject implementado
- [ ] AsyncSubject implementado
- [ ] Diferenças demonstradas
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Diferenças estão claras
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**subject-demo.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { Subject, BehaviorSubject, ReplaySubject, AsyncSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class SubjectDemoService {
  private subject = new Subject<string>();
  private behaviorSubject = new BehaviorSubject<string>('Valor inicial');
  private replaySubject = new ReplaySubject<string>(3);
  private asyncSubject = new AsyncSubject<string>();
  
  getSubject(): Subject<string> {
    return this.subject;
  }
  
  getBehaviorSubject(): BehaviorSubject<string> {
    return this.behaviorSubject;
  }
  
  getReplaySubject(): ReplaySubject<string> {
    return this.replaySubject;
  }
  
  getAsyncSubject(): AsyncSubject<string> {
    return this.asyncSubject;
  }
  
  emitSubject(value: string): void {
    this.subject.next(value);
  }
  
  emitBehaviorSubject(value: string): void {
    this.behaviorSubject.next(value);
  }
  
  emitReplaySubject(value: string): void {
    this.replaySubject.next(value);
  }
  
  emitAsyncSubject(value: string): void {
    this.asyncSubject.next(value);
  }
  
  completeAsyncSubject(): void {
    this.asyncSubject.complete();
  }
}
```

**subject-demo.component.ts**
```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { SubjectDemoService } from './subject-demo.service';

@Component({
  selector: 'app-subject-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Subjects</h2>
      
      <section>
        <h3>Subject</h3>
        <button (click)="emitSubject('Valor 1')">Emitir Valor 1</button>
        <button (click)="subscribeSubject()">Subscrever</button>
        <ul>
          @for (value of subjectValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>BehaviorSubject</h3>
        <button (click)="emitBehaviorSubject('Novo Valor')">Emitir</button>
        <button (click)="subscribeBehaviorSubject()">Subscrever</button>
        <p>Valor atual: {{ behaviorSubjectValue }}</p>
      </section>
      
      <section>
        <h3>ReplaySubject</h3>
        <button (click)="emitReplaySubject('Valor ' + replayCount)">Emitir</button>
        <button (click)="subscribeReplaySubject()">Subscrever</button>
        <ul>
          @for (value of replaySubjectValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>AsyncSubject</h3>
        <button (click)="emitAsyncSubject('Valor ' + asyncCount)">Emitir</button>
        <button (click)="completeAsyncSubject()">Completar</button>
        <button (click)="subscribeAsyncSubject()">Subscrever</button>
        <p>Valor: {{ asyncSubjectValue }}</p>
      </section>
    </div>
  `
})
export class SubjectDemoComponent implements OnInit, OnDestroy {
  subjectValues: string[] = [];
  behaviorSubjectValue: string = '';
  replaySubjectValues: string[] = [];
  asyncSubjectValue: string = '';
  
  replayCount: number = 0;
  asyncCount: number = 0;
  
  private subscriptions: Subscription[] = [];
  
  constructor(private subjectService: SubjectDemoService) {}
  
  ngOnInit(): void {
    this.subscribeBehaviorSubject();
  }
  
  emitSubject(value: string): void {
    this.subjectService.emitSubject(value);
  }
  
  subscribeSubject(): void {
    const sub = this.subjectService.getSubject().subscribe({
      next: (value) => {
        this.subjectValues.push(value);
      }
    });
    this.subscriptions.push(sub);
  }
  
  emitBehaviorSubject(value: string): void {
    this.subjectService.emitBehaviorSubject(value);
  }
  
  subscribeBehaviorSubject(): void {
    const sub = this.subjectService.getBehaviorSubject().subscribe({
      next: (value) => {
        this.behaviorSubjectValue = value;
      }
    });
    this.subscriptions.push(sub);
  }
  
  emitReplaySubject(value: string): void {
    this.replayCount++;
    this.subjectService.emitReplaySubject(value);
  }
  
  subscribeReplaySubject(): void {
    this.replaySubjectValues = [];
    const sub = this.subjectService.getReplaySubject().subscribe({
      next: (value) => {
        this.replaySubjectValues.push(value);
      }
    });
    this.subscriptions.push(sub);
  }
  
  emitAsyncSubject(value: string): void {
    this.asyncCount++;
    this.subjectService.emitAsyncSubject(value);
  }
  
  completeAsyncSubject(): void {
    this.subjectService.completeAsyncSubject();
  }
  
  subscribeAsyncSubject(): void {
    const sub = this.subjectService.getAsyncSubject().subscribe({
      next: (value) => {
        this.asyncSubjectValue = value;
      }
    });
    this.subscriptions.push(sub);
  }
  
  ngOnDestroy(): void {
    this.subscriptions.forEach(sub => sub.unsubscribe());
  }
}
```

**Explicação da Solução**:

1. Subject não mantém valor atual
2. BehaviorSubject mantém e emite valor atual
3. ReplaySubject mantém últimos N valores
4. AsyncSubject emite apenas último valor ao completar
5. Diferenças demonstradas através de comportamento
6. Subscriptions gerenciadas adequadamente

---

## Testes

### Casos de Teste

**Teste 1**: Subject funciona
- **Input**: Emitir valor e depois subscrever
- **Output Esperado**: Subscriber não recebe valor anterior

**Teste 2**: BehaviorSubject funciona
- **Input**: Subscrever antes de emitir
- **Output Esperado**: Recebe valor inicial imediatamente

**Teste 3**: ReplaySubject funciona
- **Input**: Emitir valores e depois subscrever
- **Output Esperado**: Recebe últimos 3 valores

**Teste 4**: AsyncSubject funciona
- **Input**: Emitir valores e completar
- **Output Esperado**: Recebe apenas último valor

---

## Extensões (Opcional)

1. **Comunicação Real**: Use em serviço de comunicação real
2. **Estado Global**: Implemente estado global com BehaviorSubject
3. **Cache**: Use ReplaySubject para cache

---

## Referências Úteis

- **[Subject](https://rxjs.dev/api/index/class/Subject)**: Documentação Subject
- **[BehaviorSubject](https://rxjs.dev/api/index/class/BehaviorSubject)**: Documentação BehaviorSubject
- **[ReplaySubject](https://rxjs.dev/api/index/class/ReplaySubject)**: Documentação ReplaySubject

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

