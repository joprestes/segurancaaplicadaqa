---
layout: exercise
title: "Exercício 3.5.3: Quando Usar Signals vs Observables"
slug: "decisao"
lesson_id: "lesson-3-5"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **decisão entre Signals e Observables** através da **criação de exemplos demonstrando quando usar cada abordagem**.

Ao completar este exercício, você será capaz de:

- Identificar quando usar Signals
- Identificar quando usar Observables
- Tomar decisões arquiteturais corretas
- Criar aplicações eficientes
- Aplicar melhor prática para cada caso

---

## Descrição

Você precisa criar exemplos demonstrando quando usar Signals e quando usar Observables.

### Contexto

Uma aplicação precisa tomar decisões arquiteturais corretas sobre quando usar Signals vs Observables.

### Tarefa

Crie:

1. **Exemplos Signals**: Casos onde Signals são melhores
2. **Exemplos Observables**: Casos onde Observables são melhores
3. **Comparação**: Comparar abordagens
4. **Documentação**: Documentar decisões

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Exemplos de uso de Signals criados
- [ ] Exemplos de uso de Observables criados
- [ ] Comparação documentada
- [ ] Decisões justificadas
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Decisões estão corretas
- [ ] Documentação é clara

---

## Solução Esperada

### Abordagem Recomendada

**signals-examples.component.ts**

{% raw %}
```typescript
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-signals-examples',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Casos de Uso: Signals</h2>
      
      <div class="example">
        <h3>1. Estado Local Simples</h3>
        <p>Contador: {{ count() }}</p>
        <button (click)="increment()">Incrementar</button>
        <p>Dobro: {{ doubleCount() }}</p>
      </div>
      
      <div class="example">
        <h3>2. Valores Computados</h3>
        <input [value]="firstName()" (input)="firstName.set($any($event.target).value)">
        <input [value]="lastName()" (input)="lastName.set($any($event.target).value)">
        <p>Nome completo: {{ fullName() }}</p>
      </div>
      
      <div class="example">
        <h3>3. Estado de UI</h3>
        <button (click)="toggleMenu()">Menu</button>
        @if (menuOpen()) {
          <div class="menu">Menu aberto</div>
        }
      </div>
    </div>
  `
})
export class SignalsExamplesComponent {
  count = signal(0);
  doubleCount = computed(() => this.count() * 2);
  
  firstName = signal('');
  lastName = signal('');
  fullName = computed(() => `${this.firstName()} ${this.lastName()}`);
  
  menuOpen = signal(false);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
  
  toggleMenu(): void {
    this.menuOpen.update(v => !v);
  }
}
```
{% endraw %}

**observables-examples.component.ts**

{% raw %}
```typescript
import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Observable, interval, fromEvent } from 'rxjs';
import { debounceTime, map, switchMap } from 'rxjs/operators';

@Component({
  selector: 'app-observables-examples',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Casos de Uso: Observables</h2>
      
      <div class="example">
        <h3>1. Operações HTTP</h3>
        <button (click)="loadData()">Carregar</button>
        <ul>
          @for (item of data$ | async; track item.id) {
            <li>{{ item.name }}</li>
          }
        </ul>
      </div>
      
      <div class="example">
        <h3>2. Eventos do Usuário</h3>
        <input #input placeholder="Digite...">
        <p>Valor com debounce: {{ debouncedValue$ | async }}</p>
      </div>
      
      <div class="example">
        <h3>3. Timers e Intervalos</h3>
        <p>Tempo: {{ timer$ | async }}</p>
      </div>
      
      <div class="example">
        <h3>4. Streams Complexos</h3>
        <button #button>Clique</button>
        <p>Cliques: {{ clickCount$ | async }}</p>
      </div>
    </div>
  `
})
export class ObservablesExamplesComponent {
  private http = inject(HttpClient);
  
  data$: Observable<any[]>;
  debouncedValue$: Observable<string>;
  timer$: Observable<number>;
  clickCount$: Observable<number>;
  
  constructor() {
    this.data$ = this.http.get<any[]>('/api/data');
    
    this.debouncedValue$ = fromEvent(document.querySelector('input')!, 'input').pipe(
      debounceTime(300),
      map((e: any) => e.target.value)
    );
    
    this.timer$ = interval(1000);
    
    this.clickCount$ = fromEvent(document.querySelector('button')!, 'click').pipe(
      map(() => 1),
      switchMap(() => interval(1000))
    );
  }
  
  loadData(): void {
    this.data$ = this.http.get<any[]>('/api/data');
  }
}
```
import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Observable, interval, fromEvent } from 'rxjs';
import { debounceTime, map, switchMap } from 'rxjs/operators';

@Component({
  selector: 'app-observables-examples',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Casos de Uso: Observables</h2>
      
      <div class="example">
        <h3>1. Operações HTTP</h3>
        <button (click)="loadData()">Carregar</button>
        <ul>
          @for (item of data$ | async; track item.id) {
            <li>{{ item.name }}</li>
          }
        </ul>
      </div>
      
      <div class="example">
        <h3>2. Eventos do Usuário</h3>
        <input #input placeholder="Digite...">
        <p>Valor com debounce: {{ debouncedValue$ | async }}</p>
      </div>
      
      <div class="example">
        <h3>3. Timers e Intervalos</h3>
        <p>Tempo: {{ timer$ | async }}</p>
      </div>
      
      <div class="example">
        <h3>4. Streams Complexos</h3>
        <button #button>Clique</button>
        <p>Cliques: {{ clickCount$ | async }}</p>
      </div>
    </div>
  `
})
export class ObservablesExamplesComponent {
  private http = inject(HttpClient);
  
  data$: Observable<any[]>;
  debouncedValue$: Observable<string>;
  timer$: Observable<number>;
  clickCount$: Observable<number>;
  
  constructor() {
    this.data$ = this.http.get<any[]>('/api/data');
    
    this.debouncedValue$ = fromEvent(document.querySelector('input')!, 'input').pipe(
      debounceTime(300),
      map((e: any) => e.target.value)
    );
    
    this.timer$ = interval(1000);
    
    this.clickCount$ = fromEvent(document.querySelector('button')!, 'click').pipe(
      map(() => 1),
      switchMap(() => interval(1000))
    );
  }
  
  loadData(): void {
    this.data$ = this.http.get<any[]>('/api/data');
  }
}
```
{% endraw %}

**decision-guide.md**
```markdown
# Guia de Decisão: Signals vs Observables

## Use Signals quando:

1. **Estado Local Simples**
   - Contadores, flags, valores simples
   - Estado de UI (menu aberto/fechado)
   - Valores síncronos

2. **Valores Computados**
   - Valores derivados de outros signals
   - Cálculos simples
   - Transformações síncronas

3. **Performance Crítica**
   - Quando precisa de melhor performance
   - Change detection otimizada
   - Menos overhead

## Use Observables quando:

1. **Operações HTTP**
   - Requisições assíncronas
   - APIs REST
   - WebSockets

2. **Eventos do Usuário**
   - Cliques, inputs, scrolls
   - Eventos DOM
   - Eventos customizados

3. **Streams Complexos**
   - Múltiplas fontes de dados
   - Operadores RxJS avançados
   - Transformações complexas

4. **Timers e Intervalos**
   - setInterval, setTimeout
   - Operações periódicas
   - Polling

## Híbrido (toSignal/toObservable):

- Use quando precisa integrar ambos
- Converta Observable HTTP para Signal
- Converta Signal para Observable para operadores
- Mantenha consistência na aplicação
```

**Explicação da Solução**:

1. Exemplos demonstram casos de uso de Signals
2. Exemplos demonstram casos de uso de Observables
3. Comparação clara entre abordagens
4. Guia de decisão documentado
5. Justificativas para cada escolha
6. Código funcional e demonstrativo

---

## Testes

### Casos de Teste

**Teste 1**: Signals funcionam
- **Input**: Usar exemplos de Signals
- **Output Esperado**: Funciona corretamente

**Teste 2**: Observables funcionam
- **Input**: Usar exemplos de Observables
- **Output Esperado**: Funciona corretamente

**Teste 3**: Decisões são corretas
- **Input**: Analisar casos de uso
- **Output Esperado**: Decisões justificadas

---

## Extensões (Opcional)

1. **Mais Exemplos**: Adicione mais casos de uso
2. **Benchmarks**: Compare performance
3. **Migration Guide**: Crie guia de migração

---

## Referências Úteis

- **[Signals Guide](https://angular.io/guide/signals)**: Guia Signals
- **[RxJS Guide](https://rxjs.dev/guide/overview)**: Guia RxJS
- **[Best Practices](https://angular.io/guide/signals#when-to-use-signals)**: Boas práticas

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

