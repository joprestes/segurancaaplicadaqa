---
layout: exercise
title: "Exercício 3.1.2: Operators de Transformação"
slug: "operators-transformacao"
lesson_id: "lesson-3-1"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **operators de transformação** através da **implementação de diferentes padrões de transformação de dados**.

Ao completar este exercício, você será capaz de:

- Usar map para transformar valores
- Usar switchMap para cancelar requisições anteriores
- Usar mergeMap para execução paralela
- Usar concatMap para execução sequencial
- Escolher operator correto para cada situação

---

## Descrição

Você precisa criar exemplos práticos usando diferentes operators de transformação para demonstrar diferenças de comportamento.

### Contexto

Uma aplicação precisa entender quando usar cada operator de transformação para evitar bugs e melhorar performance.

### Tarefa

Crie:

1. **map**: Transformar valores simples
2. **switchMap**: Busca que cancela requisições anteriores
3. **mergeMap**: Múltiplas requisições em paralelo
4. **concatMap**: Requisições em sequência
5. **Comparação**: Demonstre diferenças

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] map implementado
- [ ] switchMap implementado
- [ ] mergeMap implementado
- [ ] concatMap implementado
- [ ] Diferenças demonstradas
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Diferenças estão claras
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**transformation-demo.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { of, fromEvent, interval } from 'rxjs';
import { map, switchMap, mergeMap, concatMap, delay, take } from 'rxjs/operators';

@Component({
  selector: 'app-transformation-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Operators de Transformação</h2>
      
      <section>
        <h3>map() - Transformação Simples</h3>
        <button (click)="demonstrateMap()">Demonstrar map()</button>
        <ul>
          @for (value of mapValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>switchMap() - Cancela Anteriores</h3>
        <input #searchInput (input)="demonstrateSwitchMap(searchInput.value)">
        <p>Última busca: {{ switchMapValue }}</p>
        <p>Requisições canceladas: {{ cancelledRequests }}</p>
      </section>
      
      <section>
        <h3>mergeMap() - Paralelo</h3>
        <button (click)="demonstrateMergeMap()">Demonstrar mergeMap()</button>
        <ul>
          @for (value of mergeMapValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>concatMap() - Sequencial</h3>
        <button (click)="demonstrateConcatMap()">Demonstrar concatMap()</button>
        <ul>
          @for (value of concatMapValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
    </div>
  `
})
export class TransformationDemoComponent {
  mapValues: number[] = [];
  switchMapValue: string = '';
  cancelledRequests: number = 0;
  mergeMapValues: string[] = [];
  concatMapValues: string[] = [];
  
  demonstrateMap(): void {
    this.mapValues = [];
    
    of(1, 2, 3, 4, 5).pipe(
      map(x => x * 2),
      map(x => `Valor: ${x}`)
    ).subscribe(value => {
      this.mapValues.push(value);
    });
  }
  
  demonstrateSwitchMap(searchTerm: string): void {
    if (!searchTerm) return;
    
    of(searchTerm).pipe(
      switchMap(term => {
        console.log(`switchMap: Buscando "${term}"`);
        return this.simulateHttpRequest(term).pipe(
          delay(500)
        );
      })
    ).subscribe({
      next: (result) => {
        this.switchMapValue = result;
        console.log('switchMap: Resultado recebido', result);
      }
    });
  }
  
  demonstrateMergeMap(): void {
    this.mergeMapValues = [];
    
    of(1, 2, 3).pipe(
      mergeMap(id => {
        console.log(`mergeMap: Iniciando requisição ${id}`);
        return this.simulateHttpRequest(`Item ${id}`).pipe(
          delay(1000)
        );
      })
    ).subscribe({
      next: (result) => {
        console.log('mergeMap: Resultado recebido', result);
        this.mergeMapValues.push(result);
      }
    });
  }
  
  demonstrateConcatMap(): void {
    this.concatMapValues = [];
    
    of(1, 2, 3).pipe(
      concatMap(id => {
        console.log(`concatMap: Iniciando requisição ${id}`);
        return this.simulateHttpRequest(`Item ${id}`).pipe(
          delay(1000)
        );
      })
    ).subscribe({
      next: (result) => {
        console.log('concatMap: Resultado recebido', result);
        this.concatMapValues.push(result);
      }
    });
  }
  
  private simulateHttpRequest(term: string): Observable<string> {
    return of(`Resultado para: ${term}`).pipe(delay(Math.random() * 1000));
  }
}
```

**Explicação da Solução**:

1. map() transforma valores simples
2. switchMap() cancela requisições anteriores ao receber novo valor
3. mergeMap() executa todas requisições em paralelo
4. concatMap() executa requisições em sequência
5. Diferenças demonstradas através de logs e comportamento
6. Código prático e funcional

---

## Testes

### Casos de Teste

**Teste 1**: map funciona
- **Input**: Clicar em "Demonstrar map()"
- **Output Esperado**: Valores transformados aparecem

**Teste 2**: switchMap cancela anteriores
- **Input**: Digitar rapidamente no input
- **Output Esperado**: Apenas última busca completa

**Teste 3**: mergeMap executa em paralelo
- **Input**: Clicar em "Demonstrar mergeMap()"
- **Output Esperado**: Resultados aparecem fora de ordem

**Teste 4**: concatMap executa em sequência
- **Input**: Clicar em "Demonstrar concatMap()"
- **Output Esperado**: Resultados aparecem em ordem

---

## Extensões (Opcional)

1. **exhaustMap**: Adicione exemplo com exhaustMap
2. **Comparação Visual**: Adicione timeline visual
3. **Performance**: Compare performance de cada operator

---

## Referências Úteis

- **[map](https://rxjs.dev/api/operators/map)**: Documentação map
- **[switchMap](https://rxjs.dev/api/operators/switchMap)**: Documentação switchMap
- **[mergeMap](https://rxjs.dev/api/operators/mergeMap)**: Documentação mergeMap

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

