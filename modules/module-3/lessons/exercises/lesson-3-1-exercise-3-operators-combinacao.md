---
layout: exercise
title: "Exercício 3.1.3: Operators de Combinação"
slug: "operators-combinacao"
lesson_id: "lesson-3-1"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **operators de combinação** através da **implementação de diferentes formas de combinar múltiplos Observables**.

Ao completar este exercício, você será capaz de:

- Usar combineLatest para combinar últimos valores
- Usar forkJoin para combinar valores finais
- Usar merge para combinar streams
- Usar zip para combinar por índice
- Escolher operator correto para cada situação

---

## Descrição

Você precisa criar exemplos práticos usando diferentes operators de combinação para demonstrar quando usar cada um.

### Contexto

Uma aplicação precisa combinar dados de múltiplas fontes de forma eficiente.

### Tarefa

Crie:

1. **combineLatest**: Combinar últimos valores de múltiplos Observables
2. **forkJoin**: Esperar todos completarem e combinar valores finais
3. **merge**: Combinar múltiplos Observables em um
4. **zip**: Combinar valores por índice
5. **Comparação**: Demonstre diferenças práticas

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] combineLatest implementado
- [ ] forkJoin implementado
- [ ] merge implementado
- [ ] zip implementado
- [ ] Diferenças demonstradas
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Diferenças estão claras
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**combination-demo.component.ts**
{% raw %}
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { combineLatest, forkJoin, merge, zip, interval, of, timer } from 'rxjs';
import { take, map } from 'rxjs/operators';

@Component({
  selector: 'app-combination-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Operators de Combinação</h2>
      
      <section>
        <h3>combineLatest - Últimos Valores</h3>
        <button (click)="demonstrateCombineLatest()">Demonstrar</button>
        <p>{{ combineLatestResult }}</p>
      </section>
      
      <section>
        <h3>forkJoin - Valores Finais</h3>
        <button (click)="demonstrateForkJoin()">Demonstrar</button>
        <p>{{ forkJoinResult }}</p>
      </section>
      
      <section>
        <h3>merge - Combinar Streams</h3>
        <button (click)="demonstrateMerge()">Demonstrar</button>
        <ul>
          @for (value of mergeValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>zip - Combinar por Índice</h3>
        <button (click)="demonstrateZip()">Demonstrar</button>
        <ul>
          @for (value of zipValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
    </div>
  `
{% endraw %}
})
export class CombinationDemoComponent {
  combineLatestResult: string = '';
  forkJoinResult: string = '';
  mergeValues: string[] = [];
  zipValues: string[] = [];
  
  demonstrateCombineLatest(): void {
    const source1 = interval(1000).pipe(take(3), map(x => `A${x}`));
    const source2 = interval(1500).pipe(take(3), map(x => `B${x}`));
    
    combineLatest([source1, source2]).subscribe({
      next: ([a, b]) => {
        this.combineLatestResult = `${a} + ${b}`;
        console.log('combineLatest:', a, b);
      }
    });
  }
  
  demonstrateForkJoin(): void {
    const source1 = timer(1000).pipe(map(() => 'Resultado 1'));
    const source2 = timer(2000).pipe(map(() => 'Resultado 2'));
    const source3 = timer(1500).pipe(map(() => 'Resultado 3'));
    
    forkJoin([source1, source2, source3]).subscribe({
      next: (results) => {
        this.forkJoinResult = results.join(' | ');
        console.log('forkJoin:', results);
      }
    });
  }
  
  demonstrateMerge(): void {
    this.mergeValues = [];
    
    const source1 = interval(1000).pipe(take(3), map(x => `Source1: ${x}`));
    const source2 = interval(800).pipe(take(3), map(x => `Source2: ${x}`));
    
    merge(source1, source2).subscribe({
      next: (value) => {
        this.mergeValues.push(value);
        console.log('merge:', value);
      }
    });
  }
  
  demonstrateZip(): void {
    this.zipValues = [];
    
    const source1 = of('A', 'B', 'C');
    const source2 = of(1, 2, 3);
    const source3 = of('X', 'Y', 'Z');
    
    zip(source1, source2, source3).subscribe({
      next: ([a, b, c]) => {
        const value = `${a}${b}${c}`;
        this.zipValues.push(value);
        console.log('zip:', value);
      }
    });
  }
}
```

**Explicação da Solução**:

1. combineLatest emite sempre que qualquer Observable emite
2. forkJoin espera todos completarem antes de emitir
3. merge combina todos valores de todos Observables
4. zip combina valores por índice (primeiro com primeiro, etc)
5. Diferenças demonstradas através de comportamento
6. Exemplos práticos e funcionais

---

## Testes

### Casos de Teste

**Teste 1**: combineLatest funciona
- **Input**: Clicar em "Demonstrar"
- **Output Esperado**: Valores combinados aparecem quando qualquer fonte emite

**Teste 2**: forkJoin funciona
- **Input**: Clicar em "Demonstrar"
- **Output Esperado**: Resultado aparece apenas quando todos completam

**Teste 3**: merge funciona
- **Input**: Clicar em "Demonstrar"
- **Output Esperado**: Valores de ambas fontes aparecem misturados

**Teste 4**: zip funciona
- **Input**: Clicar em "Demonstrar"
- **Output Esperado**: Valores combinados por índice

---

## Extensões (Opcional)

1. **withLatestFrom**: Adicione exemplo com withLatestFrom
2. **race**: Adicione exemplo com race
3. **startWith**: Adicione exemplo com startWith

---

## Referências Úteis

- **[combineLatest](https://rxjs.dev/api/index/function/combineLatest)**: Documentação combineLatest
- **[forkJoin](https://rxjs.dev/api/index/function/forkJoin)**: Documentação forkJoin
- **[merge](https://rxjs.dev/api/index/function/merge)**: Documentação merge

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

