---
layout: exercise
title: "Exercício 3.1.6: Hot vs Cold Observables"
slug: "hot-cold"
lesson_id: "lesson-3-1"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Hot vs Cold Observables** através da **demonstração de diferenças e uso de share()**.

Ao completar este exercício, você será capaz de:

- Entender diferença entre Hot e Cold Observables
- Converter Cold em Hot usando share()
- Usar shareReplay para cache
- Escolher estratégia correta para cada situação
- Evitar múltiplas execuções desnecessárias

---

## Descrição

Você precisa criar exemplos que demonstram diferença entre Hot e Cold Observables e como converter entre eles.

### Contexto

Uma aplicação precisa entender quando usar Hot vs Cold para evitar múltiplas execuções desnecessárias.

### Tarefa

Crie:

1. **Cold Observable**: Demonstre execução múltipla
2. **Hot Observable**: Demonstre execução compartilhada
3. **share()**: Converta Cold em Hot
4. **shareReplay()**: Cache de valores
5. **Comparação**: Demonstre diferenças práticas

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Cold Observable demonstrado
- [ ] Hot Observable demonstrado
- [ ] share() implementado
- [ ] shareReplay() implementado
- [ ] Diferenças claras
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Diferenças estão claras
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**hot-cold-demo.component.ts**
{% raw %}
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Observable, interval, Subject } from 'rxjs';
import { share, shareReplay, take, tap } from 'rxjs/operators';

@Component({
  selector: 'app-hot-cold-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Hot vs Cold Observables</h2>
      
      <section>
        <h3>Cold Observable - Nova Execução</h3>
        <button (click)="demonstrateCold()">Demonstrar</button>
        <p>Execuções: {{ coldExecutions }}</p>
        <ul>
          @for (value of coldValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>Hot Observable - Execução Compartilhada</h3>
        <button (click)="demonstrateHot()">Demonstrar</button>
        <p>Execuções: {{ hotExecutions }}</p>
        <ul>
          @for (value of hotValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
      
      <section>
        <h3>shareReplay - Cache</h3>
        <button (click)="demonstrateShareReplay()">Demonstrar</button>
        <ul>
          @for (value of shareReplayValues; track $index) {
            <li>{{ value }}</li>
          }
        </ul>
      </section>
    </div>
  `
})
export class HotColdDemoComponent {
  coldExecutions: number = 0;
  coldValues: number[] = [];
  hotExecutions: number = 0;
  hotValues: number[] = [];
  shareReplayValues: number[] = [];
  
  private hotObservable?: Observable<number>;
  
  demonstrateCold(): void {
    this.coldExecutions = 0;
    this.coldValues = [];
    
    const cold$ = new Observable<number>(observer => {
      this.coldExecutions++;
      console.log(`Cold: Nova execução ${this.coldExecutions}`);
      observer.next(Math.random());
    });
    
    cold$.subscribe(v => {
      this.coldValues.push(v);
      console.log('Cold Subscriber A:', v);
    });
    
    cold$.subscribe(v => {
      this.coldValues.push(v);
      console.log('Cold Subscriber B:', v);
    });
  }
  
  demonstrateHot(): void {
    this.hotExecutions = 0;
    this.hotValues = [];
    
    const cold$ = interval(1000).pipe(
      take(3),
      tap(() => {
        this.hotExecutions++;
        console.log(`Hot: Execução ${this.hotExecutions}`);
      }),
      share()
    );
    
    this.hotObservable = cold$;
    
    cold$.subscribe(v => {
      this.hotValues.push(v);
      console.log('Hot Subscriber A:', v);
    });
    
    setTimeout(() => {
      cold$.subscribe(v => {
        this.hotValues.push(v);
        console.log('Hot Subscriber B:', v);
      });
    }, 2000);
  }
  
  demonstrateShareReplay(): void {
    this.shareReplayValues = [];
    
    const source$ = interval(1000).pipe(
      take(3),
      shareReplay(2)
    );
    
    source$.subscribe(v => {
      this.shareReplayValues.push(v);
      console.log('ShareReplay Subscriber A:', v);
    });
    
    setTimeout(() => {
      source$.subscribe(v => {
        this.shareReplayValues.push(v);
        console.log('ShareReplay Subscriber B:', v);
      });
    }, 5000);
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. Cold Observable cria nova execução para cada subscriber
2. Hot Observable compartilha execução entre subscribers
3. share() converte Cold em Hot
4. shareReplay() cache valores para novos subscribers
5. Diferenças demonstradas através de logs e comportamento
6. Exemplos práticos e funcionais

---

## Testes

### Casos de Teste

**Teste 1**: Cold Observable cria múltiplas execuções
- **Input**: Criar múltiplos subscribers
- **Output Esperado**: Cada subscriber tem execução separada

**Teste 2**: Hot Observable compartilha execução
- **Input**: Criar múltiplos subscribers
- **Output Esperado**: Execução compartilhada

**Teste 3**: shareReplay cache valores
- **Input**: Subscrever depois de valores emitidos
- **Output Esperado**: Recebe valores em cache

---

## Extensões (Opcional)

1. **Performance**: Compare performance de Hot vs Cold
2. **HTTP Requests**: Use shareReplay em requisições HTTP
3. **State Management**: Use Hot Observables para estado

---

## Referências Úteis

- **[Hot vs Cold](https://rxjs.dev/guide/observable#hot-vs-cold-observables)**: Guia Hot vs Cold
- **[share](https://rxjs.dev/api/operators/share)**: Documentação share
- **[shareReplay](https://rxjs.dev/api/operators/shareReplay)**: Documentação shareReplay

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

