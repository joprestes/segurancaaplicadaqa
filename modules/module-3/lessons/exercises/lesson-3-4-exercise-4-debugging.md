---
layout: exercise
title: "Exercício 3.4.4: Debugging Memory Leaks"
slug: "debugging"
lesson_id: "lesson-3-4"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **debugging de memory leaks** através da **identificação e correção de memory leaks usando ferramentas**.

Ao completar este exercício, você será capaz de:

- Identificar memory leaks usando Chrome DevTools
- Usar Memory Profiler para detectar leaks
- Verificar subscriptions ativas
- Corrigir memory leaks identificados
- Usar ferramentas de debugging

---

## Descrição

Você precisa criar um componente com memory leak intencional, identificá-lo usando ferramentas e corrigi-lo.

### Contexto

Uma aplicação tem memory leaks e precisa ser identificada e corrigida.

### Tarefa

Crie:

1. **Leaky Component**: Componente com memory leak
2. **Detection**: Usar ferramentas para identificar leak
3. **Fix**: Corrigir memory leak
4. **Verification**: Verificar que leak foi corrigido

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente com memory leak criado
- [ ] Memory leak identificado usando DevTools
- [ ] Memory leak corrigido
- [ ] Verificação de correção
- [ ] Documentação do processo
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Memory leak foi identificado e corrigido
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**leaky.component.ts** (COM LEAK)
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { DataService } from './data.service';

@Component({
  selector: 'app-leaky',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Componente com Memory Leak</h2>
      <p>Dados: {{ data }}</p>
      <button (click)="load()">Carregar</button>
    </div>
  `
})
export class LeakyComponent implements OnInit {
  data = '';
  
  constructor(private dataService: DataService) {}
  
  ngOnInit(): void {
    this.load();
  }
  
  load(): void {
    this.dataService.getData().subscribe(data => {
      this.data = data;
    });
  }
}
```

**fixed.component.ts** (CORRIGIDO)
```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { DataService } from './data.service';

@Component({
  selector: 'app-fixed',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Componente Corrigido</h2>
      <p>Dados: {{ data }}</p>
      <button (click)="load()">Carregar</button>
    </div>
  `
})
export class FixedComponent implements OnInit, OnDestroy {
  data = '';
  private destroy$ = new Subject<void>();
  
  constructor(private dataService: DataService) {}
  
  ngOnInit(): void {
    this.load();
  }
  
  load(): void {
    this.dataService.getData()
      .pipe(takeUntil(this.destroy$))
      .subscribe(data => {
        this.data = data;
      });
  }
  
  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
    console.log('Component destroyed, subscription cleaned');
  }
}
```

**debugging-guide.md**
```markdown
# Guia de Debugging Memory Leaks

## 1. Identificar Memory Leak

### Usando Chrome DevTools:

1. Abra Chrome DevTools (F12)
2. Vá para aba "Memory"
3. Selecione "Heap snapshot"
4. Tire snapshot antes de criar componente
5. Crie e destrua componente múltiplas vezes
6. Tire outro snapshot
7. Compare snapshots
8. Procure por objetos não coletados

### Usando Performance Monitor:

1. Abra Chrome DevTools
2. Vá para aba "Performance"
3. Marque "Memory"
4. Grave performance
5. Crie e destrua componentes
6. Pare gravação
7. Verifique uso de memória

## 2. Verificar Subscriptions

### No código:

```
import { Subscription } from 'rxjs';

export class DebugComponent {
  private subscriptions: Subscription[] = [];
  
  ngOnInit(): void {
    const sub = this.service.getData().subscribe();
    this.subscriptions.push(sub);
    console.log('Active subscriptions:', this.subscriptions.length);
  }
  
  ngOnDestroy(): void {
    this.subscriptions.forEach(sub => {
      console.log('Unsubscribing:', sub);
      sub.unsubscribe();
    });
  }
}
```

## 3. Usar RxJS Spy (Opcional)

```
npm install rxjs-spy
```

```
import { create } from 'rxjs-spy';
const spy = create();

spy.show();
```

## 4. Corrigir Memory Leak

- Usar async pipe quando possível
- Usar takeUntil pattern
- Implementar ngOnDestroy
- Limpar timers e event listeners
```

**Explicação da Solução**:

1. Componente com leak não desinscreve subscription
2. Chrome DevTools identifica objetos não coletados
3. Performance Monitor mostra aumento de memória
4. Componente corrigido usa takeUntil
5. ngOnDestroy garante cleanup
6. Verificação confirma correção

---

## Testes

### Casos de Teste

**Teste 1**: Memory leak identificado
- **Input**: Usar DevTools para identificar leak
- **Output Esperado**: Leak identificado

**Teste 2**: Memory leak corrigido
- **Input**: Aplicar correção
- **Output Esperado**: Leak corrigido

**Teste 3**: Verificação de correção
- **Input**: Verificar novamente com DevTools
- **Output Esperado**: Sem memory leaks

---

## Extensões (Opcional)

1. **Automated Testing**: Crie testes automatizados para detectar leaks
2. **Monitoring**: Implemente monitoramento em produção
3. **Alerts**: Configure alertas para memory leaks

---

## Referências Úteis

- **[Chrome DevTools Memory](https://developer.chrome.com/docs/devtools/memory-problems/)**: Guia Memory Profiler
- **[RxJS Spy](https://github.com/cartant/rxjs-spy)**: RxJS Spy tool

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

