---
layout: exercise
title: "Exercício 3.4.3: Prevenção de Memory Leaks"
slug: "prevencao"
lesson_id: "lesson-3-4"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **prevenção de memory leaks** através da **criação de componente que previne leaks em múltiplos cenários**.

Ao completar este exercício, você será capaz de:

- Prevenir memory leaks em diferentes cenários
- Limpar subscriptions, timers e event listeners
- Aplicar múltiplas técnicas de prevenção
- Criar componente completamente seguro
- Entender quando usar cada técnica

---

## Descrição

Você precisa criar um componente que previne memory leaks em múltiplos cenários: subscriptions, timers, event listeners.

### Contexto

Uma aplicação precisa garantir que todos os recursos sejam limpos adequadamente.

### Tarefa

Crie:

1. **Subscriptions**: Limpar subscriptions com takeUntil
2. **Timers**: Limpar setInterval/setTimeout
3. **Event Listeners**: Remover event listeners
4. **Component**: Componente completo e seguro

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Subscriptions limpas com takeUntil
- [ ] Timers cancelados no ngOnDestroy
- [ ] Event listeners removidos
- [ ] Todos recursos limpos
- [ ] Memory leaks prevenidos
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todas técnicas de prevenção aplicadas
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**realtime-data.component.ts**
```typescript
import { Component, OnInit, OnDestroy, HostListener } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subject, interval } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { DataService } from './data.service';

@Component({
  selector: 'app-realtime-data',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Dados em Tempo Real</h2>
      <p>Contador: {{ counter }}</p>
      <p>Dados: {{ data }}</p>
      <p>Cliques: {{ clickCount }}</p>
      <p>Última atualização: {{ lastUpdate | date:'medium' }}</p>
    </div>
  `
})
export class RealtimeDataComponent implements OnInit, OnDestroy {
  counter = 0;
  data = '';
  clickCount = 0;
  lastUpdate = new Date();
  
  private destroy$ = new Subject<void>();
  private intervalId?: number;
  private timeoutId?: number;
  
  constructor(private dataService: DataService) {}
  
  ngOnInit(): void {
    this.startInterval();
    this.startTimeout();
    this.subscribeToData();
    this.setupEventListeners();
  }
  
  private startInterval(): void {
    this.intervalId = window.setInterval(() => {
      this.counter++;
      this.lastUpdate = new Date();
    }, 1000);
  }
  
  private startTimeout(): void {
    this.timeoutId = window.setTimeout(() => {
      console.log('Timeout executed');
    }, 5000);
  }
  
  private subscribeToData(): void {
    this.dataService.getData()
      .pipe(takeUntil(this.destroy$))
      .subscribe(data => {
        this.data = data;
        this.lastUpdate = new Date();
      });
    
    interval(2000)
      .pipe(takeUntil(this.destroy$))
      .subscribe(() => {
        this.dataService.refresh();
      });
  }
  
  @HostListener('window:click', ['$event'])
  onWindowClick(event: MouseEvent): void {
    this.clickCount++;
  }
  
  private setupEventListeners(): void {
    window.addEventListener('resize', this.onResize);
    window.addEventListener('scroll', this.onScroll);
  }
  
  private onResize = (): void => {
    console.log('Window resized');
  };
  
  private onScroll = (): void => {
    console.log('Window scrolled');
  };
  
  ngOnDestroy(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
    
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
    }
    
    window.removeEventListener('resize', this.onResize);
    window.removeEventListener('scroll', this.onScroll);
    
    this.destroy$.next();
    this.destroy$.complete();
    
    console.log('All resources cleaned up');
  }
}
```

**Explicação da Solução**:

1. takeUntil usado para subscriptions
2. clearInterval limpa setInterval
3. clearTimeout limpa setTimeout
4. removeEventListener remove event listeners
5. Arrow functions mantêm contexto para removeEventListener
6. Todos recursos limpos no ngOnDestroy

---

## Testes

### Casos de Teste

**Teste 1**: Subscriptions limpas
- **Input**: Destruir componente
- **Output Esperado**: Subscriptions desinscritas

**Teste 2**: Timers cancelados
- **Input**: Destruir componente durante execução
- **Output Esperado**: Timers cancelados

**Teste 3**: Event listeners removidos
- **Input**: Destruir componente
- **Output Esperado**: Event listeners removidos

---

## Extensões (Opcional)

1. **WebSocket**: Adicione cleanup para WebSocket
2. **Animation**: Adicione cleanup para animações
3. **Third-party**: Adicione cleanup para bibliotecas terceiras

---

## Referências Úteis

- **[Memory Management](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Memory_Management)**: Guia gerenciamento de memória
- **[Cleanup Patterns](https://angular.io/guide/lifecycle-hooks)**: Padrões de cleanup

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

