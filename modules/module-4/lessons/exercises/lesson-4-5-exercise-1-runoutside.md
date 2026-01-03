---
layout: exercise
title: "Exercício 4.5.1: runOutsideAngular()"
slug: "runoutside"
lesson_id: "lesson-4-5"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **runOutsideAngular()** através da **criação de componente que usa runOutsideAngular() para otimizar operações pesadas**.

Ao completar este exercício, você será capaz de:

- Usar NgZone para controle de change detection
- Implementar runOutsideAngular() para operações pesadas
- Entender quando usar runOutsideAngular()
- Otimizar performance com NgZone
- Balancear performance e reatividade

---

## Descrição

Você precisa criar um componente que executa operações pesadas usando runOutsideAngular() para evitar change detection desnecessária.

### Contexto

Uma aplicação precisa executar operações pesadas sem causar lag na interface.

### Tarefa

Crie:

1. **Componente**: Criar componente com operação pesada
2. **runOutsideAngular()**: Usar runOutsideAngular() para otimização
3. **Comparação**: Comparar com e sem runOutsideAngular()
4. **Otimização**: Verificar melhoria de performance

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente criado
- [ ] runOutsideAngular() implementado
- [ ] Performance melhorada
- [ ] Comparação realizada
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] runOutsideAngular() está usado corretamente
- [ ] Performance é otimizada

---

## Solução Esperada

### Abordagem Recomendada

**optimized-component.component.ts**
```typescript
import { Component, NgZone, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-optimized',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Otimização com runOutsideAngular()</h2>
      
      <div class="controls">
        <button (click)="heavyOperationWithZone()">Com Zone (Lento)</button>
        <button (click)="heavyOperationOutsideZone()">Sem Zone (Rápido)</button>
        <button (click)="reset()">Resetar</button>
      </div>
      
      <div class="results">
        <p>Resultado: {{ result }}</p>
        <p>Tempo: {{ duration }}ms</p>
        <p>Iterações: {{ iterations }}</p>
      </div>
      
      <div class="status">
        <p>Status: {{ status }}</p>
      </div>
    </div>
  `,
  styles: [`
    .controls {
      display: flex;
      gap: 1rem;
      margin: 1rem 0;
    }
    
    button {
      padding: 0.75rem 1.5rem;
      background: #3498db;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    
    button:hover {
      background: #2980b9;
    }
    
    .results {
      padding: 1rem;
      background: #f8f9fa;
      border-radius: 4px;
      margin: 1rem 0;
    }
    
    .status {
      padding: 1rem;
      background: #e8f5e9;
      border-radius: 4px;
    }
  `]
})
export class OptimizedComponent {
  result = 0;
  duration = 0;
  iterations = 0;
  status = 'Pronto';
  
  constructor(
    private ngZone: NgZone,
    private cdr: ChangeDetectorRef
  ) {}
  
  heavyOperationWithZone(): void {
    this.status = 'Processando (com Zone)...';
    const start = performance.now();
    
    let sum = 0;
    const iterations = 10000000;
    
    for (let i = 0; i < iterations; i++) {
      sum += Math.sqrt(i);
      if (i % 1000000 === 0) {
        this.iterations = i;
        this.result = sum;
      }
    }
    
    this.result = sum;
    this.iterations = iterations;
    this.duration = performance.now() - start;
    this.status = 'Concluído (com Zone)';
  }
  
  heavyOperationOutsideZone(): void {
    this.status = 'Processando (sem Zone)...';
    const start = performance.now();
    
    this.ngZone.runOutsideAngular(() => {
      let sum = 0;
      const iterations = 10000000;
      
      for (let i = 0; i < iterations; i++) {
        sum += Math.sqrt(i);
      }
      
      this.ngZone.run(() => {
        this.result = sum;
        this.iterations = iterations;
        this.duration = performance.now() - start;
        this.status = 'Concluído (sem Zone)';
        this.cdr.markForCheck();
      });
    });
  }
  
  reset(): void {
    this.result = 0;
    this.duration = 0;
    this.iterations = 0;
    this.status = 'Pronto';
  }
}
```

**Explicação da Solução**:

1. NgZone injetado no construtor
2. Operação pesada executada dentro do Zone (lenta)
3. Operação pesada executada fora do Zone (rápida)
4. run() usado para atualizar UI após conclusão
5. markForCheck() garante atualização
6. Performance significativamente melhorada

---

## Testes

### Casos de Teste

**Teste 1**: runOutsideAngular funciona
- **Input**: Executar operação pesada
- **Output Esperado**: Operação completa sem lag

**Teste 2**: Performance melhorada
- **Input**: Comparar com/sem Zone
- **Output Esperado**: Operação sem Zone mais rápida

**Teste 3**: UI atualizada
- **Input**: Verificar interface
- **Output Esperado**: UI atualizada após conclusão

---

## Extensões (Opcional)

1. **Animation**: Use runOutsideAngular() para animações
2. **Canvas**: Otimize operações Canvas
3. **Web Workers**: Combine com Web Workers

---

## Referências Úteis

- **[NgZone](https://angular.io/api/core/NgZone)**: Documentação NgZone
- **[runOutsideAngular](https://angular.io/api/core/NgZone#runOutsideAngular)**: Documentação runOutsideAngular

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

