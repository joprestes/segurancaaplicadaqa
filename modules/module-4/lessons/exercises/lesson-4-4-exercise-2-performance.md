---
layout: exercise
title: "Exercício 4.4.2: Performance Profiling"
slug: "performance"
lesson_id: "lesson-4-4"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **performance profiling** através do **uso do Chrome DevTools para fazer profiling de performance e identificar gargalos**.

Ao completar este exercício, você será capaz de:

- Usar Chrome DevTools Performance tab
- Gravar timeline de performance
- Identificar long tasks
- Analisar JavaScript execution
- Identificar e corrigir gargalos

---

## Descrição

Você precisa usar Chrome DevTools para fazer profiling de performance de uma aplicação Angular.

### Contexto

Uma aplicação tem problemas de performance e precisa ser analisada para identificar gargalos.

### Tarefa

Crie:

1. **Gravação**: Gravar timeline de performance
2. **Análise**: Analisar timeline
3. **Identificação**: Identificar gargalos
4. **Otimização**: Aplicar otimizações
5. **Comparação**: Comparar antes/depois

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Timeline gravada
- [ ] Gargalos identificados
- [ ] Otimizações aplicadas
- [ ] Performance melhorada
- [ ] Comparação documentada

### Critérios de Qualidade

- [ ] Profiling está completo
- [ ] Gargalos estão identificados
- [ ] Otimizações são efetivas

---

## Solução Esperada

### Abordagem Recomendada

**performance-test.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-performance-test',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Performance Test</h2>
      <button (click)="heavyOperation()">Heavy Operation</button>
      <button (click)="renderList()">Render Large List</button>
      <button (click)="triggerChangeDetection()">Trigger Change Detection</button>
      
      <ul>
        @for (item of items; track item.id) {
          <li>{{ item.name }} - {{ item.value }}</li>
        }
      </ul>
    </div>
  `
})
export class PerformanceTestComponent implements OnInit {
  items: any[] = [];
  
  ngOnInit(): void {
    this.loadData();
  }
  
  heavyOperation(): void {
    console.time('Heavy Operation');
    let sum = 0;
    for (let i = 0; i < 10000000; i++) {
      sum += Math.sqrt(i);
    }
    console.timeEnd('Heavy Operation');
    console.log('Sum:', sum);
  }
  
  renderList(): void {
    this.items = Array.from({ length: 10000 }, (_, i) => ({
      id: i,
      name: `Item ${i}`,
      value: Math.random() * 1000
    }));
  }
  
  triggerChangeDetection(): void {
    this.items.forEach(item => {
      item.value = Math.random() * 1000;
    });
  }
  
  private loadData(): void {
    this.items = Array.from({ length: 100 }, (_, i) => ({
      id: i,
      name: `Item ${i}`,
      value: Math.random() * 1000
    }));
  }
}
```

**profiling-guide.md**
```markdown
# Guia de Performance Profiling

## 1. Preparação

1. Abrir Chrome DevTools (F12)
2. Ir para Performance tab
3. Configurar CPU throttling (opcional)
4. Configurar Network throttling (opcional)

## 2. Gravação

1. Clicar em Record (ou Ctrl+E)
2. Interagir com aplicação
3. Executar operações problemáticas
4. Parar gravação (Ctrl+E novamente)

## 3. Análise

### Timeline
- Verificar FPS (deve ser ~60)
- Identificar frame drops
- Verificar long tasks (>50ms)

### JavaScript
- Identificar funções lentas
- Verificar call stacks
- Encontrar hot paths

### Rendering
- Verificar paint times
- Identificar layout shifts
- Verificar compositing

## 4. Otimização

- Otimizar funções lentas
- Reduzir long tasks
- Melhorar change detection
- Otimizar rendering

## 5. Verificação

- Gravar novamente após otimizações
- Comparar métricas
- Validar melhorias
```

**Explicação da Solução**:

1. Componente criado com operações pesadas
2. Performance tab usado para gravar
3. Timeline analisada para identificar problemas
4. Gargalos identificados e documentados
5. Otimizações aplicadas
6. Performance melhorada e verificada

---

## Testes

### Casos de Teste

**Teste 1**: Gravação funciona
- **Input**: Gravar timeline
- **Output Esperado**: Timeline gravada com sucesso

**Teste 2**: Gargalos identificados
- **Input**: Analisar timeline
- **Output Esperado**: Problemas claramente identificados

**Teste 3**: Otimizações efetivas
- **Input**: Comparar antes/depois
- **Output Esperado**: Melhorias mensuráveis

---

## Extensões (Opcional)

1. **Automated Profiling**: Automatize profiling em CI/CD
2. **Performance Budgets**: Configure budgets de performance
3. **Continuous Monitoring**: Implemente monitoramento contínuo

---

## Referências Úteis

- **[Chrome DevTools Performance](https://developer.chrome.com/docs/devtools/performance/)**: Guia Performance
- **[Performance Analysis](https://web.dev/performance-scoring/)**: Guia análise performance

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

