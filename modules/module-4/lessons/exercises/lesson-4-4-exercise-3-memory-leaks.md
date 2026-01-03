---
layout: exercise
title: "Exercício 4.4.3: Memory Leaks Detection"
slug: "memory-leaks"
lesson_id: "lesson-4-4"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **detecção de memory leaks** através do **uso do Chrome DevTools para detectar e corrigir memory leaks**.

Ao completar este exercício, você será capaz de:

- Usar Chrome DevTools Memory tab
- Tirar heap snapshots
- Comparar snapshots
- Identificar memory leaks
- Corrigir memory leaks

---

## Descrição

Você precisa usar Chrome DevTools para detectar e corrigir memory leaks em uma aplicação Angular.

### Contexto

Uma aplicação tem memory leaks e precisa ser analisada e corrigida.

### Tarefa

Crie:

1. **Componente com Leak**: Criar componente com memory leak
2. **Heap Snapshots**: Tirar snapshots antes/depois
3. **Análise**: Analisar e identificar leaks
4. **Correção**: Corrigir memory leaks
5. **Verificação**: Verificar que leaks foram corrigidos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente com leak criado
- [ ] Heap snapshots tirados
- [ ] Leaks identificados
- [ ] Leaks corrigidos
- [ ] Verificação realizada

### Critérios de Qualidade

- [ ] Leaks estão identificados corretamente
- [ ] Correções são efetivas
- [ ] Código está otimizado

---

## Solução Esperada

### Abordagem Recomendada

**leaky-component.component.ts** (COM LEAK)
{% raw %}
```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { interval, Subscription } from 'rxjs';

@Component({
  selector: 'app-leaky',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Componente com Memory Leak</h2>
      <p>Contador: {{ count }}</p>
      <button (click)="start()">Iniciar</button>
      <button (click)="stop()">Parar</button>
    </div>
  `
})
export class LeakyComponent implements OnInit {
  count = 0;
  private subscription?: Subscription;
  
  ngOnInit(): void {
    this.start();
  }
  
  start(): void {
    this.subscription = interval(100).subscribe(() => {
      this.count++;
    });
  }
  
  stop(): void {
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }
}
```
{% endraw %}

**fixed-component.component.ts** (CORRIGIDO)
{% raw %}
```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { interval, Subscription } from 'rxjs';

@Component({
  selector: 'app-fixed',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Componente Corrigido</h2>
      <p>Contador: {{ count }}</p>
      <button (click)="start()">Iniciar</button>
      <button (click)="stop()">Parar</button>
    </div>
  `
})
export class FixedComponent implements OnInit, OnDestroy {
  count = 0;
  private subscription?: Subscription;
  
  ngOnInit(): void {
    this.start();
  }
  
  start(): void {
    this.stop();
    this.subscription = interval(100).subscribe(() => {
      this.count++;
    });
  }
  
  stop(): void {
    if (this.subscription) {
      this.subscription.unsubscribe();
      this.subscription = undefined;
    }
  }
  
  ngOnDestroy(): void {
    this.stop();
  }
}
```
{% endraw %}

**detection-guide.md**
```markdown
# Guia de Detecção de Memory Leaks

## 1. Preparação

1. Abrir Chrome DevTools (F12)
2. Ir para Memory tab
3. Selecionar "Heap snapshot"

## 2. Baseline

1. Carregar aplicação
2. Aguardar estabilização
3. Tirar snapshot inicial
4. Nomear como "Baseline"

## 3. Teste

1. Criar componente com leak
2. Destruir componente
3. Repetir múltiplas vezes
4. Forçar garbage collection (se disponível)

## 4. Comparação

1. Tirar novo snapshot
2. Nomear como "After Test"
3. Comparar com Baseline
4. Procurar por:
   - Objetos não coletados
   - Subscriptions ativas
   - Event listeners
   - Timers

## 5. Correção

1. Identificar causa do leak
2. Implementar cleanup
3. Verificar correção
4. Documentar solução
```

**Explicação da Solução**:

1. Componente com leak não desinscreve subscription
2. Heap snapshots mostram objetos não coletados
3. Comparação identifica crescimento de memória
4. Correção implementa ngOnDestroy
5. Verificação confirma que leak foi corrigido
6. Código limpo e sem leaks

---

## Testes

### Casos de Teste

**Teste 1**: Leak identificado
- **Input**: Comparar snapshots
- **Output Esperado**: Objetos não coletados identificados

**Teste 2**: Leak corrigido
- **Input**: Aplicar correção
- **Output Esperado**: Sem objetos não coletados

**Teste 3**: Verificação funciona
- **Input**: Verificar novamente
- **Output Esperado**: Memory estável

---

## Extensões (Opcional)

1. **Automated Detection**: Automatize detecção de leaks
2. **Memory Monitoring**: Implemente monitoramento contínuo
3. **Leak Prevention**: Crie padrões para prevenir leaks

---

## Referências Úteis

- **[Memory Profiling](https://developer.chrome.com/docs/devtools/memory-problems/)**: Guia memory profiling
- **[Memory Leaks](https://angular.io/guide/lifecycle-hooks#oninit-and-ondestroy)**: Guia memory leaks Angular

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

