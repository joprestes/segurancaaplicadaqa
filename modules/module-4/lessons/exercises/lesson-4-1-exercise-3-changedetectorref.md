---
layout: exercise
title: "Exercício 4.1.3: ChangeDetectorRef Manual"
slug: "changedetectorref"
lesson_id: "lesson-4-1"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **ChangeDetectorRef** através da **implementação de controle manual de change detection**.

Ao completar este exercício, você será capaz de:

- Usar ChangeDetectorRef para controle manual
- Usar markForCheck() para marcar verificação
- Usar detach() e reattach() para controle fino
- Entender quando usar controle manual
- Otimizar change detection manualmente

---

## Descrição

Você precisa criar componente que usa ChangeDetectorRef para controle manual de change detection.

### Contexto

Uma aplicação precisa de controle fino sobre change detection em cenários específicos.

### Tarefa

Crie:

1. **ChangeDetectorRef**: Injetar ChangeDetectorRef
2. **markForCheck()**: Usar markForCheck() quando necessário
3. **detach/reattach**: Demonstrar detach() e reattach()
4. **Component**: Componente completo demonstrando controle manual

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] ChangeDetectorRef injetado
- [ ] markForCheck() usado
- [ ] detach() e reattach() demonstrados
- [ ] Controle manual funciona
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] ChangeDetectorRef está usado corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**manual-detection.component.ts**
{% raw %}
```typescript
import { Component, ChangeDetectionStrategy, ChangeDetectorRef, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-manual-detection',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
{% raw %}
  template: `
    <div>
      <h2>Controle Manual de Change Detection</h2>
      
      <div class="controls">
        <button (click)="loadData()">Carregar Dados</button>
        <button (click)="updateData()">Atualizar Dados</button>
        <button (click)="toggleDetection()">
          {{ isDetached() ? 'Reativar' : 'Desativar' }} Change Detection
        </button>
        <button (click)="forceCheck()">Forçar Verificação</button>
      </div>
      
      <div class="status">
        <p>Status: {{ isDetached() ? 'Desconectado' : 'Conectado' }}</p>
        <p>Dados: {{ data() }}</p>
        <p>Última atualização: {{ lastUpdate() | date:'medium' }}</p>
      </div>
      
      <ul>
        @for (item of items(); track item.id) {
          <li>{{ item.name }}</li>
        }
      </ul>
    </div>
  `
{% endraw %}
})
export class ManualDetectionComponent {
  data = signal<string>('Nenhum dado');
  items = signal<any[]>([]);
  lastUpdate = signal<Date>(new Date());
  isDetached = signal<boolean>(false);
  
  constructor(
    private cdr: ChangeDetectorRef,
    private http: HttpClient
  ) {}
  
  loadData(): void {
    this.http.get<any[]>('/api/data').subscribe(items => {
      this.items.set(items);
      this.data.set(`Carregados ${items.length} itens`);
      this.lastUpdate.set(new Date());
      
      if (this.isDetached()) {
        this.cdr.markForCheck();
      }
    });
  }
  
  updateData(): void {
    this.data.set('Dados atualizados manualmente');
    this.lastUpdate.set(new Date());
    
    if (this.isDetached()) {
      this.cdr.markForCheck();
    }
  }
  
  toggleDetection(): void {
    if (this.isDetached()) {
      this.cdr.reattach();
      this.isDetached.set(false);
    } else {
      this.cdr.detach();
      this.isDetached.set(true);
    }
  }
  
  forceCheck(): void {
    this.cdr.detectChanges();
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. ChangeDetectorRef injetado no construtor
2. markForCheck() usado após atualizações assíncronas
3. detach() desconecta do ciclo de change detection
4. reattach() reconecta ao ciclo
5. detectChanges() força verificação imediata
6. Controle manual completo implementado

---

## Testes

### Casos de Teste

**Teste 1**: markForCheck funciona
- **Input**: Atualizar dados e chamar markForCheck
- **Output Esperado**: Mudanças detectadas

**Teste 2**: detach/reattach funciona
- **Input**: Detachar e reatachar
- **Output Esperado**: Change detection desativado/ativado

**Teste 3**: detectChanges funciona
- **Input**: Chamar detectChanges
- **Output Esperado**: Verificação forçada imediatamente

---

## Extensões (Opcional)

1. **Performance Monitoring**: Monitore impacto de controle manual
2. **Conditional Detection**: Implemente detecção condicional
3. **Advanced Patterns**: Explore padrões avançados

---

## Referências Úteis

- **[ChangeDetectorRef](https://angular.io/api/core/ChangeDetectorRef)**: Documentação ChangeDetectorRef
- **[Manual Change Detection](https://angular.io/guide/change-detection#optimize-change-detection)**: Guia controle manual

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

