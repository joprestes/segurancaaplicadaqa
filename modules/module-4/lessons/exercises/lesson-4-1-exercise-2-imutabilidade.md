---
layout: exercise
title: "Exercício 4.1.2: Imutabilidade e OnPush"
slug: "imutabilidade"
lesson_id: "lesson-4-1"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **imutabilidade com OnPush** através da **criação de componente que usa imutabilidade para atualizar estado**.

Ao completar este exercício, você será capaz de:

- Implementar imutabilidade em OnPush
- Atualizar arrays e objetos de forma imutável
- Entender por que imutabilidade é necessária
- Usar Signals para imutabilidade automática

---

## Descrição

Você precisa criar um componente OnPush que gerencia lista de itens usando imutabilidade.

### Contexto

Uma aplicação precisa gerenciar lista de itens em componente OnPush usando imutabilidade.

### Tarefa

Crie:

1. **Componente OnPush**: Componente com OnPush strategy
2. **Lista Imutável**: Lista gerenciada de forma imutável
3. **Operações CRUD**: Criar, ler, atualizar, deletar usando imutabilidade
4. **Verificação**: Verificar que OnPush detecta mudanças

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente usa OnPush
- [ ] Lista gerenciada de forma imutável
- [ ] Operações CRUD implementadas
- [ ] OnPush detecta mudanças corretamente
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Imutabilidade está implementada corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**item-list.component.ts**
{% raw %}
```typescript
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Item {
  id: number;
  name: string;
  completed: boolean;
}

@Component({
  selector: 'app-item-list',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>Lista de Itens (OnPush + Imutabilidade)</h2>
      
      <input 
        #input
        (keyup.enter)="addItem(input.value); input.value = ''"
        placeholder="Novo item">
      
      <ul>
        @for (item of items(); track item.id) {
          <li>
            <input 
              type="checkbox" 
              [checked]="item.completed"
              (change)="toggleItem(item.id)">
            <span [class.completed]="item.completed">{{ item.name }}</span>
            <button (click)="updateItem(item.id, 'Updated')">Atualizar</button>
            <button (click)="removeItem(item.id)">Remover</button>
          </li>
        }
      </ul>
      
      <p>Total: {{ items().length }} | Completos: {{ completedCount() }}</p>
    </div>
  `
{% endraw %}
})
export class ItemListComponent {
  items = signal<Item[]>([]);
  
  completedCount = signal(0);
  
  addItem(name: string): void {
    if (name.trim()) {
      const newItem: Item = {
        id: Date.now(),
        name: name.trim(),
        completed: false
      };
      
      this.items.update(items => [...items, newItem]);
      this.updateCompletedCount();
    }
  }
  
  toggleItem(id: number): void {
    this.items.update(items =>
      items.map(item => 
        item.id === id ? { ...item, completed: !item.completed } : item
      )
    );
    this.updateCompletedCount();
  }
  
  updateItem(id: number, newName: string): void {
    this.items.update(items =>
      items.map(item => 
        item.id === id ? { ...item, name: newName } : item
      )
    );
  }
  
  removeItem(id: number): void {
    this.items.update(items => items.filter(item => item.id !== id));
    this.updateCompletedCount();
  }
  
  private updateCompletedCount(): void {
    this.completedCount.set(
      this.items().filter(item => item.completed).length
    );
  }
}
```

**Explicação da Solução**:

1. OnPush strategy configurada
2. Signal usado para lista imutável
3. Operações criam novos arrays/objetos
4. Spread operator usado para imutabilidade
5. Change detection detecta mudanças por referência
6. Código limpo e performático

---

## Testes

### Casos de Teste

**Teste 1**: Adicionar item funciona
- **Input**: Adicionar novo item
- **Output Esperado**: Item adicionado e exibido

**Teste 2**: Atualizar item funciona
- **Input**: Atualizar item existente
- **Output Esperado**: Item atualizado e exibido

**Teste 3**: OnPush detecta mudanças
- **Input**: Verificar change detection
- **Output Esperado**: Mudanças detectadas corretamente

---

## Extensões (Opcional)

1. **Undo/Redo**: Implemente undo/redo usando imutabilidade
2. **Deep Immutability**: Use bibliotecas como Immer
3. **Performance**: Compare performance com mutação

---

## Referências Úteis

- **[Immutability Guide](https://angular.io/guide/change-detection#optimize-change-detection)**: Guia imutabilidade
- **[Signal Updates](https://angular.io/guide/signals)**: Guia Signals

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

