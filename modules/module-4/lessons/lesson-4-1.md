---
layout: lesson
title: "Aula 4.1: Change Detection Strategies"
slug: change-detection
module: module-4
lesson_id: lesson-4-1
duration: "120 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-3-5"
exercises:
  - 
  - "lesson-4-1-exercise-1"
  - "lesson-4-1-exercise-2"
  - "lesson-4-1-exercise-3"
  - "lesson-4-1-exercise-4"
  - "lesson-4-1-exercise-5"
  - "lesson-4-1-exercise-6"
podcast:
  file: "assets/podcasts/04.1-OnPush_Imutabilidade_e_Performance_de_Apps.m4a"
  title: "OnPush, Imutabilidade e Performance de Apps"
  description: "Change Detection é crítico para performance."
  duration: "60-75 minutos"
---

## Introdução

Nesta aula, você dominará estratégias avançadas de change detection no Angular. Change detection é um dos aspectos mais importantes para performance em aplicações Angular, e entender como otimizá-la é essencial para criar aplicações rápidas e responsivas.

### O que você vai aprender

- Entender Default vs OnPush change detection
- Implementar OnPush strategy em componentes
- Trabalhar com imutabilidade
- Usar ChangeDetectorRef para controle manual
- Implementar trackBy functions para otimização
- Aplicar OnPush everywhere pattern

### Por que isso é importante

Change detection pode ser um grande gargalo de performance em aplicações Angular. OnPush strategy pode reduzir drasticamente o número de verificações de mudanças, melhorando significativamente a performance. É uma das otimizações mais impactantes que você pode fazer.

---

## Conceitos Teóricos

### Default Strategy

**Definição**: Default strategy verifica mudanças em todos os componentes em cada ciclo de change detection.

**Explicação Detalhada**:

Default Strategy:
- Verifica todos componentes em cada ciclo
- Executa após eventos, timers, HTTP, etc.
- Compara valores usando === (referência)
- Pode ser ineficiente em aplicações grandes
- Fácil de usar mas pode causar problemas de performance

**Analogia**:

Default strategy é como verificar todas as portas de um prédio toda vez que algo acontece, mesmo que apenas uma porta tenha mudado.

**Visualização**:

```
Event ──→ Zone.js ──→ Change Detection ──→ Check ALL Components
```

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-default',
  standalone: true,
  template: `<p>{{ data }}</p>`
})
export class DefaultComponent {
  data = 'Hello';
}
```

---

### OnPush Strategy

**Definição**: OnPush strategy verifica mudanças apenas quando inputs mudam ou eventos ocorrem no componente.

**Explicação Detalhada**:

OnPush Strategy:
- Verifica apenas quando inputs mudam (por referência)
- Verifica quando eventos ocorrem no componente
- Requer imutabilidade para funcionar corretamente
- Muito mais eficiente que Default
- Reduz drasticamente verificações desnecessárias

**Analogia**:

OnPush é como verificar apenas as portas que realmente mudaram, economizando tempo e recursos.

**Visualização**:

```
Input Change ──→ OnPush Check ──→ Update if Changed
Event ──→ OnPush Check ──→ Update if Changed
```

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-onpush',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<p>{{ data }}</p>`
})
export class OnPushComponent {
  @Input() data = 'Hello';
}
```

---

### Imutabilidade

**Definição**: Imutabilidade significa não modificar objetos existentes, mas criar novos objetos quando mudanças são necessárias.

**Explicação Detalhada**:

Imutabilidade:
- Não modifica objetos existentes
- Cria novos objetos para mudanças
- Permite comparação por referência (===)
- Essencial para OnPush funcionar
- Facilita debugging e testes

**Analogia**:

Imutabilidade é como criar uma nova versão de um documento ao invés de editar o original. Você sempre sabe qual é a versão atual.

**Exemplo Prático**:

```typescript
export class ImmutableComponent {
  items = signal<Item[]>([]);
  
  addItem(item: Item): void {
    this.items.update(items => [...items, item]);
  }
  
  updateItem(id: number, changes: Partial<Item>): void {
    this.items.update(items =>
      items.map(item => item.id === id ? { ...item, ...changes } : item)
    );
  }
}
```

---

### ChangeDetectorRef

**Definição**: ChangeDetectorRef fornece métodos para controlar change detection manualmente.

**Explicação Detalhada**:

ChangeDetectorRef:
- detectChanges(): Força verificação imediata
- detach(): Desconecta do ciclo de change detection
- reattach(): Reconecta ao ciclo
- markForCheck(): Marca para verificação no próximo ciclo
- Útil para otimizações avançadas

**Analogia**:

ChangeDetectorRef é como um controle remoto para change detection. Você pode forçar verificações quando necessário ou desabilitar quando não precisa.

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-manual',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<p>{{ data }}</p>`
})
export class ManualComponent {
  data = 'Hello';
  
  constructor(private cdr: ChangeDetectorRef) {}
  
  updateData(): void {
    this.data = 'Updated';
    this.cdr.markForCheck();
  }
  
  detachComponent(): void {
    this.cdr.detach();
  }
  
  reattachComponent(): void {
    this.cdr.reattach();
  }
}
```

---

### trackBy Functions

**Definição**: trackBy functions ajudam Angular a identificar itens em listas, melhorando performance de *ngFor.

**Explicação Detalhada**:

trackBy Functions:
- Identifica itens únicos em listas
- Evita re-renderização desnecessária
- Melhora performance de *ngFor
- Reduz trabalho do change detection
- Essencial para listas grandes

**Analogia**:

trackBy é como dar um ID único para cada item em uma lista. Angular sabe exatamente qual item mudou sem precisar verificar todos.

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-trackby',
  standalone: true,
  template: `
    <ul>
      @for (item of items(); track trackById($index, item)) {
        <li>{{ item.name }}</li>
      }
    </ul>
  `
})
export class TrackByComponent {
  items = signal<Item[]>([]);
  
  trackById(index: number, item: Item): number {
    return item.id;
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Componente OnPush Completo

**Contexto**: Criar componente completo usando OnPush strategy com imutabilidade.

**Código**:

{% raw %}
```typescript
import { Component, Input, ChangeDetectionStrategy, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>Usuários (OnPush)</h2>
      <p>Total: {{ userCount() }}</p>
      <ul>
        @for (user of users(); track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
      <button (click)="addUser()">Adicionar Usuário</button>
    </div>
  `
})
export class UserListComponent {
  users = signal<User[]>([]);
  
  userCount = computed(() => this.users().length);
  
  addUser(): void {
    const newUser: User = {
      id: Date.now(),
      name: `User ${this.users().length + 1}`,
      email: `user${this.users().length + 1}@example.com`
    };
    
    this.users.update(users => [...users, newUser]);
  }
  
  updateUser(id: number, changes: Partial<User>): void {
    this.users.update(users =>
      users.map(user => user.id === id ? { ...user, ...changes } : user)
    );
  }
  
  removeUser(id: number): void {
    this.users.update(users => users.filter(user => user.id !== id));
  }
}
```
{% endraw %}

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use OnPush sempre que possível**
   - **Por quê**: Melhor performance
   - **Exemplo**: `changeDetection: ChangeDetectionStrategy.OnPush`

2. **Mantenha imutabilidade**
   - **Por quê**: OnPush requer imutabilidade
   - **Exemplo**: `[...items, newItem]` ao invés de `items.push(newItem)`

3. **Use trackBy em listas**
   - **Por quê**: Melhora performance de *ngFor
   - **Exemplo**: `track trackById($index, item)`

4. **Use markForCheck() quando necessário**
   - **Por quê**: Força verificação em OnPush
   - **Exemplo**: Após atualizações assíncronas

### ❌ Anti-padrões Comuns

1. **Não mutar objetos em OnPush**
   - **Problema**: Change detection não detecta mudanças
   - **Solução**: Sempre criar novos objetos

2. **Não esquecer trackBy em listas grandes**
   - **Problema**: Performance ruim
   - **Solução**: Sempre usar trackBy

3. **Não usar Default quando OnPush é possível**
   - **Problema**: Performance desnecessariamente ruim
   - **Solução**: Prefira OnPush

---

## Exercícios Práticos

### Exercício 1: Implementar OnPush Básico (Básico)

**Objetivo**: Converter componente para OnPush

**Descrição**: 
Converta componente de Default para OnPush strategy.

**Arquivo**: `exercises/exercise-4-1-1-onpush-basico.md`

---

### Exercício 2: Imutabilidade e OnPush (Intermediário)

**Objetivo**: Implementar imutabilidade com OnPush

**Descrição**:
Crie componente OnPush que usa imutabilidade para atualizar estado.

**Arquivo**: `exercises/exercise-4-1-2-imutabilidade.md`

---

### Exercício 3: ChangeDetectorRef Manual (Intermediário)

**Objetivo**: Usar ChangeDetectorRef para controle manual

**Descrição**:
Crie componente que usa ChangeDetectorRef para controle manual de change detection.

**Arquivo**: `exercises/exercise-4-1-3-changedetectorref.md`

---

### Exercício 4: trackBy Functions (Intermediário)

**Objetivo**: Implementar trackBy functions

**Descrição**:
Crie componente com lista grande usando trackBy para otimização.

**Arquivo**: `exercises/exercise-4-1-4-trackby.md`

---

### Exercício 5: OnPush Everywhere (Avançado)

**Objetivo**: Aplicar OnPush em toda aplicação

**Descrição**:
Converta aplicação completa para usar OnPush em todos componentes.

**Arquivo**: `exercises/exercise-4-1-5-onpush-everywhere.md`

---

### Exercício 6: Otimização Completa (Avançado)

**Objetivo**: Otimizar aplicação completa

**Descrição**:
Aplique todas técnicas de otimização de change detection em aplicação real.

**Arquivo**: `exercises/exercise-4-1-6-otimizacao-completa.md`

---

## Referências Externas

### Documentação Oficial

- **[Change Detection](https://angular.io/guide/change-detection)**: Guia completo
- **[OnPush](https://angular.io/api/core/ChangeDetectionStrategy)**: Documentação OnPush
- **[ChangeDetectorRef](https://angular.io/api/core/ChangeDetectorRef)**: Documentação ChangeDetectorRef

---

## Resumo

### Principais Conceitos

- Default strategy verifica todos componentes
- OnPush strategy verifica apenas quando necessário
- Imutabilidade é essencial para OnPush
- ChangeDetectorRef permite controle manual
- trackBy functions melhoram performance de listas

### Pontos-Chave para Lembrar

- Use OnPush sempre que possível
- Mantenha imutabilidade
- Use trackBy em listas
- Use markForCheck() quando necessário
- Prefira OnPush sobre Default

### Próximos Passos

- Próxima aula: Lazy Loading e Code Splitting
- Praticar OnPush em componentes
- Explorar otimizações avançadas

---

## Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 3.5: Integração Signals + Observables](./lesson-3-5-signals-observables.md)  
**Próxima Aula**: [Aula 4.2: Lazy Loading e Code Splitting](./lesson-4-2-lazy-loading.md)  
**Voltar ao Módulo**: [Módulo 4: Performance e Otimização](../modules/module-4-performance-otimizacao.md)

