---
layout: exercise
title: "Exercício 4.3.1: @defer Básico"
slug: "defer-basico"
lesson_id: "lesson-4-3"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **@defer básico** através da **criação de componente que usa @defer para carregar componente pesado**.

Ao completar este exercício, você será capaz de:

- Usar @defer block básico
- Carregar componente sob demanda
- Entender benefícios de @defer
- Verificar que componente é carregado lazy

---

## Descrição

Você precisa criar um componente que usa @defer para carregar um componente pesado sob demanda.

### Contexto

Uma aplicação precisa reduzir bundle inicial carregando componente pesado apenas quando necessário.

### Tarefa

Crie:

1. **Componente Pesado**: Criar componente que será defer-loaded
2. **Componente Principal**: Criar componente que usa @defer
3. **Verificação**: Verificar que componente é carregado lazy

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente pesado criado
- [ ] @defer block implementado
- [ ] Componente carregado sob demanda
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] @defer está implementado corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**heavy.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-heavy',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="heavy-component">
      <h3>Componente Pesado</h3>
      <p>Este componente foi carregado sob demanda usando @defer!</p>
      <ul>
        @for (item of items; track item) {
          <li>{{ item }}</li>
        }
      </ul>
    </div>
  `,
  styles: [`
    .heavy-component {
      padding: 2rem;
      border: 2px solid #3498db;
      border-radius: 8px;
      background: #f8f9fa;
    }
  `]
})
export class HeavyComponent {
  items = ['Item 1', 'Item 2', 'Item 3', 'Item 4', 'Item 5'];
}
```

**main.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HeavyComponent } from './heavy.component';

@Component({
  selector: 'app-main',
  standalone: true,
  imports: [CommonModule, HeavyComponent],
  template: `
    <div>
      <h2>Componente Principal</h2>
      <p>Este conteúdo é carregado imediatamente</p>
      
      @defer {
        <app-heavy></app-heavy>
      }
    </div>
  `
})
export class MainComponent {}
```

**Explicação da Solução**:

1. HeavyComponent criado como componente standalone
2. @defer block usado no template
3. Componente carregado apenas quando necessário
4. Bundle inicial reduzido
5. Performance melhorada

---

## Testes

### Casos de Teste

**Teste 1**: Componente carregado
- **Input**: Renderizar componente principal
- **Output Esperado**: HeavyComponent carregado e exibido

**Teste 2**: Lazy loading funciona
- **Input**: Verificar Network tab
- **Output Esperado**: Chunk carregado apenas quando necessário

**Teste 3**: Bundle reduzido
- **Input**: Comparar bundle antes/depois
- **Output Esperado**: Bundle inicial menor

---

## Extensões (Opcional)

1. **Múltiplos Defer**: Adicione múltiplos @defer blocks
2. **Nested Defer**: Implemente defer aninhado
3. **Conditional Defer**: Use defer condicionalmente

---

## Referências Úteis

- **[@defer](https://angular.io/guide/defer)**: Guia @defer
- **[Deferrable Views](https://angular.io/api/core/defer)**: Documentação deferrable views

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

