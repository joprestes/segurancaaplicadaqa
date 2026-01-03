---
layout: exercise
title: "Exercício 1.3.6: Projeção de Conteúdo"
slug: "projecao-conteudo"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **projeção de conteúdo** através da **criação de um componente Card reutilizável com múltiplos slots**.

Ao completar este exercício, você será capaz de:

- Usar `ng-content` para projeção básica
- Criar múltiplos slots com `select`
- Usar `ng-template` para conteúdo condicional
- Criar componentes wrapper reutilizáveis
- Entender padrões avançados de projeção

---

## Descrição

Você precisa criar um componente `CardComponent` que usa projeção de conteúdo para criar um card flexível e reutilizável. O componente deve suportar múltiplos slots (header, body, footer) e conteúdo condicional.

### Contexto

Um sistema precisa de um componente de card reutilizável que pode ser usado em diferentes contextos com conteúdo variável. Projeção de conteúdo permite criar componentes flexíveis.

### Tarefa

Crie um componente `CardComponent` com:

1. **Slot Header**: `ng-content` com `select="[slot=header]"`
2. **Slot Body**: `ng-content` padrão (conteúdo principal)
3. **Slot Footer**: `ng-content` com `select="[slot=footer]"`
4. **Slot Actions**: `ng-content` com `select="[slot=actions]"`
5. **Propriedades**: `@Input() title?: string`, `@Input() showHeader: boolean = true`
6. **Template Condicional**: Usar `*ngIf` para mostrar/ocultar slots
7. **Estilos**: Card estilizado com header, body e footer distintos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente Card criado com múltiplos slots
- [ ] Slot header com `select="[slot=header]"`
- [ ] Slot body padrão (sem select)
- [ ] Slot footer com `select="[slot=footer]"`
- [ ] Slot actions com `select="[slot=actions]"`
- [ ] @Input para controlar visibilidade do header
- [ ] Componente pode ser usado com diferentes conteúdos

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Slots são bem definidos e funcionais
- [ ] Componente é flexível e reutilizável
- [ ] Estilos são apropriados
- [ ] Código é bem organizado

---

## Dicas

### Dica 1: ng-content Básico

```html
<ng-content></ng-content>
```

### Dica 2: ng-content com Select

```html
<ng-content select="[slot=header]"></ng-content>
```

### Dica 3: Múltiplos Slots

```html
<div class="card-header">
  <ng-content select="[slot=header]"></ng-content>
</div>
<div class="card-body">
  <ng-content></ng-content>
</div>
<div class="card-footer">
  <ng-content select="[slot=footer]"></ng-content>
</div>
```

### Dica 4: Usar no Template Pai

```html
<app-card>
  <h1 slot="header">Título</h1>
  <p>Conteúdo principal</p>
  <button slot="footer">Ação</button>
</app-card>
```

### Dica 5: Condicional com *ngIf

```html
<div class="card-header" *ngIf="showHeader">
  <ng-content select="[slot=header]"></ng-content>
</div>
```

---

## Solução Esperada

### Abordagem Recomendada

**card.component.ts**
```typescript
import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-card',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './card.component.html',
  styleUrls: ['./card.component.css']
})
export class CardComponent {
  @Input() title?: string;
  @Input() showHeader: boolean = true;
  @Input() showFooter: boolean = true;
  @Input() variant: 'default' | 'outlined' | 'elevated' = 'default';
}
```

**card.component.html**
```html
<div class="card" [class]="'card-' + variant">
  <div class="card-header" *ngIf="showHeader">
    <ng-content select="[slot=header]">
      <h3 *ngIf="title">{{ title }}</h3>
    </ng-content>
  </div>
  
  <div class="card-body">
    <ng-content></ng-content>
  </div>
  
  <div class="card-actions" *ngIf="hasActions">
    <ng-content select="[slot=actions]"></ng-content>
  </div>
  
  <div class="card-footer" *ngIf="showFooter">
    <ng-content select="[slot=footer]"></ng-content>
  </div>
</div>
```

**card.component.css**
```css
.card {
  border-radius: 8px;
  overflow: hidden;
  background-color: white;
  margin: 1rem 0;
}

.card-default {
  border: 1px solid #e0e0e0;
}

.card-outlined {
  border: 2px solid #1976d2;
}

.card-elevated {
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  border: none;
}

.card-header {
  padding: 1.5rem;
  background-color: #f5f5f5;
  border-bottom: 1px solid #e0e0e0;
}

.card-header h3 {
  margin: 0;
  color: #333;
  font-size: 1.25rem;
}

.card-body {
  padding: 1.5rem;
  color: #424242;
  line-height: 1.6;
}

.card-actions {
  padding: 0.75rem 1.5rem;
  background-color: #fafafa;
  border-top: 1px solid #e0e0e0;
  display: flex;
  gap: 0.5rem;
  justify-content: flex-end;
}

.card-footer {
  padding: 1rem 1.5rem;
  background-color: #f9f9f9;
  border-top: 1px solid #e0e0e0;
  font-size: 0.875rem;
  color: #666;
}
```

**exemplo-uso.component.ts**
```typescript
import { Component } from '@angular/core';
import { CardComponent } from './card/card.component';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-exemplo-uso',
  standalone: true,
  imports: [CardComponent, CommonModule],
{% raw %}
  template: `
    <h1>Exemplos de Uso do Card Component</h1>
    
    <app-card title="Card Simples">
      <p>Este é um card simples com apenas título e conteúdo.</p>
    </app-card>
    
    <app-card variant="outlined">
      <h2 slot="header">Card com Header Customizado</h2>
      <p>Este card tem um header customizado usando slot.</p>
      <span slot="footer">Footer customizado</span>
    </app-card>
    
    <app-card variant="elevated" [showHeader]="false">
      <p>Card sem header, apenas conteúdo.</p>
      <button slot="actions">Ação 1</button>
      <button slot="actions">Ação 2</button>
    </app-card>
    
    <app-card>
      <div slot="header">
        <h2>Card Completo</h2>
        <span class="badge">Novo</span>
      </div>
      <p>Este é um card completo com todos os slots preenchidos.</p>
      <ul>
        <li>Item 1</li>
        <li>Item 2</li>
        <li>Item 3</li>
      </ul>
      <div slot="actions">
        <button class="btn-primary">Salvar</button>
        <button class="btn-secondary">Cancelar</button>
      </div>
      <div slot="footer">
        <small>Última atualização: {{ lastUpdate }}</small>
      </div>
    </app-card>
  `
{% endraw %}
})
export class ExemploUsoComponent {
  lastUpdate: string = new Date().toLocaleDateString();
}
```

**Explicação da Solução**:

1. Componente Card com múltiplos slots definidos
2. Slot header com fallback para título via @Input
3. Slot body padrão para conteúdo principal
4. Slot actions para botões de ação
5. Slot footer para informações adicionais
6. Variantes de estilo via @Input
7. Controle de visibilidade de slots

**Decisões de Design**:

- Múltiplos slots para máxima flexibilidade
- Fallback para título quando slot header vazio
- Variantes de estilo para diferentes casos de uso
- Controle de visibilidade para slots opcionais
- Estrutura semântica e acessível

---

## Testes

### Casos de Teste

**Teste 1**: Card básico com título
- **Input**: `<app-card title="Teste"></app-card>`
- **Output Esperado**: Card deve exibir título no header

**Teste 2**: Card com header customizado
- **Input**: `<app-card><h1 slot="header">Custom</h1></app-card>`
- **Output Esperado**: Header customizado deve aparecer

**Teste 3**: Card sem header
- **Input**: `<app-card [showHeader]="false"></app-card>`
- **Output Esperado**: Header não deve aparecer

**Teste 4**: Card com todos os slots
- **Input**: Card com header, body, actions e footer
- **Output Esperado**: Todos os slots devem aparecer corretamente

**Teste 5**: Variantes de estilo
- **Input**: Cards com `variant="default"`, `variant="outlined"`, `variant="elevated"`
- **Output Esperado**: Cada card deve ter estilo correspondente

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Adicionar ng-template**: Use `ng-template` para conteúdo condicional avançado
2. **Adicionar Animação**: Animações de entrada/saída para o card
3. **Adicionar Loading**: Slot para estado de carregamento
4. **Adicionar Acessibilidade**: Atributos ARIA apropriados

---

## Referências Úteis

- **[Content Projection](https://angular.io/guide/content-projection)**: Guia oficial de projeção de conteúdo
- **[ng-content](https://angular.io/api/core/ng-content)**: Documentação ng-content
- **[ng-template](https://angular.io/api/core/ng-template)**: Documentação ng-template

---

## Checklist de Qualidade

Antes de considerar este exercício completo:

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

