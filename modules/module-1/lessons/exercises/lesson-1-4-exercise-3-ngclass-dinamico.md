---
layout: exercise
title: "Exercício 1.4.3: Classes Dinâmicas com ngClass"
slug: "ngclass-dinamico"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **ngClass** através da **criação de um componente de status com classes CSS dinâmicas**.

Ao completar este exercício, você será capaz de:

- Usar `[ngClass]` com objetos
- Usar `[ngClass]` com arrays
- Usar `[ngClass]` com strings
- Aplicar classes condicionalmente baseado em estado
- Criar interfaces visuais dinâmicas

---

## Descrição

Você precisa criar um componente `StatusComponent` que exibe diferentes estados (ativo, inativo, pendente, erro) com classes CSS que mudam dinamicamente baseado no estado atual.

### Contexto

Um sistema precisa exibir status de diferentes entidades (pedidos, usuários, tarefas) com cores e estilos diferentes para cada estado. O componente deve ser reutilizável e flexível.

### Tarefa

Crie um componente `StatusComponent` com:

1. **Estados**: 'active', 'inactive', 'pending', 'error'
2. **ngClass com Objeto**: Usar objeto para aplicar classes condicionalmente
3. **ngClass com Método**: Criar método que retorna objeto de classes
4. **Múltiplos Estados**: Componente deve suportar múltiplos estados simultaneamente
5. **Estilos CSS**: Classes CSS para cada estado

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente criado com propriedade `status`
- [ ] `[ngClass]` usado com objeto
- [ ] Método que retorna objeto de classes
- [ ] Classes CSS definidas para cada estado
- [ ] Componente funciona com diferentes estados
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Classes são aplicadas corretamente
- [ ] Código é legível e bem organizado
- [ ] Componente é reutilizável

---

## Dicas

### Dica 1: ngClass com Objeto

```html
<div [ngClass]="{ 'active': isActive, 'error': hasError }">
```

### Dica 2: ngClass com Método

```typescript
getStatusClasses(): {[key: string]: boolean} {
  return {
    'status-active': this.status === 'active',
    'status-pending': this.status === 'pending'
  };
}
```

### Dica 3: ngClass com Array

```html
<div [ngClass]="['base-class', statusClass]">
```

### Dica 4: Múltiplas Condições

```typescript
getClasses(): {[key: string]: boolean} {
  return {
    'status-active': this.status === 'active',
    'status-disabled': this.isDisabled,
    'status-highlight': this.isHighlighted
  };
}
```

---

## Solução Esperada

### Abordagem Recomendada

**status.component.ts**
```typescript
import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

type Status = 'active' | 'inactive' | 'pending' | 'error';

@Component({
  selector: 'app-status',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './status.component.html',
  styleUrls: ['./status.component.css']
})
export class StatusComponent {
  @Input() status: Status = 'pending';
  @Input() label?: string;
  @Input() showIcon: boolean = true;
  
  getStatusClasses(): {[key: string]: boolean} {
    return {
      'status-active': this.status === 'active',
      'status-inactive': this.status === 'inactive',
      'status-pending': this.status === 'pending',
      'status-error': this.status === 'error'
    };
  }
  
  getStatusLabel(): string {
    if (this.label) return this.label;
    
    const labels: {[key: string]: string} = {
      'active': 'Ativo',
      'inactive': 'Inativo',
      'pending': 'Pendente',
      'error': 'Erro'
    };
    
    return labels[this.status] || 'Desconhecido';
  }
  
  getStatusIcon(): string {
    const icons: {[key: string]: string} = {
      'active': '✓',
      'inactive': '○',
      'pending': '⏳',
      'error': '✗'
    };
    
    return icons[this.status] || '?';
  }
}
```

**status.component.html**
```html
<div class="status-badge" [ngClass]="getStatusClasses()">
  <span class="status-icon" *ngIf="showIcon">
    {{ getStatusIcon() }}
  </span>
  <span class="status-label">{{ getStatusLabel() }}</span>
</div>
```

**status.component.css**
```css
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-radius: 20px;
  font-size: 0.875rem;
  font-weight: 500;
  transition: all 0.3s ease;
}

.status-icon {
  font-size: 1rem;
}

.status-active {
  background-color: #e8f5e9;
  color: #2e7d32;
  border: 1px solid #4caf50;
}

.status-inactive {
  background-color: #f5f5f5;
  color: #757575;
  border: 1px solid #bdbdbd;
}

.status-pending {
  background-color: #fff3e0;
  color: #e65100;
  border: 1px solid #ff9800;
}

.status-error {
  background-color: #ffebee;
  color: #c62828;
  border: 1px solid #f44336;
}

.status-badge:hover {
  transform: scale(1.05);
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}
```

**exemplo-uso.component.ts**
```typescript
import { Component } from '@angular/core';
import { StatusComponent } from './status/status.component';

@Component({
  selector: 'app-exemplo-uso',
  standalone: true,
  imports: [StatusComponent],
  template: `
    <div class="status-examples">
      <h2>Exemplos de Status</h2>
      
      <app-status status="active"></app-status>
      <app-status status="inactive"></app-status>
      <app-status status="pending"></app-status>
      <app-status status="error"></app-status>
      
      <app-status status="active" label="Online"></app-status>
      <app-status status="error" label="Falha na Conexão" [showIcon]="false"></app-status>
    </div>
  `
})
export class ExemploUsoComponent {}
```

**Explicação da Solução**:

1. Tipo `Status` garante type safety
2. `@Input` permite configurar status externamente
3. `getStatusClasses()` retorna objeto de classes condicionais
4. `getStatusLabel()` fornece labels em português
5. `getStatusIcon()` retorna ícones por estado
6. Template usa `[ngClass]` com método
7. CSS define estilos para cada estado

**Decisões de Design**:

- Método `getStatusClasses()` centraliza lógica
- Labels e ícones configuráveis
- Estilos consistentes e acessíveis
- Hover effects para interatividade

---

## Testes

### Casos de Teste

**Teste 1**: Classe aplicada corretamente
- **Input**: `<app-status status="active"></app-status>`
- **Output Esperado**: Classe `status-active` deve ser aplicada

**Teste 2**: Múltiplas classes
- **Input**: Componente com diferentes estados
- **Output Esperado**: Apenas classe do estado atual deve ser aplicada

**Teste 3**: Label customizado
- **Input**: `<app-status status="active" label="Online"></app-status>`
- **Output Esperado**: Label "Online" deve aparecer

**Teste 4**: Ícone oculto
- **Input**: `<app-status [showIcon]="false"></app-status>`
- **Output Esperado**: Ícone não deve aparecer

---

## Extensões (Opcional)

1. **Animações**: Adicione animações CSS para transições de estado
2. **Mais Estados**: Adicione estados como 'warning', 'info', 'success'
3. **Tamanhos**: Adicione @Input para tamanhos (small, medium, large)
4. **Tooltip**: Adicione tooltip com descrição do estado

---

## Referências Úteis

- **[ngClass](https://angular.io/api/common/NgClass)**: Documentação oficial
- **[Class Binding](https://angular.io/guide/attribute-binding#class-binding)**: Guia de binding de classes

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

