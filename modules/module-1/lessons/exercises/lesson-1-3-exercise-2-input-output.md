---
layout: exercise
title: "Exercício 1.3.2: Componente com Input e Output"
slug: "input-output"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **comunicação entre componentes** através da **implementação de @Input e @Output**.

Ao completar este exercício, você será capaz de:

- Usar `@Input()` para receber dados do componente pai
- Usar `@Output()` e `EventEmitter` para emitir eventos
- Entender comunicação unidirecional de dados
- Criar componentes reutilizáveis e comunicativos

---

## Descrição

Você precisa criar um componente `ButtonComponent` que recebe configurações via `@Input` e emite eventos via `@Output` quando clicado. O componente deve ser flexível e reutilizável.

### Contexto

Um sistema precisa de um componente de botão reutilizável que pode ser configurado com diferentes textos, estilos e ações. O componente deve comunicar cliques ao componente pai.

### Tarefa

Crie um componente `ButtonComponent` com:

1. **@Input `label`**: Texto do botão (string, obrigatório)
2. **@Input `variant`**: Variante do botão - 'primary' | 'secondary' | 'danger' (padrão: 'primary')
3. **@Input `disabled`**: Se o botão está desabilitado (boolean, padrão: false)
4. **@Input `size`**: Tamanho do botão - 'small' | 'medium' | 'large' (padrão: 'medium')
5. **@Output `clicked`**: EventEmitter que emite quando botão é clicado
6. **Template**: Botão com classes dinâmicas baseadas nas propriedades
7. **Estilos**: CSS para diferentes variantes e tamanhos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] `@Input()` decorators implementados corretamente
- [ ] `@Output()` com `EventEmitter` implementado
- [ ] Template usa property binding para classes dinâmicas
- [ ] Event binding no botão chama método que emite evento
- [ ] Estilos CSS para diferentes variantes
- [ ] Estilos CSS para diferentes tamanhos
- [ ] Componente pode ser usado com diferentes configurações

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Tipos são explícitos (não usa `any`)
- [ ] EventEmitter é tipado corretamente
- [ ] Código é legível e bem organizado
- [ ] Componente é reutilizável

---

## Dicas

### Dica 1: @Input Básico

```typescript
import { Input } from '@angular/core';

@Input() label: string = '';
```

### Dica 2: @Input com Valor Padrão

```typescript
@Input() variant: 'primary' | 'secondary' | 'danger' = 'primary';
```

### Dica 3: @Output com EventEmitter

```typescript
import { Output, EventEmitter } from '@angular/core';

@Output() clicked = new EventEmitter<void>();

onClick(): void {
  this.clicked.emit();
}
```

### Dica 4: Classes Dinâmicas no Template

{% raw %}
```html
<button 
  [class.btn-primary]="variant === 'primary'"
  [class.btn-secondary]="variant === 'secondary'"
  [disabled]="disabled">
  {{ label }}
</button>
```
{% endraw %}

### Dica 5: Usar ngClass

```html
<button 
  [ngClass]="{
    'btn-primary': variant === 'primary',
    'btn-small': size === 'small'
  }">
```

---

## Solução Esperada

### Abordagem Recomendada

**button.component.ts**
```typescript
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-button',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './button.component.html',
  styleUrls: ['./button.component.css']
})
export class ButtonComponent {
  @Input() label: string = '';
  @Input() variant: 'primary' | 'secondary' | 'danger' = 'primary';
  @Input() disabled: boolean = false;
  @Input() size: 'small' | 'medium' | 'large' = 'medium';
  
  @Output() clicked = new EventEmitter<void>();

  onClick(): void {
    if (!this.disabled) {
      this.clicked.emit();
    }
  }

  get buttonClasses(): string {
    return `btn btn-${this.variant} btn-${this.size}`;
  }
}
```

**button.component.html**
```html
<button 
  [class]="buttonClasses"
  [disabled]="disabled"
  (click)="onClick()">
  {{ label }}
</button>
```

**button.component.css**
```css
.btn {
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.3s ease;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-primary {
  background-color: #1976d2;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background-color: #1565c0;
}

.btn-secondary {
  background-color: #757575;
  color: white;
}

.btn-secondary:hover:not(:disabled) {
  background-color: #616161;
}

.btn-danger {
  background-color: #d32f2f;
  color: white;
}

.btn-danger:hover:not(:disabled) {
  background-color: #c62828;
}

.btn-small {
  padding: 6px 12px;
  font-size: 0.875rem;
}

.btn-medium {
  padding: 10px 20px;
  font-size: 1rem;
}

.btn-large {
  padding: 14px 28px;
  font-size: 1.125rem;
}
```

**app.component.ts** (exemplo de uso)

```typescript
import { Component } from '@angular/core';
import { ButtonComponent } from './button/button.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [ButtonComponent],
  template: `
    <app-button 
      label="Clique Aqui"
      variant="primary"
      size="medium"
      (clicked)="onButtonClick()">
    </app-button>
    
    <app-button 
      label="Cancelar"
      variant="secondary"
      size="small"
      (clicked)="onCancel()">
    </app-button>
    
    <app-button 
      label="Deletar"
      variant="danger"
      size="large"
      [disabled]="isDeleting"
      (clicked)="onDelete()">
    </app-button>
  `
})
export class AppComponent {
  isDeleting: boolean = false;

  onButtonClick(): void {
    console.log('Botão clicado!');
  }

  onCancel(): void {
    console.log('Cancelado');
  }

  onDelete(): void {
    this.isDeleting = true;
    console.log('Deletando...');
  }
}
```

**Explicação da Solução**:

1. `@Input()` decorators recebem dados do componente pai
2. `@Output()` com `EventEmitter` emite eventos
3. Método `onClick()` verifica se está desabilitado antes de emitir
4. `buttonClasses` getter gera classes dinâmicas
5. Template usa property binding e event binding
6. Estilos CSS para diferentes variantes e tamanhos

**Decisões de Design**:

- Tipos union para variantes e tamanhos garantem type safety
- Getter `buttonClasses` centraliza lógica de classes
- Verificação de `disabled` previne eventos quando desabilitado
- Estilos seguem padrão de design consistente

---

## Testes

### Casos de Teste

**Teste 1**: Botão com label personalizado
- **Input**: `<app-button label="Meu Botão"></app-button>`
- **Output Esperado**: Botão deve exibir "Meu Botão"

**Teste 2**: Variantes diferentes
- **Input**: Botões com `variant="primary"`, `variant="secondary"`, `variant="danger"`
- **Output Esperado**: Cada botão deve ter cor correspondente

**Teste 3**: Tamanhos diferentes
- **Input**: Botões com `size="small"`, `size="medium"`, `size="large"`
- **Output Esperado**: Cada botão deve ter tamanho correspondente

**Teste 4**: Botão desabilitado
- **Input**: `<app-button [disabled]="true"></app-button>`
- **Output Esperado**: Botão deve estar desabilitado e não emitir eventos

**Teste 5**: Evento emitido ao clicar
- **Input**: Clicar no botão
- **Output Esperado**: Evento `clicked` deve ser emitido (verificar no console)

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Adicionar Ícone**: Adicione `@Input() icon?: string` para exibir ícones
2. **Adicionar Loading**: Adicione `@Input() loading: boolean` com spinner
3. **Emitir Dados**: Modifique `EventEmitter` para emitir dados: `EventEmitter<{label: string, timestamp: number}>`
4. **Acessibilidade**: Adicione atributos ARIA para melhor acessibilidade

---

## Referências Úteis

- **[@Input Decorator](https://angular.io/api/core/Input)**: Documentação oficial
- **[@Output Decorator](https://angular.io/api/core/Output)**: Documentação oficial
- **[EventEmitter](https://angular.io/api/core/EventEmitter)**: Documentação do EventEmitter
- **[Component Communication](https://angular.io/guide/inputs-outputs)**: Guia de comunicação

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

