---
layout: exercise
title: "Exercício 1.4.5: Diretiva Customizada Highlight"
slug: "diretiva-customizada"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **criação de diretivas customizadas** através da **implementação de uma diretiva highlight que muda cor de fundo ao passar o mouse**.

Ao completar este exercício, você será capaz de:

- Criar diretivas customizadas standalone
- Usar `@HostBinding` para modificar propriedades do host
- Usar `@HostListener` para responder a eventos
- Usar `@Input` para receber dados na diretiva
- Acessar elemento com `ElementRef`

---

## Descrição

Você precisa criar uma diretiva `HighlightDirective` que muda a cor de fundo de um elemento quando o mouse passa sobre ele. A diretiva deve aceitar cor customizada via `@Input`.

### Contexto

Um sistema precisa de uma forma reutilizável de destacar elementos quando o usuário interage com eles. Uma diretiva customizada é a solução ideal para este caso.

### Tarefa

Crie uma diretiva `HighlightDirective` com:

1. **@Input `appHighlight`**: Cor de destaque (padrão: 'yellow')
2. **@Input `defaultColor`**: Cor padrão (padrão: 'transparent')
3. **@HostBinding**: Modificar `style.backgroundColor`
4. **@HostListener**: Responder a `mouseenter` e `mouseleave`
5. **Standalone**: Diretiva deve ser standalone
6. **Uso**: Aplicar diretiva em elementos HTML

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Diretiva criada com decorator `@Directive`
- [ ] `@Input` para cor de highlight
- [ ] `@Input` para cor padrão
- [ ] `@HostBinding` para backgroundColor
- [ ] `@HostListener` para mouseenter
- [ ] `@HostListener` para mouseleave
- [ ] Diretiva funciona quando aplicada

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Diretiva é reutilizável
- [ ] Código é legível e bem organizado
- [ ] Diretiva é standalone

---

## Dicas

### Dica 1: Estrutura Básica

```typescript
import { Directive } from '@angular/core';

@Directive({
  selector: '[appHighlight]',
  standalone: true
})
export class HighlightDirective {}
```

### Dica 2: @HostBinding

```typescript
@HostBinding('style.backgroundColor') backgroundColor: string = '';
```

### Dica 3: @HostListener

```typescript
@HostListener('mouseenter') onMouseEnter(): void {
  this.backgroundColor = 'yellow';
}
```

### Dica 4: @Input com Mesmo Nome do Seletor

```typescript
@Input() appHighlight: string = 'yellow';
```

---

## Solução Esperada

### Abordagem Recomendada

**highlight.directive.ts**
```typescript
import { Directive, HostBinding, HostListener, Input, OnInit } from '@angular/core';

@Directive({
  selector: '[appHighlight]',
  standalone: true
})
export class HighlightDirective implements OnInit {
  @Input() appHighlight: string = 'yellow';
  @Input() defaultColor: string = 'transparent';
  
  @HostBinding('style.backgroundColor') backgroundColor: string = '';
  @HostBinding('style.cursor') cursor: string = 'pointer';
  @HostBinding('style.transition') transition: string = 'background-color 0.3s ease';
  
  ngOnInit(): void {
    this.backgroundColor = this.defaultColor;
  }
  
  @HostListener('mouseenter') onMouseEnter(): void {
    this.backgroundColor = this.appHighlight;
  }
  
  @HostListener('mouseleave') onMouseLeave(): void {
    this.backgroundColor = this.defaultColor;
  }
}
```

**exemplo-uso.component.ts**
```typescript
import { Component } from '@angular/core';
import { HighlightDirective } from './highlight.directive';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-exemplo-uso',
  standalone: true,
  imports: [HighlightDirective, CommonModule],
  template: `
    <div class="highlight-examples">
      <h2>Exemplos de Highlight Directive</h2>
      
      <div class="example-section">
        <h3>Highlight Padrão (Amarelo)</h3>
        <p appHighlight>
          Passe o mouse sobre este texto para ver o highlight padrão.
        </p>
      </div>
      
      <div class="example-section">
        <h3>Highlight Customizado</h3>
        <p 
          appHighlight 
          [appHighlight]="'lightblue'"
          [defaultColor]="'lightgray'">
          Este texto tem cor de highlight customizada (azul claro).
        </p>
      </div>
      
      <div class="example-section">
        <h3>Diferentes Cores</h3>
        <div class="color-grid">
          <div 
            *ngFor="let color of colors"
            class="color-box"
            [appHighlight]="color"
            [defaultColor]="'white'">
            {{ color }}
          </div>
        </div>
      </div>
      
      <div class="example-section">
        <h3>Em Botões</h3>
        <button 
          appHighlight 
          [appHighlight]="'#4caf50'"
          [defaultColor]="'#1976d2'">
          Botão com Highlight
        </button>
      </div>
      
      <div class="example-section">
        <h3>Em Cards</h3>
        <div 
          class="card"
          appHighlight
          [appHighlight]="'#fff3e0'"
          [defaultColor]="'white'">
          <h4>Card com Highlight</h4>
          <p>Passe o mouse sobre o card inteiro.</p>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .highlight-examples {
      max-width: 900px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    .example-section {
      margin-bottom: 2rem;
      padding: 1.5rem;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
    }
    
    .color-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
      gap: 1rem;
      margin-top: 1rem;
    }
    
    .color-box {
      padding: 2rem;
      text-align: center;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-weight: 500;
    }
    
    .card {
      padding: 1.5rem;
      border: 1px solid #ddd;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
  `]
})
export class ExemploUsoComponent {
  colors: string[] = [
    'lightblue',
    'lightgreen',
    'lightyellow',
    'lightpink',
    'lightcoral',
    'lightcyan'
  ];
}
```

**Explicação da Solução**:

1. Diretiva criada com `@Directive` e `standalone: true`
2. `@Input appHighlight` recebe cor de destaque
3. `@Input defaultColor` recebe cor padrão
4. `@HostBinding` modifica `style.backgroundColor`
5. `@HostListener` responde a eventos de mouse
6. `ngOnInit` inicializa cor padrão
7. Diretiva pode ser aplicada em qualquer elemento

**Decisões de Design**:

- Nome do seletor igual ao `@Input` para conveniência
- Transição CSS para animação suave
- Cursor pointer indica interatividade
- Valores padrão sensatos

---

## Testes

### Casos de Teste

**Teste 1**: Highlight padrão funciona
- **Input**: `<p appHighlight>Texto</p>`
- **Output Esperado**: Fundo deve mudar para amarelo ao passar mouse

**Teste 2**: Cor customizada funciona
- **Input**: `<p [appHighlight]="'blue'">Texto</p>`
- **Output Esperado**: Fundo deve mudar para azul ao passar mouse

**Teste 3**: Cor padrão funciona
- **Input**: `<p [defaultColor]="'gray'">Texto</p>`
- **Output Esperado**: Fundo inicial deve ser cinza

**Teste 4**: Mouseleave restaura cor
- **Input**: Passar mouse e depois remover
- **Output Esperado**: Cor deve voltar ao padrão

---

## Extensões (Opcional)

1. **Click Highlight**: Adicione highlight ao clicar
2. **Delay**: Adicione delay antes de aplicar highlight
3. **Animação**: Adicione animação mais complexa
4. **Múltiplas Propriedades**: Modifique outras propriedades além de backgroundColor

---

## Referências Úteis

- **[Attribute Directives](https://angular.io/guide/attribute-directives)**: Guia oficial
- **[@Directive](https://angular.io/api/core/Directive)**: Documentação @Directive
- **[@HostBinding](https://angular.io/api/core/HostBinding)**: Documentação @HostBinding
- **[@HostListener](https://angular.io/api/core/HostListener)**: Documentação @HostListener

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

