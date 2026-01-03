---
layout: exercise
title: "Exercício 2.5.2: ViewChild e ContentChild"
slug: "viewchild-contentchild"
lesson_id: "lesson-2-5"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **ViewChild e ContentChild** através da **criação de componentes que acessam filhos e conteúdo projetado**.

Ao completar este exercício, você será capaz de:

- Usar ViewChild para acessar componente filho
- Usar ViewChildren para acessar múltiplos filhos
- Usar ContentChild para acessar conteúdo projetado
- Trabalhar com Template Reference Variables
- Entender lifecycle hooks relacionados

---

## Descrição

Você precisa criar um componente card que usa ViewChild para acessar header e ContentChild para conteúdo projetado.

### Contexto

Uma aplicação precisa de componentes que acessam filhos diretamente para chamar métodos ou acessar propriedades.

### Tarefa

Crie:

1. **CardHeaderComponent**: Componente header
2. **CardComponent**: Componente que usa ViewChild e ContentChild
3. **ParentComponent**: Componente que usa CardComponent
4. **Acesso**: Demonstre acesso a filhos e conteúdo

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] ViewChild implementado
- [ ] ContentChild implementado
- [ ] Template Reference Variables usadas
- [ ] Métodos de filhos são chamados
- [ ] Lifecycle hooks implementados
- [ ] Acesso funciona corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Acesso está bem implementado
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**card-header.component.ts**
```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-card-header',
  standalone: true,
  template: `
    <div class="card-header">
      <ng-content></ng-content>
    </div>
  `,
  styles: [`
    .card-header {
      padding: 1rem;
      background-color: #f0f0f0;
      border-bottom: 1px solid #ccc;
    }
  `]
})
export class CardHeaderComponent {
  title: string = '';
  
  setTitle(title: string): void {
    this.title = title;
    console.log('Title set to:', title);
  }
}
```

**card.component.ts**
```typescript
import { Component, ViewChild, ContentChild, AfterViewInit, AfterContentInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CardHeaderComponent } from './card-header.component';

@Component({
  selector: 'app-card',
  standalone: true,
  imports: [CommonModule, CardHeaderComponent],
  template: `
    <div class="card">
      <ng-content select="app-card-header"></ng-content>
      <div class="card-body">
        <ng-content></ng-content>
      </div>
      <div class="card-footer">
        <button (click)="updateHeader()">Atualizar Header</button>
      </div>
    </div>
  `,
  styles: [`
    .card {
      border: 1px solid #ccc;
      border-radius: 4px;
      margin: 1rem;
    }
    
    .card-body {
      padding: 1rem;
    }
    
    .card-footer {
      padding: 1rem;
      background-color: #f9f9f9;
      border-top: 1px solid #ccc;
    }
  `]
})
export class CardComponent implements AfterViewInit, AfterContentInit {
  @ViewChild(CardHeaderComponent) headerComponent!: CardHeaderComponent;
  @ContentChild(CardHeaderComponent) contentHeader!: CardHeaderComponent;
  
  ngAfterViewInit(): void {
    console.log('ViewChild header:', this.headerComponent);
    if (this.headerComponent) {
      this.headerComponent.setTitle('Título do ViewChild');
    }
  }
  
  ngAfterContentInit(): void {
    console.log('ContentChild header:', this.contentHeader);
    if (this.contentHeader) {
      this.contentHeader.setTitle('Título do ContentChild');
    }
  }
  
  updateHeader(): void {
    if (this.headerComponent) {
      this.headerComponent.setTitle('Título Atualizado');
    }
    if (this.contentHeader) {
      this.contentHeader.setTitle('Título Atualizado via ContentChild');
    }
  }
}
```

**parent.component.ts**
```typescript
import { Component, ViewChild, AfterViewInit } from '@angular/core';
import { CardComponent } from './card.component';
import { CardHeaderComponent } from './card-header.component';

@Component({
  selector: 'app-parent',
  standalone: true,
  imports: [CardComponent, CardHeaderComponent],
  template: `
    <div>
      <h2>Exemplo ViewChild e ContentChild</h2>
      
      <app-card>
        <app-card-header #headerRef>
          <h3>Header Projetado</h3>
        </app-card-header>
        <p>Conteúdo do card aqui</p>
      </app-card>
      
      <button (click)="callCardMethod()">Chamar Método do Card</button>
    </div>
  `
})
export class ParentComponent implements AfterViewInit {
  @ViewChild(CardComponent) cardComponent!: CardComponent;
  
  ngAfterViewInit(): void {
    console.log('Card component:', this.cardComponent);
  }
  
  callCardMethod(): void {
    if (this.cardComponent) {
      this.cardComponent.updateHeader();
    }
  }
}
```

**Explicação da Solução**:

1. CardHeaderComponent é componente reutilizável
2. CardComponent usa ViewChild para acessar header no template
3. CardComponent usa ContentChild para acessar header projetado
4. ngAfterViewInit e ngAfterContentInit garantem acesso
5. Métodos de filhos são chamados via ViewChild
6. Template Reference Variables facilitam acesso

---

## Testes

### Casos de Teste

**Teste 1**: ViewChild funciona
- **Input**: Acessar componente via ViewChild
- **Output Esperado**: Componente acessível e métodos funcionam

**Teste 2**: ContentChild funciona
- **Input**: Acessar conteúdo projetado
- **Output Esperado**: Conteúdo acessível

**Teste 3**: Métodos são chamados
- **Input**: Chamar método do filho
- **Output Esperado**: Método executa corretamente

---

## Extensões (Opcional)

1. **ViewChildren**: Implemente ViewChildren para múltiplos filhos
2. **ContentChildren**: Implemente ContentChildren para múltiplos conteúdos
3. **QueryList**: Trabalhe com QueryList reativo

---

## Referências Úteis

- **[ViewChild](https://angular.io/api/core/ViewChild)**: Documentação ViewChild
- **[ContentChild](https://angular.io/api/core/ContentChild)**: Documentação ContentChild
- **[Lifecycle Hooks](https://angular.io/guide/lifecycle-hooks)**: Guia lifecycle hooks

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

