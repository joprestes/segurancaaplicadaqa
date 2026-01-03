---
layout: exercise
title: "Exercício 5.3.1: Proteção XSS e Sanitization"
slug: "xss-sanitization"
lesson_id: "lesson-5-3"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **proteção XSS** através da **implementação de proteção XSS usando DomSanitizer**.

Ao completar este exercício, você será capaz de:

- Entender vulnerabilidades XSS
- Usar DomSanitizer corretamente
- Sanitizar HTML, CSS e URLs
- Prevenir ataques XSS
- Usar SafeHtml, SafeUrl, SafeStyle

---

## Descrição

Você precisa implementar proteção XSS em um componente que exibe conteúdo do usuário.

### Contexto

Uma aplicação precisa exibir conteúdo HTML do usuário de forma segura.

### Tarefa

Crie:

1. **Componente**: Criar componente que exibe conteúdo HTML
2. **Sanitization**: Implementar sanitization
3. **Verificação**: Verificar proteção XSS
4. **Testes**: Testar com conteúdo malicioso

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] DomSanitizer implementado
- [ ] HTML sanitizado
- [ ] URLs sanitizadas
- [ ] Proteção XSS funcionando
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Sanitization está implementada corretamente
- [ ] Proteção XSS está funcionando

---

## Solução Esperada

### Abordagem Recomendada

**safe-content.component.ts**
```typescript
import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { DomSanitizer, SafeHtml, SafeUrl, SafeStyle } from '@angular/platform-browser';

@Component({
  selector: 'app-safe-content',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="content">
      <h2>Conteúdo Seguro</h2>
      
      <div class="section">
        <h3>HTML Seguro</h3>
        <div [innerHTML]="safeHtml"></div>
      </div>
      
      <div class="section">
        <h3>URL Segura</h3>
        <a [href]="safeUrl" target="_blank">Link Seguro</a>
      </div>
      
      <div class="section">
        <h3>Style Seguro</h3>
        <div [style]="safeStyle">Texto com estilo seguro</div>
      </div>
      
      <div class="section">
        <h3>Input do Usuário</h3>
        <textarea 
          [(ngModel)]="userInput" 
          placeholder="Digite HTML aqui">
        </textarea>
        <button (click)="sanitizeUserInput()">Sanitizar e Exibir</button>
        <div [innerHTML]="sanitizedUserInput"></div>
      </div>
    </div>
  `,
  styles: [`
    .content {
      padding: 2rem;
    }
    
    .section {
      margin: 2rem 0;
      padding: 1rem;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    
    textarea {
      width: 100%;
      min-height: 100px;
      padding: 0.5rem;
      margin: 0.5rem 0;
    }
    
    button {
      padding: 0.75rem 1.5rem;
      background: #1976d2;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
  `]
})
export class SafeContentComponent {
  @Input() htmlContent: string = '';
  @Input() urlContent: string = '';
  @Input() styleContent: string = '';
  
  userInput: string = '';
  sanitizedUserInput: SafeHtml | null = null;
  
  safeHtml: SafeHtml;
  safeUrl: SafeUrl;
  safeStyle: SafeStyle;
  
  constructor(private sanitizer: DomSanitizer) {
    this.safeHtml = this.sanitizer.sanitize(
      1,
      '<p>Este é HTML <strong>seguro</strong></p>'
    ) as SafeHtml;
    
    this.safeUrl = this.sanitizer.bypassSecurityTrustUrl('https://angular.io');
    
    this.safeStyle = this.sanitizer.bypassSecurityTrustStyle(
      'color: blue; font-weight: bold;'
    );
  }
  
  sanitizeUserInput(): void {
    if (!this.userInput) {
      return;
    }
    
    const sanitized = this.sanitizer.sanitize(1, this.userInput);
    this.sanitizedUserInput = sanitized as SafeHtml;
  }
}
```

**xss-demo.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SafeContentComponent } from './safe-content.component';

@Component({
  selector: 'app-xss-demo',
  standalone: true,
  imports: [CommonModule, SafeContentComponent],
  template: `
    <div>
      <h1>Demonstração de Proteção XSS</h1>
      
      <div class="warning">
        <h3>⚠️ Conteúdo Malicioso de Teste</h3>
        <p>Os exemplos abaixo demonstram como Angular protege contra XSS:</p>
        <ul>
          <li>Scripts são removidos automaticamente</li>
          <li>Event handlers são removidos</li>
          <li>JavaScript em URLs é bloqueado</li>
        </ul>
      </div>
      
      <app-safe-content></app-safe-content>
      
      <div class="examples">
        <h3>Exemplos de Tentativas XSS (Bloqueadas)</h3>
        <div class="example">
          <strong>Script Injection:</strong>
          <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
        </div>
        <div class="example">
          <strong>Event Handler:</strong>
          <code>&lt;img src="x" onerror="alert('XSS')"&gt;</code>
        </div>
        <div class="example">
          <strong>JavaScript URL:</strong>
          <code>javascript:alert('XSS')</code>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .warning {
      background: #fff3cd;
      border: 1px solid #ffc107;
      padding: 1rem;
      margin: 1rem 0;
      border-radius: 4px;
    }
    
    .examples {
      margin: 2rem 0;
      padding: 1rem;
      background: #f8f9fa;
      border-radius: 4px;
    }
    
    .example {
      margin: 1rem 0;
      padding: 0.5rem;
      background: white;
      border-left: 3px solid #dc3545;
    }
    
    code {
      display: block;
      padding: 0.5rem;
      background: #f1f1f1;
      margin-top: 0.5rem;
    }
  `]
})
export class XssDemoComponent {}
```

**Explicação da Solução**:

1. DomSanitizer injetado no componente
2. SafeHtml usado para HTML seguro
3. SafeUrl usado para URLs seguras
4. SafeStyle usado para CSS seguro
5. sanitize() remove código perigoso
6. bypassSecurityTrustUrl() apenas quando necessário

---

## Testes

### Casos de Teste

**Teste 1**: HTML sanitizado
- **Input**: HTML com script malicioso
- **Output Esperado**: Script removido

**Teste 2**: URL sanitizada
- **Input**: URL javascript:
- **Output Esperado**: URL bloqueada

**Teste 3**: Style sanitizado
- **Input**: CSS com expression()
- **Output Esperado**: Expression removida

---

## Extensões (Opcional)

1. **Custom Sanitizer**: Crie sanitizer customizado
2. **Whitelist**: Configure whitelist de tags
3. **Logging**: Registre tentativas XSS

---

## Referências Úteis

- **[DomSanitizer](https://angular.io/api/platform-browser/DomSanitizer)**: Documentação DomSanitizer
- **[Security Guide](https://angular.io/guide/security)**: Guia segurança Angular

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

