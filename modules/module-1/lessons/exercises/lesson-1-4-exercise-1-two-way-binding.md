---
layout: exercise
title: "Exercício 1.4.1: Formulário com Two-Way Binding"
slug: "two-way-binding"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **two-way data binding** através da **criação de um formulário de contato com sincronização bidirecional**.

Ao completar este exercício, você será capaz de:

- Usar `[(ngModel)]` para two-way binding
- Importar `FormsModule` corretamente
- Criar formulários com sincronização automática
- Exibir dados em tempo real

---

## Descrição

Você precisa criar um componente `ContactFormComponent` que permite preencher um formulário de contato e ver os dados atualizados em tempo real abaixo do formulário.

### Contexto

Um site precisa de um formulário de contato onde o usuário pode ver os dados que está digitando sendo atualizados em tempo real, facilitando a revisão antes de enviar.

### Tarefa

Crie um componente `ContactFormComponent` com:

1. **Campos do Formulário**: Nome, Email, Telefone, Mensagem
2. **Two-Way Binding**: Use `[(ngModel)]` em todos os campos
3. **Exibição em Tempo Real**: Mostre os dados abaixo do formulário
4. **Botão de Envio**: Botão que exibe dados quando clicado
5. **Validação Básica**: Desabilite botão se campos obrigatórios vazios

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente criado com `FormsModule` importado
- [ ] Campos nome, email, telefone e mensagem com `[(ngModel)]`
- [ ] Dados exibidos em tempo real abaixo do formulário
- [ ] Botão de envio funcional
- [ ] Validação básica implementada
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Two-way binding funciona corretamente
- [ ] Formulário é funcional e intuitivo
- [ ] Código é legível e bem organizado

---

## Dicas

### Dica 1: Importar FormsModule

```typescript
import { FormsModule } from '@angular/forms';

@Component({
  imports: [FormsModule]
})
```

### Dica 2: Two-Way Binding

```html
<input [(ngModel)]="contact.name" name="name">
```

### Dica 3: Exibir em Tempo Real

```html
<div>
  <p>Nome: {{ contact.name }}</p>
  <p>Email: {{ contact.email }}</p>
</div>
```

### Dica 4: Validação Básica

```typescript
isValid(): boolean {
  return this.contact.name.length > 0 && 
         this.contact.email.includes('@');
}
```

---

## Solução Esperada

### Abordagem Recomendada

**contact-form.component.ts**
```typescript
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

interface Contact {
  name: string;
  email: string;
  phone: string;
  message: string;
}

@Component({
  selector: 'app-contact-form',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './contact-form.component.html',
  styleUrls: ['./contact-form.component.css']
})
export class ContactFormComponent {
  contact: Contact = {
    name: '',
    email: '',
    phone: '',
    message: ''
  };
  
  submitted: boolean = false;
  
  isValid(): boolean {
    return this.contact.name.trim().length > 0 && 
           this.contact.email.trim().length > 0 &&
           this.contact.email.includes('@') &&
           this.contact.message.trim().length > 0;
  }
  
  onSubmit(): void {
    if (this.isValid()) {
      this.submitted = true;
      console.log('Formulário enviado:', this.contact);
    }
  }
  
  resetForm(): void {
    this.contact = {
      name: '',
      email: '',
      phone: '',
      message: ''
    };
    this.submitted = false;
  }
}
```

**contact-form.component.html**
{% raw %}
```html
<div class="contact-form">
  <h2>Formulário de Contato</h2>
  
  <form (ngSubmit)="onSubmit()">
    <div class="form-group">
      <label for="name">Nome *</label>
      <input 
        id="name"
        type="text" 
        [(ngModel)]="contact.name" 
        name="name"
        required
        placeholder="Seu nome">
    </div>
    
    <div class="form-group">
      <label for="email">Email *</label>
      <input 
        id="email"
        type="email" 
        [(ngModel)]="contact.email" 
        name="email"
        required
        placeholder="seu@email.com">
    </div>
    
    <div class="form-group">
      <label for="phone">Telefone</label>
      <input 
        id="phone"
        type="tel" 
        [(ngModel)]="contact.phone" 
        name="phone"
        placeholder="(00) 00000-0000">
    </div>
    
    <div class="form-group">
      <label for="message">Mensagem *</label>
      <textarea 
        id="message"
        [(ngModel)]="contact.message" 
        name="message"
        required
        rows="5"
        placeholder="Sua mensagem..."></textarea>
    </div>
    
    <button 
      type="submit" 
      [disabled]="!isValid()"
      [class.disabled]="!isValid()">
      Enviar
    </button>
    
    <button 
      type="button" 
      (click)="resetForm()"
      class="btn-secondary">
      Limpar
    </button>
  </form>
  
  <div class="preview" *ngIf="contact.name || contact.email">
    <h3>Preview em Tempo Real</h3>
    <div class="preview-content">
      <p><strong>Nome:</strong> {{ contact.name || '(vazio)' }}</p>
      <p><strong>Email:</strong> {{ contact.email || '(vazio)' }}</p>
      <p><strong>Telefone:</strong> {{ contact.phone || '(vazio)' }}</p>
      <p><strong>Mensagem:</strong></p>
      <p class="message-preview">{{ contact.message || '(vazio)' }}</p>
    </div>
  </div>
  
  <div class="submitted-message" *ngIf="submitted">
    <h3>✅ Formulário Enviado com Sucesso!</h3>
    <pre>{{ contact | json }}</pre>
  </div>
</div>
```
{% endraw %}

**contact-form.component.css**
```css
.contact-form {
  max-width: 600px;
  margin: 0 auto;
  padding: 2rem;
}

.form-group {
  margin-bottom: 1.5rem;
}

label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: #333;
}

input, textarea {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
  box-sizing: border-box;
}

input:focus, textarea:focus {
  outline: none;
  border-color: #1976d2;
}

button {
  padding: 0.75rem 1.5rem;
  margin-right: 1rem;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  background-color: #1976d2;
  color: white;
}

button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  background-color: #757575;
}

.preview {
  margin-top: 2rem;
  padding: 1.5rem;
  background-color: #f5f5f5;
  border-radius: 4px;
  border-left: 4px solid #1976d2;
}

.preview-content {
  margin-top: 1rem;
}

.message-preview {
  white-space: pre-wrap;
  background-color: white;
  padding: 1rem;
  border-radius: 4px;
  margin-top: 0.5rem;
}

.submitted-message {
  margin-top: 2rem;
  padding: 1.5rem;
  background-color: #e8f5e9;
  border-radius: 4px;
  border-left: 4px solid #4caf50;
}

pre {
  background-color: white;
  padding: 1rem;
  border-radius: 4px;
  overflow-x: auto;
}
```

**Explicação da Solução**:

1. `FormsModule` importado para habilitar `[(ngModel)]`
2. Interface `Contact` define estrutura de dados
3. Two-way binding em todos os campos com `[(ngModel)]`
4. Preview em tempo real usando interpolação
5. Validação básica desabilita botão quando inválido
6. Método `onSubmit()` processa formulário
7. Método `resetForm()` limpa dados

**Decisões de Design**:

- Campos obrigatórios marcados com `*`
- Preview só aparece quando há dados
- Validação básica de email (contém @)
- Mensagem de sucesso após envio
- Estilos organizados e responsivos

---

## Testes

### Casos de Teste

**Teste 1**: Two-way binding funciona
- **Input**: Digitar no campo nome
- **Output Esperado**: Nome deve aparecer no preview imediatamente

**Teste 2**: Validação desabilita botão
- **Input**: Deixar campos obrigatórios vazios
- **Output Esperado**: Botão deve estar desabilitado

**Teste 3**: Validação habilita botão
- **Input**: Preencher todos os campos obrigatórios
- **Output Esperado**: Botão deve estar habilitado

**Teste 4**: Envio do formulário
- **Input**: Preencher e clicar em "Enviar"
- **Output Esperado**: Mensagem de sucesso deve aparecer com dados

**Teste 5**: Reset do formulário
- **Input**: Clicar em "Limpar"
- **Output Esperado**: Todos os campos devem ser limpos

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Validação Avançada**: Adicione validação de email com regex
2. **Máscara de Telefone**: Adicione máscara para campo telefone
3. **Contador de Caracteres**: Mostre contador de caracteres na mensagem
4. **Salvar LocalStorage**: Salve dados no localStorage automaticamente

---

## Referências Úteis

- **[Two-Way Binding](https://angular.io/guide/two-way-binding)**: Documentação oficial
- **[FormsModule](https://angular.io/api/forms/FormsModule)**: Documentação FormsModule
- **[ngModel](https://angular.io/api/forms/NgModel)**: Documentação ngModel

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

