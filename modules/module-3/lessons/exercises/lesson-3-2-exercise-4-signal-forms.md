---
layout: exercise
title: "Exercício 3.2.4: Signal-Based Forms"
slug: "signal-forms"
lesson_id: "lesson-3-2"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Signal-Based Forms** através da **criação de formulário completo usando Signal Forms API**.

Ao completar este exercício, você será capaz de:

- Criar formulários baseados em Signals
- Implementar validação com Signals
- Trabalhar com estado de formulário
- Criar formulários reativos eficientes
- Entender diferenças com Reactive Forms

---

## Descrição

Você precisa criar um formulário de registro completo usando Signal Forms API com validação.

### Contexto

Uma aplicação precisa de formulário moderno usando Signals ao invés de Reactive Forms.

### Tarefa

Crie:

1. **Form Signals**: Criar signals para cada campo
2. **Validação**: Implementar validação com Signals
3. **Estado**: Gerenciar estado do formulário
4. **Submit**: Processar submissão
5. **Feedback**: Fornecer feedback visual

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Signals criados para campos
- [ ] Validação implementada
- [ ] Estado do formulário gerenciado
- [ ] Submit funciona
- [ ] Feedback visual implementado
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Formulário está completo
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**signal-form.component.ts**
{% raw %}
```typescript
import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-signal-form',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <form (ngSubmit)="onSubmit()">
      <h2>Registro com Signals</h2>
      
      <div class="field">
        <label>Nome</label>
        <input 
          [value]="name()" 
          (input)="name.set($any($event.target).value)"
          [class.error]="nameError()">
        @if (nameError()) {
          <span class="error">{{ nameError() }}</span>
        }
      </div>
      
      <div class="field">
        <label>Email</label>
        <input 
          type="email"
          [value]="email()" 
          (input)="email.set($any($event.target).value)"
          [class.error]="emailError()">
        @if (emailError()) {
          <span class="error">{{ emailError() }}</span>
        }
      </div>
      
      <div class="field">
        <label>Senha</label>
        <input 
          type="password"
          [value]="password()" 
          (input)="password.set($any($event.target).value)"
          [class.error]="passwordError()">
        @if (passwordError()) {
          <span class="error">{{ passwordError() }}</span>
        }
      </div>
      
      <div class="field">
        <label>Confirmar Senha</label>
        <input 
          type="password"
          [value]="confirmPassword()" 
          (input)="confirmPassword.set($any($event.target).value)"
          [class.error]="confirmPasswordError()">
        @if (confirmPasswordError()) {
          <span class="error">{{ confirmPasswordError() }}</span>
        }
      </div>
      
      <button type="submit" [disabled]="!isValid()">
        Registrar
      </button>
      
      @if (submitted()) {
        <div class="success">
          <p>Registro realizado com sucesso!</p>
          <pre>{{ formData() | json }}</pre>
        </div>
      }
    </form>
  `,
  styles: [`
{% endraw %}
    .field {
      margin-bottom: 1rem;
    }
    
    .field label {
      display: block;
      margin-bottom: 0.5rem;
    }
    
    .field input {
      width: 100%;
      padding: 0.5rem;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    
    .field input.error {
      border-color: #f44336;
    }
    
    .error {
      color: #f44336;
      font-size: 0.875rem;
      display: block;
      margin-top: 0.25rem;
    }
    
    .success {
      margin-top: 1rem;
      padding: 1rem;
      background-color: #e8f5e9;
      border-radius: 4px;
    }
  `]
})
export class SignalFormComponent {
  name = signal<string>('');
  email = signal<string>('');
  password = signal<string>('');
  confirmPassword = signal<string>('');
  submitted = signal<boolean>(false);
  
  nameError = computed(() => {
    const value = this.name();
    if (!value) return 'Nome é obrigatório';
    if (value.length < 3) return 'Nome deve ter pelo menos 3 caracteres';
    return '';
  });
  
  emailError = computed(() => {
    const value = this.email();
    if (!value) return 'Email é obrigatório';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Email inválido';
    return '';
  });
  
  passwordError = computed(() => {
    const value = this.password();
    if (!value) return 'Senha é obrigatória';
    if (value.length < 8) return 'Senha deve ter pelo menos 8 caracteres';
    return '';
  });
  
  confirmPasswordError = computed(() => {
    const value = this.confirmPassword();
    if (!value) return 'Confirmação é obrigatória';
    if (value !== this.password()) return 'Senhas não coincidem';
    return '';
  });
  
  isValid = computed(() => {
    return !this.nameError() && 
           !this.emailError() && 
           !this.passwordError() && 
           !this.confirmPasswordError();
  });
  
  formData = computed(() => ({
    name: this.name(),
    email: this.email(),
    password: this.password()
  }));
  
  onSubmit(): void {
    if (this.isValid()) {
      this.submitted.set(true);
      console.log('Form submitted:', this.formData());
    }
  }
}
```

**Explicação da Solução**:

1. Signals criados para cada campo
2. Computed signals para validação
3. isValid computed verifica se form é válido
4. formData computed prepara dados para submit
5. Feedback visual baseado em computed errors
6. Formulário completo e funcional

---

## Testes

### Casos de Teste

**Teste 1**: Validação funciona
- **Input**: Deixar campos vazios
- **Output Esperado**: Erros aparecem

**Teste 2**: Validação em tempo real
- **Input**: Digitar valores inválidos
- **Output Esperado**: Erros aparecem/desaparecem automaticamente

**Teste 3**: Submit funciona
- **Input**: Preencher form válido e submeter
- **Output Esperado**: Form submetido com sucesso

---

## Extensões (Opcional)

1. **Validação Assíncrona**: Adicione validação assíncrona
2. **Custom Validators**: Crie validators customizados
3. **Form Arrays**: Implemente arrays de campos

---

## Referências Úteis

- **[Signal Forms](https://angular.io/guide/signals#signal-based-forms)**: Guia Signal Forms
- **[Form Validation](https://angular.io/guide/form-validation)**: Guia validação

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

