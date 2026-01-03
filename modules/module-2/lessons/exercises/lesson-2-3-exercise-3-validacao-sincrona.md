---
layout: exercise
title: "Exercício 2.3.3: Validação Síncrona"
slug: "validacao-sincrona"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **validação síncrona** através da **implementação de múltiplos validators e feedback visual**.

Ao completar este exercício, você será capaz de:

- Usar validators built-in do Angular
- Combinar múltiplos validators
- Acessar erros de validação
- Mostrar mensagens de erro no template
- Entender estados de formulário

---

## Descrição

Você precisa criar um formulário de registro com validação completa e feedback visual para o usuário.

### Contexto

Uma aplicação precisa validar dados de entrada antes de processar, garantindo qualidade dos dados.

### Tarefa

Crie:

1. **Formulário**: Com campos name, email, password, age
2. **Validação**: Validators apropriados para cada campo
3. **Feedback**: Mensagens de erro visuais
4. **Estados**: Verificação de estados (touched, dirty, invalid)

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Formulário criado com FormBuilder
- [ ] Validators aplicados a cada campo
- [ ] Mensagens de erro exibidas
- [ ] Erros só aparecem quando apropriado (touched/dirty)
- [ ] Botão submit desabilitado quando inválido
- [ ] Validação funciona corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Validação está completa
- [ ] Feedback visual é claro

---

## Solução Esperada

### Abordagem Recomendada

**register-form.component.ts**
```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, FormControl, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-register-form',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  template: `
    <form [formGroup]="registerForm" (ngSubmit)="onSubmit()">
      <h2>Registro</h2>
      
      <div class="field">
        <label for="name">Nome</label>
        <input 
          id="name" 
          type="text" 
          formControlName="name"
          [class.error]="hasError('name')">
        @if (hasError('name')) {
          <span class="error-message">{{ getError('name') }}</span>
        }
      </div>
      
      <div class="field">
        <label for="email">Email</label>
        <input 
          id="email" 
          type="email" 
          formControlName="email"
          [class.error]="hasError('email')">
        @if (hasError('email')) {
          <span class="error-message">{{ getError('email') }}</span>
        }
      </div>
      
      <div class="field">
        <label for="password">Senha</label>
        <input 
          id="password" 
          type="password" 
          formControlName="password"
          [class.error]="hasError('password')">
        @if (hasError('password')) {
          <span class="error-message">{{ getError('password') }}</span>
        }
      </div>
      
      <div class="field">
        <label for="age">Idade</label>
        <input 
          id="age" 
          type="number" 
          formControlName="age"
          [class.error]="hasError('age')">
        @if (hasError('age')) {
          <span class="error-message">{{ getError('age') }}</span>
        }
      </div>
      
      <button type="submit" [disabled]="registerForm.invalid">
        Registrar
      </button>
      
      <div *ngIf="submitted">
        <h3>Registro realizado com sucesso!</h3>
        <pre>{{ registerForm.value | json }}</pre>
      </div>
    </form>
  `,
  styles: [`
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
    
    .error-message {
      color: #f44336;
      font-size: 0.875rem;
      display: block;
      margin-top: 0.25rem;
    }
    
    button {
      padding: 0.75rem 1.5rem;
      background-color: #007bff;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    
    button:disabled {
      background-color: #ccc;
      cursor: not-allowed;
    }
  `]
})
export class RegisterFormComponent {
  registerForm: FormGroup;
  submitted = false;
  
  constructor(private fb: FormBuilder) {
    this.registerForm = this.fb.group({
      name: ['', [Validators.required, Validators.minLength(3)]],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8)]],
      age: [0, [Validators.required, Validators.min(18), Validators.max(100)]]
    });
  }
  
  hasError(controlName: string): boolean {
    const control = this.registerForm.get(controlName);
    return !!(control && control.invalid && (control.dirty || control.touched));
  }
  
  getError(controlName: string): string {
    const control = this.registerForm.get(controlName);
    if (!control || !control.errors) return '';
    
    const errors = control.errors;
    
    if (errors['required']) {
      return 'Campo obrigatório';
    }
    
    if (errors['email']) {
      return 'Email inválido';
    }
    
    if (errors['minlength']) {
      return `Mínimo ${errors['minlength'].requiredLength} caracteres`;
    }
    
    if (errors['min']) {
      return `Valor mínimo é ${errors['min'].min}`;
    }
    
    if (errors['max']) {
      return `Valor máximo é ${errors['max'].max}`;
    }
    
    return 'Erro de validação';
  }
  
  onSubmit(): void {
    if (this.registerForm.valid) {
      this.submitted = true;
      console.log('Form válido:', this.registerForm.value);
    } else {
      this.registerForm.markAllAsTouched();
    }
  }
  
  getControl(controlName: string): FormControl {
    return this.registerForm.get(controlName) as FormControl;
  }
}
```

**Explicação da Solução**:

1. FormBuilder usado para criar formulário com validators
2. Múltiplos validators combinados em arrays
3. hasError() verifica se deve mostrar erro
4. getError() retorna mensagem apropriada
5. Erros só aparecem quando touched ou dirty
6. Botão desabilitado quando form inválido

---

## Testes

### Casos de Teste

**Teste 1**: Validação required funciona
- **Input**: Deixar campo vazio e tocar
- **Output Esperado**: Erro "Campo obrigatório" aparece

**Teste 2**: Validação email funciona
- **Input**: Digitar email inválido
- **Output Esperado**: Erro "Email inválido" aparece

**Teste 3**: Validação minLength funciona
- **Input**: Digitar menos que mínimo
- **Output Esperado**: Erro com tamanho mínimo aparece

---

## Extensões (Opcional)

1. **Validação Customizada**: Adicione validator customizado
2. **Validação Cross-field**: Valide relação entre campos
3. **Indicadores Visuais**: Adicione indicadores de força de senha

---

## Referências Úteis

- **[Validators](https://angular.io/api/forms/Validators)**: Documentação Validators
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

