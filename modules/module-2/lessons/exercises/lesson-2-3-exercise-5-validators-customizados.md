---
layout: exercise
title: "Exercício 2.3.5: Validators Customizados"
slug: "validators-customizados"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **validators customizados** através da **criação de validators específicos para senha forte e confirmação de senha**.

Ao completar este exercício, você será capaz de:

- Criar validators customizados síncronos
- Implementar ValidatorFn
- Criar validators cross-field
- Validar múltiplos campos juntos
- Aplicar validators customizados

---

## Descrição

Você precisa criar validators customizados para validar força de senha e confirmação de senha.

### Contexto

Uma aplicação precisa de validação específica de senha que não está disponível nos validators padrão do Angular.

### Tarefa

Crie:

1. **Password Strength Validator**: Valida força da senha
2. **Password Match Validator**: Valida se senhas coincidem
3. **Formulário**: Usa os validators customizados
4. **Feedback**: Mensagens específicas para cada erro

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] PasswordStrengthValidator criado
- [ ] PasswordMatchValidator criado
- [ ] Validators aplicados ao formulário
- [ ] Mensagens de erro específicas
- [ ] Validação funciona corretamente
- [ ] Cross-field validation funciona

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Validators são reutilizáveis
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**custom-validators.ts**
```typescript
import { AbstractControl, ValidationErrors, ValidatorFn } from '@angular/forms';

export function passwordStrengthValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    if (!control.value) {
      return null;
    }
    
    const value = control.value;
    const errors: ValidationErrors = {};
    
    if (value.length < 8) {
      errors['minLength'] = { requiredLength: 8, actualLength: value.length };
    }
    
    if (!/[a-z]/.test(value)) {
      errors['lowercase'] = true;
    }
    
    if (!/[A-Z]/.test(value)) {
      errors['uppercase'] = true;
    }
    
    if (!/\d/.test(value)) {
      errors['number'] = true;
    }
    
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(value)) {
      errors['special'] = true;
    }
    
    return Object.keys(errors).length > 0 ? errors : null;
  };
}

export function passwordMatchValidator(passwordControlName: string, confirmPasswordControlName: string): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const password = control.get(passwordControlName)?.value;
    const confirmPassword = control.get(confirmPasswordControlName)?.value;
    
    if (!password || !confirmPassword) {
      return null;
    }
    
    if (password !== confirmPassword) {
      return { passwordMismatch: true };
    }
    
    return null;
  };
}
```

**password-form.component.ts**
```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, FormControl, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { passwordStrengthValidator, passwordMatchValidator } from './custom-validators';

@Component({
  selector: 'app-password-form',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  template: `
    <form [formGroup]="passwordForm" (ngSubmit)="onSubmit()">
      <h2>Alterar Senha</h2>
      
      <div class="field">
        <label for="password">Nova Senha</label>
        <input 
          id="password" 
          type="password" 
          formControlName="password"
          [class.error]="hasError('password')">
        @if (hasError('password')) {
          <div class="error-messages">
            @if (getPasswordErrors().minLength) {
              <span class="error">Mínimo 8 caracteres</span>
            }
            @if (getPasswordErrors().lowercase) {
              <span class="error">Deve conter letra minúscula</span>
            }
            @if (getPasswordErrors().uppercase) {
              <span class="error">Deve conter letra maiúscula</span>
            }
            @if (getPasswordErrors().number) {
              <span class="error">Deve conter número</span>
            }
            @if (getPasswordErrors().special) {
              <span class="error">Deve conter caractere especial</span>
            }
          </div>
        }
        @if (!hasError('password') && passwordForm.get('password')?.value) {
          <span class="success">Senha forte!</span>
        }
      </div>
      
      <div class="field">
        <label for="confirmPassword">Confirmar Senha</label>
        <input 
          id="confirmPassword" 
          type="password" 
          formControlName="confirmPassword"
          [class.error]="hasError('confirmPassword') || hasFormError('passwordMismatch')">
        @if (hasError('confirmPassword')) {
          <span class="error">{{ getError('confirmPassword') }}</span>
        }
        @if (hasFormError('passwordMismatch')) {
          <span class="error">Senhas não coincidem</span>
        }
      </div>
      
      <button type="submit" [disabled]="passwordForm.invalid">
        Alterar Senha
      </button>
    </form>
  `,
  styles: [`
    .field {
      margin-bottom: 1.5rem;
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
    
    .error-messages {
      margin-top: 0.5rem;
    }
    
    .error {
      color: #f44336;
      font-size: 0.875rem;
      display: block;
      margin-top: 0.25rem;
    }
    
    .success {
      color: #4caf50;
      font-size: 0.875rem;
      display: block;
      margin-top: 0.25rem;
    }
  `]
})
export class PasswordFormComponent {
  passwordForm: FormGroup;
  
  constructor(private fb: FormBuilder) {
    this.passwordForm = this.fb.group({
      password: ['', [Validators.required, passwordStrengthValidator()]],
      confirmPassword: ['', Validators.required]
    }, { validators: passwordMatchValidator('password', 'confirmPassword') });
  }
  
  hasError(controlName: string): boolean {
    const control = this.passwordForm.get(controlName);
    return !!(control && control.invalid && (control.dirty || control.touched));
  }
  
  hasFormError(errorName: string): boolean {
    return !!(this.passwordForm.errors && this.passwordForm.errors[errorName] && 
               (this.passwordForm.dirty || this.passwordForm.touched));
  }
  
  getPasswordErrors(): any {
    const control = this.passwordForm.get('password');
    return control?.errors || {};
  }
  
  getError(controlName: string): string {
    const control = this.passwordForm.get(controlName);
    if (!control || !control.errors) return '';
    
    if (control.errors['required']) {
      return 'Campo obrigatório';
    }
    
    return 'Erro de validação';
  }
  
  onSubmit(): void {
    if (this.passwordForm.valid) {
      console.log('Senha alterada:', this.passwordForm.value);
    } else {
      this.passwordForm.markAllAsTouched();
    }
  }
}
```

**Explicação da Solução**:

1. passwordStrengthValidator valida múltiplos critérios
2. passwordMatchValidator valida cross-field
3. Validator aplicado ao FormGroup para cross-field
4. Mensagens específicas para cada erro
5. Feedback visual para senha forte
6. Validação funciona em tempo real

---

## Testes

### Casos de Teste

**Teste 1**: Validação de força funciona
- **Input**: Digitar senha fraca
- **Output Esperado**: Erros específicos aparecem

**Teste 2**: Validação de match funciona
- **Input**: Senhas diferentes
- **Output Esperado**: Erro "Senhas não coincidem"

**Teste 3**: Senha forte funciona
- **Input**: Senha que atende todos critérios
- **Output Esperado**: Mensagem "Senha forte!"

---

## Extensões (Opcional)

1. **Indicador de Força**: Adicione barra de força de senha
2. **Mais Critérios**: Adicione mais critérios de validação
3. **Validação Assíncrona**: Combine com validação assíncrona

---

## Referências Úteis

- **[Custom Validators](https://angular.io/guide/form-validation#custom-validators)**: Guia validators customizados
- **[ValidatorFn](https://angular.io/api/forms/ValidatorFn)**: Documentação ValidatorFn

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

