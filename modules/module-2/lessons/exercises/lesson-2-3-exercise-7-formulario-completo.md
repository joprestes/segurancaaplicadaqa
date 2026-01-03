---
layout: exercise
title: "Exercício 2.3.7: Formulário Completo com Validação"
slug: "formulario-completo"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **todas as técnicas de formulários reativos** através da **criação de um formulário completo de cadastro usando todas as funcionalidades aprendidas**.

Ao completar este exercício, você será capaz de:

- Combinar todas as técnicas aprendidas
- Criar formulário complexo e funcional
- Implementar validação completa
- Fornecer feedback visual adequado
- Gerenciar formulários grandes

---

## Descrição

Você precisa criar um formulário completo de cadastro de usuário que usa FormGroup, FormArray, validação síncrona/assíncrona e validators customizados.

### Contexto

Uma aplicação precisa de um formulário completo de cadastro que coleta informações pessoais, endereços múltiplos e preferências.

### Tarefa

Crie:

1. **FormGroup Principal**: Com múltiplos grupos aninhados
2. **FormArray**: Para endereços múltiplos
3. **Validação Síncrona**: Validators built-in
4. **Validação Assíncrona**: Verificação de email único
5. **Validators Customizados**: Validação de senha forte
6. **Feedback Visual**: Mensagens de erro e estados

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] FormGroup com grupos aninhados
- [ ] FormArray para endereços
- [ ] Validação síncrona completa
- [ ] Validação assíncrona implementada
- [ ] Validators customizados aplicados
- [ ] Feedback visual adequado
- [ ] Formulário funcional e completo

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todas as técnicas são aplicadas
- [ ] Formulário é útil e realista
- [ ] Código é bem organizado

---

## Solução Esperada

### Abordagem Recomendada

**complete-register.component.ts**
{% raw %}
```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, FormArray, FormControl, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { UserService } from './user.service';
import { emailExistsValidator } from './email-exists.validator';
import { passwordStrengthValidator } from './custom-validators';

@Component({
  selector: 'app-complete-register',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
{% raw %}
  template: `
    <form [formGroup]="registerForm" (ngSubmit)="onSubmit()">
      <h2>Cadastro Completo</h2>
      
      <fieldset formGroupName="personalInfo">
        <legend>Informações Pessoais</legend>
        
        <div class="field">
          <label>Nome Completo</label>
          <input formControlName="fullName" [class.error]="hasError('personalInfo.fullName')">
          @if (hasError('personalInfo.fullName')) {
            <span class="error">{{ getError('personalInfo.fullName') }}</span>
          }
        </div>
        
        <div class="field">
          <label>Email</label>
          <input type="email" formControlName="email" 
                 [class.error]="hasError('personalInfo.email')"
                 [class.pending]="isPending('personalInfo.email')">
          @if (isPending('personalInfo.email')) {
            <span class="pending">Verificando...</span>
          }
          @if (hasError('personalInfo.email')) {
            <span class="error">{{ getError('personalInfo.email') }}</span>
          }
        </div>
        
        <div class="field">
          <label>Senha</label>
          <input type="password" formControlName="password" 
                 [class.error]="hasError('personalInfo.password')">
          @if (hasError('personalInfo.password')) {
            <div class="error-messages">
              @if (getPasswordErrors().minLength) {
                <span class="error">Mínimo 8 caracteres</span>
              }
              @if (getPasswordErrors().lowercase) {
                <span class="error">Letra minúscula</span>
              }
              @if (getPasswordErrors().uppercase) {
                <span class="error">Letra maiúscula</span>
              }
              @if (getPasswordErrors().number) {
                <span class="error">Número</span>
              }
            </div>
          }
        </div>
      </fieldset>
      
      <fieldset>
        <legend>Endereços</legend>
        <div formArrayName="addresses">
          @for (address of addresses.controls; track $index) {
            <div [formGroupName]="$index" class="address-group">
              <h3>Endereço {{ $index + 1 }}</h3>
              <div class="field">
                <label>Rua</label>
                <input formControlName="street">
              </div>
              <div class="field">
                <label>Cidade</label>
                <input formControlName="city">
              </div>
              <div class="field">
                <label>CEP</label>
                <input formControlName="zipCode">
              </div>
              <button type="button" (click)="removeAddress($index)">Remover</button>
            </div>
          }
        </div>
        <button type="button" (click)="addAddress()">Adicionar Endereço</button>
      </fieldset>
      
      <fieldset formGroupName="preferences">
        <legend>Preferências</legend>
        <div class="field">
          <label>
            <input type="checkbox" formControlName="newsletter">
            Receber newsletter
          </label>
        </div>
        <div class="field">
          <label>
            <input type="checkbox" formControlName="notifications">
            Receber notificações
          </label>
        </div>
      </fieldset>
      
      <button type="submit" [disabled]="registerForm.invalid">
        Cadastrar
      </button>
    </form>
  `
{% endraw %}
})
export class CompleteRegisterComponent {
  registerForm: FormGroup;
  
  constructor(
    private fb: FormBuilder,
    private userService: UserService
  ) {
    this.registerForm = this.fb.group({
      personalInfo: this.fb.group({
        fullName: ['', [Validators.required, Validators.minLength(3)]],
        email: ['', 
          [Validators.required, Validators.email],
          [emailExistsValidator(this.userService)]
        ],
        password: ['', [Validators.required, passwordStrengthValidator()]]
      }),
      addresses: this.fb.array([
        this.createAddressGroup()
      ]),
      preferences: this.fb.group({
        newsletter: [false],
        notifications: [false]
      })
    });
  }
  
  get personalInfo(): FormGroup {
    return this.registerForm.get('personalInfo') as FormGroup;
  }
  
  get addresses(): FormArray {
    return this.registerForm.get('addresses') as FormArray;
  }
  
  get preferences(): FormGroup {
    return this.registerForm.get('preferences') as FormGroup;
  }
  
  createAddressGroup(): FormGroup {
    return this.fb.group({
      street: ['', Validators.required],
      city: ['', Validators.required],
      zipCode: ['', Validators.required]
    });
  }
  
  addAddress(): void {
    this.addresses.push(this.createAddressGroup());
  }
  
  removeAddress(index: number): void {
    if (this.addresses.length > 1) {
      this.addresses.removeAt(index);
    }
  }
  
  hasError(path: string): boolean {
    const control = this.registerForm.get(path);
    return !!(control && control.invalid && (control.dirty || control.touched) && !control.pending);
  }
  
  isPending(path: string): boolean {
    const control = this.registerForm.get(path);
    return !!(control && control.pending);
  }
  
  getError(path: string): string {
    const control = this.registerForm.get(path);
    if (!control || !control.errors) return '';
    
    const errors = control.errors;
    if (errors['required']) return 'Campo obrigatório';
    if (errors['email']) return 'Email inválido';
    if (errors['emailExists']) return 'Email já cadastrado';
    if (errors['minlength']) {
      return `Mínimo ${errors['minlength'].requiredLength} caracteres`;
    }
    return 'Erro de validação';
  }
  
  getPasswordErrors(): any {
    return this.personalInfo.get('password')?.errors || {};
  }
  
  onSubmit(): void {
    if (this.registerForm.valid) {
      console.log('Form válido:', this.registerForm.value);
    } else {
      this.registerForm.markAllAsTouched();
    }
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. FormGroup principal com grupos aninhados
2. FormArray para endereços múltiplos
3. Validação síncrona com múltiplos validators
4. Validação assíncrona para email
5. Validator customizado para senha
6. Feedback visual completo
7. Estrutura bem organizada

---

## Testes

### Casos de Teste

**Teste 1**: Formulário completo funciona
- **Input**: Preencher todos os campos
- **Output Esperado**: Formulário válido e submetido

**Teste 2**: Validação funciona
- **Input**: Deixar campos inválidos
- **Output Esperado**: Erros aparecem

**Teste 3**: FormArray funciona
- **Input**: Adicionar/remover endereços
- **Output Esperado**: Endereços gerenciados corretamente

---

## Extensões (Opcional)

1. **Typed Forms**: Converta para Typed Forms
2. **Validação Cross-field**: Adicione validação entre campos
3. **Salvamento**: Implemente salvamento de rascunho

---

## Referências Úteis

- **[Reactive Forms Guide](https://angular.io/guide/reactive-forms)**: Guia completo
- **[All Form Techniques](https://angular.io/guide/form-validation)**: Todas as técnicas

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

