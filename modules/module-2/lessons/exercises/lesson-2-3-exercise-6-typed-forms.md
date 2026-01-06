---
layout: exercise
title: "Exercício 2.3.6: Typed Forms"
slug: "typed-forms"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Typed Forms** através da **conversão de formulário existente para Typed Forms com type safety completo**.

Ao completar este exercício, você será capaz de:

- Criar interfaces para formulários
- Usar FormGroup<T> e FormControl<T>
- Aproveitar type safety
- Converter formulários existentes
- Entender benefícios de Typed Forms

---

## Descrição

Você precisa converter um formulário existente para Typed Forms, garantindo type safety completo.

### Contexto

Uma aplicação precisa melhorar type safety em formulários para prevenir erros e melhorar experiência de desenvolvimento.

### Tarefa

Crie:

1. **Interface**: Defina tipo do formulário
2. **Typed FormGroup**: Converta FormGroup para FormGroup<T>
3. **Typed FormControls**: Converta FormControls para FormControl<T>
4. **Uso**: Demonstre type safety em ação

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Interface criada para estrutura do formulário
- [ ] FormGroup convertido para FormGroup<T>
- [ ] FormControls convertidos para FormControl<T>
- [ ] Type safety funciona
- [ ] Autocomplete funciona corretamente
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Types estão bem definidos
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**user-form.interface.ts**
```typescript
export interface UserForm {
  name: string;
  email: string;
  age: number;
  address: {
    street: string;
    city: string;
    zipCode: string;
  };
  preferences: {
    newsletter: boolean;
    notifications: boolean;
  };
}
```

**typed-user-form.component.ts**

{% raw %}
```typescript
import { Component } from '@angular/core';
import { FormGroup, FormControl, FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { UserForm } from './user-form.interface';

@Component({
  selector: 'app-typed-user-form',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  template: `
    <form [formGroup]="userForm" (ngSubmit)="onSubmit()">
      <h2>Cadastro de Usuário (Typed)</h2>
      
      <div class="field">
        <label for="name">Nome</label>
        <input id="name" type="text" formControlName="name">
      </div>
      
      <div class="field">
        <label for="email">Email</label>
        <input id="email" type="email" formControlName="email">
      </div>
      
      <div class="field">
        <label for="age">Idade</label>
        <input id="age" type="number" formControlName="age">
      </div>
      
      <fieldset formGroupName="address">
        <legend>Endereço</legend>
        <div class="field">
          <label for="street">Rua</label>
          <input id="street" type="text" formControlName="street">
        </div>
        <div class="field">
          <label for="city">Cidade</label>
          <input id="city" type="text" formControlName="city">
        </div>
        <div class="field">
          <label for="zipCode">CEP</label>
          <input id="zipCode" type="text" formControlName="zipCode">
        </div>
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
      
      <button type="submit" [disabled]="userForm.invalid">
        Cadastrar
      </button>
      
      <div *ngIf="submitted">
        <h3>Dados cadastrados:</h3>
        <pre>{{ submittedData | json }}</pre>
      </div>
    </form>
  `
})
export class TypedUserFormComponent {
  userForm: FormGroup<UserForm>;
  submitted = false;
  submittedData: UserForm | null = null;
  
  constructor(private fb: FormBuilder) {
    this.userForm = this.fb.group<UserForm>({
      name: new FormControl<string>('', { nonNullable: true, validators: [Validators.required] }),
      email: new FormControl<string>('', { nonNullable: true, validators: [Validators.required, Validators.email] }),
      age: new FormControl<number>(0, { nonNullable: true, validators: [Validators.required, Validators.min(18)] }),
      address: this.fb.group({
        street: new FormControl<string>('', { nonNullable: true }),
        city: new FormControl<string>('', { nonNullable: true }),
        zipCode: new FormControl<string>('', { nonNullable: true })
      }),
      preferences: this.fb.group({
        newsletter: new FormControl<boolean>(false, { nonNullable: true }),
        notifications: new FormControl<boolean>(false, { nonNullable: true })
      })
    });
  }
  
  onSubmit(): void {
    if (this.userForm.valid) {
      const formValue: UserForm = this.userForm.value;
      this.submittedData = formValue;
      this.submitted = true;
      console.log('Form válido:', formValue);
    } else {
      this.userForm.markAllAsTouched();
    }
  }
  
  getFormValue(): UserForm {
    return this.userForm.value;
  }
  
  getControl<K extends keyof UserForm>(controlName: K): FormControl<UserForm[K]> {
    return this.userForm.get(controlName) as FormControl<UserForm[K]>;
  }
}
```
import { Component } from '@angular/core';
import { FormGroup, FormControl, FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { UserForm } from './user-form.interface';

@Component({
  selector: 'app-typed-user-form',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  template: `
    <form [formGroup]="userForm" (ngSubmit)="onSubmit()">
      <h2>Cadastro de Usuário (Typed)</h2>
      
      <div class="field">
        <label for="name">Nome</label>
        <input id="name" type="text" formControlName="name">
      </div>
      
      <div class="field">
        <label for="email">Email</label>
        <input id="email" type="email" formControlName="email">
      </div>
      
      <div class="field">
        <label for="age">Idade</label>
        <input id="age" type="number" formControlName="age">
      </div>
      
      <fieldset formGroupName="address">
        <legend>Endereço</legend>
        <div class="field">
          <label for="street">Rua</label>
          <input id="street" type="text" formControlName="street">
        </div>
        <div class="field">
          <label for="city">Cidade</label>
          <input id="city" type="text" formControlName="city">
        </div>
        <div class="field">
          <label for="zipCode">CEP</label>
          <input id="zipCode" type="text" formControlName="zipCode">
        </div>
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
      
      <button type="submit" [disabled]="userForm.invalid">
        Cadastrar
      </button>
      
      <div *ngIf="submitted">
        <h3>Dados cadastrados:</h3>
        <pre>{{ submittedData | json }}</pre>
      </div>
    </form>
  `
})
export class TypedUserFormComponent {
  userForm: FormGroup<UserForm>;
  submitted = false;
  submittedData: UserForm | null = null;
  
  constructor(private fb: FormBuilder) {
    this.userForm = this.fb.group<UserForm>({
      name: new FormControl<string>('', { nonNullable: true, validators: [Validators.required] }),
      email: new FormControl<string>('', { nonNullable: true, validators: [Validators.required, Validators.email] }),
      age: new FormControl<number>(0, { nonNullable: true, validators: [Validators.required, Validators.min(18)] }),
      address: this.fb.group({
        street: new FormControl<string>('', { nonNullable: true }),
        city: new FormControl<string>('', { nonNullable: true }),
        zipCode: new FormControl<string>('', { nonNullable: true })
      }),
      preferences: this.fb.group({
        newsletter: new FormControl<boolean>(false, { nonNullable: true }),
        notifications: new FormControl<boolean>(false, { nonNullable: true })
      })
    });
  }
  
  onSubmit(): void {
    if (this.userForm.valid) {
      const formValue: UserForm = this.userForm.value;
      this.submittedData = formValue;
      this.submitted = true;
      console.log('Form válido:', formValue);
    } else {
      this.userForm.markAllAsTouched();
    }
  }
  
  getFormValue(): UserForm {
    return this.userForm.value;
  }
  
  getControl<K extends keyof UserForm>(controlName: K): FormControl<UserForm[K]> {
    return this.userForm.get(controlName) as FormControl<UserForm[K]>;
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. Interface UserForm define estrutura completa
2. FormGroup<UserForm> garante type safety
3. FormControl<T> tipa cada controle
4. nonNullable garante valores não nulos
5. getControl() retorna tipo correto
6. Autocomplete funciona perfeitamente

---

## Testes

### Casos de Teste

**Teste 1**: Type safety funciona
- **Input**: Tentar acessar campo inexistente
- **Output Esperado**: Erro de compilação

**Teste 2**: Autocomplete funciona
- **Input**: Digitar userForm.
- **Output Esperado**: Autocomplete mostra campos corretos

**Teste 3**: Valores são tipados
- **Input**: Acessar form.value
- **Output Esperado**: Tipo é UserForm

---

## Extensões (Opcional)

1. **Partial Types**: Use Partial para formulários opcionais
2. **Nested Types**: Crie tipos mais complexos
3. **Utility Types**: Use utility types do TypeScript

---

## Referências Úteis

- **[Typed Forms](https://angular.io/guide/typed-forms)**: Guia oficial
- **[FormGroup](https://angular.io/api/forms/FormGroup)**: Documentação FormGroup

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

