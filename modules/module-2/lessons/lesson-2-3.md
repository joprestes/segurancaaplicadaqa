---
layout: lesson
title: "Aula 2.3: Formulários Reativos e Validação"
slug: formularios-reativos
module: module-2
lesson_id: lesson-2-3
duration: "120 minutos"
level: "Intermediário"
prerequisites: 
  - "lesson-2-2"
exercises:
  - 
  - "lesson-2-3-exercise-1"
  - "lesson-2-3-exercise-2"
  - "lesson-2-3-exercise-3"
  - "lesson-2-3-exercise-4"
  - "lesson-2-3-exercise-5"
  - "lesson-2-3-exercise-6"
  - "lesson-2-3-exercise-7"
podcast:
  file: "assets/podcasts/02.3-Dominando_os_Formulários_Reativos_do_Angular.m4a"
  title: "Dominando os Formulários Reativos do Angular"
  description: "Formulários reativos são uma das funcionalidades mais poderosas do Angular."
  duration: "60-75 minutos"
---

## Introdução

Nesta aula, você dominará Formulários Reativos do Angular, a abordagem moderna e poderosa para criar formulários complexos com validação robusta. Formulários reativos oferecem controle total sobre o estado e validação, sendo essenciais para aplicações profissionais.

### O que você vai aprender

- Criar FormControl, FormGroup e FormArray
- Usar FormBuilder para simplificar criação
- Implementar validação síncrona e assíncrona
- Criar validators customizados
- Trabalhar com Typed Forms
- Entender estados de formulário
- Criar formulários dinâmicos
- Fornecer feedback visual ao usuário

### Por que isso é importante

Formulários são fundamentais em qualquer aplicação web. Formulários reativos oferecem melhor testabilidade, controle de estado e validação complexa comparado a template-driven forms. São essenciais para criar UX profissional.

---

## Conceitos Teóricos

### FormControl

**Definição**: `FormControl` é a classe fundamental que representa um único campo de formulário e seu estado (valor, validação, erros).

**Explicação Detalhada**:

FormControl encapsula:
- Valor atual do campo
- Estado de validação
- Erros de validação
- Status (pristine, dirty, touched, untouched, valid, invalid)
- Observables para mudanças

**Analogia**:

FormControl é como um guarda de trânsito que controla um único cruzamento. Ele monitora o estado (valor), verifica regras (validação) e reporta problemas (erros).

**Visualização**:

```
FormControl
┌─────────────────────┐
│ value: "João"       │
│ valid: true         │
│ touched: true       │
│ errors: null       │
│ status: "VALID"     │
└─────────────────────┘
```

**Exemplo Prático**:

```typescript
import { FormControl } from '@angular/forms';

export class MyComponent {
  nameControl = new FormControl('João');
  
  ngOnInit(): void {
    this.nameControl.valueChanges.subscribe(value => {
      console.log('Valor mudou:', value);
    });
    
    this.nameControl.statusChanges.subscribe(status => {
      console.log('Status mudou:', status);
    });
  }
  
  getValue(): string {
    return this.nameControl.value || '';
  }
  
  setValue(value: string): void {
    this.nameControl.setValue(value);
  }
}
```

---

### FormGroup

**Definição**: `FormGroup` agrupa múltiplos FormControls em uma estrutura hierárquica, permitindo gerenciar formulários complexos.

**Explicação Detalhada**:

FormGroup permite:
- Agrupar controles relacionados
- Validar grupo inteiro
- Acessar valores de múltiplos controles
- Gerenciar estado do grupo
- Nested groups (grupos aninhados)

**Analogia**:

FormGroup é como um formulário físico com múltiplos campos. Cada campo (FormControl) faz parte do formulário (FormGroup), e você pode validar o formulário inteiro.

**Visualização**:

```
FormGroup
┌─────────────────────────────┐
│ userForm                     │
│ ├─ name: FormControl         │
│ ├─ email: FormControl        │
│ └─ address: FormGroup        │
│    ├─ street: FormControl    │
│    └─ city: FormControl      │
└─────────────────────────────┘
```

**Exemplo Prático**:

```typescript
import { FormGroup, FormControl } from '@angular/forms';

export class UserFormComponent {
  userForm = new FormGroup({
    name: new FormControl(''),
    email: new FormControl(''),
    age: new FormControl(0)
  });
  
  onSubmit(): void {
    if (this.userForm.valid) {
      console.log('Form válido:', this.userForm.value);
    } else {
      console.log('Form inválido');
      this.userForm.markAllAsTouched();
    }
  }
  
  get nameControl(): FormControl {
    return this.userForm.get('name') as FormControl;
  }
}
```

---

### FormArray

**Definição**: `FormArray` permite criar arrays dinâmicos de FormControls ou FormGroups, útil para listas de campos variáveis.

**Explicação Detalhada**:

FormArray é usado para:
- Listas dinâmicas de campos
- Adicionar/remover campos em runtime
- Validar arrays de dados
- Formulários com campos repetidos

**Analogia**:

FormArray é como uma lista de compras onde você pode adicionar ou remover itens dinamicamente. Cada item é um FormControl ou FormGroup.

**Exemplo Prático**:

```typescript
import { FormArray, FormGroup, FormControl, FormBuilder } from '@angular/forms';

export class DynamicFormComponent {
  form: FormGroup;
  
  constructor(private fb: FormBuilder) {
    this.form = this.fb.group({
      items: this.fb.array([])
    });
  }
  
  get items(): FormArray {
    return this.form.get('items') as FormArray;
  }
  
  addItem(): void {
    const itemGroup = this.fb.group({
      name: [''],
      quantity: [0]
    });
    this.items.push(itemGroup);
  }
  
  removeItem(index: number): void {
    this.items.removeAt(index);
  }
  
  getItemsValue(): any[] {
    return this.items.value;
  }
}
```

---

### FormBuilder

**Definição**: `FormBuilder` é um serviço que simplifica a criação de FormGroups e FormArrays através de métodos helper.

**Explicação Detalhada**:

FormBuilder oferece:
- Sintaxe mais limpa
- Menos boilerplate
- Facilita criação de formulários complexos
- Suporta validação inline

**Analogia**:

FormBuilder é como um assistente que ajuda a preencher formulários complexos mais rapidamente, fornecendo métodos simplificados.

**Exemplo Prático**:

```typescript
import { FormBuilder, FormGroup, Validators } from '@angular/forms';

export class FormBuilderComponent {
  form: FormGroup;
  
  constructor(private fb: FormBuilder) {
    this.form = this.fb.group({
      name: ['', [Validators.required, Validators.minLength(3)]],
      email: ['', [Validators.required, Validators.email]],
      age: [0, [Validators.required, Validators.min(18)]],
      address: this.fb.group({
        street: [''],
        city: ['', Validators.required]
      })
    });
  }
}
```

---

### Validação Síncrona

**Definição**: Validação síncrona executa imediatamente quando o valor muda, usando validators do Angular ou customizados.

**Explicação Detalhada**:

Validators síncronos:
- `Validators.required`: Campo obrigatório
- `Validators.email`: Valida formato de email
- `Validators.minLength(n)`: Tamanho mínimo
- `Validators.maxLength(n)`: Tamanho máximo
- `Validators.min(n)`: Valor mínimo
- `Validators.max(n)`: Valor máximo
- `Validators.pattern(regex)`: Padrão regex

**Analogia**:

Validação síncrona é como um guarda que verifica documentos na entrada. A verificação acontece imediatamente quando você apresenta o documento.

**Exemplo Prático**:

```typescript
import { FormGroup, FormControl, Validators } from '@angular/forms';

export class ValidationComponent {
  form = new FormGroup({
    email: new FormControl('', [
      Validators.required,
      Validators.email
    ]),
    password: new FormControl('', [
      Validators.required,
      Validators.minLength(8),
      Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    ]),
    age: new FormControl(0, [
      Validators.required,
      Validators.min(18),
      Validators.max(100)
    ])
  });
  
  get emailControl(): FormControl {
    return this.form.get('email') as FormControl;
  }
  
  getEmailError(): string {
    if (this.emailControl.hasError('required')) {
      return 'Email é obrigatório';
    }
    if (this.emailControl.hasError('email')) {
      return 'Email inválido';
    }
    return '';
  }
}
```

---

### Validação Assíncrona

**Definição**: Validação assíncrona executa operações que levam tempo (como chamadas HTTP) para validar campos.

**Explicação Detalhada**:

Validators assíncronos:
- Retornam `Observable<ValidationErrors | null>`
- Executam após validators síncronos
- Úteis para verificar disponibilidade (email, username)
- Podem ser combinados com validators síncronos

**Analogia**:

Validação assíncrona é como verificar se um email já está cadastrado. Você precisa fazer uma consulta ao servidor, que leva tempo.

**Exemplo Prático**:

```typescript
import { AbstractControl, ValidationErrors, AsyncValidatorFn } from '@angular/forms';
import { Observable, of } from 'rxjs';
import { map, catchError, delay } from 'rxjs/operators';
import { UserService } from './user.service';

export function emailExistsValidator(userService: UserService): AsyncValidatorFn {
  return (control: AbstractControl): Observable<ValidationErrors | null> => {
    if (!control.value) {
      return of(null);
    }
    
    return userService.checkEmailExists(control.value).pipe(
      delay(500),
      map(exists => exists ? { emailExists: true } : null),
      catchError(() => of(null))
    );
  };
}

export class AsyncValidationComponent {
  form: FormGroup;
  
  constructor(private fb: FormBuilder, private userService: UserService) {
    this.form = this.fb.group({
      email: ['', 
        [Validators.required, Validators.email],
        [emailExistsValidator(this.userService)]
      ]
    });
  }
  
  get emailControl(): FormControl {
    return this.form.get('email') as FormControl;
  }
  
  getEmailError(): string {
    if (this.emailControl.hasError('required')) {
      return 'Email é obrigatório';
    }
    if (this.emailControl.hasError('email')) {
      return 'Email inválido';
    }
    if (this.emailControl.hasError('emailExists')) {
      return 'Email já cadastrado';
    }
    if (this.emailControl.pending) {
      return 'Verificando...';
    }
    return '';
  }
}
```

---

### Validators Customizados

**Definição**: Validators customizados permitem criar regras de validação específicas para suas necessidades.

**Explicação Detalhada**:

Validators customizados:
- Podem ser síncronos ou assíncronos
- Retornam `ValidationErrors | null`
- Podem receber parâmetros
- Podem validar múltiplos campos

**Analogia**:

Validators customizados são como regras específicas de um negócio. Por exemplo, "senha deve conter pelo menos um número e uma letra maiúscula".

**Exemplo Prático**:

```typescript
import { AbstractControl, ValidationErrors, ValidatorFn } from '@angular/forms';

export function passwordStrengthValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    if (!control.value) {
      return null;
    }
    
    const value = control.value;
    const errors: ValidationErrors = {};
    
    if (!/[a-z]/.test(value)) {
      errors['lowercase'] = true;
    }
    if (!/[A-Z]/.test(value)) {
      errors['uppercase'] = true;
    }
    if (!/\d/.test(value)) {
      errors['number'] = true;
    }
    if (!/[!@#$%^&*]/.test(value)) {
      errors['special'] = true;
    }
    
    return Object.keys(errors).length > 0 ? errors : null;
  };
}

export function matchValidator(controlName: string, matchingControlName: string): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const controlValue = control.get(controlName)?.value;
    const matchingControlValue = control.get(matchingControlName)?.value;
    
    if (controlValue !== matchingControlValue) {
      return { mismatch: true };
    }
    
    return null;
  };
}

export class CustomValidatorsComponent {
  form: FormGroup;
  
  constructor(private fb: FormBuilder) {
    this.form = this.fb.group({
      password: ['', [Validators.required, passwordStrengthValidator()]],
      confirmPassword: ['', Validators.required]
    }, { validators: matchValidator('password', 'confirmPassword') });
  }
}
```

---

### Typed Forms

**Definição**: Typed Forms (Angular 14+) fornecem type safety completo para formulários, prevenindo erros em tempo de compilação.

**Explicação Detalhada**:

Typed Forms oferecem:
- Type safety completo
- Autocomplete melhorado
- Prevenção de erros de digitação
- Melhor experiência de desenvolvimento

**Analogia**:

Typed Forms são como ter um GPS que conhece todos os endereços. Você não pode digitar um endereço inválido porque o sistema conhece todos os tipos.

**Exemplo Prático**:

```typescript
import { FormGroup, FormControl } from '@angular/forms';

interface UserForm {
  name: string;
  email: string;
  age: number;
  address: {
    street: string;
    city: string;
  };
}

export class TypedFormsComponent {
  form = new FormGroup<UserForm>({
    name: new FormControl<string>('', { nonNullable: true }),
    email: new FormControl<string>('', { nonNullable: true }),
    age: new FormControl<number>(0, { nonNullable: true }),
    address: new FormGroup({
      street: new FormControl<string>('', { nonNullable: true }),
      city: new FormControl<string>('', { nonNullable: true })
    })
  });
  
  onSubmit(): void {
    const value: UserForm = this.form.value; // Type-safe!
    console.log(value);
  }
}
```

---

### Estados de Formulário

**Definição**: Estados de formulário indicam condição atual dos controles (pristine, dirty, touched, valid, etc.).

**Explicação Detalhada**:

Estados principais:
- `pristine`: Valor não foi alterado
- `dirty`: Valor foi alterado
- `touched`: Campo foi focado
- `untouched`: Campo nunca foi focado
- `valid`: Campo passa todas as validações
- `invalid`: Campo falha em alguma validação
- `pending`: Validação assíncrona em andamento

**Analogia**:

Estados são como indicadores de status. Um campo pode estar "limpo" (pristine), "modificado" (dirty), "visitado" (touched) ou "inválido" (invalid).

**Exemplo Prático**:

```typescript
export class FormStateComponent {
  form: FormGroup;
  
  constructor(private fb: FormBuilder) {
    this.form = this.fb.group({
      name: ['', Validators.required]
    });
  }
  
  get nameControl(): FormControl {
    return this.form.get('name') as FormControl;
  }
  
  showError(): boolean {
    const control = this.nameControl;
    return control.invalid && (control.dirty || control.touched);
  }
  
  resetForm(): void {
    this.form.reset();
  }
  
  markAsTouched(): void {
    this.form.markAllAsTouched();
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Formulário Completo com Validação

**Contexto**: Criar formulário de registro de usuário com validação completa.

**Código**:

```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, AbstractControl } from '@angular/forms';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  template: `
    <form [formGroup]="registerForm" (ngSubmit)="onSubmit()">
      <div>
        <label>Nome</label>
        <input formControlName="name">
        @if (showError('name')) {
          <span class="error">{{ getError('name') }}</span>
        }
      </div>
      
      <div>
        <label>Email</label>
        <input formControlName="email" type="email">
        @if (showError('email')) {
          <span class="error">{{ getError('email') }}</span>
        }
      </div>
      
      <div>
        <label>Senha</label>
        <input formControlName="password" type="password">
        @if (showError('password')) {
          <span class="error">{{ getError('password') }}</span>
        }
      </div>
      
      <div>
        <label>Confirmar Senha</label>
        <input formControlName="confirmPassword" type="password">
        @if (showError('confirmPassword')) {
          <span class="error">{{ getError('confirmPassword') }}</span>
        }
      </div>
      
      <button type="submit" [disabled]="registerForm.invalid">
        Registrar
      </button>
    </form>
  `
})
export class RegisterComponent {
  registerForm: FormGroup;
  
  constructor(private fb: FormBuilder) {
    this.registerForm = this.fb.group({
      name: ['', [Validators.required, Validators.minLength(3)]],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8)]],
      confirmPassword: ['', Validators.required]
    }, { validators: this.passwordMatchValidator });
  }
  
  passwordMatchValidator(control: AbstractControl): ValidationErrors | null {
    const password = control.get('password')?.value;
    const confirmPassword = control.get('confirmPassword')?.value;
    
    if (password !== confirmPassword) {
      return { mismatch: true };
    }
    
    return null;
  }
  
  showError(controlName: string): boolean {
    const control = this.registerForm.get(controlName);
    return !!(control && control.invalid && (control.dirty || control.touched));
  }
  
  getError(controlName: string): string {
    const control = this.registerForm.get(controlName);
    if (!control || !control.errors) return '';
    
    if (control.errors['required']) return 'Campo obrigatório';
    if (control.errors['email']) return 'Email inválido';
    if (control.errors['minlength']) {
      return `Mínimo ${control.errors['minlength'].requiredLength} caracteres`;
    }
    if (control.errors['mismatch']) return 'Senhas não coincidem';
    
    return 'Erro de validação';
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

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use FormBuilder para formulários complexos**
   - **Por quê**: Sintaxe mais limpa e menos boilerplate
   - **Exemplo**: `this.fb.group({ ... })`

2. **Valide no lado do servidor para dados críticos**
   - **Por quê**: Segurança e consistência
   - **Exemplo**: Validação assíncrona para email único

3. **Forneça feedback visual imediato**
   - **Por quê**: Melhora UX
   - **Exemplo**: Mostrar erros quando touched e invalid

4. **Use Typed Forms quando possível**
   - **Por quê**: Type safety e menos erros
   - **Exemplo**: `FormGroup<UserForm>`

### ❌ Anti-padrões Comuns

1. **Não valide apenas no cliente**
   - **Problema**: Inseguro, pode ser burlado
   - **Solução**: Sempre valide no servidor também

2. **Não mostre erros antes do usuário interagir**
   - **Problema**: UX ruim
   - **Solução**: Mostre apenas quando touched ou dirty

3. **Não use FormControl sem FormGroup para formulários**
   - **Problema**: Dificulta gerenciamento
   - **Solução**: Use FormGroup mesmo para um campo

---

## Exercícios Práticos

### Exercício 1: FormControl e FormGroup Básicos (Básico)

**Objetivo**: Criar primeiro formulário reativo

**Descrição**: 
Crie formulário simples com FormControl e FormGroup para cadastro básico.

**Arquivo**: `exercises/exercise-2-3-1-formcontrol-formgroup.md`

---

### Exercício 2: FormArray e Formulários Dinâmicos (Intermediário)

**Objetivo**: Trabalhar com listas dinâmicas de campos

**Descrição**:
Crie formulário com FormArray que permite adicionar/remover itens dinamicamente.

**Arquivo**: `exercises/exercise-2-3-2-formarray-dinamico.md`

---

### Exercício 3: Validação Síncrona (Intermediário)

**Objetivo**: Implementar validação síncrona completa

**Descrição**:
Crie formulário com múltiplos validators síncronos e feedback visual.

**Arquivo**: `exercises/exercise-2-3-3-validacao-sincrona.md`

---

### Exercício 4: Validação Assíncrona (Avançado)

**Objetivo**: Implementar validação assíncrona

**Descrição**:
Crie validator assíncrono que verifica disponibilidade de email via API.

**Arquivo**: `exercises/exercise-2-3-4-validacao-assincrona.md`

---

### Exercício 5: Validators Customizados (Avançado)

**Objetivo**: Criar validators customizados

**Descrição**:
Crie validators customizados para senha forte e confirmação de senha.

**Arquivo**: `exercises/exercise-2-3-5-validators-customizados.md`

---

### Exercício 6: Typed Forms (Avançado)

**Objetivo**: Trabalhar com Typed Forms

**Descrição**:
Converta formulário existente para Typed Forms com type safety completo.

**Arquivo**: `exercises/exercise-2-3-6-typed-forms.md`

---

### Exercício 7: Formulário Completo com Validação (Avançado)

**Objetivo**: Criar formulário completo usando todas as técnicas

**Descrição**:
Crie formulário completo de cadastro com FormGroup, FormArray, validação síncrona/assíncrona e validators customizados.

**Arquivo**: `exercises/exercise-2-3-7-formulario-completo.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular Reactive Forms](https://angular.io/guide/reactive-forms)**: Guia oficial
- **[FormControl](https://angular.io/api/forms/FormControl)**: Documentação FormControl
- **[FormGroup](https://angular.io/api/forms/FormGroup)**: Documentação FormGroup
- **[Validators](https://angular.io/api/forms/Validators)**: Documentação Validators
- **[Typed Forms](https://angular.io/guide/typed-forms)**: Guia Typed Forms

---

## Resumo

### Principais Conceitos

- FormControl representa um campo individual
- FormGroup agrupa múltiplos controles
- FormArray permite listas dinâmicas
- FormBuilder simplifica criação
- Validação pode ser síncrona ou assíncrona
- Validators customizados permitem regras específicas
- Typed Forms oferecem type safety

### Pontos-Chave para Lembrar

- Use FormBuilder para formulários complexos
- Valide no servidor para dados críticos
- Forneça feedback visual imediato
- Use Typed Forms quando possível
- Entenda estados de formulário

### Próximos Passos

- Próxima aula: HTTP Client e Interceptors
- Praticar criando formulários complexos
- Explorar Signal Forms (Angular 19+)

---

## Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 2.2: Roteamento e Navegação Avançada](./lesson-2-2-roteamento.md)  
**Próxima Aula**: [Aula 2.4: HTTP Client e Interceptors](./lesson-2-4-http-client.md)  
**Voltar ao Módulo**: [Módulo 2: Desenvolvimento Intermediário](../modules/module-2-desenvolvimento-intermediario.md)

