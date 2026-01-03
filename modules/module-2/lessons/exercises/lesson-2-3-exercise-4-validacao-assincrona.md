---
layout: exercise
title: "Exercício 2.3.4: Validação Assíncrona"
slug: "validacao-assincrona"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **validação assíncrona** através da **implementação de validator que verifica disponibilidade de email via API**.

Ao completar este exercício, você será capaz de:

- Criar async validators
- Implementar AsyncValidatorFn
- Lidar com estado pending
- Combinar validators síncronos e assíncronos
- Tratar erros em validação assíncrona

---

## Descrição

Você precisa criar um formulário onde o email é validado assincronamente verificando se já está cadastrado.

### Contexto

Uma aplicação precisa verificar se um email já está em uso antes de permitir registro, evitando duplicatas.

### Tarefa

Crie:

1. **UserService**: Serviço que verifica disponibilidade de email
2. **Async Validator**: Validator que usa o serviço
3. **Formulário**: Com validação assíncrona no campo email
4. **Feedback**: Indicador de loading durante validação

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] UserService criado com método checkEmailExists
- [ ] Async validator implementado
- [ ] Validator aplicado ao campo email
- [ ] Estado pending é tratado
- [ ] Mensagens de erro apropriadas
- [ ] Validação funciona corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Validação assíncrona está completa
- [ ] Feedback visual durante validação

---

## Solução Esperada

### Abordagem Recomendada

**user.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { Observable, of, delay } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private existingEmails = ['test@example.com', 'admin@example.com', 'user@example.com'];
  
  checkEmailExists(email: string): Observable<boolean> {
    const exists = this.existingEmails.includes(email.toLowerCase());
    return of(exists).pipe(delay(1000));
  }
}
```

**email-exists.validator.ts**
```typescript
import { AbstractControl, ValidationErrors, AsyncValidatorFn } from '@angular/forms';
import { Observable, of } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { UserService } from './user.service';

export function emailExistsValidator(userService: UserService): AsyncValidatorFn {
  return (control: AbstractControl): Observable<ValidationErrors | null> => {
    if (!control.value) {
      return of(null);
    }
    
    return userService.checkEmailExists(control.value).pipe(
      map(exists => exists ? { emailExists: true } : null),
      catchError(() => of(null))
    );
  };
}
```

**register-async.component.ts**
{% raw %}
```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, FormControl, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { UserService } from './user.service';
import { emailExistsValidator } from './email-exists.validator';

@Component({
  selector: 'app-register-async',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
{% raw %}
  template: `
    <form [formGroup]="registerForm" (ngSubmit)="onSubmit()">
      <h2>Registro com Validação Assíncrona</h2>
      
      <div class="field">
        <label for="email">Email</label>
        <input 
          id="email" 
          type="email" 
          formControlName="email"
          [class.error]="hasError('email')"
          [class.pending]="isPending('email')">
        @if (isPending('email')) {
          <span class="pending-message">Verificando disponibilidade...</span>
        }
        @if (hasError('email')) {
          <span class="error-message">{{ getError('email') }}</span>
        }
      </div>
      
      <div class="field">
        <label for="name">Nome</label>
        <input id="name" type="text" formControlName="name">
      </div>
      
      <button type="submit" [disabled]="registerForm.invalid || isPending('email')">
        Registrar
      </button>
    </form>
  `,
  styles: [`
{% endraw %}
    .field {
      margin-bottom: 1rem;
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
    
    .field input.pending {
      border-color: #ff9800;
    }
    
    .error-message {
      color: #f44336;
      font-size: 0.875rem;
      display: block;
      margin-top: 0.25rem;
    }
    
    .pending-message {
      color: #ff9800;
      font-size: 0.875rem;
      display: block;
      margin-top: 0.25rem;
    }
  `]
})
export class RegisterAsyncComponent {
  registerForm: FormGroup;
  
  constructor(
    private fb: FormBuilder,
    private userService: UserService
  ) {
    this.registerForm = this.fb.group({
      email: ['', 
        [Validators.required, Validators.email],
        [emailExistsValidator(this.userService)]
      ],
      name: ['', Validators.required]
    });
  }
  
  hasError(controlName: string): boolean {
    const control = this.registerForm.get(controlName);
    return !!(control && control.invalid && (control.dirty || control.touched) && !control.pending);
  }
  
  isPending(controlName: string): boolean {
    const control = this.registerForm.get(controlName);
    return !!(control && control.pending);
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
    
    if (errors['emailExists']) {
      return 'Este email já está cadastrado';
    }
    
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
{% endraw %}

**Explicação da Solução**:

1. UserService simula verificação de email via API
2. emailExistsValidator cria async validator
3. Validator aplicado como terceiro parâmetro do FormControl
4. Estado pending verificado e exibido
5. Erros só aparecem quando não está pending
6. Botão desabilitado durante validação

---

## Testes

### Casos de Teste

**Teste 1**: Validação assíncrona funciona
- **Input**: Digitar email existente
- **Output Esperado**: Erro "Email já cadastrado" após delay

**Teste 2**: Estado pending funciona
- **Input**: Digitar email
- **Output Esperado**: Mensagem "Verificando..." aparece

**Teste 3**: Email disponível funciona
- **Input**: Digitar email novo
- **Output Esperado**: Nenhum erro, form válido

---

## Extensões (Opcional)

1. **Debounce**: Adicione debounce antes de validar
2. **Cache**: Implemente cache de validações
3. **Múltiplos Campos**: Valide outros campos assincronamente

---

## Referências Úteis

- **[Async Validators](https://angular.io/guide/form-validation#async-validation)**: Guia validação assíncrona
- **[AsyncValidatorFn](https://angular.io/api/forms/AsyncValidatorFn)**: Documentação AsyncValidatorFn

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

