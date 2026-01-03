---
layout: exercise
title: "Exercício 1.4.7: Formulário com Validação Visual"
slug: "validacao-visual"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **validação visual de formulários** através da **criação de formulário com feedback visual baseado no estado de validação**.

Ao completar este exercício, você será capaz de:

- Detectar estados de validação (valid, invalid, touched, dirty)
- Aplicar classes CSS condicionalmente baseado em estado
- Aplicar estilos dinamicamente para feedback visual
- Criar formulários com UX aprimorada

---

## Descrição

Você precisa criar um componente `ValidatedFormComponent` que exibe formulário com validação visual. Campos devem mudar aparência baseado no estado de validação.

### Contexto

Um sistema precisa de formulários que fornecem feedback visual claro sobre o estado de validação de cada campo, melhorando a experiência do usuário.

### Tarefa

Crie um componente `ValidatedFormComponent` com:

1. **Campos Validados**: Nome, Email, Senha, Confirmação de Senha
2. **Estados Detectados**: valid, invalid, touched, dirty, pristine
3. **Classes Dinâmicas**: [ngClass] baseado em estados
4. **Estilos Dinâmicos**: [ngStyle] para feedback visual
5. **Mensagens de Erro**: Exibir mensagens quando inválido
6. **Indicadores Visuais**: Bordas coloridas, ícones

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Formulário com campos validados
- [ ] Estados de validação detectados
- [ ] Classes CSS aplicadas condicionalmente
- [ ] Estilos dinâmicos aplicados
- [ ] Mensagens de erro exibidas
- [ ] Feedback visual claro

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Validação visual é clara e intuitiva
- [ ] Código é legível e bem organizado
- [ ] UX é aprimorada

---

## Solução Esperada

### Abordagem Recomendada

**validated-form.component.ts**
```typescript
import { Component } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-validated-form',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './validated-form.component.html',
  styleUrls: ['./validated-form.component.css']
})
export class ValidatedFormComponent {
  formData = {
    name: '',
    email: '',
    password: '',
    confirmPassword: ''
  };
  
  getFieldClasses(field: any, form: NgForm): {[key: string]: boolean} {
    const control = form.controls[field];
    if (!control) return {};
    
    return {
      'field-valid': control.valid && control.touched,
      'field-invalid': control.invalid && control.touched,
      'field-touched': control.touched,
      'field-dirty': control.dirty,
      'field-pristine': control.pristine
    };
  }
  
  getFieldStyles(field: any, form: NgForm): {[key: string]: string} {
    const control = form.controls[field];
    if (!control) return {};
    
    if (control.invalid && control.touched) {
      return {
        'border-color': '#f44336',
        'border-width': '2px'
      };
    } else if (control.valid && control.touched) {
      return {
        'border-color': '#4caf50',
        'border-width': '2px'
      };
    }
    
    return {};
  }
  
  getErrorMessage(field: string, form: NgForm): string {
    const control = form.controls[field];
    if (!control || !control.errors || !control.touched) return '';
    
    if (control.errors['required']) {
      return `${field} é obrigatório`;
    }
    if (control.errors['email']) {
      return 'Email inválido';
    }
    if (control.errors['minlength']) {
      return `Mínimo de ${control.errors['minlength'].requiredLength} caracteres`;
    }
    
    return 'Campo inválido';
  }
  
  passwordsMatch(form: NgForm): boolean {
    return this.formData.password === this.formData.confirmPassword;
  }
  
  onSubmit(form: NgForm): void {
    if (form.valid && this.passwordsMatch(form)) {
      console.log('Formulário válido:', this.formData);
    }
  }
}
```

**validated-form.component.html**
```html
<form #form="ngForm" (ngSubmit)="onSubmit(form)">
  <div class="form-container">
    <h2>Formulário com Validação Visual</h2>
    
    <div class="form-group">
      <label for="name">Nome *</label>
      <input 
        id="name"
        type="text"
        name="name"
        [(ngModel)]="formData.name"
        required
        minlength="3"
        [ngClass]="getFieldClasses('name', form)"
        [ngStyle]="getFieldStyles('name', form)"
        placeholder="Seu nome">
      <span 
        class="error-message"
        *ngIf="form.controls['name']?.invalid && form.controls['name']?.touched">
        {{ getErrorMessage('name', form) }}
      </span>
      <span 
        class="success-icon"
        *ngIf="form.controls['name']?.valid && form.controls['name']?.touched">
        ✓
      </span>
    </div>
    
    <div class="form-group">
      <label for="email">Email *</label>
      <input 
        id="email"
        type="email"
        name="email"
        [(ngModel)]="formData.email"
        required
        email
        [ngClass]="getFieldClasses('email', form)"
        [ngStyle]="getFieldStyles('email', form)"
        placeholder="seu@email.com">
      <span 
        class="error-message"
        *ngIf="form.controls['email']?.invalid && form.controls['email']?.touched">
        {{ getErrorMessage('email', form) }}
      </span>
      <span 
        class="success-icon"
        *ngIf="form.controls['email']?.valid && form.controls['email']?.touched">
        ✓
      </span>
    </div>
    
    <div class="form-group">
      <label for="password">Senha *</label>
      <input 
        id="password"
        type="password"
        name="password"
        [(ngModel)]="formData.password"
        required
        minlength="6"
        [ngClass]="getFieldClasses('password', form)"
        [ngStyle]="getFieldStyles('password', form)"
        placeholder="Mínimo 6 caracteres">
      <span 
        class="error-message"
        *ngIf="form.controls['password']?.invalid && form.controls['password']?.touched">
        {{ getErrorMessage('password', form) }}
      </span>
      <span 
        class="success-icon"
        *ngIf="form.controls['password']?.valid && form.controls['password']?.touched">
        ✓
      </span>
    </div>
    
    <div class="form-group">
      <label for="confirmPassword">Confirmar Senha *</label>
      <input 
        id="confirmPassword"
        type="password"
        name="confirmPassword"
        [(ngModel)]="formData.confirmPassword"
        required
        [ngClass]="getFieldClasses('confirmPassword', form)"
        [ngStyle]="getFieldStyles('confirmPassword', form)"
        [class.field-match]="passwordsMatch(form) && formData.confirmPassword.length > 0"
        [class.field-mismatch]="!passwordsMatch(form) && formData.confirmPassword.length > 0"
        placeholder="Confirme sua senha">
      <span 
        class="error-message"
        *ngIf="form.controls['confirmPassword']?.invalid && form.controls['confirmPassword']?.touched">
        {{ getErrorMessage('confirmPassword', form) }}
      </span>
      <span 
        class="error-message"
        *ngIf="!passwordsMatch(form) && formData.confirmPassword.length > 0">
        Senhas não coincidem
      </span>
      <span 
        class="success-icon"
        *ngIf="passwordsMatch(form) && formData.confirmPassword.length > 0">
        ✓
      </span>
    </div>
    
    <button 
      type="submit"
      [disabled]="!form.valid || !passwordsMatch(form)"
      [ngClass]="{'btn-disabled': !form.valid || !passwordsMatch(form)}">
      Enviar
    </button>
    
    <div class="form-status" *ngIf="form.touched">
      <p [ngClass]="{'status-valid': form.valid, 'status-invalid': form.invalid}">
        Status: {{ form.valid ? 'Válido' : 'Inválido' }}
      </p>
    </div>
  </div>
</form>
```

**validated-form.component.css**
```css
.form-container {
  max-width: 600px;
  margin: 0 auto;
  padding: 2rem;
}

.form-group {
  margin-bottom: 1.5rem;
  position: relative;
}

label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

input {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
  transition: all 0.3s ease;
  box-sizing: border-box;
}

input:focus {
  outline: none;
}

.field-valid {
  border-color: #4caf50 !important;
  background-color: #f1f8f4;
}

.field-invalid {
  border-color: #f44336 !important;
  background-color: #fff5f5;
}

.error-message {
  display: block;
  color: #f44336;
  font-size: 0.875rem;
  margin-top: 0.25rem;
}

.success-icon {
  position: absolute;
  right: 10px;
  top: 38px;
  color: #4caf50;
  font-weight: bold;
}

.field-match {
  border-color: #4caf50 !important;
}

.field-mismatch {
  border-color: #f44336 !important;
}

button {
  width: 100%;
  padding: 0.75rem;
  background-color: #1976d2;
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  transition: all 0.3s;
}

button:hover:not(:disabled) {
  background-color: #1565c0;
}

button:disabled,
.btn-disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.form-status {
  margin-top: 1rem;
  padding: 1rem;
  border-radius: 4px;
  text-align: center;
}

.status-valid {
  background-color: #e8f5e9;
  color: #2e7d32;
}

.status-invalid {
  background-color: #ffebee;
  color: #c62828;
}
```

**Explicação da Solução**:

1. Template-driven form com `NgForm`
2. Métodos helper para classes e estilos
3. Detecção de estados de validação
4. Feedback visual com cores e ícones
5. Mensagens de erro contextuais
6. Validação customizada para senhas
7. Botão desabilitado quando inválido

---

## Testes

### Casos de Teste

**Teste 1**: Campo válido mostra verde
- **Input**: Preencher campo válido e sair
- **Output Esperado**: Borda verde e ícone de sucesso

**Teste 2**: Campo inválido mostra vermelho
- **Input**: Preencher campo inválido e sair
- **Output Esperado**: Borda vermelha e mensagem de erro

**Teste 3**: Senhas coincidem
- **Input**: Digitar senhas iguais
- **Output Esperado**: Campo deve ficar verde

**Teste 4**: Botão desabilitado quando inválido
- **Input**: Formulário inválido
- **Output Esperado**: Botão deve estar desabilitado

---

## Extensões (Opcional)

1. **Validação Assíncrona**: Adicione validação de email único
2. **Força da Senha**: Indicador visual de força da senha
3. **Máscaras**: Adicione máscaras para campos específicos
4. **Animações**: Adicione animações para transições de estado

---

## Referências Úteis

- **[Form Validation](https://angular.io/guide/form-validation)**: Guia de validação
- **[Template-driven Forms](https://angular.io/guide/forms)**: Formulários template-driven

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

