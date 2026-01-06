---
layout: exercise
title: "Exercício 2.3.1: FormControl e FormGroup Básicos"
slug: "formcontrol-formgroup"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **FormControl e FormGroup básicos** através da **criação de um formulário reativo simples**.

Ao completar este exercício, você será capaz de:

- Criar FormControl individual
- Criar FormGroup com múltiplos controles
- Conectar formulário ao template
- Ler valores do formulário
- Entender estrutura básica de formulários reativos

---

## Descrição

Você precisa criar um formulário de contato simples usando FormControl e FormGroup.

### Contexto

Uma aplicação precisa de um formulário de contato básico para coletar informações dos usuários.

### Tarefa

Crie:

1. **FormGroup**: Com campos name, email e message
2. **FormControls**: Um para cada campo
3. **Template**: Formulário HTML conectado
4. **Submit**: Método para processar dados

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] FormGroup criado com três FormControls
- [ ] ReactiveFormsModule importado
- [ ] Template conectado com formGroup e formControlName
- [ ] Método onSubmit implementado
- [ ] Valores são lidos corretamente
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Formulário está funcional
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**contact-form.component.ts**

{% raw %}
```typescript
import { Component } from '@angular/core';
import { FormGroup, FormControl, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-contact-form',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  template: `
    <form [formGroup]="contactForm" (ngSubmit)="onSubmit()">
      <div>
        <label for="name">Nome</label>
        <input id="name" type="text" formControlName="name">
      </div>
      
      <div>
        <label for="email">Email</label>
        <input id="email" type="email" formControlName="email">
      </div>
      
      <div>
        <label for="message">Mensagem</label>
        <textarea id="message" formControlName="message"></textarea>
      </div>
      
      <button type="submit">Enviar</button>
      
      <div *ngIf="submitted">
        <h3>Dados enviados:</h3>
        <pre>{{ submittedData | json }}</pre>
      </div>
    </form>
  `
})
export class ContactFormComponent {
  contactForm = new FormGroup({
    name: new FormControl(''),
    email: new FormControl(''),
    message: new FormControl('')
  });
  
  submitted = false;
  submittedData: any = null;
  
  onSubmit(): void {
    if (this.contactForm.valid) {
      this.submittedData = this.contactForm.value;
      this.submitted = true;
      console.log('Form submitted:', this.contactForm.value);
    }
  }
  
  get nameControl(): FormControl {
    return this.contactForm.get('name') as FormControl;
  }
  
  get emailControl(): FormControl {
    return this.contactForm.get('email') as FormControl;
  }
  
  get messageControl(): FormControl {
    return this.contactForm.get('message') as FormControl;
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. FormGroup criado com três FormControls
2. ReactiveFormsModule importado para usar diretivas
3. Template usa [formGroup] e formControlName
4. onSubmit lê valores via form.value
5. Getters facilitam acesso aos controles
6. Validação básica com form.valid

---

## Testes

### Casos de Teste

**Teste 1**: Formulário funciona
- **Input**: Preencher e submeter formulário
- **Output Esperado**: Dados são exibidos

**Teste 2**: Valores são lidos corretamente
- **Input**: Preencher campos específicos
- **Output Esperado**: Valores corretos no console

**Teste 3**: Controles são acessíveis
- **Input**: Usar getters para acessar controles
- **Output Esperado**: Controles retornados corretamente

---

## Extensões (Opcional)

1. **Validação**: Adicione validação básica
2. **Reset**: Adicione botão para resetar formulário
3. **Valores Padrão**: Defina valores padrão

---

## Referências Úteis

- **[Reactive Forms](https://angular.io/guide/reactive-forms)**: Guia oficial
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

