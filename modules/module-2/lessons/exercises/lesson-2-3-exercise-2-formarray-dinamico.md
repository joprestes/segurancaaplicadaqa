---
layout: exercise
title: "Exercício 2.3.2: FormArray e Formulários Dinâmicos"
slug: "formarray-dinamico"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **FormArray e formulários dinâmicos** através da **criação de um formulário que permite adicionar e remover campos dinamicamente**.

Ao completar este exercício, você será capaz de:

- Criar FormArray
- Adicionar controles dinamicamente
- Remover controles dinamicamente
- Iterar sobre FormArray no template
- Gerenciar formulários com campos variáveis

---

## Descrição

Você precisa criar um formulário de lista de compras onde o usuário pode adicionar e remover itens dinamicamente.

### Contexto

Uma aplicação precisa de um formulário onde o número de campos pode variar baseado na interação do usuário.

### Tarefa

Crie:

1. **FormArray**: Para lista de itens
2. **Métodos**: addItem() e removeItem()
3. **Template**: Iteração sobre FormArray
4. **Validação**: Validação básica para cada item

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] FormArray criado dentro de FormGroup
- [ ] Método addItem() implementado
- [ ] Método removeItem() implementado
- [ ] Template itera sobre FormArray
- [ ] Botões de adicionar/remover funcionam
- [ ] Valores são lidos corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Formulário está funcional
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**shopping-list.component.ts**
{% raw %}
```typescript
import { Component } from '@angular/core';
import { FormArray, FormGroup, FormControl, FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-shopping-list',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  template: `
    <form [formGroup]="shoppingForm" (ngSubmit)="onSubmit()">
      <h2>Lista de Compras</h2>
      
      <div formArrayName="items">
        @for (item of items.controls; track $index) {
          <div [formGroupName]="$index" class="item-row">
            <input formControlName="name" placeholder="Nome do item">
            <input formControlName="quantity" type="number" placeholder="Quantidade" min="1">
            <button type="button" (click)="removeItem($index)">Remover</button>
          </div>
        }
      </div>
      
      <button type="button" (click)="addItem()">Adicionar Item</button>
      <button type="submit" [disabled]="shoppingForm.invalid">Salvar Lista</button>
      
      <div *ngIf="submitted">
        <h3>Lista salva:</h3>
        <pre>{{ submittedData | json }}</pre>
      </div>
    </form>
  `,
  styles: [`
{% endraw %}
    .item-row {
      display: flex;
      gap: 1rem;
      margin-bottom: 1rem;
      align-items: center;
    }
    
    .item-row input {
      flex: 1;
      padding: 0.5rem;
    }
  `]
})
export class ShoppingListComponent {
  shoppingForm: FormGroup;
  submitted = false;
  submittedData: any = null;
  
  constructor(private fb: FormBuilder) {
    this.shoppingForm = this.fb.group({
      items: this.fb.array([])
    });
  }
  
  get items(): FormArray {
    return this.shoppingForm.get('items') as FormArray;
  }
  
  addItem(): void {
    const itemGroup = this.fb.group({
      name: ['', [Validators.required, Validators.minLength(2)]],
      quantity: [1, [Validators.required, Validators.min(1)]]
    });
    
    this.items.push(itemGroup);
  }
  
  removeItem(index: number): void {
    if (this.items.length > 0) {
      this.items.removeAt(index);
    }
  }
  
  onSubmit(): void {
    if (this.shoppingForm.valid) {
      this.submittedData = this.shoppingForm.value;
      this.submitted = true;
      console.log('Shopping list:', this.shoppingForm.value);
    } else {
      this.shoppingForm.markAllAsTouched();
    }
  }
  
  getItemControl(index: number, controlName: string): FormControl {
    return this.items.at(index).get(controlName) as FormControl;
  }
  
  hasError(index: number, controlName: string): boolean {
    const control = this.getItemControl(index, controlName);
    return !!(control && control.invalid && (control.dirty || control.touched));
  }
}
```

**Explicação da Solução**:

1. FormArray criado dentro de FormGroup usando FormBuilder
2. addItem() cria novo FormGroup e adiciona ao array
3. removeItem() remove item por índice
4. Template usa formArrayName e formGroupName para iteração
5. Validação aplicada a cada item
6. Getters facilitam acesso aos controles

---

## Testes

### Casos de Teste

**Teste 1**: Adicionar item funciona
- **Input**: Clicar em "Adicionar Item"
- **Output Esperado**: Novo campo aparece

**Teste 2**: Remover item funciona
- **Input**: Clicar em "Remover" em um item
- **Output Esperado**: Item é removido

**Teste 3**: Validação funciona
- **Input**: Tentar submeter com campos vazios
- **Output Esperado**: Formulário não é submetido

---

## Extensões (Opcional)

1. **Valores Padrão**: Adicione alguns itens por padrão
2. **Reordenação**: Permita reordenar itens
3. **Validação Customizada**: Valide que não há itens duplicados

---

## Referências Úteis

- **[FormArray](https://angular.io/api/forms/FormArray)**: Documentação FormArray
- **[Dynamic Forms](https://angular.io/guide/reactive-forms#creating-dynamic-forms)**: Guia formulários dinâmicos

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

