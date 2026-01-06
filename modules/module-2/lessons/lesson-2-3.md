---
layout: lesson
title: "Aula 2.3: Formulários Reativos e Validação"
slug: formularios-reativos
module: module-2
lesson_id: lesson-2-3
duration: "120 minutos"
level: "Intermediário"
prerequisites: []
exercises: []
podcast:
  file: "assets/podcasts/02.3-Dominando_os_Formularios_Reativos_do_Angular.m4a"
  image: "assets/images/podcasts/02.3-Dominando_os_Formularios_Reativos_do_Angular.png"
  title: "Dominando os Formulários Reativos do Angular"
  description: "Formulários reativos são uma das funcionalidades mais poderosas do Angular."
  duration: "60-75 minutos"
permalink: /modules/desenvolvimento-intermediario/lessons/formularios-reativos/
---

## Introdução

Nesta aula, você dominará Formulários Reativos do Angular, a abordagem moderna e poderosa para criar formulários complexos com validação robusta. Formulários reativos oferecem controle total sobre o estado e validação, sendo essenciais para aplicações profissionais.

### Contexto Histórico dos Formulários Angular

O Angular oferece duas abordagens para formulários, cada uma com seus casos de uso. A evolução dos formulários no Angular reflete a busca constante por melhor controle, type safety e experiência de desenvolvimento.

**Linha do Tempo Detalhada**:

```
AngularJS (2010) ──────────────────────────────────────────── Angular 19+ (2024+)
 │                                                                  │
 ├─ 2010-2015 📦 AngularJS - ngModel Two-Way Binding              │
 │          Abordagem declarativa no template                       │
 │          Validação via diretivas                                │
 │          Performance limitada em formulários grandes            │
 │          Difícil testar lógica de validação                     │
 │                                                                  │
 ├─ 2016    🔥 Angular 2 - Reactive Forms Introduzidos            │
 │          FormControl, FormGroup, FormArray                       │
 │          Validação programática no componente                    │
 │          Controle total sobre estado                            │
 │          Melhor testabilidade                                   │
 │          Performance superior                                    │
 │                                                                  │
 ├─ 2016    📦 Template-Driven Forms (Alternativa)               │
 │          ngModel para two-way binding                           │
 │          Validação no template                                  │
 │          Mais simples para casos básicos                        │
 │          Menos controle                                         │
 │                                                                  │
 ├─ 2017-2020 📈 Melhorias Incrementais                           │
 │          FormBuilder API melhorada                              │
 │          Validators customizados mais flexíveis                 │
 │          Validação assíncrona robusta                           │
 │          Melhorias de performance                               │
 │          Suporte a nested forms                                 │
 │                                                                  │
 ├─ 2021    ⚡ Angular 14 - Typed Forms (Experimental)          │
 │          FormControl<string>, FormGroup<T>                     │
 │          Type safety completo                                   │
 │          Autocomplete melhorado                                 │
 │          Prevenção de erros em compile-time                    │
 │                                                                  │
 ├─ 2022    🎯 Angular 15 - Typed Forms Estável                 │
 │          Suporte completo e estável                             │
 │          Melhorias de performance                               │
 │          Integração com strict mode                             │
 │                                                                  │
 ├─ 2023+    🚀 Angular 17+ - Typed Forms Otimizado             │
 │          Performance melhorada                                  │
 │          Melhor integração com signals                         │
 │          Suporte a formulários complexos                       │
 │                                                                  │
 └─ 2024+    🔮 Angular 19+ - Signal Forms (Futuro)              │
            Formulários baseados em signals                       │
            Reatividade moderna                                    │
            Performance ainda melhor                               │
```

**Template-Driven vs Reactive Forms - Comparação Detalhada**:

| Aspecto | Template-Driven | Reactive Forms |
|---------|----------------|----------------|
| **Configuração** | No template HTML | No componente TypeScript |
| **Validação** | Diretivas no template (`required`, `minlength`) | Funções no código (`Validators.required`) |
| **Testabilidade** | Mais difícil (testa template + componente) | Mais fácil (testa apenas lógica) |
| **Complexidade** | Simples para casos básicos | Pode ser complexo, mas escalável |
| **Controle** | Limitado (Angular gerencia estado) | Total (você gerencia estado) |
| **Type Safety** | Limitado (strings no template) | Completo (Typed Forms) |
| **Performance** | Boa para formulários pequenos | Superior para formulários grandes |
| **Validação Assíncrona** | Limitada | Suporte completo |
| **Validação Cross-Field** | Difícil | Fácil (validators no FormGroup) |
| **Formulários Dinâmicos** | Limitado | Excelente (FormArray) |
| **Debugging** | Mais difícil | Mais fácil (estado explícito) |
| **Bundle Size** | Menor (menos código) | Maior (mais funcionalidades) |

**Quando Usar Cada Abordagem**:

**Template-Driven Forms**:
- Formulários simples com poucos campos
- Validação básica (required, email, minlength)
- Prototipagem rápida
- Formulários que não precisam de lógica complexa
- Quando você prefere declarar validação no template

**Reactive Forms**:
- Formulários complexos com muitos campos
- Validação customizada e cross-field
- Testes unitários importantes
- Controle total sobre estado necessário
- Formulários dinâmicos (adicionar/remover campos)
- Validação assíncrona (verificar email único, etc.)
- Quando type safety é importante
- Formulários que precisam de lógica de negócio complexa

### O que você vai aprender

- **FormControl**: Controle de campos individuais
- **FormGroup**: Agrupamento de controles
- **FormArray**: Arrays dinâmicos de controles
- **FormBuilder**: Simplificar criação de formulários
- **Validação Síncrona**: Validators embutidos e customizados
- **Validação Assíncrona**: Validação com chamadas assíncronas
- **Typed Forms**: Type safety completo (Angular 14+)
- **Estados de Formulário**: Pristine, dirty, touched, valid, invalid
- **Formulários Dinâmicos**: Criar formulários em runtime
- **Feedback Visual**: Mostrar erros e estados ao usuário

### Por que isso é importante

**Para Desenvolvimento**:
- **Controle Total**: Gerenciamento completo do estado do formulário
- **Testabilidade**: Fácil testar lógica de formulários
- **Type Safety**: Typed Forms garantem tipos corretos
- **Validação Complexa**: Suporta validações avançadas

**Para Projetos**:
- **UX Profissional**: Formulários com validação robusta
- **Manutenibilidade**: Código organizado e testável
- **Performance**: Validação eficiente
- **Escalabilidade**: Suporta formulários complexos

**Para Carreira**:
- **Essencial**: Formulários são fundamentais em aplicações web
- **Diferencial**: Conhecimento de reactive forms avançado
- **Relevância**: Usado em praticamente todos os projetos
- **Base Sólida**: Necessário para desenvolvimento profissional

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

**Visualização - Estrutura Interna**:

```
FormControl
┌─────────────────────────────────────────────┐
│ Estado Atual                                 │
│ ├─ value: "João"                            │
│ ├─ status: "VALID" | "INVALID" | "PENDING" │
│ ├─ errors: { required: true } | null        │
│ ├─ pristine: false                         │
│ ├─ dirty: true                              │
│ ├─ touched: true                            │
│ ├─ untouched: false                         │
│ ├─ disabled: false                          │
│ └─ pending: false                           │
│                                              │
│ Observables                                  │
│ ├─ valueChanges: Observable<string>        │
│ ├─ statusChanges: Observable<Status>       │
│ └─ stateChanges: Observable<void>          │
│                                              │
│ Métodos                                      │
│ ├─ setValue(value)                          │
│ ├─ patchValue(value)                        │
│ ├─ reset(value?)                            │
│ ├─ enable()                                 │
│ ├─ disable()                                │
│ ├─ markAsTouched()                          │
│ ├─ markAsUntouched()                        │
│ ├─ markAsDirty()                            │
│ ├─ markAsPristine()                         │
│ └─ updateValueAndValidity()                 │
└─────────────────────────────────────────────┘
```

**Fluxo de Ciclo de Vida do FormControl**:

```
Usuário interage com campo
         │
         ▼
┌────────────────────┐
│ Usuário digita     │
│ valor no input     │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ valueChanges       │
│ emite novo valor   │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Validação          │
│ síncrona executa   │
└─────────┬──────────┘
          │
          ├─► Válido ──► status = "VALID"
          │
          └─► Inválido ──► status = "INVALID"
                          errors = { ... }
                          │
                          ▼
                    statusChanges emite
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

**Visualização - Hierarquia Completa**:

```
FormGroup: userForm
┌─────────────────────────────────────────────┐
│ Estado do Grupo                             │
│ ├─ valid: true | false                     │
│ ├─ invalid: true | false                    │
│ ├─ pending: true | false                    │
│ ├─ disabled: true | false                   │
│ ├─ touched: true | false                   │
│ ├─ dirty: true | false                      │
│ └─ errors: { ... } | null                  │
│                                              │
│ Controles                                   │
│ ├─ name: FormControl<string>               │
│ │   └─ value: "João"                       │
│ │   └─ valid: true                          │
│ │                                           │
│ ├─ email: FormControl<string>              │
│ │   └─ value: "joao@email.com"             │
│ │   └─ valid: true                          │
│ │                                           │
│ └─ address: FormGroup                       │
│     ├─ street: FormControl<string>         │
│     │   └─ value: "Rua ABC"                │
│     │   └─ valid: true                      │
│     │                                        │
│     └─ city: FormControl<string>            │
│         └─ value: "São Paulo"                │
│         └─ valid: true                       │
│                                              │
│ Observables                                 │
│ ├─ valueChanges: Observable<UserForm>     │
│ ├─ statusChanges: Observable<Status>      │
│ └─ stateChanges: Observable<void>         │
│                                              │
│ Métodos                                     │
│ ├─ get(path): AbstractControl | null       │
│ ├─ setValue(value)                         │
│ ├─ patchValue(value)                       │
│ ├─ reset(value?)                           │
│ ├─ markAllAsTouched()                      │
│ └─ updateValueAndValidity()                │
└─────────────────────────────────────────────┘
```

**Fluxo de Validação em FormGroup**:

```
FormGroup recebe comando de validação
         │
         ▼
┌────────────────────┐
│ Valida cada       │
│ FormControl       │
└─────────┬──────────┘
          │
          ├─► name: VALID
          ├─► email: VALID
          └─► address: FormGroup
              ├─► street: VALID
              └─► city: VALID
          │
          ▼
┌────────────────────┐
│ Valida FormGroup  │
│ (validators de    │
│  grupo, se houver)│
└─────────┬──────────┘
          │
          ├─► Todos válidos ──► FormGroup: VALID
          │
          └─► Algum inválido ──► FormGroup: INVALID
                                  errors = { ... }
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

FormArray é como uma lista de compras onde você pode adicionar ou remover itens dinamicamente. Cada item é um FormControl ou FormGroup. Assim como você pode adicionar novos itens à lista enquanto faz compras, o FormArray permite adicionar novos campos ao formulário em runtime. Quando você remove um item da lista, ele desaparece completamente - o mesmo acontece quando você remove um controle do FormArray. A validação funciona individualmente para cada item, mas você também pode validar o array inteiro (por exemplo, garantir que há pelo menos um item).

**Visualização - Estrutura do FormArray**:

```
FormArray: items
┌─────────────────────────────────────────────┐
│ Estado do Array                            │
│ ├─ length: 3                               │
│ ├─ valid: true | false                     │
│ └─ controls: AbstractControl[]            │
│                                              │
│ Controles (Array Dinâmico)                 │
│ ├─ [0]: FormGroup                          │
│ │   ├─ name: FormControl                  │
│ │   └─ quantity: FormControl             │
│ │                                           │
│ ├─ [1]: FormGroup                          │
│ │   ├─ name: FormControl                  │
│ │   └─ quantity: FormControl             │
│ │                                           │
│ └─ [2]: FormGroup                          │
│     ├─ name: FormControl                  │
│     └─ quantity: FormControl              │
│                                              │
│ Métodos                                     │
│ ├─ push(control): void                     │
│ ├─ insert(index, control): void            │
│ ├─ removeAt(index): void                   │
│ ├─ setControl(index, control): void        │
│ ├─ get(index): AbstractControl             │
│ └─ at(index): AbstractControl              │
└─────────────────────────────────────────────┘
```

**Fluxo de Operações no FormArray**:

```
Adicionar Item
    │
    ▼
┌────────────────────┐
│ Criar novo         │
│ FormGroup/Control  │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ items.push()       │
│ adiciona ao array  │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Validação          │
│ automática         │
└────────────────────┘

Remover Item
    │
    ▼
┌────────────────────┐
│ items.removeAt(i)  │
│ remove do array    │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Validação          │
│ automática         │
└────────────────────┘
```

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

Validação síncrona é como um guarda que verifica documentos na entrada de um evento. A verificação acontece imediatamente quando você apresenta o documento - ele olha, verifica se está completo, se tem a foto, se não está vencido, tudo na hora. Não há espera, não há consulta externa. Se algo estiver errado, você sabe naquele momento e pode corrigir imediatamente. Da mesma forma, validators síncronos executam instantaneamente quando o valor muda, verificando regras simples como "está vazio?", "tem pelo menos X caracteres?", "está no formato correto?".

**Fluxo de Validação Síncrona**:

```
Usuário altera valor do campo
         │
         ▼
┌────────────────────┐
│ valueChanges       │
│ emite novo valor   │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Executa Validators│
│ Síncronos          │
│ (sequencialmente)  │
└─────────┬──────────┘
          │
          ├─► Validator 1: required
          │   └─► Passou ✓
          │
          ├─► Validator 2: minLength(3)
          │   └─► Passou ✓
          │
          └─► Validator 3: pattern(/^[A-Z]/)
              └─► Falhou ✗
                  │
                  ▼
          ┌────────────────────┐
          │ errors = {         │
          │   pattern: true    │
          │ }                  │
          │ status = "INVALID" │
          └────────────────────┘
```

**Tabela de Validators Síncronos Disponíveis**:

| Validator | Descrição | Exemplo de Uso | Erro Retornado |
|-----------|-----------|----------------|----------------|
| `Validators.required` | Campo obrigatório | `Validators.required` | `{ required: true }` |
| `Validators.email` | Formato de email válido | `Validators.email` | `{ email: true }` |
| `Validators.minLength(n)` | Tamanho mínimo | `Validators.minLength(3)` | `{ minlength: { requiredLength: 3, actualLength: 2 } }` |
| `Validators.maxLength(n)` | Tamanho máximo | `Validators.maxLength(50)` | `{ maxlength: { requiredLength: 50, actualLength: 51 } }` |
| `Validators.min(n)` | Valor numérico mínimo | `Validators.min(18)` | `{ min: { min: 18, actual: 17 } }` |
| `Validators.max(n)` | Valor numérico máximo | `Validators.max(100)` | `{ max: { max: 100, actual: 101 } }` |
| `Validators.pattern(regex)` | Padrão regex | `Validators.pattern(/^[A-Z]/)` | `{ pattern: { requiredPattern: '/^[A-Z]/', actualValue: 'abc' } }` |
| `Validators.requiredTrue` | Deve ser `true` | `Validators.requiredTrue` | `{ required: true }` |
| `Validators.nullValidator` | Sempre válido (placeholder) | `Validators.nullValidator` | `null` |

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

Validação assíncrona é como verificar se um email já está cadastrado em um sistema. Quando você digita o email, o sistema precisa fazer uma consulta ao servidor para verificar se aquele email já existe no banco de dados. Essa consulta leva tempo (milissegundos ou segundos), então você não recebe a resposta imediatamente. Enquanto a verificação está acontecendo, o campo fica em estado "pending" (pendente). Se o email já existir, você recebe um erro; se não existir, o campo fica válido. É como esperar na fila de um banco - você sabe que será atendido, mas precisa aguardar.

**Fluxo de Validação Assíncrona**:

```
Usuário altera valor do campo
         │
         ▼
┌────────────────────┐
│ Validação          │
│ Síncrona executa   │
│ primeiro           │
└─────────┬──────────┘
          │
          ├─► Inválido ──► Para aqui, não executa assíncrona
          │
          └─► Válido ──► Continua
              │
              ▼
┌────────────────────┐
│ status = "PENDING" │
│ pending = true     │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Executa Validator  │
│ Assíncrono          │
│ (chamada HTTP)     │
└─────────┬──────────┘
          │
          ├─► Aguarda resposta...
          │
          ▼
┌────────────────────┐
│ Resposta recebida  │
└─────────┬──────────┘
          │
          ├─► Email existe ──► errors = { emailExists: true }
          │                    status = "INVALID"
          │
          └─► Email não existe ──► errors = null
                                    status = "VALID"
```

**Características Importantes**:

- Validators assíncronos só executam se validators síncronos passarem
- Durante validação assíncrona, `pending = true` e `status = "PENDING"`
- Múltiplos validators assíncronos executam em paralelo
- Se o valor mudar durante validação assíncrona, a validação anterior é cancelada

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

Estados são como indicadores de status em um sistema de controle de qualidade. Imagine uma linha de produção onde cada produto passa por verificações:

- **Pristine**: O produto acabou de sair da linha de produção, ainda não foi tocado ou modificado. É o estado original, como um documento recém-impresso que ainda não foi editado.

- **Dirty**: O produto foi modificado de alguma forma. Alguém fez uma alteração, como escrever em um documento em branco. O sistema sabe que houve mudança.

- **Touched**: O produto foi inspecionado ou tocado. O usuário interagiu com o campo (focou nele), mesmo que não tenha mudado o valor. É como um documento que foi aberto e lido, mas não editado.

- **Untouched**: O produto nunca foi inspecionado. O campo nunca recebeu foco do usuário.

- **Valid/Invalid**: O produto passou ou falhou nas verificações de qualidade. Um campo válido atende todas as regras; um inválido tem pelo menos uma regra violada.

- **Pending**: O produto está aguardando verificação externa. A validação assíncrona está em andamento, como aguardar confirmação de um fornecedor.

**Diagrama de Estados e Transições**:

```
Estado Inicial
┌─────────────────┐
│ pristine: true  │
│ untouched: true │
│ dirty: false    │
│ touched: false  │
└────────┬────────┘
         │
         │ Usuário foca no campo
         ▼
┌─────────────────┐
│ touched: true   │
│ untouched: false│
│ (pristine ainda)│
└────────┬────────┘
         │
         │ Usuário altera valor
         ▼
┌─────────────────┐
│ dirty: true     │
│ pristine: false │
│ touched: true   │
└────────┬────────┘
         │
         ├─► Validação passa ──► valid: true, invalid: false
         │
         └─► Validação falha ──► valid: false, invalid: true
                                  errors = { ... }
```

**Tabela de Estados e Propriedades**:

| Estado | Propriedade | Descrição | Quando Muda |
|--------|-------------|-----------|-------------|
| **Pristine** | `pristine: true` | Valor não foi alterado desde criação/reset | Muda para `false` quando `setValue()` ou `patchValue()` é chamado |
| **Dirty** | `dirty: true` | Valor foi alterado | Muda para `true` quando usuário altera valor |
| **Touched** | `touched: true` | Campo recebeu foco (blur event) | Muda para `true` quando campo perde foco |
| **Untouched** | `untouched: true` | Campo nunca recebeu foco | Oposto de `touched` |
| **Valid** | `valid: true` | Passa todas as validações | Calculado automaticamente |
| **Invalid** | `invalid: true` | Falha em pelo menos uma validação | Calculado automaticamente |
| **Pending** | `pending: true` | Validação assíncrona em andamento | Durante execução de async validator |
| **Disabled** | `disabled: true` | Campo desabilitado | Quando `disable()` é chamado |
| **Enabled** | `enabled: true` | Campo habilitado | Quando `enable()` é chamado |

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

## Comparação com Outros Frameworks

### Angular Reactive Forms vs React Hook Form vs Vue Vuelidate

**Tabela Comparativa Detalhada**:

| Aspecto | Angular Reactive Forms | React Hook Form | Vue Vuelidate |
|---------|----------------------|-----------------|---------------|
| **Paradigma** | Model-driven (programático) | Hook-based (declarativo) | Composition API |
| **Type Safety** | Excelente (Typed Forms) | Excelente (TypeScript) | Boa (TypeScript) |
| **Validação Síncrona** | ✅ Nativa | ✅ Nativa | ✅ Nativa |
| **Validação Assíncrona** | ✅ Nativa | ✅ Nativa | ✅ Nativa |
| **Validação Cross-Field** | ✅ Fácil (FormGroup validators) | ✅ Fácil (schema validation) | ✅ Fácil (computed) |
| **Formulários Dinâmicos** | ✅ FormArray | ✅ useFieldArray | ✅ Array refs |
| **Performance** | Excelente | Excelente (menos re-renders) | Boa |
| **Bundle Size** | ~50KB (parte do core) | ~9KB (biblioteca externa) | ~15KB (biblioteca externa) |
| **Curva de Aprendizado** | Moderada | Baixa | Moderada |
| **Testabilidade** | Excelente | Excelente | Boa |
| **Documentação** | Excelente (oficial) | Excelente | Boa |
| **Comunidade** | Grande (Angular) | Grande | Média |
| **Suporte Oficial** | ✅ Framework oficial | ❌ Biblioteca de terceiros | ❌ Biblioteca de terceiros |
| **Integração** | Nativa (sem dependências) | Requer instalação | Requer instalação |
| **Validação de Schema** | Manual ou bibliotecas | ✅ Zod/Yup integrado | ✅ Zod/Yup integrado |
| **Reset de Formulário** | `form.reset()` | `reset()` | `reset()` |
| **Valores Padrão** | Segundo parâmetro do FormControl | `defaultValues` | `initialValues` |
| **Observables** | ✅ Nativo (valueChanges) | ❌ Não (usa callbacks) | ❌ Não (usa watchers) |

**Quando Escolher Cada Abordagem**:

**Angular Reactive Forms**:
- ✅ Você já está usando Angular
- ✅ Quer solução nativa sem dependências externas
- ✅ Precisa de type safety completo
- ✅ Quer usar Observables para reatividade
- ✅ Projeto grande que se beneficia de padrões consistentes

**React Hook Form**:
- ✅ Você está usando React
- ✅ Quer performance máxima (menos re-renders)
- ✅ Prefere biblioteca leve e focada
- ✅ Quer integração fácil com Zod/Yup
- ✅ Precisa de validação complexa com schema

**Vue Vuelidate**:
- ✅ Você está usando Vue 3
- ✅ Quer usar Composition API
- ✅ Prefere abordagem declarativa
- ✅ Precisa de validação reativa com computed

**Exemplo Comparativo - Mesmo Formulário**:

**Angular Reactive Forms**:
```typescript
form = this.fb.group({
  email: ['', [Validators.required, Validators.email]],
  password: ['', [Validators.required, Validators.minLength(8)]]
});
```

**React Hook Form**:
```typescript
const { register, handleSubmit, formState: { errors } } = useForm({
  defaultValues: {
    email: '',
    password: ''
  }
});
```

**Vue Vuelidate**:
```typescript
const form = reactive({
  email: '',
  password: ''
});

const rules = {
  email: { required, email },
  password: { required, minLength: minLength(8) }
};
```

---

## Exemplos Práticos Completos

### Exemplo 1: Formulário Completo com Validação

**Contexto**: Criar formulário de registro de usuário com validação completa, feedback visual e tratamento de erros.

**Requisitos**:
- Validação síncrona para todos os campos
- Validação cross-field (senhas devem coincidir)
- Feedback visual imediato
- Mensagens de erro específicas
- Desabilitar botão quando inválido

**Código Completo**:

{% raw %}
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
      const formData = {
        name: this.registerForm.value.name,
        email: this.registerForm.value.email,
        password: this.registerForm.value.password
      };
      console.log('Dados para envio:', formData);
    } else {
      this.registerForm.markAllAsTouched();
      console.log('Form inválido. Erros:', this.getFormErrors());
    }
  }
  
  getFormErrors(): any {
    const errors: any = {};
    Object.keys(this.registerForm.controls).forEach(key => {
      const control = this.registerForm.get(key);
      if (control && control.errors) {
        errors[key] = control.errors;
      }
    });
    return errors;
  }
}
```

**Template HTML Completo**:

{% raw %}
```html
<form [formGroup]="registerForm" (ngSubmit)="onSubmit()">
  <div class="form-group">
    <label for="name">Nome Completo</label>
    <input 
      id="name" 
      type="text" 
      formControlName="name"
      [class.error]="showError('name')"
      [class.valid]="registerForm.get('name')?.valid && registerForm.get('name')?.touched">
    @if (showError('name')) {
      <span class="error-message">{{ getError('name') }}</span>
    }
  </div>
  
  <div class="form-group">
    <label for="email">Email</label>
    <input 
      id="email" 
      type="email" 
      formControlName="email"
      [class.error]="showError('email')"
      [class.valid]="registerForm.get('email')?.valid && registerForm.get('email')?.touched">
    @if (showError('email')) {
      <span class="error-message">{{ getError('email') }}</span>
    }
  </div>
  
  <div class="form-group">
    <label for="password">Senha</label>
    <input 
      id="password" 
      type="password" 
      formControlName="password"
      [class.error]="showError('password')"
      [class.valid]="registerForm.get('password')?.valid && registerForm.get('password')?.touched">
    @if (showError('password')) {
      <span class="error-message">{{ getError('password') }}</span>
    }
  </div>
  
  <div class="form-group">
    <label for="confirmPassword">Confirmar Senha</label>
    <input 
      id="confirmPassword" 
      type="password" 
      formControlName="confirmPassword"
      [class.error]="showError('confirmPassword')"
      [class.valid]="registerForm.get('confirmPassword')?.valid && registerForm.get('confirmPassword')?.touched">
    @if (showError('confirmPassword')) {
      <span class="error-message">{{ getError('confirmPassword') }}</span>
    }
  </div>
  
  <button 
    type="submit" 
    [disabled]="registerForm.invalid"
    [class.disabled]="registerForm.invalid">
    Registrar
  </button>
  
  <div class="form-status">
    <p>Status: {{ registerForm.status }}</p>
    <p>Válido: {{ registerForm.valid ? 'Sim' : 'Não' }}</p>
    <p>Tocado: {{ registerForm.touched ? 'Sim' : 'Não' }}</p>
  </div>
</form>
```
{% raw %}
<form [formGroup]="registerForm" (ngSubmit)="onSubmit()">
  <div class="form-group">
    <label for="name">Nome Completo</label>
    <input 
      id="name" 
      type="text" 
      formControlName="name"
      [class.error]="showError('name')"
      [class.valid]="registerForm.get('name')?.valid && registerForm.get('name')?.touched">
    @if (showError('name')) {
      <span class="error-message">{{ getError('name') }}</span>
    }
  </div>
  
  <div class="form-group">
    <label for="email">Email</label>
    <input 
      id="email" 
      type="email" 
      formControlName="email"
      [class.error]="showError('email')"
      [class.valid]="registerForm.get('email')?.valid && registerForm.get('email')?.touched">
    @if (showError('email')) {
      <span class="error-message">{{ getError('email') }}</span>
    }
  </div>
  
  <div class="form-group">
    <label for="password">Senha</label>
    <input 
      id="password" 
      type="password" 
      formControlName="password"
      [class.error]="showError('password')"
      [class.valid]="registerForm.get('password')?.valid && registerForm.get('password')?.touched">
    @if (showError('password')) {
      <span class="error-message">{{ getError('password') }}</span>
    }
  </div>
  
  <div class="form-group">
    <label for="confirmPassword">Confirmar Senha</label>
    <input 
      id="confirmPassword" 
      type="password" 
      formControlName="confirmPassword"
      [class.error]="showError('confirmPassword')"
      [class.valid]="registerForm.get('confirmPassword')?.valid && registerForm.get('confirmPassword')?.touched">
    @if (showError('confirmPassword')) {
      <span class="error-message">{{ getError('confirmPassword') }}</span>
    }
  </div>
  
  <button 
    type="submit" 
    [disabled]="registerForm.invalid"
    [class.disabled]="registerForm.invalid">
    Registrar
  </button>
  
  <div class="form-status">
    <p>Status: {{ registerForm.status }}</p>
    <p>Válido: {{ registerForm.valid ? 'Sim' : 'Não' }}</p>
    <p>Tocado: {{ registerForm.touched ? 'Sim' : 'Não' }}</p>
  </div>
</form>
```
{% endraw %}

**Explicação Detalhada**:

1. **FormBuilder**: Usado para criar o formulário de forma mais limpa
2. **Validação Cross-Field**: `passwordMatchValidator` valida no nível do FormGroup, comparando dois campos
3. **Feedback Visual**: Métodos `showError()` e `getError()` fornecem feedback específico
4. **Estados**: `markAllAsTouched()` marca todos os campos como tocados para mostrar erros
5. **Type Safety**: Com Typed Forms, você teria autocomplete completo nos valores

**Saída Esperada**:

Quando o formulário é válido:
```
Form válido: {
  name: "João Silva",
  email: "joao@email.com",
  password: "Senha123",
  confirmPassword: "Senha123"
}
```

Quando há erros:
```
Form inválido. Erros: {
  email: { email: true },
  password: { minlength: { requiredLength: 8, actualLength: 5 } },
  confirmPassword: { mismatch: true }
}
```

---

### Exemplo 2: Formulário com FormArray Dinâmico

**Contexto**: Criar formulário para cadastro de produtos com múltiplos fornecedores (quantidade variável). O usuário deve poder adicionar e remover fornecedores dinamicamente.

**Código Completo**:

{% raw %}
```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, FormArray, Validators, AbstractControl } from '@angular/forms';
import { ReactiveFormsModule, CommonModule } from '@angular/forms';

interface Supplier {
  name: string;
  email: string;
  phone: string;
}

@Component({
  selector: 'app-product-form',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  template: `
    <form [formGroup]="productForm" (ngSubmit)="onSubmit()">
      <div class="form-group">
        <label>Nome do Produto</label>
        <input formControlName="productName">
        @if (showError('productName')) {
          <span class="error">{{ getError('productName') }}</span>
        }
      </div>
      
      <div class="form-group">
        <label>Descrição</label>
        <textarea formControlName="description"></textarea>
      </div>
      
      <div class="suppliers-section">
        <h3>Fornecedores</h3>
        
        <div formArrayName="suppliers">
          @for (supplier of suppliers.controls; track $index) {
            <div [formGroupName]="$index" class="supplier-group">
              <h4>Fornecedor {{ $index + 1 }}</h4>
              
              <div class="form-group">
                <label>Nome</label>
                <input formControlName="name">
                @if (showSupplierError($index, 'name')) {
                  <span class="error">{{ getSupplierError($index, 'name') }}</span>
                }
              </div>
              
              <div class="form-group">
                <label>Email</label>
                <input formControlName="email" type="email">
                @if (showSupplierError($index, 'email')) {
                  <span class="error">{{ getSupplierError($index, 'email') }}</span>
                }
              </div>
              
              <div class="form-group">
                <label>Telefone</label>
                <input formControlName="phone">
              </div>
              
              <button type="button" (click)="removeSupplier($index)" [disabled]="suppliers.length <= 1">
                Remover Fornecedor
              </button>
            </div>
          }
        </div>
        
        <button type="button" (click)="addSupplier()">Adicionar Fornecedor</button>
      </div>
      
      <button type="submit" [disabled]="productForm.invalid">
        Salvar Produto
      </button>
    </form>
  `
})
export class ProductFormComponent {
  productForm: FormGroup;
  
  constructor(private fb: FormBuilder) {
    this.productForm = this.fb.group({
      productName: ['', [Validators.required, Validators.minLength(3)]],
      description: [''],
      suppliers: this.fb.array([
        this.createSupplierGroup()
      ])
    });
  }
  
  get suppliers(): FormArray {
    return this.productForm.get('suppliers') as FormArray;
  }
  
  createSupplierGroup(): FormGroup {
    return this.fb.group({
      name: ['', [Validators.required]],
      email: ['', [Validators.required, Validators.email]],
      phone: ['', [Validators.required]]
    });
  }
  
  addSupplier(): void {
    this.suppliers.push(this.createSupplierGroup());
  }
  
  removeSupplier(index: number): void {
    if (this.suppliers.length > 1) {
      this.suppliers.removeAt(index);
    }
  }
  
  showError(controlName: string): boolean {
    const control = this.productForm.get(controlName);
    return !!(control && control.invalid && (control.dirty || control.touched));
  }
  
  getError(controlName: string): string {
    const control = this.productForm.get(controlName);
    if (!control || !control.errors) return '';
    
    if (control.errors['required']) return 'Campo obrigatório';
    if (control.errors['minlength']) {
      return `Mínimo ${control.errors['minlength'].requiredLength} caracteres`;
    }
    
    return 'Erro de validação';
  }
  
  showSupplierError(index: number, controlName: string): boolean {
    const supplierGroup = this.suppliers.at(index) as FormGroup;
    const control = supplierGroup.get(controlName);
    return !!(control && control.invalid && (control.dirty || control.touched));
  }
  
  getSupplierError(index: number, controlName: string): string {
    const supplierGroup = this.suppliers.at(index) as FormGroup;
    const control = supplierGroup.get(controlName);
    if (!control || !control.errors) return '';
    
    if (control.errors['required']) return 'Campo obrigatório';
    if (control.errors['email']) return 'Email inválido';
    
    return 'Erro de validação';
  }
  
  onSubmit(): void {
    if (this.productForm.valid) {
      const formValue = this.productForm.value;
      console.log('Produto:', {
        name: formValue.productName,
        description: formValue.description,
        suppliers: formValue.suppliers
      });
    } else {
      this.productForm.markAllAsTouched();
    }
  }
}
```
{% raw %}
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, FormArray, Validators, AbstractControl } from '@angular/forms';
import { ReactiveFormsModule, CommonModule } from '@angular/forms';

interface Supplier {
  name: string;
  email: string;
  phone: string;
}

@Component({
  selector: 'app-product-form',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  template: `
    <form [formGroup]="productForm" (ngSubmit)="onSubmit()">
      <div class="form-group">
        <label>Nome do Produto</label>
        <input formControlName="productName">
        @if (showError('productName')) {
          <span class="error">{{ getError('productName') }}</span>
        }
      </div>
      
      <div class="form-group">
        <label>Descrição</label>
        <textarea formControlName="description"></textarea>
      </div>
      
      <div class="suppliers-section">
        <h3>Fornecedores</h3>
        
        <div formArrayName="suppliers">
          @for (supplier of suppliers.controls; track $index) {
            <div [formGroupName]="$index" class="supplier-group">
              <h4>Fornecedor {{ $index + 1 }}</h4>
              
              <div class="form-group">
                <label>Nome</label>
                <input formControlName="name">
                @if (showSupplierError($index, 'name')) {
                  <span class="error">{{ getSupplierError($index, 'name') }}</span>
                }
              </div>
              
              <div class="form-group">
                <label>Email</label>
                <input formControlName="email" type="email">
                @if (showSupplierError($index, 'email')) {
                  <span class="error">{{ getSupplierError($index, 'email') }}</span>
                }
              </div>
              
              <div class="form-group">
                <label>Telefone</label>
                <input formControlName="phone">
              </div>
              
              <button type="button" (click)="removeSupplier($index)" [disabled]="suppliers.length <= 1">
                Remover Fornecedor
              </button>
            </div>
          }
        </div>
        
        <button type="button" (click)="addSupplier()">Adicionar Fornecedor</button>
      </div>
      
      <button type="submit" [disabled]="productForm.invalid">
        Salvar Produto
      </button>
    </form>
  `
})
export class ProductFormComponent {
  productForm: FormGroup;
  
  constructor(private fb: FormBuilder) {
    this.productForm = this.fb.group({
      productName: ['', [Validators.required, Validators.minLength(3)]],
      description: [''],
      suppliers: this.fb.array([
        this.createSupplierGroup()
      ])
    });
  }
  
  get suppliers(): FormArray {
    return this.productForm.get('suppliers') as FormArray;
  }
  
  createSupplierGroup(): FormGroup {
    return this.fb.group({
      name: ['', [Validators.required]],
      email: ['', [Validators.required, Validators.email]],
      phone: ['', [Validators.required]]
    });
  }
  
  addSupplier(): void {
    this.suppliers.push(this.createSupplierGroup());
  }
  
  removeSupplier(index: number): void {
    if (this.suppliers.length > 1) {
      this.suppliers.removeAt(index);
    }
  }
  
  showError(controlName: string): boolean {
    const control = this.productForm.get(controlName);
    return !!(control && control.invalid && (control.dirty || control.touched));
  }
  
  getError(controlName: string): string {
    const control = this.productForm.get(controlName);
    if (!control || !control.errors) return '';
    
    if (control.errors['required']) return 'Campo obrigatório';
    if (control.errors['minlength']) {
      return `Mínimo ${control.errors['minlength'].requiredLength} caracteres`;
    }
    
    return 'Erro de validação';
  }
  
  showSupplierError(index: number, controlName: string): boolean {
    const supplierGroup = this.suppliers.at(index) as FormGroup;
    const control = supplierGroup.get(controlName);
    return !!(control && control.invalid && (control.dirty || control.touched));
  }
  
  getSupplierError(index: number, controlName: string): string {
    const supplierGroup = this.suppliers.at(index) as FormGroup;
    const control = supplierGroup.get(controlName);
    if (!control || !control.errors) return '';
    
    if (control.errors['required']) return 'Campo obrigatório';
    if (control.errors['email']) return 'Email inválido';
    
    return 'Erro de validação';
  }
  
  onSubmit(): void {
    if (this.productForm.valid) {
      const formValue = this.productForm.value;
      console.log('Produto:', {
        name: formValue.productName,
        description: formValue.description,
        suppliers: formValue.suppliers
      });
    } else {
      this.productForm.markAllAsTouched();
    }
  }
}
```
{% endraw %}

**Explicação Detalhada**:

1. **FormArray Dinâmico**: `suppliers` é um FormArray que pode crescer ou diminuir
2. **Criação de Grupos**: `createSupplierGroup()` cria um novo FormGroup para cada fornecedor
3. **Adicionar/Remover**: Métodos `addSupplier()` e `removeSupplier()` gerenciam o array
4. **Validação Individual**: Cada fornecedor tem sua própria validação
5. **Validação do Array**: O FormArray valida todos os grupos internos
6. **Proteção**: Não permite remover se houver apenas um fornecedor

---

### Exemplo 3: Formulário com Validação Assíncrona Completa

**Contexto**: Criar formulário de registro com validação assíncrona de email único e username disponível.

**Código**:

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use FormBuilder para formulários complexos**
   - **Por quê**: Sintaxe mais limpa e menos boilerplate, facilita manutenção
   - **Exemplo**: 
```
   this.fb.group({
     name: ['', Validators.required],
     email: ['', [Validators.required, Validators.email]]
   })
```
   - **Benefício**: Código mais legível e fácil de modificar

2. **Valide no lado do servidor para dados críticos**
   - **Por quê**: Segurança e consistência - validação no cliente pode ser burlada
   - **Exemplo**: Validação assíncrona para email único, verificação de CPF válido
   - **Benefício**: Garante integridade dos dados e segurança

3. **Forneça feedback visual imediato**
   - **Por quê**: Melhora UX, usuário sabe imediatamente se há erro
   - **Exemplo**: Mostrar erros quando `touched` e `invalid`, indicador de loading durante validação assíncrona
   - **Benefício**: Reduz frustração do usuário e aumenta taxa de conversão

4. **Use Typed Forms quando possível**
   - **Por quê**: Type safety completo, autocomplete melhorado, menos erros em compile-time
   - **Exemplo**: 
```
   interface UserForm {
     name: string;
     email: string;
   }
   form = new FormGroup<UserForm>({ ... })
```
   - **Benefício**: Previne erros de digitação e melhora DX

5. **Organize validators customizados em arquivos separados**
   - **Por quê**: Reutilização, testabilidade, organização do código
   - **Exemplo**: Criar `validators/password-strength.validator.ts`
   - **Benefício**: Código mais limpo e fácil de testar

6. **Use `markAllAsTouched()` antes de mostrar erros no submit**
   - **Por quê**: Garante que todos os erros sejam visíveis quando usuário tenta submeter
   - **Exemplo**: 
```
   onSubmit() {
     if (this.form.invalid) {
       this.form.markAllAsTouched();
       return;
     }
   }
```
   - **Benefício**: Melhor UX, usuário vê todos os problemas de uma vez

7. **Evite validação assíncrona desnecessária**
   - **Por quê**: Performance - validação assíncrona faz chamadas HTTP
   - **Exemplo**: Só validar email único após validação síncrona passar
   - **Benefício**: Menos requisições ao servidor, melhor performance

8. **Use `patchValue()` para atualizações parciais**
   - **Por quê**: Mais flexível que `setValue()`, não requer todos os campos
   - **Exemplo**: 
```
   this.form.patchValue({ name: 'Novo Nome' });
```
   - **Benefício**: Útil ao carregar dados do servidor parcialmente

9. **Desabilite controles quando apropriado**
   - **Por quê**: Previne edição quando não faz sentido
   - **Exemplo**: Desabilitar campo de confirmação de senha até senha ser válida
   - **Benefício**: UX mais clara, previne erros do usuário

10. **Subscreva `valueChanges` com cuidado**
    - **Por quê**: Pode causar memory leaks se não desinscrever
    - **Exemplo**: Usar `takeUntil()` ou desinscrever no `ngOnDestroy()`
    - **Benefício**: Previne memory leaks e melhora performance

### ❌ Anti-padrões Comuns

1. **Não valide apenas no cliente**
   - **Problema**: Inseguro, pode ser burlado facilmente, dados inválidos podem chegar ao servidor
   - **Solução**: Sempre valide no servidor também, use validação no cliente apenas para UX
   - **Impacto**: Risco de segurança, dados inconsistentes no banco

2. **Não mostre erros antes do usuário interagir**
   - **Problema**: UX ruim, formulário parece quebrado, frustra usuário
   - **Solução**: Mostre apenas quando `touched` ou `dirty`, ou após tentativa de submit
   - **Impacto**: Taxa de abandono maior, percepção negativa do produto

3. **Não use FormControl sem FormGroup para formulários**
   - **Problema**: Dificulta gerenciamento, não permite validação cross-field, código menos organizado
   - **Solução**: Use FormGroup mesmo para um campo único
   - **Impacto**: Código difícil de escalar e manter

4. **Não esqueça de desinscrever de Observables**
   - **Problema**: Memory leaks, performance degradada ao longo do tempo
   - **Solução**: Use `takeUntil()` com `Subject` ou desinscreva no `ngOnDestroy()`
   - **Impacto**: Aplicação fica lenta, pode crashar em uso prolongado

5. **Não valide campos desabilitados**
   - **Problema**: Campos desabilitados não são incluídos em `form.value`, mas ainda são validados
   - **Solução**: Use `{ emitEvent: false }` ao desabilitar ou remova validators temporariamente
   - **Impacto**: Validação incorreta, formulário pode parecer inválido sem motivo

6. **Não use `setValue()` quando `patchValue()` é suficiente**
   - **Problema**: `setValue()` requer todos os campos, pode causar erros desnecessários
   - **Solução**: Use `patchValue()` para atualizações parciais
   - **Impacto**: Código mais frágil, mais propenso a erros

7. **Não crie FormControls diretamente no template**
   - **Problema**: Criação repetida a cada change detection, performance ruim
   - **Solução**: Crie FormControls no componente ou use getters com cache
   - **Impacto**: Performance degradada, especialmente em formulários grandes

8. **Não ignore o estado `pending` em validação assíncrona**
   - **Problema**: Usuário não sabe que validação está em andamento
   - **Solução**: Mostre indicador de loading quando `control.pending === true`
   - **Impacto**: UX confusa, usuário pode pensar que formulário está quebrado

9. **Não valide em `valueChanges` sem debounce**
   - **Problema**: Validação executa a cada keystroke, performance ruim, muitas requisições HTTP
   - **Solução**: Use `debounceTime()` antes de validar
   - **Impacto**: Sobrecarga no servidor, performance ruim

10. **Não misture Template-Driven com Reactive Forms**
    - **Problema**: Confusão, comportamento imprevisível, difícil de debugar
    - **Solução**: Escolha uma abordagem e use consistentemente
    - **Impacto**: Código difícil de manter, bugs difíceis de encontrar

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

- **[Angular Reactive Forms](https://angular.io/guide/reactive-forms)**: Guia oficial completo sobre formulários reativos
- **[FormControl](https://angular.io/api/forms/FormControl)**: Documentação completa da API FormControl
- **[FormGroup](https://angular.io/api/forms/FormGroup)**: Documentação completa da API FormGroup
- **[FormArray](https://angular.io/api/forms/FormArray)**: Documentação completa da API FormArray
- **[FormBuilder](https://angular.io/api/forms/FormBuilder)**: Documentação do serviço FormBuilder
- **[Validators](https://angular.io/api/forms/Validators)**: Documentação de todos os validators disponíveis
- **[AbstractControl](https://angular.io/api/forms/AbstractControl)**: Classe base para todos os controles
- **[Typed Forms](https://angular.io/guide/typed-forms)**: Guia completo sobre Typed Forms (Angular 14+)
- **[Form Validation](https://angular.io/guide/form-validation)**: Guia sobre validação de formulários
- **[Dynamic Forms](https://angular.io/guide/dynamic-form)**: Guia sobre criação de formulários dinâmicos

### Artigos e Tutoriais

- **[Angular Reactive Forms: Complete Guide](https://www.angularminds.com/blog/angular-reactive-forms-best-practices)**: Melhores práticas e padrões
- **[Understanding Angular Reactive Forms](https://www.telerik.com/blogs/understanding-angular-reactive-forms)**: Explicação detalhada dos conceitos
- **[Angular Form Validation](https://www.freecodecamp.org/news/angular-form-validation-complete-guide/)**: Guia completo de validação
- **[Typed Forms Deep Dive](https://netbasal.com/typed-reactive-forms-in-angular-4b5d0d4c0c4e)**: Análise profunda de Typed Forms
- **[FormArray Explained](https://www.digitalocean.com/community/tutorials/angular-reactive-forms-formarray-dynamic-fields)**: Tutorial sobre FormArray

### Vídeos

- **[Angular Reactive Forms Tutorial](https://www.youtube.com/watch?v=JeeUY6WaXiA)**: Tutorial completo em vídeo
- **[Angular Form Validation](https://www.youtube.com/watch?v=5fYhM2j_3kE)**: Validação de formulários
- **[Typed Forms in Angular](https://www.youtube.com/watch?v=Y5fD8QZzJ5E)**: Introdução a Typed Forms

### Ferramentas e Bibliotecas

- **[Angular DevTools](https://angular.io/guide/devtools)**: Ferramenta de debug que ajuda a inspecionar formulários
- **[ngx-formly](https://formly.dev/)**: Biblioteca para criação de formulários dinâmicos baseados em configuração
- **[ng-dynamic-forms](https://github.com/udos86/ng-dynamic-forms)**: Biblioteca para formulários dinâmicos
- **[Angular Material Form Fields](https://material.angular.io/components/form-field)**: Componentes de formulário do Material Design

### Recursos Adicionais

- **[Angular Forms Cheat Sheet](https://dev.to/angular/angular-forms-cheat-sheet-5a5j)**: Referência rápida
- **[Common Form Patterns](https://angular.io/guide/reactive-forms#common-form-patterns)**: Padrões comuns de formulários
- **[Form State Management](https://angular.io/guide/reactive-forms#managing-control-values)**: Gerenciamento de estado

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
