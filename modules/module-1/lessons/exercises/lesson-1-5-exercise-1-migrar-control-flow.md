---
layout: exercise
title: "Exercício 1.5.1: Migrar para Control Flow"
slug: "migrar-control-flow"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **migração para Control Flow** através da **conversão de componente que usa diretivas estruturais antigas para Control Flow moderno**.

Ao completar este exercício, você será capaz de:

- Migrar *ngIf para @if
- Migrar *ngFor para @for
- Migrar *ngSwitch para @switch
- Entender diferenças entre sintaxes
- Aplicar melhorias de performance

---

## Descrição

Você precisa pegar um componente existente que usa diretivas estruturais (*ngIf, *ngFor, *ngSwitch) e migrar completamente para Control Flow moderno (@if, @for, @switch).

### Contexto

Um projeto Angular antigo precisa ser atualizado para usar Control Flow moderno. A migração melhora performance e torna o código mais legível.

### Tarefa

Migre o componente fornecido:

1. **Substituir *ngIf**: Converter todos os `*ngIf` para `@if`
2. **Substituir *ngFor**: Converter todos os `*ngFor` para `@for` com track
3. **Substituir *ngSwitch**: Converter `*ngSwitch` para `@switch`
4. **Adicionar @empty**: Usar `@empty` quando apropriado
5. **Testar**: Garantir que funcionalidade permanece igual

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Todos os *ngIf migrados para @if
- [ ] Todos os *ngFor migrados para @for com track
- [ ] Todos os *ngSwitch migrados para @switch
- [ ] @empty usado quando lista vazia
- [ ] Funcionalidade permanece idêntica
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Sintaxe Control Flow está correta
- [ ] Track functions são eficientes
- [ ] Código é mais legível após migração

---

## Dicas

### Dica 1: Migração *ngIf

```html
Antes: <div *ngIf="condition">Conteúdo</div>
Depois: @if (condition) { <div>Conteúdo</div> }
```

### Dica 2: Migração *ngFor

```html
Antes: <div *ngFor="let item of items; trackBy: trackFn">
Depois: @for (item of items; track item.id) { <div>...</div> }
```

### Dica 3: Migração *ngSwitch

```html
Antes: 
<div [ngSwitch]="value">
  <p *ngSwitchCase="'a'">A</p>
  <p *ngSwitchDefault>Default</p>
</div>

Depois:
@switch (value) {
  @case ('a') { <p>A</p> }
  @default { <p>Default</p> }
}
```

### Dica 4: @empty Block

```html
@for (item of items; track item.id) {
  <div>{{ item }}</div>
} @empty {
  <p>Lista vazia</p>
}
```

---

## Solução Esperada

### Componente Antigo (Antes)

{% raw %}
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

interface User {
  id: number;
  name: string;
  role: 'admin' | 'user' | 'guest';
  active: boolean;
}

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="user-list">
      <h2>Lista de Usuários</h2>
      
      <div *ngIf="users.length === 0" class="empty">
        Nenhum usuário encontrado
      </div>
      
      <ul *ngIf="users.length > 0">
        <li *ngFor="let user of users; trackBy: trackById" 
            [class.active]="user.active">
          <span>{{ user.name }}</span>
          <span [ngSwitch]="user.role">
            <span *ngSwitchCase="'admin'" class="badge admin">Admin</span>
            <span *ngSwitchCase="'user'" class="badge user">Usuário</span>
            <span *ngSwitchDefault class="badge guest">Convidado</span>
          </span>
          <span *ngIf="user.active" class="status">Ativo</span>
          <span *ngIf="!user.active" class="status inactive">Inativo</span>
        </li>
      </ul>
    </div>
  `
{% endraw %}
})
export class UserListComponent {
  users: User[] = [
    { id: 1, name: 'João', role: 'admin', active: true },
    { id: 2, name: 'Maria', role: 'user', active: true },
    { id: 3, name: 'Pedro', role: 'guest', active: false }
  ];
  
  trackById(index: number, user: User): number {
    return user.id;
  }
}
```

### Componente Migrado (Depois)

{% raw %}
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

interface User {
  id: number;
  name: string;
  role: 'admin' | 'user' | 'guest';
  active: boolean;
}

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="user-list">
      <h2>Lista de Usuários</h2>
      
      @if (users.length === 0) {
        <div class="empty">
          Nenhum usuário encontrado
        </div>
      } @else {
        <ul>
          @for (user of users; track user.id) {
            <li [class.active]="user.active">
              <span>{{ user.name }}</span>
              
              @switch (user.role) {
                @case ('admin') {
                  <span class="badge admin">Admin</span>
                }
                @case ('user') {
                  <span class="badge user">Usuário</span>
                }
                @default {
                  <span class="badge guest">Convidado</span>
                }
              }
              
              @if (user.active) {
                <span class="status">Ativo</span>
              } @else {
                <span class="status inactive">Inativo</span>
              }
            </li>
          }
        </ul>
      }
    </div>
  `
{% endraw %}
})
export class UserListComponent {
  users: User[] = [
    { id: 1, name: 'João', role: 'admin', active: true },
    { id: 2, name: 'Maria', role: 'user', active: true },
    { id: 3, name: 'Pedro', role: 'guest', active: false }
  };
}
```

**Explicação da Solução**:

1. `*ngIf` migrado para `@if` com `@else`
2. `*ngFor` migrado para `@for` com `track user.id` (não precisa mais de função)
3. `*ngSwitch` migrado para `@switch` com `@case` e `@default`
4. `@empty` pode ser usado, mas neste caso `@if/@else` é mais apropriado
5. Funcionalidade permanece idêntica
6. Código mais limpo e performático

**Decisões de Design**:

- Track integrado no @for (não precisa de função separada)
- Sintaxe mais limpa e legível
- Melhor performance nativa
- Estrutura mais clara com blocos explícitos

---

## Testes

### Casos de Teste

**Teste 1**: Lista vazia funciona
- **Input**: `users = []`
- **Output Esperado**: Mensagem "Nenhum usuário encontrado" deve aparecer

**Teste 2**: Lista com usuários funciona
- **Input**: Array com usuários
- **Output Esperado**: Todos os usuários devem aparecer

**Teste 3**: Roles são exibidos corretamente
- **Input**: Usuários com diferentes roles
- **Output Esperado**: Badges corretos devem aparecer

**Teste 4**: Status ativo/inativo funciona
- **Input**: Usuários com diferentes status
- **Output Esperado**: Status correto deve aparecer

---

## Extensões (Opcional)

1. **Usar @empty**: Refatore para usar `@empty` block ao invés de `@if/@else`
2. **Adicionar Filtros**: Adicione filtros usando Control Flow
3. **Animações**: Adicione animações de entrada/saída
4. **Performance**: Compare performance antes/depois da migração

---

## Referências Úteis

- **[Control Flow Migration](https://angular.io/guide/control-flow)**: Guia de migração
- **[Control Flow Syntax](https://angular.io/guide/control-flow#control-flow-syntax)**: Sintaxe completa

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

