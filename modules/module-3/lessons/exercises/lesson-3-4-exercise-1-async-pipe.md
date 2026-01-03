---
layout: exercise
title: "Exercício 3.4.1: async pipe"
slug: "async-pipe"
lesson_id: "lesson-3-4"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **async pipe** através da **criação de componente que usa async pipe para prevenir memory leaks**.

Ao completar este exercício, você será capaz de:

- Usar async pipe no template
- Entender gerenciamento automático de subscriptions
- Prevenir memory leaks com async pipe
- Trabalhar com Observables no template
- Usar async pipe com diferentes tipos de dados

---

## Descrição

Você precisa criar um componente que exibe dados de Observable usando async pipe.

### Contexto

Uma aplicação precisa exibir dados de API sem gerenciar subscriptions manualmente.

### Tarefa

Crie:

1. **Service**: Serviço que retorna Observable
2. **Component**: Componente que usa async pipe
3. **Template**: Template que exibe dados com async pipe
4. **Verificação**: Verificar que não há memory leaks

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Service retorna Observable
- [ ] Component usa async pipe no template
- [ ] Dados são exibidos corretamente
- [ ] Não há subscriptions manuais
- [ ] Memory leak prevenido automaticamente
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] async pipe está usado corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**user.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, delay } from 'rxjs';
import { User } from './user.model';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  constructor(private http: HttpClient) {}
  
  getUsers(): Observable<User[]> {
    return this.http.get<User[]>('/api/users').pipe(
      delay(1000)
    );
  }
}
```

**user-list.component.ts**
{% raw %}
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Observable } from 'rxjs';
import { UserService } from './user.service';
import { User } from './user.model';

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
{% raw %}
  template: `
    <div>
      <h2>Usuários (async pipe)</h2>
      
      @if (users$ | async; as users) {
        <ul>
          @for (user of users; track user.id) {
            <li>{{ user.name }} - {{ user.email }}</li>
          }
        </ul>
      } @else {
        <p>Carregando...</p>
      }
      
      <p>Total: {{ (users$ | async)?.length || 0 }}</p>
    </div>
  `
{% endraw %}
})
export class UserListComponent {
  users$: Observable<User[]>;
  
  constructor(private userService: UserService) {
    this.users$ = this.userService.getUsers();
  }
}
```
{% endraw %}

**Explicação da Solução**:

1. Service retorna Observable
2. Component armazena Observable em propriedade
3. Template usa async pipe para subscrever
4. async pipe gerencia subscription automaticamente
5. Não há necessidade de ngOnDestroy
6. Memory leak prevenido automaticamente

---

## Testes

### Casos de Teste

**Teste 1**: Dados são exibidos
- **Input**: Carregar componente
- **Output Esperado**: Lista de usuários exibida

**Teste 2**: Loading state funciona
- **Input**: Durante carregamento
- **Output Esperado**: "Carregando..." aparece

**Teste 3**: Memory leak prevenido
- **Input**: Destruir e recriar componente
- **Output Esperado**: Sem memory leaks

---

## Extensões (Opcional)

1. **Error Handling**: Adicione tratamento de erros com async pipe
2. **Multiple Observables**: Use múltiplos async pipes
3. **Combining**: Combine múltiplos Observables

---

## Referências Úteis

- **[async pipe](https://angular.io/api/common/AsyncPipe)**: Documentação async pipe
- **[Observables Guide](https://angular.io/guide/observables)**: Guia Observables

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

