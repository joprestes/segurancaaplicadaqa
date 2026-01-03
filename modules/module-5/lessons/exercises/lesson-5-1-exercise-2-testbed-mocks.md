---
layout: exercise
title: "Exercício 5.1.2: TestBed e Mocks"
slug: "testbed-mocks"
lesson_id: "lesson-5-1"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **TestBed e Mocks** através da **criação de testes usando TestBed e mocks de dependências**.

Ao completar este exercício, você será capaz de:

- Configurar TestBed corretamente
- Criar mocks de serviços
- Usar spies para verificar chamadas
- Isolar unidades sob teste
- Testar componentes com dependências

---

## Descrição

Você precisa criar testes para componente que depende de serviço, usando mocks.

### Contexto

Uma aplicação precisa testar componentes que têm dependências externas.

### Tarefa

Crie:

1. **Serviço**: Criar serviço que será mockado
2. **Componente**: Criar componente que usa serviço
3. **Mocks**: Criar mocks do serviço
4. **Testes**: Escrever testes usando mocks

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Serviço criado
- [ ] Componente criado
- [ ] Mocks implementados
- [ ] Testes escritos
- [ ] Testes executam com sucesso

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Mocks estão bem implementados
- [ ] Testes são isolados

---

## Solução Esperada

### Abordagem Recomendada

**user.service.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface User {
  id: number;
  name: string;
  email: string;
}

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private http = inject(HttpClient);
  
  getUsers(): Observable<User[]> {
    return this.http.get<User[]>('/api/users');
  }
  
  getUserById(id: number): Observable<User> {
    return this.http.get<User>(`/api/users/${id}`);
  }
  
  createUser(user: Omit<User, 'id'>): Observable<User> {
    return this.http.post<User>('/api/users', user);
  }
}
```

**user-list.component.ts**
```typescript
import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { UserService, User } from './user.service';

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Usuários</h2>
      <button (click)="loadUsers()">Carregar</button>
      <ul>
        @for (user of users(); track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
    </div>
  `
})
export class UserListComponent implements OnInit {
  users = signal<User[]>([]);
  
  constructor(private userService: UserService) {}
  
  ngOnInit(): void {
    this.loadUsers();
  }
  
  loadUsers(): void {
    this.userService.getUsers().subscribe(users => {
      this.users.set(users);
    });
  }
}
```

**user-list.component.spec.ts**
```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { UserListComponent } from './user-list.component';
import { UserService, User } from './user.service';

describe('UserListComponent', () => {
  let component: UserListComponent;
  let fixture: ComponentFixture<UserListComponent>;
  let userService: jest.Mocked<UserService>;

  const mockUsers: User[] = [
    { id: 1, name: 'User 1', email: 'user1@example.com' },
    { id: 2, name: 'User 2', email: 'user2@example.com' }
  ];

  beforeEach(async () => {
    userService = {
      getUsers: jest.fn()
    } as any;

    await TestBed.configureTestingModule({
      imports: [UserListComponent],
      providers: [
        { provide: UserService, useValue: userService }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(UserListComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should load users on init', () => {
    userService.getUsers.mockReturnValue(of(mockUsers));
    
    fixture.detectChanges();
    
    expect(userService.getUsers).toHaveBeenCalled();
    expect(component.users()).toEqual(mockUsers);
  });

  it('should load users on button click', () => {
    userService.getUsers.mockReturnValue(of(mockUsers));
    
    const button = fixture.debugElement.query(
      (el) => el.nativeElement.textContent === 'Carregar'
    );
    button.nativeElement.click();
    
    expect(userService.getUsers).toHaveBeenCalledTimes(1);
    expect(component.users()).toEqual(mockUsers);
  });

  it('should display users in list', () => {
    component.users.set(mockUsers);
    fixture.detectChanges();
    
    const listItems = fixture.debugElement.queryAll('li');
    expect(listItems.length).toBe(2);
    expect(listItems[0].nativeElement.textContent).toContain('User 1');
  });
});
```

**Explicação da Solução**:

1. UserService mockado usando jest.Mocked
2. Mock retorna Observable com dados de teste
3. TestBed configura componente com mock
4. Testes verificam interações com serviço
5. Testes verificam renderização
6. Unidade isolada completamente

---

## Testes

### Casos de Teste

**Teste 1**: Componente criado
- **Input**: Criar componente
- **Output Esperado**: Componente criado com mock

**Teste 2**: Serviço chamado
- **Input**: Carregar usuários
- **Output Esperado**: getUsers() chamado

**Teste 3**: Dados exibidos
- **Input**: Usuários carregados
- **Output Esperado**: Lista exibida corretamente

---

## Extensões (Opcional)

1. **Error Handling**: Teste tratamento de erros
2. **Loading States**: Teste estados de loading
3. **Multiple Mocks**: Use múltiplos mocks

---

## Referências Úteis

- **[TestBed](https://angular.io/api/core/testing/TestBed)**: Documentação TestBed
- **[Mocking](https://angular.io/guide/testing#testing-services)**: Guia mocking

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

