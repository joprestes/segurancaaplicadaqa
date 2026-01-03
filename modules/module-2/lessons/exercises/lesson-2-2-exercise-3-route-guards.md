---
layout: exercise
title: "Exercício 2.2.3: Route Guards"
slug: "route-guards"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Route Guards** através da **implementação de proteção de rotas baseada em autenticação e permissões**.

Ao completar este exercício, você será capaz de:

- Criar guards funcionais (CanActivateFn)
- Proteger rotas com guards
- Implementar verificação de autenticação
- Implementar verificação de permissões
- Criar guard de desativação (CanDeactivate)

---

## Descrição

Você precisa criar um sistema de autenticação com guards que protegem rotas administrativas e controlam acesso baseado em roles.

### Contexto

Uma aplicação precisa proteger áreas administrativas e garantir que usuários não percam dados ao sair de formulários não salvos.

### Tarefa

Crie:

1. **AuthService**: Serviço simples de autenticação
2. **AuthGuard**: Guard que verifica autenticação
3. **AdminGuard**: Guard que verifica role admin
4. **UnsavedChangesGuard**: Guard que previne saída com dados não salvos
5. **Rotas Protegidas**: Aplique guards nas rotas

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] AuthService criado com métodos de autenticação
- [ ] AuthGuard implementado
- [ ] AdminGuard implementado
- [ ] UnsavedChangesGuard implementado
- [ ] Rotas protegidas configuradas
- [ ] Redirecionamento funciona quando acesso negado
- [ ] Guard de desativação funciona

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Guards são funcionais (CanActivateFn)
- [ ] Tratamento de erros implementado
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**auth.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface User {
  id: number;
  email: string;
  role: 'user' | 'admin';
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private currentUser$ = new BehaviorSubject<User | null>(null);
  
  login(email: string, password: string, role: 'user' | 'admin' = 'user'): boolean {
    const user: User = {
      id: 1,
      email,
      role
    };
    this.currentUser$.next(user);
    localStorage.setItem('user', JSON.stringify(user));
    return true;
  }
  
  logout(): void {
    this.currentUser$.next(null);
    localStorage.removeItem('user');
  }
  
  isAuthenticated(): boolean {
    return this.currentUser$.value !== null;
  }
  
  hasRole(role: 'user' | 'admin'): boolean {
    return this.currentUser$.value?.role === role;
  }
  
  getCurrentUser(): User | null {
    return this.currentUser$.value;
  }
  
  loadUser(): void {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      this.currentUser$.next(JSON.parse(userStr));
    }
  }
}
```

**auth.guard.ts**
```typescript
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  if (authService.isAuthenticated()) {
    return true;
  }
  
  router.navigate(['/login'], {
    queryParams: { returnUrl: state.url }
  });
  return false;
};
```

**admin.guard.ts**
```typescript
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const adminGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  if (!authService.isAuthenticated()) {
    router.navigate(['/login'], {
      queryParams: { returnUrl: state.url }
    });
    return false;
  }
  
  if (!authService.hasRole('admin')) {
    router.navigate(['/unauthorized']);
    return false;
  }
  
  return true;
};
```

**unsaved-changes.guard.ts**
```typescript
import { inject } from '@angular/core';
import { CanDeactivateFn } from '@angular/router';

export interface CanComponentDeactivate {
  canDeactivate: () => boolean | Promise<boolean>;
}

export const unsavedChangesGuard: CanDeactivateFn<CanComponentDeactivate> = (component) => {
  if (component.canDeactivate) {
    return component.canDeactivate();
  }
  return true;
};
```

**app.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { LoginComponent } from './auth/login.component';
import { DashboardComponent } from './dashboard/dashboard.component';
import { AdminComponent } from './admin/admin.component';
import { ProfileComponent } from './profile/profile.component';
import { authGuard } from './guards/auth.guard';
import { adminGuard } from './guards/admin.guard';
import { unsavedChangesGuard } from './guards/unsaved-changes.guard';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  {
    path: 'dashboard',
    component: DashboardComponent,
    canActivate: [authGuard]
  },
  {
    path: 'admin',
    component: AdminComponent,
    canActivate: [adminGuard]
  },
  {
    path: 'profile',
    component: ProfileComponent,
    canActivate: [authGuard],
    canDeactivate: [unsavedChangesGuard]
  }
];
```

**profile.component.ts**
```typescript
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CanComponentDeactivate } from '../guards/unsaved-changes.guard';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div>
      <h1>Perfil</h1>
      <form>
        <input [(ngModel)]="name" name="name" placeholder="Nome">
        <input [(ngModel)]="email" name="email" placeholder="Email">
        <button type="submit" (click)="save()">Salvar</button>
      </form>
    </div>
  `
})
export class ProfileComponent implements CanComponentDeactivate {
  name: string = '';
  email: string = '';
  private saved: boolean = false;
  
  save(): void {
    this.saved = true;
  }
  
  canDeactivate(): boolean {
    if (this.saved) {
      return true;
    }
    return confirm('Você tem alterações não salvas. Deseja sair?');
  }
}
```

**login.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div>
      <h1>Login</h1>
      <form (ngSubmit)="login()">
        <input [(ngModel)]="email" name="email" placeholder="Email">
        <select [(ngModel)]="role" name="role">
          <option value="user">Usuário</option>
          <option value="admin">Admin</option>
        </select>
        <button type="submit">Login</button>
      </form>
    </div>
  `
})
export class LoginComponent implements OnInit {
  email: string = '';
  role: 'user' | 'admin' = 'user';
  returnUrl: string = '/';
  
  constructor(
    private authService: AuthService,
    private router: Router,
    private route: ActivatedRoute
  ) {}
  
  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      this.returnUrl = params['returnUrl'] || '/';
    });
  }
  
  login(): void {
    if (this.authService.login(this.email, 'password', this.role)) {
      this.router.navigate([this.returnUrl]);
    }
  }
}
```

**Explicação da Solução**:

1. AuthService gerencia estado de autenticação
2. authGuard verifica se usuário está autenticado
3. adminGuard verifica role admin
4. unsavedChangesGuard previne perda de dados
5. Guards são funcionais (CanActivateFn)
6. Redirecionamento com returnUrl preserva destino original

---

## Testes

### Casos de Teste

**Teste 1**: AuthGuard bloqueia acesso não autenticado
- **Input**: Tentar acessar /dashboard sem login
- **Output Esperado**: Redireciona para /login

**Teste 2**: AdminGuard bloqueia acesso não-admin
- **Input**: Login como user e tentar acessar /admin
- **Output Esperado**: Redireciona para /unauthorized

**Teste 3**: UnsavedChangesGuard previne saída
- **Input**: Modificar perfil e tentar sair sem salvar
- **Output Esperado**: Confirmação aparece

---

## Extensões (Opcional)

1. **CanLoad Guard**: Implemente guard para lazy loading
2. **Multi-Guards**: Combine múltiplos guards
3. **Async Guards**: Implemente guards assíncronos

---

## Referências Úteis

- **[Route Guards](https://angular.io/guide/router#guards)**: Guia oficial
- **[CanActivate](https://angular.io/api/router/CanActivateFn)**: Documentação CanActivateFn

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

