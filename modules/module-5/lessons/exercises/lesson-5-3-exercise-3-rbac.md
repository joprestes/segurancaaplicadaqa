---
layout: exercise
title: "Exercício 5.3.3: Role-Based Access Control"
slug: "rbac"
lesson_id: "lesson-5-3"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **RBAC** através da **implementação de sistema completo de RBAC com guards e diretivas**.

Ao completar este exercício, você será capaz de:

- Implementar sistema RBAC
- Criar guards baseados em roles
- Criar diretivas para UI
- Gerenciar permissões
- Controlar acesso a recursos
- Verificar roles e permissões

---

## Descrição

Você precisa implementar sistema completo de RBAC para uma aplicação.

### Contexto

Uma aplicação precisa controlar acesso baseado em roles de usuários.

### Tarefa

Crie:

1. **RoleService**: Criar serviço de roles
2. **RoleGuard**: Criar guard baseado em roles
3. **Directive**: Criar diretiva para UI
4. **Verificação**: Verificar acesso
5. **Testes**: Testar RBAC

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] RoleService criado
- [ ] RoleGuard implementado
- [ ] Diretiva criada
- [ ] RBAC funciona corretamente
- [ ] UI controlada por roles

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] RBAC está implementado corretamente
- [ ] Segurança está adequada

---

## Solução Esperada

### Abordagem Recomendada

**role.service.ts**
```typescript
import { Injectable, inject, signal } from '@angular/core';
import { AuthService } from './auth.service';

export type Role = 'admin' | 'manager' | 'user' | 'guest';
export type Permission = 'read' | 'write' | 'delete' | 'manage';

@Injectable({
  providedIn: 'root'
})
export class RoleService {
  private authService = inject(AuthService);
  
  private rolePermissions: Record<Role, Permission[]> = {
    admin: ['read', 'write', 'delete', 'manage'],
    manager: ['read', 'write', 'delete'],
    user: ['read', 'write'],
    guest: ['read']
  };
  
  getCurrentRole(): Role {
    const user = this.authService.currentUser();
    if (!user) {
      return 'guest';
    }
    return user.role || 'user';
  }
  
  hasRole(role: Role): boolean {
    const currentRole = this.getCurrentRole();
    const roleHierarchy: Record<Role, number> = {
      guest: 0,
      user: 1,
      manager: 2,
      admin: 3
    };
    
    return roleHierarchy[currentRole] >= roleHierarchy[role];
  }
  
  hasAnyRole(roles: Role[]): boolean {
    return roles.some(role => this.hasRole(role));
  }
  
  hasPermission(permission: Permission): boolean {
    const role = this.getCurrentRole();
    return this.rolePermissions[role]?.includes(permission) || false;
  }
  
  hasAnyPermission(permissions: Permission[]): boolean {
    return permissions.some(permission => this.hasPermission(permission));
  }
}
```

**role.guard.ts**
```typescript
import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { RoleService, Role } from './role.service';

export const roleGuard = (requiredRole: Role | Role[]): CanActivateFn => {
  return (route, state) => {
    const roleService = inject(RoleService);
    const router = inject(Router);
    
    const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
    const hasAccess = roleService.hasAnyRole(roles);
    
    if (hasAccess) {
      return true;
    }
    
    router.navigate(['/unauthorized']);
    return false;
  };
};
```

**permission.guard.ts**
```typescript
import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { RoleService, Permission } from './role.service';

export const permissionGuard = (requiredPermission: Permission | Permission[]): CanActivateFn => {
  return (route, state) => {
    const roleService = inject(RoleService);
    const router = inject(Router);
    
    const permissions = Array.isArray(requiredPermission) 
      ? requiredPermission 
      : [requiredPermission];
    const hasAccess = roleService.hasAnyPermission(permissions);
    
    if (hasAccess) {
      return true;
    }
    
    router.navigate(['/unauthorized']);
    return false;
  };
};
```

**has-role.directive.ts**
```typescript
import { Directive, Input, TemplateRef, ViewContainerRef, inject } from '@angular/core';
import { RoleService, Role } from './role.service';

@Directive({
  selector: '[appHasRole]',
  standalone: true
})
export class HasRoleDirective {
  private templateRef = inject(TemplateRef<any>);
  private viewContainer = inject(ViewContainerRef);
  private roleService = inject(RoleService);
  
  @Input() set appHasRole(roles: Role | Role[]) {
    const roleArray = Array.isArray(roles) ? roles : [roles];
    const hasAccess = this.roleService.hasAnyRole(roleArray);
    
    if (hasAccess) {
      this.viewContainer.createEmbeddedView(this.templateRef);
    } else {
      this.viewContainer.clear();
    }
  }
}
```

**has-permission.directive.ts**
```typescript
import { Directive, Input, TemplateRef, ViewContainerRef, inject } from '@angular/core';
import { RoleService, Permission } from './role.service';

@Directive({
  selector: '[appHasPermission]',
  standalone: true
})
export class HasPermissionDirective {
  private templateRef = inject(TemplateRef<any>);
  private viewContainer = inject(ViewContainerRef);
  private roleService = inject(RoleService);
  
  @Input() set appHasPermission(permissions: Permission | Permission[]) {
    const permissionArray = Array.isArray(permissions) ? permissions : [permissions];
    const hasAccess = this.roleService.hasAnyPermission(permissionArray);
    
    if (hasAccess) {
      this.viewContainer.createEmbeddedView(this.templateRef);
    } else {
      this.viewContainer.clear();
    }
  }
}
```

**app.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { authGuard } from './guards/auth.guard';
import { roleGuard } from './guards/role.guard';
import { permissionGuard } from './guards/permission.guard';

export const routes: Routes = [
  {
    path: 'dashboard',
    loadComponent: () => import('./dashboard/dashboard.component'),
    canActivate: [authGuard]
  },
  {
    path: 'admin',
    loadComponent: () => import('./admin/admin.component'),
    canActivate: [authGuard, roleGuard('admin')]
  },
  {
    path: 'users',
    loadComponent: () => import('./users/users.component'),
    canActivate: [authGuard, permissionGuard('manage')]
  },
  {
    path: 'settings',
    loadComponent: () => import('./settings/settings.component'),
    canActivate: [authGuard, roleGuard(['admin', 'manager'])]
  }
];
```

**admin.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HasRoleDirective } from './directives/has-role.directive';
import { HasPermissionDirective } from './directives/has-permission.directive';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [CommonModule, HasRoleDirective, HasPermissionDirective],
  template: `
    <div>
      <h1>Painel Administrativo</h1>
      
      <div *appHasRole="'admin'">
        <h2>Área Admin</h2>
        <p>Apenas administradores podem ver isso.</p>
      </div>
      
      <div *appHasPermission="'manage'">
        <h2>Gerenciamento</h2>
        <button>Gerenciar Usuários</button>
      </div>
      
      <div *appHasPermission="['read', 'write']">
        <h2>Edição</h2>
        <button>Editar</button>
      </div>
      
      <div *appHasRole="['admin', 'manager']">
        <h2>Configurações</h2>
        <button>Configurar</button>
      </div>
    </div>
  `
})
export class AdminComponent {}
```

**Explicação da Solução**:

1. RoleService gerencia roles e permissões
2. roleGuard protege rotas por role
3. permissionGuard protege rotas por permissão
4. HasRoleDirective controla UI por role
5. HasPermissionDirective controla UI por permissão
6. Hierarquia de roles implementada

---

## Testes

### Casos de Teste

**Teste 1**: Role guard funciona
- **Input**: Acessar rota protegida
- **Output Esperado**: Acesso negado se sem role

**Teste 2**: Diretiva funciona
- **Input**: Elemento com diretiva
- **Output Esperado**: Exibido apenas se tem role

**Teste 3**: Permissões funcionam
- **Input**: Verificar permissão
- **Output Esperado**: Acesso baseado em permissão

---

## Extensões (Opcional)

1. **Dynamic Roles**: Implemente roles dinâmicas
2. **Permission Groups**: Crie grupos de permissões
3. **Audit Log**: Registre acessos

---

## Referências Úteis

- **[Route Guards](https://angular.io/guide/router#preventing-unauthorized-access)**: Guia guards
- **[Structural Directives](https://angular.io/guide/structural-directives)**: Guia diretivas estruturais

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

