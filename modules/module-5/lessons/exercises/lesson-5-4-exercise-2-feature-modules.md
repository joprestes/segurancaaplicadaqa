---
layout: exercise
title: "Exercício 5.4.2: Feature Modules e Barrel Exports"
slug: "feature-modules"
lesson_id: "lesson-5-4"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Feature Modules e Barrel Exports** através da **organização de aplicação usando Feature Modules e Barrel Exports**.

Ao completar este exercício, você será capaz de:

- Organizar código em Feature Modules
- Criar Barrel Exports
- Configurar Lazy Loading
- Estruturar aplicação escalável
- Simplificar imports

---

## Descrição

Você precisa organizar aplicação usando Feature Modules e Barrel Exports.

### Contexto

Uma aplicação precisa ser organizada de forma escalável e manutenível.

### Tarefa

Crie:

1. **Feature Modules**: Criar módulos por feature
2. **Barrel Exports**: Criar arquivos index
3. **Lazy Loading**: Configurar lazy loading
4. **Estrutura**: Organizar estrutura completa
5. **Imports**: Simplificar imports

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Feature Modules criados
- [ ] Barrel Exports criados
- [ ] Lazy Loading configurado
- [ ] Estrutura organizada
- [ ] Imports simplificados

### Critérios de Qualidade

- [ ] Código está bem organizado
- [ ] Barrel exports estão corretos
- [ ] Lazy loading funciona

---

## Solução Esperada

### Abordagem Recomendada

**Estrutura de Pastas**:
```
src/app/
├── core/
│   ├── services/
│   │   ├── auth.service.ts
│   │   └── logger.service.ts
│   └── index.ts
├── shared/
│   ├── components/
│   │   ├── button/
│   │   └── card/
│   ├── pipes/
│   ├── directives/
│   └── index.ts
└── features/
    ├── tasks/
    │   ├── components/
    │   ├── services/
    │   ├── tasks.routes.ts
    │   └── index.ts
    └── users/
        ├── components/
        ├── services/
        ├── users.routes.ts
        └── index.ts
```

**core/index.ts**
```typescript
export * from './services/auth.service';
export * from './services/logger.service';
```

**shared/index.ts**
```typescript
export * from './components/button/button.component';
export * from './components/card/card.component';
export * from './pipes/currency.pipe';
export * from './directives/highlight.directive';
```

**features/tasks/index.ts**
```typescript
export * from './components/task-list/task-list.component';
export * from './components/task-form/task-form.component';
export * from './services/task.service';
export * from './tasks.routes';
```

**features/users/index.ts**
```typescript
export * from './components/user-list/user-list.component';
export * from './components/user-profile/user-profile.component';
export * from './services/user.service';
export * from './users.routes';
```

**app.routes.ts**
```typescript
import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: 'tasks',
    loadChildren: () => import('./features/tasks').then(m => m.TASK_ROUTES)
  },
  {
    path: 'users',
    loadChildren: () => import('./features/users').then(m => m.USER_ROUTES)
  },
  {
    path: '',
    redirectTo: '/tasks',
    pathMatch: 'full'
  }
];
```

**features/tasks/tasks.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { TaskListComponent } from './components/task-list/task-list.component';
import { TaskFormComponent } from './components/task-form/task-form.component';

export const TASK_ROUTES: Routes = [
  {
    path: '',
    component: TaskListComponent
  },
  {
    path: 'new',
    component: TaskFormComponent
  },
  {
    path: ':id/edit',
    component: TaskFormComponent
  }
];
```

**features/users/users.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { UserListComponent } from './components/user-list/user-list.component';
import { UserProfileComponent } from './components/user-profile/user-profile.component';

export const USER_ROUTES: Routes = [
  {
    path: '',
    component: UserListComponent
  },
  {
    path: ':id',
    component: UserProfileComponent
  }
];
```

**Uso em Componentes**:
```typescript
import { Component } from '@angular/core';
import { ButtonComponent, CardComponent } from '@shared';
import { TaskService } from '@features/tasks';

@Component({
  selector: 'app-example',
  standalone: true,
  imports: [ButtonComponent, CardComponent],
  template: `
    <app-card>
      <app-button>Click me</app-button>
    </app-card>
  `
})
export class ExampleComponent {
  constructor(private taskService: TaskService) {}
}
```

**tsconfig.json** (path mapping):
```json
{
  "compilerOptions": {
    "paths": {
      "@core/*": ["src/app/core/*"],
      "@shared/*": ["src/app/shared/*"],
      "@features/*": ["src/app/features/*"]
    }
  }
}
```

**Explicação da Solução**:

1. Feature Modules organizam por funcionalidade
2. Barrel exports simplificam imports
3. Lazy loading melhora performance
4. Path mapping facilita imports
5. Estrutura escalável e manutenível
6. Separação clara de responsabilidades

---

## Testes

### Casos de Teste

**Teste 1**: Barrel exports funcionam
- **Input**: Importar de barrel
- **Output Esperado**: Imports funcionam

**Teste 2**: Lazy loading funciona
- **Input**: Navegar para rota lazy
- **Output Esperado**: Módulo carregado sob demanda

**Teste 3**: Estrutura organizada
- **Input**: Verificar estrutura
- **Output Esperado**: Código bem organizado

---

## Extensões (Opcional)

1. **More Features**: Adicione mais features
2. **Shared Services**: Crie serviços compartilhados
3. **Module Guards**: Adicione guards aos módulos

---

## Referências Úteis

- **[Feature Modules](https://angular.io/guide/feature-modules)**: Guia feature modules
- **[Lazy Loading](https://angular.io/guide/lazy-loading-ngmodules)**: Guia lazy loading

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

