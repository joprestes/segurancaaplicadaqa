---
layout: exercise
title: "Exercício 2.2.5: Lazy Loading"
slug: "lazy-loading"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Lazy Loading** através da **implementação de carregamento sob demanda de módulos e rotas**.

Ao completar este exercício, você será capaz de:

- Configurar lazy loading com loadChildren
- Criar rotas em arquivos separados
- Entender code splitting e bundle optimization
- Verificar redução de bundle inicial
- Implementar lazy loading para features grandes

---

## Descrição

Você precisa criar uma aplicação onde módulos de Admin e Products são carregados apenas quando necessário, reduzindo o bundle inicial.

### Contexto

Uma aplicação grande precisa otimizar o carregamento inicial carregando features apenas quando necessário.

### Tarefa

Crie:

1. **Módulo Admin**: Rotas e componentes de admin em arquivo separado
2. **Módulo Products**: Rotas e componentes de products em arquivo separado
3. **Lazy Loading**: Configure lazy loading nas rotas principais
4. **Verificação**: Verifique redução de bundle

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Módulos admin e products criados
- [ ] Rotas configuradas em arquivos separados
- [ ] Lazy loading configurado com loadChildren
- [ ] Rotas funcionam corretamente
- [ ] Bundle inicial reduzido
- [ ] Chunks são carregados sob demanda

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Estrutura está organizada
- [ ] Lazy loading funciona corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**app.routes.ts**
```typescript
import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', loadComponent: () => import('./home/home.component').then(m => m.HomeComponent) },
  {
    path: 'admin',
    loadChildren: () => import('./admin/admin.routes').then(m => m.adminRoutes)
  },
  {
    path: 'products',
    loadChildren: () => import('./products/products.routes').then(m => m.productRoutes)
  }
];
```

**admin/admin.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { AdminComponent } from './admin.component';
import { UserManagementComponent } from './user-management/user-management.component';
import { SettingsComponent } from './settings/settings.component';

export const adminRoutes: Routes = [
  {
    path: '',
    component: AdminComponent,
    children: [
      { path: '', redirectTo: 'users', pathMatch: 'full' },
      { path: 'users', component: UserManagementComponent },
      { path: 'settings', component: SettingsComponent }
    ]
  }
];
```

**admin/admin.component.ts**
```typescript
import { Component } from '@angular/core';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [RouterModule, CommonModule],
{% raw %}
  template: `
    <div class="admin-layout">
      <nav>
        <h2>Admin</h2>
        <ul>
          <li><a routerLink="users" routerLinkActive="active">Usuários</a></li>
          <li><a routerLink="settings" routerLinkActive="active">Configurações</a></li>
        </ul>
      </nav>
      <main>
        <router-outlet></router-outlet>
      </main>
    </div>
  `,
  styles: [`
{% endraw %}
    .admin-layout {
      display: flex;
    }
    
    nav {
      width: 200px;
      padding: 1rem;
      background-color: #f0f0f0;
    }
    
    main {
      flex: 1;
      padding: 1rem;
    }
  `]
})
export class AdminComponent {}
```

**admin/user-management/user-management.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-user-management',
  standalone: true,
  imports: [CommonModule],
{% raw %}
  template: `
    <div>
      <h1>Gerenciamento de Usuários</h1>
      <p>Lista de usuários aqui...</p>
    </div>
  `
{% endraw %}
})
export class UserManagementComponent {}
```

**admin/settings/settings.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule],
{% raw %}
  template: `
    <div>
      <h1>Configurações</h1>
      <p>Configurações do sistema aqui...</p>
    </div>
  `
{% endraw %}
})
export class SettingsComponent {}
```

**products/products.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { ProductListComponent } from './product-list/product-list.component';
import { ProductDetailComponent } from './product-detail/product-detail.component';

export const productRoutes: Routes = [
  { path: '', component: ProductListComponent },
  { path: ':id', component: ProductDetailComponent }
];
```

**products/product-list/product-list.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-product-list',
  standalone: true,
  imports: [CommonModule, RouterModule],
{% raw %}
  template: `
    <div>
      <h1>Produtos</h1>
      <ul>
        <li><a routerLink="1">Produto 1</a></li>
        <li><a routerLink="2">Produto 2</a></li>
      </ul>
    </div>
  `
{% endraw %}
})
export class ProductListComponent {}
```

**products/product-detail/product-detail.component.ts**
{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-product-detail',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h1>Detalhes do Produto {{ productId }}</h1>
    </div>
  `
{% endraw %}
})
export class ProductDetailComponent implements OnInit {
  productId: string | null = null;
  
  constructor(private route: ActivatedRoute) {}
  
  ngOnInit(): void {
    this.productId = this.route.snapshot.paramMap.get('id');
  }
}
```

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes)
  ]
});
```

**Explicação da Solução**:

1. loadChildren usa função arrow com import dinâmico
2. Rotas lazy-loaded em arquivos separados
3. Cada módulo tem suas próprias rotas
4. Bundle inicial contém apenas código essencial
5. Chunks são carregados quando rota é acessada
6. Estrutura organizada por feature

---

## Testes

### Casos de Teste

**Teste 1**: Lazy loading funciona
- **Input**: Navegar para /admin
- **Output Esperado**: Chunk admin é carregado e componente renderizado

**Teste 2**: Bundle inicial reduzido
- **Input**: Verificar bundle no DevTools
- **Output Esperado**: Bundle inicial menor, chunks separados

**Teste 3**: Rotas aninhadas funcionam
- **Input**: Navegar para /admin/users
- **Output Esperado**: Componente filho renderizado

---

## Extensões (Opcional)

1. **Preloading**: Implemente preloading strategy
2. **Loading Indicator**: Adicione indicador de carregamento
3. **Error Handling**: Trate erros de carregamento

---

## Referências Úteis

- **[Lazy Loading](https://angular.io/guide/lazy-loading-ngmodules)**: Guia oficial
- **[Code Splitting](https://angular.io/guide/router#lazy-loading)**: Documentação code splitting

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

