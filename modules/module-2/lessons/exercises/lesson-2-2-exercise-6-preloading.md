---
layout: exercise
title: "Exercício 2.2.6: Preloading Strategies"
slug: "preloading"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Preloading Strategies** através da **implementação de estratégias customizadas de pré-carregamento**.

Ao completar este exercício, você será capaz de:

- Entender diferentes estratégias de preloading
- Implementar estratégia customizada
- Otimizar carregamento baseado em prioridade
- Configurar preloading no router

---

## Descrição

Você precisa criar uma estratégia customizada de preloading que carrega módulos baseado em prioridade e condições específicas.

### Contexto

Uma aplicação precisa otimizar quando módulos lazy são pré-carregados, balanceando performance inicial e experiência do usuário.

### Tarefa

Crie:

1. **Custom Preloading Strategy**: Estratégia que pré-carrega baseado em prioridade
2. **Configuração**: Configure estratégia no router
3. **Rotas com Prioridade**: Marque rotas com prioridade
4. **Teste**: Verifique preloading funcionando

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] CustomPreloadingStrategy criada
- [ ] Estratégia implementa PreloadingStrategy
- [ ] Prioridade configurável por rota
- [ ] Preloading configurado no router
- [ ] Preloading funciona corretamente
- [ ] Logs mostram preloading

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Estratégia é flexível
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**custom-preloading-strategy.ts**
```typescript
import { PreloadingStrategy, Route } from '@angular/router';
import { Observable, of, timer } from 'rxjs';
import { mergeMap } from 'rxjs/operators';

export interface PreloadRouteData {
  preload?: boolean;
  priority?: 'high' | 'medium' | 'low';
  delay?: number;
}

export class CustomPreloadingStrategy implements PreloadingStrategy {
  preload(route: Route, load: () => Observable<any>): Observable<any> {
    const data = route.data as PreloadRouteData;
    
    if (!data || !data.preload) {
      return of(null);
    }
    
    const delay = data.delay || this.getDelayByPriority(data.priority);
    
    return timer(delay).pipe(
      mergeMap(() => {
        console.log(`Preloading: ${route.path} (priority: ${data.priority})`);
        return load();
      })
    );
  }
  
  private getDelayByPriority(priority?: string): number {
    switch (priority) {
      case 'high':
        return 1000;
      case 'medium':
        return 3000;
      case 'low':
        return 5000;
      default:
        return 3000;
    }
  }
}
```

**app.routes.ts**
```typescript
import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', loadComponent: () => import('./home/home.component').then(m => m.HomeComponent) },
  {
    path: 'admin',
    data: { preload: true, priority: 'high' },
    loadChildren: () => import('./admin/admin.routes').then(m => m.adminRoutes)
  },
  {
    path: 'products',
    data: { preload: true, priority: 'medium' },
    loadChildren: () => import('./products/products.routes').then(m => m.productRoutes)
  },
  {
    path: 'reports',
    data: { preload: true, priority: 'low' },
    loadChildren: () => import('./reports/reports.routes').then(m => m.reportRoutes)
  },
  {
    path: 'settings',
    data: { preload: false },
    loadChildren: () => import('./settings/settings.routes').then(m => m.settingsRoutes)
  }
];
```

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter, withPreloading } from '@angular/router';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';
import { CustomPreloadingStrategy } from './app/custom-preloading-strategy';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(
      routes,
      withPreloading(CustomPreloadingStrategy)
    )
  ]
});
```

**admin/admin.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { AdminComponent } from './admin.component';

export const adminRoutes: Routes = [
  { path: '', component: AdminComponent }
];
```

**products/products.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { ProductListComponent } from './product-list/product-list.component';

export const productRoutes: Routes = [
  { path: '', component: ProductListComponent }
];
```

**reports/reports.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { ReportsComponent } from './reports.component';

export const reportRoutes: Routes = [
  { path: '', component: ReportsComponent }
];
```

**settings/settings.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { SettingsComponent } from './settings.component';

export const settingsRoutes: Routes = [
  { path: '', component: SettingsComponent }
];
```

**Explicação da Solução**:

1. CustomPreloadingStrategy implementa PreloadingStrategy
2. Estratégia verifica data.preload para decidir pré-carregar
3. Prioridade determina delay de preloading
4. Rotas marcadas com data.preload e priority
5. withPreloading configura estratégia no router
6. Logs mostram quando preloading acontece

---

## Testes

### Casos de Teste

**Teste 1**: Preloading funciona
- **Input**: Carregar aplicação
- **Output Esperado**: Módulos são pré-carregados após delay

**Teste 2**: Prioridade funciona
- **Input**: Verificar ordem de preloading
- **Output Esperado**: High priority primeiro, depois medium, depois low

**Teste 3**: Preload false funciona
- **Input**: Verificar módulo settings
- **Output Esperado**: Não é pré-carregado

---

## Extensões (Opcional)

1. **Network Aware**: Implemente preloading baseado em conexão
2. **User Behavior**: Implemente preloading baseado em comportamento do usuário
3. **Time-based**: Implemente preloading em horários específicos

---

## Referências Úteis

- **[Preloading Strategies](https://angular.io/guide/router#custom-preloading-strategy)**: Guia oficial
- **[PreloadingStrategy](https://angular.io/api/router/PreloadingStrategy)**: Documentação PreloadingStrategy

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

