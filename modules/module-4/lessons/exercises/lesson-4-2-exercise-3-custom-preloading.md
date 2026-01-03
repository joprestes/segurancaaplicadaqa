---
layout: exercise
title: "Exercício 4.2.3: Custom Preloading Strategy"
slug: "custom-preloading"
lesson_id: "lesson-4-2"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **custom preloading strategy** através da **criação de estratégia personalizada que pré-carrega módulos baseado em condições**.

Ao completar este exercício, você será capaz de:

- Criar custom preloading strategy
- Implementar PreloadingStrategy interface
- Usar route data para decisões
- Criar condições customizadas
- Balancear performance e UX

---

## Descrição

Você precisa criar uma estratégia personalizada que pré-carrega apenas rotas marcadas com data.preload = true.

### Contexto

Uma aplicação precisa pré-carregar apenas rotas importantes, não todas.

### Tarefa

Crie:

1. **Custom Strategy**: Criar estratégia personalizada
2. **Route Data**: Marcar rotas com data.preload
3. **Implementação**: Implementar lógica de preloading
4. **Configuração**: Configurar estratégia no router

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Custom strategy criada
- [ ] PreloadingStrategy implementada
- [ ] Route data usado para decisões
- [ ] Estratégia configurada
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Strategy está implementada corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**selective-preloading.strategy.ts**
```typescript
import { Injectable } from '@angular/core';
import { PreloadingStrategy, Route } from '@angular/router';
import { Observable, of, timer } from 'rxjs';
import { mergeMap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class SelectivePreloadingStrategy implements PreloadingStrategy {
  preload(route: Route, load: () => Observable<any>): Observable<any> {
    if (route.data && route.data['preload'] === true) {
      if (route.data['delay']) {
        return timer(route.data['delay']).pipe(
          mergeMap(() => load())
        );
      }
      return load();
    }
    return of(null);
  }
}
```

**app.routes.ts**
```typescript
import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    redirectTo: '/home',
    pathMatch: 'full'
  },
  {
    path: 'home',
    loadComponent: () => import('./home/home.component').then(m => m.HomeComponent)
  },
  {
    path: 'products',
    loadChildren: () => import('./products/products.routes').then(m => m.routes),
    data: { preload: true }
  },
  {
    path: 'cart',
    loadComponent: () => import('./cart/cart.component').then(m => m.CartComponent),
    data: { preload: true, delay: 2000 }
  },
  {
    path: 'admin',
    loadChildren: () => import('./admin/admin.routes').then(m => m.adminRoutes),
    data: { preload: false }
  },
  {
    path: 'settings',
    loadComponent: () => import('./settings/settings.component').then(m => m.SettingsComponent),
    data: { preload: false }
  }
];
```

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';
import { SelectivePreloadingStrategy } from './app/selective-preloading.strategy';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes, {
      preloadingStrategy: SelectivePreloadingStrategy
    })
  ]
});
```

**Explicação da Solução**:

1. SelectivePreloadingStrategy implementa PreloadingStrategy
2. preload() método decide se pré-carrega
3. Route data usado para marcar rotas
4. Delay opcional para preloading atrasado
5. Apenas rotas marcadas são pré-carregadas
6. Flexibilidade e controle total

---

## Testes

### Casos de Teste

**Teste 1**: Rotas marcadas são pré-carregadas
- **Input**: Aguardar após carregamento inicial
- **Output Esperado**: Apenas rotas com preload: true carregadas

**Teste 2**: Rotas não marcadas não são pré-carregadas
- **Input**: Verificar Network tab
- **Output Esperado**: Rotas com preload: false não carregadas

**Teste 3**: Delay funciona
- **Input**: Rotas com delay
- **Output Esperado**: Preloading atrasado conforme configurado

---

## Extensões (Opcional)

1. **Network Conditions**: Adicione condições de rede
2. **User Behavior**: Baseie em comportamento do usuário
3. **Time-based**: Preload baseado em horário

---

## Referências Úteis

- **[PreloadingStrategy](https://angular.io/api/router/PreloadingStrategy)**: Documentação PreloadingStrategy
- **[Custom Preloading](https://angular.io/guide/router#custom-preloading-strategy)**: Guia custom preloading

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

