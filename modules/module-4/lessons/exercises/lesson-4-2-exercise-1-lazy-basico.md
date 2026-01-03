---
layout: exercise
title: "Exercício 4.2.1: Lazy Loading Básico"
slug: "lazy-basico"
lesson_id: "lesson-4-2"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **lazy loading básico** através da **configuração de lazy loading para uma rota simples**.

Ao completar este exercício, você será capaz de:

- Configurar lazy loading usando loadComponent
- Configurar lazy loading usando loadChildren
- Entender diferença entre eager e lazy loading
- Verificar que chunks são criados
- Entender benefícios de lazy loading

---

## Descrição

Você precisa configurar lazy loading para uma rota de produtos.

### Contexto

Uma aplicação precisa reduzir bundle inicial carregando módulo de produtos apenas quando necessário.

### Tarefa

Crie:

1. **Componente Lazy**: Criar componente que será lazy-loaded
2. **Rota Lazy**: Configurar rota com lazy loading
3. **Navegação**: Implementar navegação para rota lazy
4. **Verificação**: Verificar que chunk é criado

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente lazy criado
- [ ] Rota configurada com lazy loading
- [ ] Navegação funciona
- [ ] Chunk é criado no build
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Lazy loading está configurado corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**products.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-products',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Produtos (Lazy Loaded)</h2>
      <p>Este componente foi carregado sob demanda!</p>
      <ul>
        <li>Produto 1</li>
        <li>Produto 2</li>
        <li>Produto 3</li>
      </ul>
    </div>
  `
})
export class ProductsComponent {}
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
    loadComponent: () => import('./products/products.component').then(m => m.ProductsComponent)
  }
];
```

**app.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <nav>
      <a routerLink="/home">Home</a>
      <a routerLink="/products">Produtos</a>
    </nav>
    <router-outlet></router-outlet>
  `
})
export class AppComponent {}
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

1. Componente standalone criado
2. Rota configurada com loadComponent
3. Função import() retorna Promise
4. Chunk separado criado automaticamente
5. Componente carregado apenas quando rota é acessada
6. Bundle inicial reduzido

---

## Testes

### Casos de Teste

**Teste 1**: Navegação funciona
- **Input**: Navegar para /products
- **Output Esperado**: Componente carregado e exibido

**Teste 2**: Chunk criado
- **Input**: Executar ng build
- **Output Esperado**: Chunk separado criado para products

**Teste 3**: Lazy loading funciona
- **Input**: Verificar Network tab
- **Output Esperado**: Chunk carregado apenas ao navegar

---

## Extensões (Opcional)

1. **Múltiplas Rotas**: Adicione mais rotas lazy
2. **Nested Routes**: Implemente rotas aninhadas lazy
3. **Route Guards**: Adicione guards em rotas lazy

---

## Referências Úteis

- **[Lazy Loading](https://angular.io/guide/lazy-loading-ngmodules)**: Guia lazy loading
- **[loadComponent](https://angular.io/api/router/Route#loadComponent)**: Documentação loadComponent

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

