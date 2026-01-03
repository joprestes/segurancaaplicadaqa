---
layout: lesson
title: "Aula 2.2: Roteamento e Navegação Avançada"
slug: roteamento
module: module-2
lesson_id: lesson-2-2
duration: "120 minutos"
level: "Intermediário"
prerequisites: 
  - "lesson-2-1"
exercises:
  - 
  - "lesson-2-2-exercise-1"
  - "lesson-2-2-exercise-2"
  - "lesson-2-2-exercise-3"
  - "lesson-2-2-exercise-4"
  - "lesson-2-2-exercise-5"
  - "lesson-2-2-exercise-6"
podcast:
  file: "assets/podcasts/02.2-SilêncioRouter_Guards_Resolvers_Lazy_Loading.m4a"
  title: "Router, Guards, Resolvers e Lazy Loading"
  description: "Domine o sistema de roteamento avançado do Angular."
  duration: "55-70 minutos"
---

## Introdução

Nesta aula, você dominará o sistema de roteamento do Angular. Roteamento é essencial para criar Single Page Applications (SPAs) profissionais, permitindo navegação entre páginas sem recarregar a aplicação. Você aprenderá desde configuração básica até técnicas avançadas como guards, resolvers e lazy loading.

### O que você vai aprender

- Configurar rotas standalone
- Trabalhar com parâmetros de rota e query params
- Implementar rotas aninhadas
- Criar Route Guards para proteção
- Usar Resolvers para pré-carregar dados
- Implementar Lazy Loading
- Configurar Preloading Strategies
- Navegação programática avançada

### Por que isso é importante

Roteamento é fundamental para qualquer aplicação Angular real. Sem roteamento adequado, você não consegue criar aplicações multi-página profissionais. Guards e Resolvers são essenciais para segurança e performance. Lazy Loading é crucial para otimização de bundle.

---

## Conceitos Teóricos

### Configuração de Rotas

**Definição**: Rotas definem como a aplicação navega entre diferentes componentes baseado na URL do navegador.

**Explicação Detalhada**:

Rotas no Angular são configuradas através de um array de objetos `Route`. Cada rota define:
- `path`: Padrão de URL que corresponde à rota
- `component`: Componente a ser exibido
- `redirectTo`: Redirecionamento para outra rota
- `children`: Rotas filhas (aninhadas)
- `loadChildren`: Carregamento lazy de módulos
- `canActivate`: Guards que controlam acesso
- `resolve`: Resolvers que pré-carregam dados

**Analogia**:

Rotas são como um mapa de uma cidade. Cada endereço (path) leva você a um lugar específico (componente). O Angular Router é o GPS que te guia até lá.

**Visualização**:

```
URL: /products/123
         │
         ├─ Path: 'products'
         │   └─ Component: ProductListComponent
         │
         └─ Path: ':id'
             └─ Component: ProductDetailComponent
```

**Exemplo Prático**:

```typescript
import { Routes } from '@angular/router';
import { HomeComponent } from './home.component';
import { AboutComponent } from './about.component';
import { ProductListComponent } from './product-list.component';
import { ProductDetailComponent } from './product-detail.component';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'about', component: AboutComponent },
  { path: 'products', component: ProductListComponent },
  { path: 'products/:id', component: ProductDetailComponent },
  { path: '**', redirectTo: '' }
];
```

---

### RouterModule e provideRouter

**Definição**: `provideRouter` é a função moderna (Angular 14+) para configurar roteamento em aplicações standalone.

**Explicação Detalhada**:

Em aplicações standalone, usamos `provideRouter()` ao invés de `RouterModule.forRoot()`. Isso permite:
- Configuração mais simples
- Melhor tree-shaking
- Integração com standalone components

**Analogia**:

`provideRouter` é como registrar o sistema de GPS no carro. Uma vez configurado, você pode navegar para qualquer lugar.

**Exemplo Prático**:

```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { AppComponent } from './app.component';
import { routes } from './app.routes';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes)
  ]
});
```

---

### Parâmetros de Rota

**Definição**: Parâmetros de rota permitem passar dados dinâmicos através da URL.

**Explicação Detalhada**:

Parâmetros são definidos com `:` no path (ex: `:id`). Podem ser acessados via:
- `ActivatedRoute.snapshot.paramMap`: Valor estático
- `ActivatedRoute.paramMap`: Observable para valores dinâmicos

**Analogia**:

Parâmetros são como variáveis em uma função. A URL `/products/123` passa o valor `123` como parâmetro `id`.

**Exemplo Prático**:

{% raw %}
```typescript
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

@Component({
  selector: 'app-product-detail',
  standalone: true,
{% raw %}
  template: `
    <div>
      <h2>Produto {{ productId }}</h2>
      <button (click)="goToNext()">Próximo Produto</button>
    </div>
  `
{% endraw %}
})
export class ProductDetailComponent implements OnInit {
  productId: string | null = null;
  
  constructor(
    private route: ActivatedRoute,
    private router: Router
  ) {}
  
  ngOnInit(): void {
    this.productId = this.route.snapshot.paramMap.get('id');
    
    this.route.paramMap.subscribe(params => {
      this.productId = params.get('id');
    });
  }
  
  goToNext(): void {
    const nextId = Number(this.productId) + 1;
    this.router.navigate(['/products', nextId]);
  }
}
```
{% endraw %}

---

### Query Parameters

**Definição**: Query parameters são parâmetros opcionais passados após `?` na URL.

**Explicação Detalhada**:

Query params são úteis para:
- Filtros e busca
- Paginação
- Configurações de visualização
- Estado temporário

São acessados via `ActivatedRoute.queryParamMap`.

**Analogia**:

Query params são como opções extras em um pedido. A URL `/products?page=2&sort=price` passa opções de página e ordenação.

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-product-list',
  standalone: true,
{% raw %}
  template: `
    <div>
      <input [(ngModel)]="searchTerm" (input)="onSearch()">
      <select [(ngModel)]="sortBy" (change)="onSort()">
        <option value="name">Nome</option>
        <option value="price">Preço</option>
      </select>
    </div>
  `
{% endraw %}
})
export class ProductListComponent {
  searchTerm: string = '';
  sortBy: string = 'name';
  
  constructor(
    private route: ActivatedRoute,
    private router: Router
  ) {
    this.route.queryParamMap.subscribe(params => {
      this.searchTerm = params.get('search') || '';
      this.sortBy = params.get('sort') || 'name';
    });
  }
  
  onSearch(): void {
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { search: this.searchTerm },
      queryParamsHandling: 'merge'
    });
  }
  
  onSort(): void {
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { sort: this.sortBy },
      queryParamsHandling: 'merge'
    });
  }
}
```

---

### Rotas Aninhadas

**Definição**: Rotas aninhadas permitem criar hierarquias de rotas com componentes filhos.

**Explicação Detalhada**:

Rotas aninhadas são úteis para:
- Layouts compartilhados
- Navegação hierárquica
- Organização de features

O componente pai deve ter `<router-outlet>` para renderizar filhos.

**Analogia**:

Rotas aninhadas são como prédios com múltiplos andares. Cada andar (rota filha) está dentro do prédio (rota pai).

**Visualização**:

```
/admin (AdminLayoutComponent)
    ├─ /admin/users (UserListComponent)
    ├─ /admin/products (ProductListComponent)
    └─ /admin/settings (SettingsComponent)
```

**Exemplo Prático**:

```typescript
export const routes: Routes = [
  {
    path: 'admin',
    component: AdminLayoutComponent,
    children: [
      { path: 'users', component: UserListComponent },
      { path: 'products', component: ProductListComponent },
      { path: 'settings', component: SettingsComponent },
      { path: '', redirectTo: 'users', pathMatch: 'full' }
    ]
  }
];
```

```typescript
@Component({
  selector: 'app-admin-layout',
  standalone: true,
{% raw %}
  template: `
    <nav>
      <a routerLink="users">Usuários</a>
      <a routerLink="products">Produtos</a>
      <a routerLink="settings">Configurações</a>
    </nav>
    <router-outlet></router-outlet>
  `,
  imports: [RouterModule]
})
export class AdminLayoutComponent {}
{% endraw %}
```

---

### Route Guards

**Definição**: Guards são interfaces que controlam acesso a rotas, permitindo ou bloqueando navegação.

**Explicação Detalhada**:

Tipos de guards:
- `CanActivate`: Controla acesso à rota
- `CanActivateChild`: Controla acesso a rotas filhas
- `CanDeactivate`: Controla saída da rota
- `CanLoad`: Controla carregamento de módulos lazy
- `Resolve`: Pré-carrega dados antes de ativar rota

**Analogia**:

Guards são como seguranças em um prédio. Eles verificam se você tem permissão antes de deixar você entrar (CanActivate) ou sair (CanDeactivate).

**Exemplo Prático**:

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
  
  router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
  return false;
};
```

```typescript
export const routes: Routes = [
  { path: 'login', component: LoginComponent },
  {
    path: 'admin',
    canActivate: [authGuard],
    component: AdminComponent
  }
];
```

---

### Resolvers

**Definição**: Resolvers pré-carregam dados antes que a rota seja ativada.

**Explicação Detalhada**:

Resolvers são úteis para:
- Garantir dados disponíveis antes de renderizar
- Melhorar UX evitando estados de loading
- Centralizar lógica de carregamento

Dados são acessados via `ActivatedRoute.data`.

**Analogia**:

Resolvers são como preparar a mesa antes dos convidados chegarem. Os dados estão prontos quando o componente é renderizado.

**Exemplo Prático**:

```typescript
import { inject } from '@angular/core';
import { ResolveFn } from '@angular/router';
import { ProductService } from './product.service';
import { Product } from './product.model';

export const productResolver: ResolveFn<Product> = (route, state) => {
  const productService = inject(ProductService);
  const productId = route.paramMap.get('id')!;
  return productService.getProduct(productId);
};
```

```typescript
export const routes: Routes = [
  {
    path: 'products/:id',
    component: ProductDetailComponent,
    resolve: { product: productResolver }
  }
];
```

{% raw %}
```typescript
@Component({
  selector: 'app-product-detail',
  standalone: true,
{% raw %}
  template: `
    <div *ngIf="product">
      <h2>{{ product.name }}</h2>
      <p>{{ product.description }}</p>
    </div>
  `
{% endraw %}
})
export class ProductDetailComponent {
  product: Product | null = null;
  
  constructor(private route: ActivatedRoute) {
    this.product = this.route.snapshot.data['product'];
  }
}
```
{% endraw %}

---

### Lazy Loading

**Definição**: Lazy Loading carrega módulos/rotas apenas quando necessário, melhorando performance inicial.

**Explicação Detalhada**:

Lazy loading:
- Reduz bundle inicial
- Melhora tempo de carregamento
- Carrega código sob demanda
- Usa `loadChildren` com função arrow

**Analogia**:

Lazy loading é como carregar apenas os capítulos de um livro que você vai ler agora, ao invés de carregar o livro inteiro.

**Exemplo Prático**:

```typescript
export const routes: Routes = [
  { path: '', component: HomeComponent },
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

**admin.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { AdminComponent } from './admin.component';

export const adminRoutes: Routes = [
  { path: '', component: AdminComponent }
];
```

---

### Preloading Strategies

**Definição**: Preloading strategies definem quando módulos lazy devem ser pré-carregados.

**Explicação Detalhada**:

Estratégias disponíveis:
- `NoPreloading`: Não pré-carrega (padrão)
- `PreloadAllModules`: Pré-carrega todos após inicialização
- `QuicklinkStrategy`: Pré-carrega baseado em links visíveis
- Custom Strategy: Estratégia personalizada

**Analogia**:

Preloading é como pré-cozinhar pratos que provavelmente serão pedidos. Você prepara antecipadamente para servir mais rápido.

**Exemplo Prático**:

```typescript
import { PreloadAllModules, provideRouter, withPreloading } from '@angular/router';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(
      routes,
      withPreloading(PreloadAllModules)
    )
  ]
});
```

**Custom Strategy**:
```typescript
import { PreloadingStrategy, Route } from '@angular/router';
import { Observable, of, timer } from 'rxjs';
import { mergeMap } from 'rxjs/operators';

export class CustomPreloadStrategy implements PreloadingStrategy {
  preload(route: Route, load: () => Observable<any>): Observable<any> {
    if (route.data && route.data['preload']) {
      return timer(5000).pipe(mergeMap(() => load()));
    }
    return of(null);
  }
}
```

---

### Navegação Programática

**Definição**: Navegação programática permite navegar via código TypeScript ao invés de apenas links.

**Explicação Detalhada**:

`Router.navigate()` permite:
- Navegação com parâmetros
- Navegação relativa
- Controle de query params
- Navegação com estado

**Analogia**:

Navegação programática é como usar GPS programaticamente ao invés de clicar em um link no mapa.

**Exemplo Prático**:

```typescript
export class ProductComponent {
  constructor(private router: Router) {}
  
  goToProduct(id: number): void {
    this.router.navigate(['/products', id]);
  }
  
  goToProductWithQuery(id: number, category: string): void {
    this.router.navigate(['/products', id], {
      queryParams: { category },
      fragment: 'details'
    });
  }
  
  goRelative(): void {
    this.router.navigate(['../sibling'], { relativeTo: this.route });
  }
  
  goWithState(): void {
    this.router.navigate(['/products'], {
      state: { fromComponent: 'ProductList' }
    });
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Sistema de Roteamento Completo

**Contexto**: Criar sistema de roteamento completo com guards, resolvers e lazy loading.

**Código**:

```typescript
import { Routes } from '@angular/router';
import { authGuard } from './guards/auth.guard';
import { productResolver } from './resolvers/product.resolver';

export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  {
    path: 'products',
    canActivate: [authGuard],
    children: [
      { path: '', component: ProductListComponent },
      {
        path: ':id',
        component: ProductDetailComponent,
        resolve: { product: productResolver }
      }
    ]
  },
  {
    path: 'admin',
    canActivate: [authGuard],
    loadChildren: () => import('./admin/admin.routes').then(m => m.adminRoutes)
  },
  { path: '**', redirectTo: '/home' }
];
```

---

### Exemplo 2: Guard com Múltiplas Condições

**Contexto**: Criar guard que verifica autenticação e permissões.

**Código**:

```typescript
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const adminGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  if (!authService.isAuthenticated()) {
    router.navigate(['/login']);
    return false;
  }
  
  if (!authService.hasRole('admin')) {
    router.navigate(['/unauthorized']);
    return false;
  }
  
  return true;
};
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use lazy loading para features grandes**
   - **Por quê**: Reduz bundle inicial e melhora performance
   - **Exemplo**: `loadChildren: () => import('./feature/feature.routes')`

2. **Use guards para proteger rotas**
   - **Por quê**: Segurança e controle de acesso
   - **Exemplo**: `canActivate: [authGuard]`

3. **Use resolvers para pré-carregar dados críticos**
   - **Por quê**: Melhora UX evitando estados de loading
   - **Exemplo**: `resolve: { product: productResolver }`

4. **Organize rotas em arquivos separados**
   - **Por quê**: Mantém código organizado e escalável
   - **Exemplo**: `app.routes.ts`, `admin.routes.ts`

### ❌ Anti-padrões Comuns

1. **Não use guards síncronos para operações assíncronas**
   - **Problema**: Pode causar race conditions
   - **Solução**: Use observables ou promises corretamente

2. **Não ignore tratamento de erros em guards**
   - **Problema**: Aplicação pode travar
   - **Solução**: Sempre trate erros e redirecione apropriadamente

3. **Não carregue tudo no bundle inicial**
   - **Problema**: Performance ruim
   - **Solução**: Use lazy loading para features não críticas

---

## Exercícios Práticos

### Exercício 1: Configurar Rotas Básicas (Básico)

**Objetivo**: Criar primeira configuração de rotas

**Descrição**: 
Configure rotas básicas para home, about e contact usando provideRouter.

**Arquivo**: `exercises/exercise-2-2-1-rotas-basicas.md`

---

### Exercício 2: Parâmetros de Rota e Query Params (Básico)

**Objetivo**: Trabalhar com parâmetros dinâmicos

**Descrição**:
Crie rotas com parâmetros e query params, demonstrando leitura e escrita.

**Arquivo**: `exercises/exercise-2-2-2-parametros-query.md`

---

### Exercício 3: Route Guards (Intermediário)

**Objetivo**: Implementar proteção de rotas

**Descrição**:
Crie guards para proteger rotas administrativas e controlar acesso baseado em autenticação.

**Arquivo**: `exercises/exercise-2-2-3-route-guards.md`

---

### Exercício 4: Resolvers (Intermediário)

**Objetivo**: Pré-carregar dados antes de ativar rotas

**Descrição**:
Crie resolvers para carregar dados de produtos antes de exibir componente de detalhes.

**Arquivo**: `exercises/exercise-2-2-4-resolvers.md`

---

### Exercício 5: Lazy Loading (Avançado)

**Objetivo**: Implementar carregamento sob demanda

**Descrição**:
Configure lazy loading para módulos de admin e products, demonstrando redução de bundle.

**Arquivo**: `exercises/exercise-2-2-5-lazy-loading.md`

---

### Exercício 6: Preloading Strategies (Avançado)

**Objetivo**: Otimizar carregamento com preloading

**Descrição**:
Implemente estratégia customizada de preloading baseada em prioridade de rotas.

**Arquivo**: `exercises/exercise-2-2-6-preloading.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular Router](https://angular.io/guide/router)**: Guia oficial de roteamento
- **[Route Guards](https://angular.io/guide/router#guards)**: Documentação de guards
- **[Lazy Loading](https://angular.io/guide/lazy-loading-ngmodules)**: Guia de lazy loading
- **[Router API](https://angular.io/api/router/Router)**: Documentação Router

---

## Resumo

### Principais Conceitos

- Rotas definem navegação baseada em URL
- Parâmetros permitem dados dinâmicos na URL
- Guards controlam acesso a rotas
- Resolvers pré-carregam dados
- Lazy loading melhora performance
- Preloading strategies otimizam carregamento

### Pontos-Chave para Lembrar

- Use `provideRouter` para configuração standalone
- Guards devem retornar boolean ou Observable<boolean>
- Resolvers devem retornar Observable ou Promise
- Lazy loading reduz bundle inicial
- Preloading melhora experiência do usuário

### Próximos Passos

- Próxima aula: Formulários Reativos e Validação
- Praticar criando rotas complexas
- Explorar estratégias avançadas de preloading

---

## Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 2.1: Serviços e Injeção de Dependência](./lesson-2-1-servicos-di.md)  
**Próxima Aula**: [Aula 2.3: Formulários Reativos e Validação](./lesson-2-3-formularios-reativos.md)  
**Voltar ao Módulo**: [Módulo 2: Desenvolvimento Intermediário](../modules/module-2-desenvolvimento-intermediario.md)

