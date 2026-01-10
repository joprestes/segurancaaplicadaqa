---
layout: lesson
title: "Aula 2.2: DAST: Dynamic Application Security Testing"
slug: dast-testes-dinamicos
module: module-2
lesson_id: lesson-2-2
duration: "90 minutos"
level: "Intermediário"
prerequisites: ["lesson-2-1"]
image: "assets/images/podcasts/2.2-DAST_Testes_Dinamicos.png"
permalink: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

<!-- ⚠️ ATENÇÃO: Este arquivo contém conteúdo sobre Angular que precisa ser reescrito para Segurança em QA. 
     Veja CONTENT_ISSUES.md para mais detalhes. -->

## Introdução

Nesta aula, você dominará o sistema de roteamento do Angular. Roteamento é essencial para criar Single Page Applications (SPAs) profissionais, permitindo navegação entre páginas sem recarregar a aplicação. Você aprenderá desde configuração básica até técnicas avançadas como guards, resolvers e lazy loading.

### Contexto Histórico do Roteamento Angular

O Angular Router é um dos sistemas de roteamento mais poderosos entre os frameworks JavaScript. Sua evolução reflete a evolução do próprio Angular e representa décadas de aprendizado sobre como construir SPAs escaláveis e performáticas.

**Linha do Tempo Detalhada**:

```
AngularJS (2010) ──────────────────────────────────────────── Angular 19+ (2024+)
 │                                                                  │
 ├─ 2010    📦 ngRoute (Básico)                                    │
 │          ┌─────────────────────────────────────┐               │
 │          │ • Roteamento simples baseado em hash │               │
 │          │ • Sem guards ou lazy loading         │               │
 │          │ • Configuração via $routeProvider    │               │
 │          │ • Limitações de performance          │               │
 │          └─────────────────────────────────────┘               │
 │                                                                  │
 ├─ 2014    🚀 ui-router (Comunidade)                              │
 │          ┌─────────────────────────────────────┐               │
 │          │ • Rotas aninhadas (nested states)     │               │
 │          │ • Estados e transições                │               │
 │          │ • Mais flexível que ngRoute           │               │
 │          │ • Adotado pela comunidade             │               │
 │          └─────────────────────────────────────┘               │
 │                                                                  │
 ├─ 2016    🔥 Angular Router (Angular 2)                         │
 │          ┌─────────────────────────────────────┐               │
 │          │ • Router nativo poderoso              │               │
 │          │ • Guards (CanActivate, CanDeactivate)  │               │
 │          │ • Resolvers para pré-carregar dados   │               │
 │          │ • Lazy loading de módulos             │               │
 │          │ • HTML5 History API (sem hash)        │               │
 │          │ • Type-safe com TypeScript            │               │
 │          └─────────────────────────────────────┘               │
 │                                                                  │
 ├─ 2017-2020 📈 Melhorias Incrementais                            │
 │          ┌─────────────────────────────────────┐               │
 │          │ • Angular 5: Preloading strategies    │               │
 │          │ • Angular 6: CanLoad guard            │               │
 │          │ • Angular 7: Route reuse strategy    │               │
 │          │ • Angular 9: Ivy renderer otimizado   │               │
 │          │ • Performance melhorada               │               │
 │          │ • Bundle size reduzido                │               │
 │          └─────────────────────────────────────┘               │
 │                                                                  │
 ├─ 2022    ⚡ Angular 14 - provideRouter()                        │
 │          ┌─────────────────────────────────────┐               │
 │          │ • Standalone routing                  │               │
 │          │ • Função moderna (functional API)     │               │
 │          │ • Melhor tree-shaking                 │               │
 │          │ • Configuração simplificada           │               │
 │          │ • Compatível com standalone components │               │
 │          └─────────────────────────────────────┘               │
 │                                                                  │
 ├─ 2023    🎯 Angular 17+ - Lazy Loading Standalone              │
 │          ┌─────────────────────────────────────┐               │
 │          │ • loadComponent() para componentes    │               │
 │          │ • Performance otimizada               │               │
 │          │ • Bundle splitting inteligente        │               │
 │          │ • Deferrable views                    │               │
 │          │ • SSR improvements                    │               │
 │          └─────────────────────────────────────┘               │
 │                                                                  │
 └─ 2024    🚀 Angular 19+ - Signals Integration                  │
            ┌─────────────────────────────────────┐               │
            │ • Signals no Router                  │               │
            │ • Reactive routing                   │               │
            │ • Zoneless Angular preview            │               │
            │ • Melhorias contínuas                │               │
            └─────────────────────────────────────┘               │
```

**Por que Angular Router é Poderoso?**

O Angular Router não é apenas um sistema de navegação - é uma solução completa para gerenciamento de estado de navegação em aplicações complexas:

- **Type Safety**: Rotas tipadas com TypeScript garantem que erros sejam detectados em tempo de compilação, não em runtime
- **Lazy Loading**: Carregamento sob demanda de módulos/componentes reduz drasticamente o bundle inicial
- **Guards**: Sistema robusto de proteção de rotas com múltiplos tipos (CanActivate, CanDeactivate, CanLoad, CanActivateChild)
- **Resolvers**: Pré-carregamento de dados antes da ativação da rota elimina estados de loading no componente
- **Preloading**: Estratégias inteligentes de pré-carregamento melhoram UX sem comprometer performance inicial
- **Rotas Aninhadas**: Suporte completo para hierarquias complexas de rotas
- **Query Params e State**: Gerenciamento avançado de estado através da URL e navegação programática

### O que você vai aprender

- **Rotas Standalone**: Configuração moderna sem NgModules
- **Parâmetros e Query Params**: Trabalhar com dados na URL
- **Rotas Aninhadas**: Estrutura hierárquica de rotas
- **Route Guards**: Proteção e controle de acesso
- **Resolvers**: Pré-carregamento de dados
- **Lazy Loading**: Carregamento sob demanda para performance
- **Preloading Strategies**: Estratégias de pré-carregamento
- **Navegação Programática**: Navegação via código

### Por que isso é importante

**Para Desenvolvimento**:
- **SPAs Profissionais**: Criação de aplicações single-page modernas
- **Performance**: Lazy loading reduz bundle inicial
- **Segurança**: Guards protegem rotas sensíveis
- **UX**: Navegação fluida sem recarregar página

**Para Projetos**:
- **Escalabilidade**: Estrutura que escala com aplicações grandes
- **Manutenibilidade**: Rotas organizadas e fáceis de manter
- **Performance**: Bundle otimizado com lazy loading
- **Segurança**: Proteção adequada de rotas

**Para Carreira**:
- **Essencial**: Roteamento é fundamental para Angular
- **Diferencial**: Conhecimento de técnicas avançadas
- **Relevância**: Usado em todos os projetos Angular
- **Base Sólida**: Necessário para conceitos avançados

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
┌─────────────────────────────────────────────────────────────┐
│                    Navegação do Usuário                      │
│                  URL: /products/123                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────────────┐
        │      Angular Router (RouterService)    │
        │  ┌───────────────────────────────────┐ │
        │  │ 1. Parse da URL                   │ │
        │  │ 2. Match com rotas configuradas   │ │
        │  │ 3. Verificar guards               │ │
        │  │ 4. Executar resolvers             │ │
        │  │ 5. Ativar rota                    │ │
        │  └───────────────────────────────────┘ │
        └───────────────┬───────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
┌───────────────┐              ┌───────────────┐
│ Path: 'products'              │ Path: ':id'   │
│ Component:                    │ Component:    │
│ ProductListComponent          │ ProductDetail │
│                               │ Component     │
│ ┌───────────────────────────┐ │ ┌───────────┐ │
│ │ • Renderiza lista        │ │ │ • Recebe │ │
│ │ • Mostra todos produtos  │ │ │   id=123  │ │
│ │ • Navegação para detalhe│ │ │ • Carrega │ │
│ └───────────────────────────┘ │ │   produto│ │
└───────────────────────────────┘ └───────────┘ │
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │ Router Outlet   │
                                    │ Renderiza       │
                                    │ ProductDetail   │
                                    │ Component       │
                                    └─────────────────┘
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

```typescript
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

@Component({
  selector: 'app-product-detail',
  standalone: true,
  template: `
    <div>
      <h2>Produto {{ productId }}</h2>
      <button (click)="goToNext()">Próximo Produto</button>
    </div>
  `
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
  template: `
    <div>
      <input [(ngModel)]="searchTerm" (input)="onSearch()">
      <select [(ngModel)]="sortBy" (change)="onSort()">
        <option value="name">Nome</option>
        <option value="price">Preço</option>
      </select>
    </div>
  `
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
┌─────────────────────────────────────────────────────────────┐
│              Estrutura de Rotas Aninhadas                   │
└─────────────────────────────────────────────────────────────┘

                    ┌──────────────────┐
                    │  /admin          │
                    │  AdminLayout     │
                    │  Component       │
                    └────────┬─────────┘
                             │
                             │ <router-outlet>
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ /admin/users  │   │ /admin/products│   │ /admin/settings│
│ UserList      │   │ ProductList    │   │ Settings      │
│ Component     │   │ Component      │   │ Component     │
└───────────────┘   └───────────────┘   └───────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Fluxo de Renderização                    │
└─────────────────────────────────────────────────────────────┘

1. Usuário navega para /admin/users
   │
   ▼
2. Router ativa AdminLayoutComponent
   │
   ▼
3. AdminLayoutComponent renderiza:
   ┌─────────────────────────────────────┐
   │  <nav>                              │
   │    <a routerLink="users">...</a>     │
   │    <a routerLink="products">...</a> │
   │    <a routerLink="settings">...</a> │
   │  </nav>                             │
   │  <router-outlet></router-outlet>    │ ← Aqui renderiza filho
   └─────────────────────────────────────┘
   │
   ▼
4. Router renderiza UserListComponent no <router-outlet>
   ┌─────────────────────────────────────┐
   │  UserListComponent                 │
   │  (renderizado dentro do outlet)    │
   └─────────────────────────────────────┘
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
```

---

### Route Guards

**Definição**: Guards são interfaces que controlam acesso a rotas, permitindo ou bloqueando navegação baseado em condições customizadas. Eles são executados antes, durante ou após a navegação e podem ser síncronos ou assíncronos.

**Explicação Detalhada**:

Guards são uma das características mais poderosas do Angular Router. Eles permitem implementar lógica de autorização, validação e controle de fluxo de navegação de forma declarativa e reutilizável.

**Tipos de Guards e Quando Usar**:

1. **CanActivate**: Controla se uma rota pode ser ativada
   - Executado antes de ativar a rota
   - Útil para: autenticação, autorização, verificação de permissões
   - Retorna: `boolean | UrlTree | Observable<boolean | UrlTree> | Promise<boolean | UrlTree>`

2. **CanActivateChild**: Controla acesso a rotas filhas
   - Executado antes de ativar qualquer rota filha
   - Útil para: proteger todas as rotas filhas de uma vez
   - Retorna: mesmo que CanActivate

3. **CanDeactivate**: Controla se pode sair de uma rota
   - Executado antes de desativar a rota atual
   - Útil para: salvar dados não salvos, confirmar saída
   - Retorna: `boolean | UrlTree | Observable<boolean | UrlTree> | Promise<boolean | UrlTree>`

4. **CanLoad**: Controla carregamento de módulos lazy
   - Executado antes de carregar módulo lazy
   - Útil para: evitar carregar código não autorizado
   - Retorna: `boolean | UrlTree | Observable<boolean | UrlTree> | Promise<boolean | UrlTree>`

5. **Resolve**: Pré-carrega dados antes de ativar rota
   - Executado antes de ativar a rota
   - Útil para: garantir dados disponíveis antes de renderizar
   - Retorna: `Observable<T> | Promise<T> | T`

**Fluxo de Execução dos Guards**:

```
┌─────────────────────────────────────────────────────────────┐
│              Fluxo de Execução de Guards                    │
└─────────────────────────────────────────────────────────────┘

1. Usuário tenta navegar para /admin/users
   │
   ▼
2. Router verifica CanLoad (se rota é lazy)
   │
   ├─ false → Bloqueia navegação
   └─ true → Continua
   │
   ▼
3. Router verifica CanActivate (rota atual)
   │
   ├─ false → Redireciona ou bloqueia
   └─ true → Continua
   │
   ▼
4. Router verifica CanActivateChild (rotas filhas)
   │
   ├─ false → Bloqueia acesso a filhas
   └─ true → Continua
   │
   ▼
5. Router executa Resolvers (pré-carrega dados)
   │
   ▼
6. Router ativa rota e renderiza componente
   │
   ▼
7. Se usuário tentar sair:
   │
   ▼
8. Router verifica CanDeactivate
   │
   ├─ false → Cancela navegação
   └─ true → Permite saída
```

**Analogia Detalhada**:

Guards são como um sistema de segurança em múltiplas camadas de um prédio corporativo:

- **CanActivate** = Porteiro na entrada principal: verifica se você tem autorização para entrar no prédio
- **CanActivateChild** = Segurança no elevador: verifica se você pode acessar andares específicos
- **CanDeactivate** = Verificação ao sair: confirma se você não está deixando nada importante para trás (como documentos confidenciais abertos)
- **CanLoad** = Controle de acesso ao estacionamento: evita que você entre no prédio se não tem permissão para estacionar
- **Resolve** = Preparação antecipada: garante que sua mesa está pronta e documentos estão disponíveis antes de você chegar

**Hierarquia de Execução**:

```
┌─────────────────────────────────────────────────────────────┐
│         Ordem de Execução dos Guards                        │
└─────────────────────────────────────────────────────────────┘

Rota Lazy: /admin (lazy loaded)
│
├─ 1. CanLoad (/admin) ← Verifica antes de carregar módulo
│   │
│   └─ Se true → Carrega módulo
│
├─ 2. CanActivate (/admin) ← Verifica acesso à rota pai
│   │
│   └─ Se true → Continua
│
├─ 3. CanActivateChild (/admin) ← Verifica acesso a filhos
│   │
│   └─ Se true → Continua
│
├─ 4. Resolve (/admin) ← Pré-carrega dados da rota pai
│   │
│   └─ Aguarda dados
│
└─ 5. Ativa rota e renderiza componente
    │
    └─ Se usuário tentar sair:
        │
        └─ 6. CanDeactivate (/admin) ← Verifica se pode sair
```

**Múltiplos Guards**:

Quando múltiplos guards são aplicados, eles são executados em sequência. Todos devem retornar `true` para a navegação prosseguir:

```typescript
{
  path: 'admin',
  canActivate: [authGuard, roleGuard, subscriptionGuard],
  component: AdminComponent
}
```

Fluxo: `authGuard` → `roleGuard` → `subscriptionGuard` → Se todos `true` → Ativa rota

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

**Definição**: Resolvers são funções que pré-carregam dados antes que uma rota seja ativada, garantindo que os dados estejam disponíveis quando o componente é renderizado.

**Explicação Detalhada**:

Resolvers resolvem um problema comum em SPAs: componentes que precisam de dados da API mas não querem mostrar estados de loading. Com resolvers, os dados são carregados antes da navegação completar, resultando em uma experiência mais fluida.

**Por que Usar Resolvers?**

**Sem Resolver** (Problema):
```
1. Usuário navega para /products/123
2. Router ativa ProductDetailComponent
3. Componente renderiza com estado vazio
4. Componente faz chamada HTTP
5. Usuário vê loading spinner
6. Dados chegam e componente atualiza
```

**Com Resolver** (Solução):
```
1. Usuário navega para /products/123
2. Router executa productResolver
3. Resolver faz chamada HTTP
4. Router aguarda dados chegarem
5. Router ativa ProductDetailComponent com dados prontos
6. Componente renderiza diretamente com dados
```

**Vantagens dos Resolvers**:
- ✅ Elimina estados de loading no componente
- ✅ Centraliza lógica de carregamento de dados
- ✅ Tratamento de erros centralizado
- ✅ Dados sempre disponíveis quando componente renderiza
- ✅ Melhor UX (sem "flash" de conteúdo vazio)

**Desvantagens dos Resolvers**:
- ❌ Navegação bloqueada até dados carregarem (pode parecer lenta)
- ❌ Não ideal para dados que mudam frequentemente
- ❌ Adiciona complexidade à configuração de rotas

**Quando Usar Resolvers**:
- ✅ Dados críticos que sempre são necessários
- ✅ Dados que raramente mudam
- ✅ Quando UX sem loading é importante
- ✅ Quando lógica de carregamento é complexa

**Quando NÃO Usar Resolvers**:
- ❌ Dados opcionais ou secundários
- ❌ Dados que mudam frequentemente
- ❌ Quando loading rápido é mais importante que dados pré-carregados
- ❌ Dados que dependem de interação do usuário

**Analogia Detalhada**:

Resolvers são como um restaurante de alta qualidade:

**Sem Resolver** = Restaurante comum:
- Você chega e senta na mesa
- Garçom traz o cardápio
- Você escolhe o prato
- Cozinha prepara (você espera)
- Prato chega na mesa

**Com Resolver** = Restaurante com menu degustação pré-definido:
- Você reserva e informa preferências antecipadamente
- Cozinha prepara tudo antes de você chegar
- Você chega e senta na mesa
- Prato já está pronto e é servido imediatamente
- Experiência mais fluida, sem espera

**Fluxo de Execução**:

```
┌─────────────────────────────────────────────────────────────┐
│              Fluxo de Execução de Resolvers                 │
└─────────────────────────────────────────────────────────────┘

1. Usuário clica em link para /products/123
   │
   ▼
2. Router intercepta navegação
   │
   ▼
3. Router verifica se rota tem resolvers configurados
   │
   ├─ Não tem → Ativa rota imediatamente
   └─ Tem → Continua
   │
   ▼
4. Router executa todos os resolvers em paralelo
   │
   ├─ productResolver → HTTP GET /api/products/123
   ├─ userResolver → HTTP GET /api/user
   └─ reviewsResolver → HTTP GET /api/products/123/reviews
   │
   ▼
5. Router aguarda TODOS os resolvers completarem
   │
   ├─ Se algum falhar → Navegação pode ser cancelada ou erro tratado
   └─ Se todos sucederem → Continua
   │
   ▼
6. Router armazena dados em ActivatedRoute.data
   │
   ▼
7. Router ativa rota e renderiza componente
   │
   ▼
8. Componente acessa dados via route.snapshot.data ou route.data
   │
   └─ Dados já estão disponíveis, sem necessidade de loading!
```

**Múltiplos Resolvers**:

Você pode ter múltiplos resolvers que executam em paralelo:

```typescript
{
  path: 'products/:id',
  resolve: {
    product: productResolver,    // Executa em paralelo
    reviews: reviewsResolver,     // Executa em paralelo
    related: relatedResolver      // Executa em paralelo
  },
  component: ProductDetailComponent
}
```

Todos os resolvers executam simultaneamente e o componente só é ativado quando todos completam.

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

```typescript
@Component({
  selector: 'app-product-detail',
  standalone: true,
  template: `
    <div *ngIf="product">
      <h2>{{ product.name }}</h2>
      <p>{{ product.description }}</p>
    </div>
  `
})
export class ProductDetailComponent {
  product: Product | null = null;
  
  constructor(private route: ActivatedRoute) {
    this.product = this.route.snapshot.data['product'];
  }
}
```

---

### Lazy Loading

**Definição**: Lazy Loading é uma técnica que carrega módulos ou componentes apenas quando são necessários, ao invés de incluí-los no bundle inicial da aplicação. Isso reduz drasticamente o tamanho do bundle inicial e melhora o tempo de carregamento.

**Explicação Detalhada**:

Lazy loading é uma das técnicas mais importantes para otimização de performance em aplicações Angular grandes. Sem lazy loading, toda a aplicação é carregada de uma vez, mesmo que o usuário nunca visite certas rotas.

**Como Funciona**:

```
┌─────────────────────────────────────────────────────────────┐
│              Comparação: Eager vs Lazy Loading              │
└─────────────────────────────────────────────────────────────┘

EAGER LOADING (Sem Lazy):
┌─────────────────────────────────────────────────────────┐
│ Bundle Inicial (main.js)                                 │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│ │  Home    │ │ Products │ │  Admin   │ │ Settings │   │
│ │ Component│ │ Component│ │ Component│ │ Component│   │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│                                                          │
│ Tamanho: 2.5MB                                           │
│ Tempo de carregamento: 5s                                │
│ Usuário vê: Tudo carregado de uma vez                    │
└─────────────────────────────────────────────────────────┘

LAZY LOADING (Com Lazy):
┌─────────────────────────────────────────────────────────┐
│ Bundle Inicial (main.js)                                 │
│ ┌──────────┐                                            │
│ │  Home    │                                            │
│ │ Component│                                            │
│ └──────────┘                                            │
│                                                          │
│ Tamanho: 500KB                                           │
│ Tempo de carregamento: 1s                                │
│ Usuário vê: Apenas Home carregado                       │
└─────────────────────────────────────────────────────────┘
         │
         │ Quando usuário navega para /admin
         ▼
┌─────────────────────────────────────────────────────────┐
│ Bundle Lazy (admin.js) - Carregado sob demanda          │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐               │
│ │  Admin   │ │  Users   │ │ Settings │               │
│ │ Component│ │ Component│ │ Component│               │
│ └──────────┘ └──────────┘ └──────────┘               │
│                                                          │
│ Tamanho: 800KB (carregado apenas quando necessário)     │
│ Tempo de carregamento: 2s (apenas quando necessário)    │
└─────────────────────────────────────────────────────────┘
```

**Vantagens do Lazy Loading**:
- ✅ Bundle inicial drasticamente menor
- ✅ Tempo de carregamento inicial reduzido
- ✅ Melhor First Contentful Paint (FCP)
- ✅ Melhor Time to Interactive (TTI)
- ✅ Código carregado apenas quando necessário
- ✅ Melhor experiência para usuários em conexões lentas

**Desvantagens do Lazy Loading**:
- ❌ Pequeno delay ao navegar para rotas lazy (primeira vez)
- ❌ Múltiplas requisições HTTP (um bundle por rota lazy)
- ❌ Complexidade adicional na configuração
- ❌ Pode causar "flash" de loading se não tratado

**Quando Usar Lazy Loading**:
- ✅ Features grandes e independentes
- ✅ Rotas administrativas (não acessadas por todos)
- ✅ Módulos de relatórios ou analytics
- ✅ Qualquer feature que não seja crítica para o carregamento inicial
- ✅ Aplicações com múltiplas áreas funcionais

**Quando NÃO Usar Lazy Loading**:
- ❌ Componentes pequenos e frequentemente usados
- ❌ Rotas críticas que sempre são acessadas
- ❌ Quando o overhead de múltiplos bundles é maior que o benefício
- ❌ Aplicações muito pequenas (onde bundle único é aceitável)

**Analogia Detalhada**:

Lazy loading é como uma biblioteca digital inteligente:

**Sem Lazy Loading** = Baixar todos os livros de uma vez:
- Você quer ler "Harry Potter"
- Biblioteca baixa TODOS os 10.000 livros disponíveis
- Você espera 2 horas para tudo baixar
- Finalmente pode começar a ler
- Mas você só vai ler 1 livro mesmo

**Com Lazy Loading** = Baixar apenas o que você vai ler:
- Você quer ler "Harry Potter"
- Biblioteca baixa apenas "Harry Potter" (30 segundos)
- Você começa a ler imediatamente
- Se quiser outro livro depois, baixa na hora
- Experiência muito mais rápida e eficiente

**Tipos de Lazy Loading**:

1. **Lazy Loading de Módulos** (Angular tradicional):
```typescript
{
  path: 'admin',
  loadChildren: () => import('./admin/admin.module').then(m => m.AdminModule)
}
```

2. **Lazy Loading de Rotas Standalone** (Angular 14+):
```typescript
{
  path: 'admin',
  loadChildren: () => import('./admin/admin.routes').then(m => m.adminRoutes)
}
```

3. **Lazy Loading de Componentes** (Angular 17+):
```typescript
{
  path: 'admin',
  loadComponent: () => import('./admin/admin.component').then(m => m.AdminComponent)
}
```

**Fluxo de Carregamento Lazy**:

```
┌─────────────────────────────────────────────────────────────┐
│              Fluxo de Lazy Loading                          │
└─────────────────────────────────────────────────────────────┘

1. Usuário navega para /admin (rota lazy)
   │
   ▼
2. Router verifica se módulo/componente já foi carregado
   │
   ├─ Já carregado → Ativa rota imediatamente
   └─ Não carregado → Continua
   │
   ▼
3. Router executa função loadChildren/loadComponent
   │
   ▼
4. Browser faz requisição HTTP para bundle lazy
   │
   ├─ admin.module.js (módulo)
   ├─ admin.routes.js (rotas standalone)
   └─ admin.component.js (componente standalone)
   │
   ▼
5. Browser baixa e executa código JavaScript
   │
   ▼
6. Router registra rotas/módulo carregado
   │
   ▼
7. Router ativa rota normalmente
   │
   ▼
8. Componente renderiza
   │
   └─ Próximas navegações para /admin são instantâneas
      (código já está em cache)
```

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

## Comparação com Outros Frameworks

### Angular Router vs React Router vs Vue Router

O roteamento é uma necessidade fundamental em SPAs, mas cada framework implementa de forma diferente. Entender essas diferenças ajuda a escolher a melhor solução para cada projeto.

**Tabela Comparativa Detalhada**:

| Aspecto | Angular Router | React Router | Vue Router |
|---------|----------------|--------------|------------|
| **Tipo** | Framework integrado | Biblioteca externa | Biblioteca oficial |
| **Configuração** | Declarativa (Routes array) | Declarativa (JSX/Components) | Declarativa (Routes array) |
| **Type Safety** | ✅ Nativo TypeScript | ⚠️ Com @types/react-router | ✅ Nativo TypeScript |
| **Guards** | ✅ CanActivate, CanDeactivate, CanLoad | ⚠️ Component-based (Navigate) | ✅ beforeEnter, beforeRouteEnter |
| **Resolvers** | ✅ ResolveFn (pré-carregamento) | ⚠️ loaders (React Router v6.4+) | ✅ beforeRouteEnter |
| **Lazy Loading** | ✅ loadChildren, loadComponent | ✅ React.lazy + Suspense | ✅ Dynamic imports |
| **Rotas Aninhadas** | ✅ children (nativo) | ✅ Outlet (nativo) | ✅ children (nativo) |
| **Query Params** | ✅ queryParamMap Observable | ✅ useSearchParams Hook | ✅ $route.query |
| **State Management** | ✅ Router state + NavigationExtras | ✅ location.state | ✅ $route.meta |
| **Preloading** | ✅ Múltiplas estratégias | ⚠️ Manual | ⚠️ Manual |
| **Bundle Size** | ~15KB (gzipped) | ~5KB (gzipped) | ~8KB (gzipped) |
| **Curva de Aprendizado** | Média-Alta | Baixa-Média | Baixa |
| **Documentação** | Excelente | Boa | Excelente |
| **Comunidade** | Grande (Google) | Muito Grande | Grande |

**Análise Detalhada por Framework**:

#### Angular Router - O Sistema Completo

**Vantagens**:
- ✅ Integração profunda com Angular (DI, Zones, Change Detection)
- ✅ Type safety completo com TypeScript
- ✅ Sistema robusto de guards com múltiplos tipos
- ✅ Resolvers para pré-carregamento de dados
- ✅ Preloading strategies avançadas
- ✅ Lazy loading de módulos e componentes standalone
- ✅ Suporte completo a rotas aninhadas
- ✅ Observable-based para reatividade

**Desvantagens**:
- ❌ Bundle size maior que alternativas
- ❌ Curva de aprendizado mais íngreme
- ❌ Acoplado ao Angular (não pode usar isoladamente)
- ❌ Configuração pode ser verbosa para casos simples

**Quando Usar**:
- Projetos Angular existentes
- Aplicações enterprise que precisam de guards robustos
- Quando type safety é crítico
- Quando precisa de preloading strategies avançadas

#### React Router - A Solução Flexível

**Vantagens**:
- ✅ Bundle size pequeno
- ✅ Muito flexível e extensível
- ✅ Grande comunidade e ecossistema
- ✅ Hooks modernos (useNavigate, useParams)
- ✅ Suporte a Suspense para loading states
- ✅ Pode ser usado com qualquer biblioteca de estado

**Desvantagens**:
- ❌ Type safety requer configuração adicional
- ❌ Guards menos robustos (baseados em componentes)
- ❌ Preloading manual (sem estratégias built-in)
- ❌ Resolvers só disponíveis em versões recentes (loaders)

**Quando Usar**:
- Projetos React existentes
- Quando precisa de máxima flexibilidade
- Quando bundle size é crítico
- Quando prefere hooks ao invés de classes

#### Vue Router - O Equilíbrio

**Vantagens**:
- ✅ Type safety nativo
- ✅ API simples e intuitiva
- ✅ Integração profunda com Vue (reactive)
- ✅ Guards baseados em funções
- ✅ Suporte a rotas dinâmicas e aninhadas
- ✅ Bundle size razoável

**Desvantagens**:
- ❌ Preloading manual
- ❌ Menos recursos avançados que Angular Router
- ❌ Comunidade menor que React Router
- ❌ Menos estratégias de otimização built-in

**Quando Usar**:
- Projetos Vue existentes
- Quando precisa de simplicidade
- Quando type safety é importante mas não crítico
- Quando prefere Vue ecosystem

**Tabela de Recursos Específicos**:

| Recurso | Angular Router | React Router | Vue Router |
|---------|----------------|--------------|------------|
| **Guards Assíncronos** | ✅ Observable/Promise | ⚠️ Component-based | ✅ Funções assíncronas |
| **Route Data** | ✅ ResolveFn | ⚠️ loaders (v6.4+) | ✅ beforeRouteEnter |
| **Preloading** | ✅ PreloadAllModules, Custom | ❌ Manual | ❌ Manual |
| **Route Reuse** | ✅ RouteReuseStrategy | ⚠️ Manual | ✅ keep-alive |
| **Scroll Position** | ✅ ScrollPositionRestoration | ⚠️ Manual | ✅ scrollBehavior |
| **Route Transitions** | ⚠️ Com @angular/animations | ⚠️ Com bibliotecas | ✅ Transitions |

**Diagrama Comparativo de Arquitetura**:

```
┌─────────────────────────────────────────────────────────────┐
│              Comparação de Fluxo de Navegação               │
└─────────────────────────────────────────────────────────────┘

ANGULAR ROUTER:
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   URL    │───▶│  Router  │───▶│  Guards  │───▶│ Resolver │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
                                                      │
                                                      ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│Component │◀───│  Render  │◀───│  Activate│◀───│  Data    │
└──────────┘    └──────────┘    └──────────┘    └──────────┘

REACT ROUTER:
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   URL    │───▶│  Router  │───▶│ Navigate │───▶│ Loader   │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
                                                      │
                                                      ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│Component │◀───│ Suspense │◀───│  Render  │◀───│  Data    │
└──────────┘    └──────────┘    └──────────┘    └──────────┘

VUE ROUTER:
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   URL    │───▶│  Router  │───▶│beforeEnter│───▶│beforeRoute│
└──────────┘    └──────────┘    └──────────┘    └──────────┘
                                                      │
                                                      ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│Component │◀───│  Render  │◀───│  Activate│◀───│  Data    │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
```

**Decisão: Qual Framework Escolher?**

```
┌─────────────────────────────────────────────────────────────┐
│              Matriz de Decisão para Roteamento              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Você já está usando Angular?                                 │
│   ├─ SIM → Use Angular Router (integrado)                   │
│   └─ NÃO → Continue...                                      │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ Você precisa de guards robustos e resolvers?                │
│   ├─ SIM → Angular Router ou Vue Router                     │
│   └─ NÃO → Continue...                                      │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ Bundle size é crítico?                                      │
│   ├─ SIM → React Router (menor)                             │
│   └─ NÃO → Continue...                                      │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ Você prefere TypeScript nativo?                             │
│   ├─ SIM → Angular Router ou Vue Router                     │
│   └─ NÃO → React Router (com @types)                        │
└─────────────────────────────────────────────────────────────┘
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

### Exemplo 3: Guard Assíncrono com Observable

**Contexto**: Criar guard que verifica autenticação de forma assíncrona.

**Código**:

```typescript
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { map, take } from 'rxjs/operators';
import { AuthService } from './auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  return authService.isAuthenticated$().pipe(
    take(1),
    map(isAuthenticated => {
      if (isAuthenticated) {
        return true;
      }
      router.navigate(['/login'], { 
        queryParams: { returnUrl: state.url } 
      });
      return false;
    })
  );
};
```

---

### Exemplo 4: CanDeactivate Guard para Formulários

**Contexto**: Prevenir saída de rota se formulário tem alterações não salvas.

**Código**:

```typescript
import { inject } from '@angular/core';
import { CanDeactivateFn } from '@angular/router';
import { Observable } from 'rxjs';

export interface CanComponentDeactivate {
  canDeactivate: () => Observable<boolean> | Promise<boolean> | boolean;
}

export const unsavedChangesGuard: CanDeactivateFn<CanComponentDeactivate> = (
  component: CanComponentDeactivate
) => {
  return component.canDeactivate ? component.canDeactivate() : true;
};
```

**Uso no Componente**:

```typescript
@Component({
  selector: 'app-product-form',
  standalone: true,
  template: `...`
})
export class ProductFormComponent implements CanComponentDeactivate {
  form: FormGroup;
  hasUnsavedChanges = false;
  
  constructor(private dialog: MatDialog) {}
  
  canDeactivate(): boolean {
    if (this.hasUnsavedChanges) {
      return this.dialog.open(ConfirmDialogComponent).afterClosed();
    }
    return true;
  }
}
```

---

### Exemplo 5: Resolver com Tratamento de Erros

**Contexto**: Criar resolver robusto com tratamento de erros.

**Código**:

```typescript
import { inject } from '@angular/core';
import { ResolveFn, Router } from '@angular/router';
import { catchError, of } from 'rxjs';
import { ProductService } from './product.service';
import { Product } from './product.model';

export const productResolver: ResolveFn<Product | null> = (route, state) => {
  const productService = inject(ProductService);
  const router = inject(Router);
  const productId = route.paramMap.get('id');
  
  if (!productId) {
    router.navigate(['/products']);
    return of(null);
  }
  
  return productService.getProduct(productId).pipe(
    catchError(error => {
      console.error('Error loading product:', error);
      router.navigate(['/products']);
      return of(null);
    })
  );
};
```

---

### Exemplo 6: Sistema Completo com Preloading Customizado

**Contexto**: Criar sistema completo com estratégia de preloading personalizada.

**Código**:

```typescript
import { PreloadingStrategy, Route } from '@angular/router';
import { Observable, of, timer } from 'rxjs';
import { mergeMap } from 'rxjs/operators';

export class SelectivePreloadingStrategy implements PreloadingStrategy {
  preload(route: Route, load: () => Observable<any>): Observable<any> {
    if (route.data && route.data['preload'] === true) {
      const delay = route.data['preloadDelay'] || 0;
      return timer(delay).pipe(mergeMap(() => load()));
    }
    return of(null);
  }
}
```

**Configuração**:

```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter, withPreloading } from '@angular/router';
import { AppComponent } from './app.component';
import { routes } from './app.routes';
import { SelectivePreloadingStrategy } from './selective-preloading-strategy';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(
      routes,
      withPreloading(SelectivePreloadingStrategy)
    )
  ]
});
```

**Uso nas Rotas**:

```typescript
export const routes: Routes = [
  {
    path: 'admin',
    data: { preload: true, preloadDelay: 5000 },
    loadChildren: () => import('./admin/admin.routes').then(m => m.adminRoutes)
  },
  {
    path: 'reports',
    data: { preload: false },
    loadChildren: () => import('./reports/reports.routes').then(m => m.reportsRoutes)
  }
];
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use lazy loading para features grandes**
   - **Por quê**: Reduz bundle inicial e melhora performance
   - **Exemplo**: `loadChildren: () => import('./feature/feature.routes')`
   - **Benefício**: Bundle inicial pode ser reduzido em 60-80%

2. **Use guards para proteger rotas**
   - **Por quê**: Segurança e controle de acesso
   - **Exemplo**: `canActivate: [authGuard]`
   - **Benefício**: Previne acesso não autorizado antes mesmo de carregar código

3. **Use resolvers para pré-carregar dados críticos**
   - **Por quê**: Melhora UX evitando estados de loading
   - **Exemplo**: `resolve: { product: productResolver }`
   - **Benefício**: Componente renderiza com dados prontos, sem "flash" de conteúdo vazio

4. **Organize rotas em arquivos separados**
   - **Por quê**: Mantém código organizado e escalável
   - **Exemplo**: `app.routes.ts`, `admin.routes.ts`, `products.routes.ts`
   - **Benefício**: Facilita manutenção e colaboração em equipe

5. **Use pathMatch: 'full' em redirects**
   - **Por quê**: Evita matches parciais indesejados
   - **Exemplo**: `{ path: '', redirectTo: '/home', pathMatch: 'full' }`
   - **Benefício**: Comportamento previsível e sem bugs sutis

6. **Unsubscribe de paramMap e queryParamMap**
   - **Por quê**: Previne memory leaks
   - **Exemplo**: Use `takeUntilDestroyed()` ou unsubscribe manual
   - **Benefício**: Aplicação não acumula subscriptions órfãs

7. **Use RouterLinkActive para indicar rota ativa**
   - **Por quê**: Melhora UX mostrando navegação atual
   - **Exemplo**: `<a routerLink="/home" routerLinkActive="active">Home</a>`
   - **Benefício**: Usuário sempre sabe onde está

8. **Configure scrollPositionRestoration**
   - **Por quê**: Controla comportamento de scroll ao navegar
   - **Exemplo**: `provideRouter(routes, withViewTransitions(), withComponentInputBinding())`
   - **Benefício**: UX consistente em diferentes navegações

9. **Use route data para metadados**
   - **Por quê**: Passa informações estáticas sem query params
   - **Exemplo**: `{ path: 'admin', data: { requiresAuth: true, title: 'Admin' } }`
   - **Benefício**: Informações acessíveis sem poluir URL

10. **Trate erros de navegação**
    - **Por quê**: Previne crashes silenciosos
    - **Exemplo**: `router.events.pipe(filter(e => e instanceof NavigationError)).subscribe(...)`
    - **Benefício**: Aplicação mais robusta e debuggável

11. **Use relative navigation quando apropriado**
    - **Por quê**: Código mais flexível e menos acoplado
    - **Exemplo**: `router.navigate(['../sibling'], { relativeTo: this.route })`
    - **Benefício**: Componentes podem ser movidos sem quebrar navegação

12. **Configure preloading strategy**
    - **Por quê**: Balanceia performance inicial vs experiência posterior
    - **Exemplo**: `withPreloading(PreloadAllModules)` ou estratégia customizada
    - **Benefício**: Navegação futura mais rápida sem comprometer inicial

### ❌ Anti-padrões Comuns

1. **Não use guards síncronos para operações assíncronas**
   - **Problema**: Pode causar race conditions e comportamento imprevisível
   - **Solução**: Use observables ou promises corretamente
   - **Exemplo Ruim**: `if (this.authService.isAuthenticated())` (pode estar pendente)
   - **Exemplo Bom**: `return this.authService.isAuthenticated$()`

2. **Não ignore tratamento de erros em guards**
   - **Problema**: Aplicação pode travar ou ficar em estado inconsistente
   - **Solução**: Sempre trate erros e redirecione apropriadamente
   - **Exemplo Ruim**: `return this.service.getData()` (sem catch)
   - **Exemplo Bom**: `return this.service.getData().pipe(catchError(() => of(false)))`

3. **Não carregue tudo no bundle inicial**
   - **Problema**: Performance ruim, especialmente em conexões lentas
   - **Solução**: Use lazy loading para features não críticas
   - **Exemplo Ruim**: Importar todos os módulos em `app.module.ts`
   - **Exemplo Bom**: `loadChildren: () => import('./feature/feature.routes')`

4. **Não use pathMatch: 'prefix' quando deveria ser 'full'**
   - **Problema**: Redirects podem ser acionados incorretamente
   - **Solução**: Use `pathMatch: 'full'` para redirects de rota vazia
   - **Exemplo Ruim**: `{ path: '', redirectTo: '/home' }` (sem pathMatch)
   - **Exemplo Bom**: `{ path: '', redirectTo: '/home', pathMatch: 'full' }`

5. **Não esqueça de unsubscribe de observables do router**
   - **Problema**: Memory leaks e subscriptions órfãs
   - **Solução**: Use `takeUntilDestroyed()` ou unsubscribe manual
   - **Exemplo Ruim**: `this.route.paramMap.subscribe(...)` sem unsubscribe
   - **Exemplo Bom**: `this.route.paramMap.pipe(takeUntilDestroyed()).subscribe(...)`

6. **Não use navegação absoluta quando relativa é melhor**
   - **Problema**: Código frágil e difícil de refatorar
   - **Solução**: Use navegação relativa quando apropriado
   - **Exemplo Ruim**: `router.navigate(['/admin/users'])` de dentro de `/admin`
   - **Exemplo Bom**: `router.navigate(['users'], { relativeTo: this.route })`

7. **Não coloque lógica de negócio em guards**
   - **Problema**: Guards ficam difíceis de testar e manter
   - **Solução**: Mantenha guards simples, delegue lógica para serviços
   - **Exemplo Ruim**: Guard com 100 linhas de lógica de negócio
   - **Exemplo Bom**: Guard chama `authService.canAccess()` e retorna resultado

8. **Não use resolvers para dados que mudam frequentemente**
   - **Problema**: Dados podem estar desatualizados quando componente renderiza
   - **Solução**: Use resolvers apenas para dados estáticos ou raramente alterados
   - **Exemplo Ruim**: Resolver para dados em tempo real (chat, notificações)
   - **Exemplo Bom**: Resolver para dados de produto que raramente mudam

9. **Não ignore o tratamento de erros em resolvers**
   - **Problema**: Navegação pode travar se resolver falhar
   - **Solução**: Sempre trate erros e retorne fallback ou redirecione
   - **Exemplo Ruim**: `return this.service.getData()` sem tratamento
   - **Exemplo Bom**: `return this.service.getData().pipe(catchError(() => router.navigate(['/error'])))`

10. **Não use query params para dados sensíveis**
    - **Problema**: Dados visíveis na URL e no histórico do navegador
    - **Solução**: Use Router state ou serviços para dados sensíveis
    - **Exemplo Ruim**: `?token=abc123&password=secret` na URL
    - **Exemplo Bom**: `router.navigate(['/admin'], { state: { token: 'abc123' } })`

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

- **[Angular Router Guide](https://angular.dev/guide/routing)**: Guia completo oficial de roteamento no Angular
- **[Route Guards](https://angular.dev/guide/routing/router-guards)**: Documentação detalhada sobre guards e proteção de rotas
- **[Lazy Loading](https://angular.dev/guide/routing/lazy-loading)**: Guia completo sobre lazy loading de módulos e componentes
- **[Router API Reference](https://angular.dev/api/router)**: Documentação completa da API do Router
- **[ActivatedRoute API](https://angular.dev/api/router/ActivatedRoute)**: Documentação sobre ActivatedRoute e acesso a parâmetros
- **[RouterLink Directive](https://angular.dev/api/router/RouterLink)**: Documentação sobre diretiva RouterLink
- **[Preloading Strategies](https://angular.dev/guide/routing/preloading)**: Guia sobre estratégias de preloading

### Artigos e Tutoriais

- **[Angular Router: Complete Guide](https://www.angulararchitects.io/en/blog/angular-router-complete-guide/)**: Guia completo sobre Angular Router por Angular Architects
- **[Understanding Angular Route Guards](https://www.digitalocean.com/community/tutorials/angular-route-guards)**: Tutorial detalhado sobre guards
- **[Angular Lazy Loading Best Practices](https://blog.angular.io/angular-lazy-loading-best-practices-2023)**: Melhores práticas de lazy loading
- **[Angular Router: Advanced Patterns](https://indepth.dev/posts/1143/angular-router-series-pillar-1-navigation-basics)**: Padrões avançados de roteamento
- **[Type-Safe Routing in Angular](https://netbasal.com/type-safe-routing-in-angular-64c2983b128e)**: Como criar rotas type-safe

### Vídeos

- **[Angular Router Tutorial - Complete Guide](https://www.youtube.com/watch?v=Nehk4tBxD4o)**: Tutorial completo em vídeo sobre roteamento
- **[Angular Guards Explained](https://www.youtube.com/watch?v=O27K3X3v8-M)**: Explicação detalhada sobre guards
- **[Lazy Loading in Angular](https://www.youtube.com/watch?v=5pYjfykZbQI)**: Tutorial sobre lazy loading

### Ferramentas e Recursos

- **[Angular DevTools](https://angular.dev/tools/devtools)**: Ferramenta de debug que inclui inspeção de rotas
- **[Angular CLI Route Generator](https://angular.dev/cli/generate#route)**: Gerador de rotas do Angular CLI
- **[RxJS Operators for Router](https://rxjs.dev/guide/operators)**: Operadores RxJS úteis para trabalhar com router events

### Comunidade e Suporte

- **[Angular GitHub - Router Issues](https://github.com/angular/angular/issues?q=is%3Aissue+label%3Arouter)**: Issues e discussões sobre router no GitHub
- **[Stack Overflow - Angular Router](https://stackoverflow.com/questions/tagged/angular-router)**: Perguntas e respostas da comunidade
- **[Angular Discord](https://discord.gg/angular)**: Comunidade Discord do Angular para suporte em tempo real

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
