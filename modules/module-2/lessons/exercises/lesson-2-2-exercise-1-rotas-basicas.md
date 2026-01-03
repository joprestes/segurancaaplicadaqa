---
layout: exercise
title: "Exercício 2.2.1: Configurar Rotas Básicas"
slug: "rotas-basicas"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **configuração básica de rotas** através da **criação de uma aplicação com múltiplas páginas usando Angular Router**.

Ao completar este exercício, você será capaz de:

- Configurar rotas usando provideRouter
- Criar componentes para diferentes rotas
- Usar routerLink para navegação
- Configurar rota padrão e wildcard
- Entender estrutura básica de roteamento

---

## Descrição

Você precisa criar uma aplicação com três páginas: Home, About e Contact, configurando roteamento básico.

### Contexto

Uma aplicação precisa de navegação entre diferentes páginas sem recarregar a aplicação completa.

### Tarefa

Crie:

1. **Três Componentes**: HomeComponent, AboutComponent, ContactComponent
2. **Configuração de Rotas**: Arquivo de rotas com as três rotas
3. **Navegação**: Menu de navegação usando routerLink
4. **Rota Padrão**: Redirecionar '/' para '/home'
5. **Wildcard**: Redirecionar rotas não encontradas

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Três componentes criados
- [ ] Rotas configuradas em arquivo separado
- [ ] provideRouter configurado no bootstrap
- [ ] Menu de navegação funcional
- [ ] Rota padrão configurada
- [ ] Wildcard route configurada
- [ ] router-outlet presente no AppComponent

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Rotas estão organizadas
- [ ] Navegação funciona corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**app.routes.ts**
```typescript
import { Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { AboutComponent } from './about/about.component';
import { ContactComponent } from './contact/contact.component';

export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
  { path: 'about', component: AboutComponent },
  { path: 'contact', component: ContactComponent },
  { path: '**', redirectTo: '/home' }
];
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

**app.component.ts**
```typescript
import { Component } from '@angular/core';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterModule, CommonModule],
  template: `
    <nav>
      <ul>
        <li><a routerLink="/home" routerLinkActive="active">Home</a></li>
        <li><a routerLink="/about" routerLinkActive="active">About</a></li>
        <li><a routerLink="/contact" routerLinkActive="active">Contact</a></li>
      </ul>
    </nav>
    <router-outlet></router-outlet>
  `,
  styles: [`
    nav ul {
      list-style: none;
      display: flex;
      gap: 1rem;
      padding: 1rem;
      background-color: #f0f0f0;
    }
    
    nav a {
      text-decoration: none;
      color: #333;
      padding: 0.5rem 1rem;
      border-radius: 4px;
    }
    
    nav a.active {
      background-color: #007bff;
      color: white;
    }
  `]
})
export class AppComponent {}
```

**home.component.ts**
```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-home',
  standalone: true,
  template: `
    <div class="page">
      <h1>Home</h1>
      <p>Bem-vindo à página inicial!</p>
    </div>
  `,
  styles: [`
    .page {
      padding: 2rem;
    }
  `]
})
export class HomeComponent {}
```

**about.component.ts**
```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-about',
  standalone: true,
  template: `
    <div class="page">
      <h1>Sobre</h1>
      <p>Esta é a página sobre nós.</p>
    </div>
  `,
  styles: [`
    .page {
      padding: 2rem;
    }
  `]
})
export class AboutComponent {}
```

**contact.component.ts**
```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-contact',
  standalone: true,
  template: `
    <div class="page">
      <h1>Contato</h1>
      <p>Entre em contato conosco!</p>
    </div>
  `,
  styles: [`
    .page {
      padding: 2rem;
    }
  `]
})
export class ContactComponent {}
```

**Explicação da Solução**:

1. Rotas definidas em arquivo separado para organização
2. provideRouter usado para configuração standalone
3. routerLink usado para navegação
4. routerLinkActive para destacar rota ativa
5. router-outlet renderiza componente da rota ativa
6. Rota padrão redireciona para /home
7. Wildcard redireciona rotas não encontradas

---

## Testes

### Casos de Teste

**Teste 1**: Navegação funciona
- **Input**: Clicar em link "About"
- **Output Esperado**: URL muda para /about e AboutComponent é exibido

**Teste 2**: Rota padrão funciona
- **Input**: Acessar URL raiz '/'
- **Output Esperado**: Redireciona para /home

**Teste 3**: Wildcard funciona
- **Input**: Acessar URL inexistente '/xyz'
- **Output Esperado**: Redireciona para /home

---

## Extensões (Opcional)

1. **Breadcrumbs**: Adicione breadcrumbs para navegação
2. **Animações**: Adicione animações de transição entre rotas
3. **Meta Tags**: Adicione meta tags diferentes por rota

---

## Referências Úteis

- **[Angular Router](https://angular.io/guide/router)**: Guia oficial
- **[RouterModule](https://angular.io/api/router/RouterModule)**: Documentação RouterModule

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

