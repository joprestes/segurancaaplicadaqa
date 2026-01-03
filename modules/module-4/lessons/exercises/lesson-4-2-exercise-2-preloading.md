---
layout: exercise
title: "Exercício 4.2.2: Preloading Strategies"
slug: "preloading"
lesson_id: "lesson-4-2"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **preloading strategies** através da **configuração de diferentes estratégias e comparação de resultados**.

Ao completar este exercício, você será capaz de:

- Configurar NoPreloading
- Configurar PreloadAllModules
- Entender diferenças entre estratégias
- Comparar performance e UX
- Escolher estratégia apropriada

---

## Descrição

Você precisa configurar diferentes estratégias de preloading e comparar resultados.

### Contexto

Uma aplicação precisa balancear entre performance inicial e experiência do usuário usando preloading.

### Tarefa

Crie:

1. **NoPreloading**: Configurar sem preloading
2. **PreloadAllModules**: Configurar preload tudo
3. **Comparação**: Comparar ambas estratégias
4. **Análise**: Analisar trade-offs

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] NoPreloading configurado
- [ ] PreloadAllModules configurado
- [ ] Comparação realizada
- [ ] Análise documentada
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Estratégias estão configuradas corretamente
- [ ] Análise é clara

---

## Solução Esperada

### Abordagem Recomendada

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
    loadChildren: () => import('./products/products.routes').then(m => m.routes)
  },
  {
    path: 'cart',
    loadComponent: () => import('./cart/cart.component').then(m => m.CartComponent)
  },
  {
    path: 'admin',
    loadChildren: () => import('./admin/admin.routes').then(m => m.adminRoutes)
  }
];
```

**main-no-preload.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter, NoPreloading } from '@angular/router';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes, {
      preloadingStrategy: NoPreloading
    })
  ]
});
```

**main-preload-all.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter, PreloadAllModules } from '@angular/router';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes, {
      preloadingStrategy: PreloadAllModules
    })
  ]
});
```

**comparison.md**
```markdown
# Comparação de Preloading Strategies

## NoPreloading
- **Bundle Inicial**: Menor
- **Tempo de Carregamento Inicial**: Mais rápido
- **Navegação**: Mais lenta (carrega sob demanda)
- **Uso de Rede**: Menor inicialmente
- **Melhor para**: Aplicações com muitas rotas raramente usadas

## PreloadAllModules
- **Bundle Inicial**: Maior
- **Tempo de Carregamento Inicial**: Mais lento
- **Navegação**: Mais rápida (já carregado)
- **Uso de Rede**: Maior inicialmente
- **Melhor para**: Aplicações onde usuário navega frequentemente

## Recomendação
- Use NoPreloading para rotas raramente acessadas
- Use PreloadAllModules para rotas frequentemente acessadas
- Considere Custom Preloading Strategy para controle fino
```

**Explicação da Solução**:

1. NoPreloading não pré-carrega nada
2. PreloadAllModules pré-carrega tudo após inicialização
3. Comparação mostra trade-offs claros
4. Escolha depende do caso de uso
5. Custom strategy oferece melhor controle

---

## Testes

### Casos de Teste

**Teste 1**: NoPreloading funciona
- **Input**: Navegar para rotas lazy
- **Output Esperado**: Chunks carregados apenas ao navegar

**Teste 2**: PreloadAllModules funciona
- **Input**: Aguardar após carregamento inicial
- **Output Esperado**: Chunks pré-carregados

**Teste 3**: Comparação válida
- **Input**: Comparar Network tab
- **Output Esperado**: Diferenças claras visíveis

---

## Extensões (Opcional)

1. **Performance Metrics**: Meça métricas de performance
2. **User Experience**: Avalie impacto na UX
3. **Custom Strategy**: Crie estratégia customizada

---

## Referências Úteis

- **[Preloading](https://angular.io/guide/router#preloading)**: Guia preloading
- **[NoPreloading](https://angular.io/api/router/NoPreloading)**: Documentação NoPreloading
- **[PreloadAllModules](https://angular.io/api/router/PreloadAllModules)**: Documentação PreloadAllModules

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

