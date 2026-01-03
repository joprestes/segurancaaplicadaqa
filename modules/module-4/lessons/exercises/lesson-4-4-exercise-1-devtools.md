---
layout: exercise
title: "Exercício 4.4.1: Angular DevTools"
slug: "devtools"
lesson_id: "lesson-4-4"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Angular DevTools** através da **instalação e uso do Angular DevTools para inspecionar aplicação**.

Ao completar este exercício, você será capaz de:

- Instalar Angular DevTools
- Inspecionar componente tree
- Verificar change detection
- Identificar problemas de performance
- Usar DevTools para debugging

---

## Descrição

Você precisa instalar e usar Angular DevTools para inspecionar uma aplicação Angular.

### Contexto

Uma aplicação precisa ser inspecionada usando Angular DevTools para entender estrutura e performance.

### Tarefa

Crie:

1. **Instalação**: Instalar Angular DevTools
2. **Inspeção**: Inspecionar componente tree
3. **Análise**: Analisar change detection
4. **Documentação**: Documentar descobertas

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Angular DevTools instalado
- [ ] Componente tree inspecionado
- [ ] Change detection analisado
- [ ] Problemas identificados
- [ ] Documentação criada

### Critérios de Qualidade

- [ ] DevTools está funcionando corretamente
- [ ] Análise é completa
- [ ] Documentação é clara

---

## Solução Esperada

### Abordagem Recomendada

**instalacao.md**
```markdown
# Instalação do Angular DevTools

## Chrome/Edge

1. Abrir Chrome Web Store
2. Buscar "Angular DevTools"
3. Clicar em "Adicionar ao Chrome"
4. Confirmar instalação

## Firefox

1. Abrir Firefox Add-ons
2. Buscar "Angular DevTools"
3. Clicar em "Adicionar ao Firefox"
4. Confirmar instalação

## Verificação

1. Abrir aplicação Angular
2. Abrir DevTools (F12)
3. Verificar aba "Angular"
4. Verificar que componente tree aparece
```

**uso-devtools.md**
```markdown
# Guia de Uso do Angular DevTools

## 1. Component Tree

- Mostra hierarquia de componentes
- Permite selecionar componentes
- Mostra inputs e outputs
- Mostra state de componentes

## 2. Profiler

- Grava change detection cycles
- Mostra tempo de cada componente
- Identifica componentes lentos
- Sugere otimizações

## 3. Dependencies

- Mostra dependências injetadas
- Mostra providers
- Mostra services

## 4. Performance

- Mostra métricas de performance
- Identifica bottlenecks
- Sugere melhorias
```

**app.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './header/header.component';
import { FooterComponent } from './footer/footer.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, HeaderComponent, FooterComponent],
  template: `
    <div>
      <app-header></app-header>
      <main>
        <router-outlet></router-outlet>
      </main>
      <app-footer></app-footer>
    </div>
  `
})
export class AppComponent {}
```

**Explicação da Solução**:

1. Angular DevTools instalado no navegador
2. Aba Angular aparece no DevTools
3. Component tree mostra estrutura
4. Profiler grava change detection
5. Performance insights disponíveis
6. Debugging facilitado

---

## Testes

### Casos de Teste

**Teste 1**: DevTools instalado
- **Input**: Abrir DevTools
- **Output Esperado**: Aba Angular visível

**Teste 2**: Component tree funciona
- **Input**: Inspecionar componentes
- **Output Esperado**: Tree exibido corretamente

**Teste 3**: Profiler funciona
- **Input**: Gravar change detection
- **Output Esperado**: Dados coletados

---

## Extensões (Opcional)

1. **Advanced Profiling**: Explore profiling avançado
2. **Performance Monitoring**: Configure monitoramento contínuo
3. **Team Training**: Treine equipe no uso

---

## Referências Úteis

- **[Angular DevTools](https://angular.io/guide/devtools)**: Guia Angular DevTools
- **[Chrome Extension](https://chrome.google.com/webstore/detail/angular-devtools)**: Extensão Chrome

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

