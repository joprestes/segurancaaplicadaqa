---
layout: exercise
title: "Exercício 3.3.6: NgRx DevTools"
slug: "devtools"
lesson_id: "lesson-3-3"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **NgRx DevTools** através da **configuração e uso de DevTools para debugging**.

Ao completar este exercício, você será capaz de:

- Configurar NgRx DevTools
- Usar DevTools para inspecionar estado
- Usar time-travel debugging
- Entender histórico de actions
- Debuggar problemas de estado

---

## Descrição

Você precisa configurar NgRx DevTools e demonstrar uso para debugging de aplicação NgRx.

### Contexto

Uma aplicação precisa de ferramentas de debugging para entender e resolver problemas de estado.

### Tarefa

Crie:

1. **DevTools Configuration**: Configurar DevTools no bootstrap
2. **Application**: Aplicação NgRx funcional
3. **Debugging**: Demonstrar uso de DevTools
4. **Time-Travel**: Demonstrar time-travel debugging

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] DevTools configurado
- [ ] DevTools funciona no navegador
- [ ] Estado é inspecionável
- [ ] Actions são visíveis
- [ ] Time-travel funciona
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] DevTools está configurado corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { isDevMode } from '@angular/core';
import { provideStore } from '@ngrx/store';
import { provideStoreDevtools } from '@ngrx/store-devtools';
import { AppComponent } from './app/app.component';
import { counterReducer } from './app/store/counter.reducer';
import { userReducer } from './app/store/user.reducer';

bootstrapApplication(AppComponent, {
  providers: [
    provideStore({
      counter: counterReducer,
      users: userReducer
    }),
    provideStoreDevtools({
      maxAge: 25,
      logOnly: !isDevMode(),
      autoPause: true,
      trace: true,
      traceLimit: 75
    })
  ]
});
```

**app.component.ts**
```typescript
import { Component } from '@angular/core';
import { Store } from '@ngrx/store';
import { CounterComponent } from './counter/counter.component';
import { UserListComponent } from './users/user-list.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CounterComponent, UserListComponent],
  template: `
    <div>
      <h1>NgRx DevTools Demo</h1>
      <app-counter></app-counter>
      <app-user-list></app-user-list>
      <p>Abra Redux DevTools no navegador para inspecionar estado</p>
    </div>
  `
})
export class AppComponent {}
```

**Explicação da Solução**:

1. provideStoreDevtools configurado no bootstrap
2. maxAge limita histórico de actions
3. logOnly desabilita em produção
4. autoPause pausa quando DevTools fechado
5. trace habilita stack traces
6. DevTools disponível no navegador

---

## Testes

### Casos de Teste

**Teste 1**: DevTools aparece
- **Input**: Abrir DevTools no navegador
- **Output Esperado**: DevTools mostra estado atual

**Teste 2**: Actions são visíveis
- **Input**: Dispatch actions
- **Output Esperado**: Actions aparecem no DevTools

**Teste 3**: Time-travel funciona
- **Input**: Usar time-travel no DevTools
- **Output Esperado**: Estado volta para versão anterior

---

## Extensões (Opcional)

1. **Export/Import**: Exporte e importe estado
2. **Action Filters**: Configure filtros de actions
3. **State Diff**: Compare diferenças de estado

---

## Referências Úteis

- **[DevTools](https://ngrx.io/guide/store-devtools)**: Guia DevTools
- **[Redux DevTools](https://github.com/reduxjs/redux-devtools)**: Redux DevTools

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

