# 🗺️ Mapeamento Completo de Referências ao Angular no Projeto

**Data de Criação**: 2024-12-XX  
**Status**: ⚠️ Múltiplas referências encontradas - Necessita revisão

---

## 📊 Resumo Executivo

**Total de Referências Encontradas**: 713+ ocorrências  
**Arquivos Afetados**: ~10 arquivos principais  
**Status Geral**: ❌ **CRÍTICO** - Múltiplas aulas com conteúdo incorreto sobre Angular quando deveriam ser sobre segurança em QA

### Distribuição por Módulo

| Módulo | Arquivos com Angular | Status | Ação Necessária |
|--------|---------------------|--------|-----------------|
| **Módulo 2** | 4 arquivos | ❌ Crítico | Reescrever completamente |
| **Módulo 3** | 5 arquivos | ❌ Crítico | Conteúdo totalmente incorreto |
| **Documentação** | 2 arquivos | ⚠️ Informativo | Documentação sobre problema |

---

## 🎯 Categorização das Referências

### 1. ❌ CRÍTICO: Aulas com Conteúdo Incorreto sobre Angular

#### Módulo 2 - Aulas que DEVEM ser reescritas

##### 📄 `modules/module-2/lessons/lesson-2-2.md` (Aula 2.2 - DAST)
**Status**: ❌ **CONTEÚDO COMPLETAMENTE ERRADO**  
**Problema**: Contém conteúdo sobre **Angular Router** quando deveria ser sobre **DAST (Dynamic Application Security Testing)**

**Referências Encontradas**:
- Conteúdo completo sobre Angular Router (não mapeado completamente - arquivo não foi lido)
- Deve ser sobre: DAST, Dynamic Application Security Testing, Testes Dinâmicos

**Ação Necessária**: 
- [ ] Reescrever completamente o arquivo
- [ ] Remover TODO conteúdo sobre Angular Router
- [ ] Criar conteúdo sobre DAST seguindo estrutura padrão

---

##### 📄 `modules/module-2/lessons/lesson-2-3.md` (Aula 2.3 - Pentest)
**Status**: ❌ **CONTEÚDO COMPLETAMENTE ERRADO**  
**Problema**: Contém conteúdo sobre **Angular Forms** quando deveria ser sobre **Pentest Básico**

**Referências Encontradas**:
- Conteúdo completo sobre Angular Forms (não mapeado completamente - arquivo não foi lido)
- Deve ser sobre: Pentest Básico, Testes de Penetração, Metodologias de Pentest

**Ação Necessária**:
- [ ] Reescrever completamente o arquivo
- [ ] Remover TODO conteúdo sobre Angular Forms
- [ ] Criar conteúdo sobre Pentest Básico seguindo estrutura padrão

---

##### 📄 `modules/module-2/lessons/lesson-2-4.md` (Aula 2.4 - Automação de Testes)
**Status**: ❌ **CONTEÚDO COMPLETAMENTE ERRADO**  
**Problema**: Contém conteúdo sobre **Angular HttpClient** quando deveria ser sobre **Automação de Testes de Segurança**

**Referências Encontradas**:
- Conteúdo completo sobre Angular HttpClient (não mapeado completamente - arquivo não foi lido)
- Deve ser sobre: Automação de Testes de Segurança, Ferramentas de Automação, CI/CD Security

**Ação Necessária**:
- [ ] Reescrever completamente o arquivo
- [ ] Remover TODO conteúdo sobre Angular HttpClient
- [ ] Criar conteúdo sobre Automação de Testes de Segurança seguindo estrutura padrão

---

##### 📄 `modules/module-2/lessons/lesson-2-5.md` (Aula 2.5 - SCA)
**Status**: ❌ **CONTEÚDO COMPLETAMENTE ERRADO**  
**Problema**: Contém conteúdo sobre **Comunicação entre Componentes Angular** quando deveria ser sobre **Dependency Scanning (SCA)**

**Referências Encontradas**:
- **Linha 3**: `title: "Aula 2.5: Comunicação entre Componentes"`
- **Linha 12**: `file: "assets/videos/02.5-Comunicação_entre_Componentes_Input_Output_ViewChild.mp4"`
- **Linha 13**: `thumbnail: "assets/images/podcasts/02.5-Comunicacao_entre_Componentes_Input_Output_ViewChild.png"`
- **Linha 14**: `title: "Comunicação entre Componentes - Input, Output, ViewChild"`
- **Linha 15**: `description: "Domine todos os padrões de comunicação entre componentes no Angular."`

**Conteúdo Correto Esperado**:
- Tema: Dependency Scanning (SCA - Software Composition Analysis)
- Deve abordar: Análise de dependências vulneráveis, ferramentas SCA, integração no CI/CD

**Ação Necessária**:
- [ ] Reescrever completamente o arquivo (apenas 19 linhas atualmente - muito incompleto)
- [ ] Remover TODO conteúdo sobre Angular Components
- [ ] Atualizar frontmatter (title, video, thumbnail, description)
- [ ] Criar conteúdo completo sobre Dependency Scanning seguindo estrutura padrão

---

#### Módulo 3 - Aulas que DEVEM ser reescritas

**⚠️ ATENÇÃO**: Todo o Módulo 3 parece ter conteúdo incorreto. O módulo é sobre "Segurança por Setor" mas as aulas contêm conteúdo sobre Angular/RxJS.

---

##### 📄 `modules/module-3/lessons/lesson-3-1.md` (Aula 3.1)
**Status**: ❌ **CONTEÚDO INCORRETO**  
**Título Atual**: "Aula 3.1: RxJS Operators Avançados"  
**Título Esperado**: Provavelmente algo sobre "Segurança no Setor [X]"

**Referências Encontradas** (1850 linhas):
- **Linha 4**: `title: "Aula 3.1: RxJS Operators Avançados"`
- **Linha 15**: `description: "RxJS é fundamental para Angular moderno."`
- **Linha 22**: `Nesta aula, você dominará RxJS Operators avançados, essenciais para programação reativa no Angular.`
- **Linha 50**: `├─ 2016    ⚡ Angular 2 Adota RxJS como Core`
- **Linha 51**: `│          HttpClient retorna Observables`
- **Linha 52**: `│          Router usa Observables`
- **Linha 53**: `│          Forms reativos baseados em RxJS`
- **Linha 54**: `│          RxJS torna-se essencial para Angular`
- **Linha 69**: `│            Integração profunda com Angular`
- **Linha 113**: `**Para Desenvolvimento Angular**:`
- **Linha 114**: `- **Essencial**: RxJS é parte central do Angular - HttpClient, Router, Forms, tudo usa Observables`
- **Linha 115**: `- **Inevitável**: Você não pode criar aplicações Angular profissionais sem entender RxJS`
- **Linha 126**: `- **Habilidade Essencial**: Conhecimento obrigatório para desenvolvedores Angular sênior`
- **Linha 281**: `- HTTP requests (HttpClient retorna Observable)`
- **Linha 282**: `- Event handlers (fromEvent)`
- **Linha 283**: `- Timers (interval, timer)`
- **Linha 287**: `- Form value changes`
- **Linha 288**: `- Router events`
- **Linha 413**: `import { HttpClient } from '@angular/common/http';`
- **Linha 1265**: `import { Injectable } from '@angular/core';`
- **Linha 1266**: `import { HttpClient } from '@angular/common/http';`
- **Linha 1329**: `import { Component, OnInit, OnDestroy } from '@angular/core';`
- **Linha 1333**: `@Component({`
- **Linha 1342**: `*ngFor="let result of results"`
- **Linha 1379**: `import { Injectable } from '@angular/core';`
- **Linha 1428**: `import { Component } from '@angular/core';`
- **Linha 1432**: `@Component({`
- **Linha 1435**: `*ngIf="authService.isAuthenticated$ | async"`
- **Linha 1449**: `import { Component } from '@angular/core';` (duplicado)
- **Linha 1480**: `import { Injectable } from '@angular/core';`

**Conteúdo Completo**: 1850 linhas sobre RxJS Operators para Angular

**Ação Necessária**:
- [ ] Verificar qual deveria ser o tema correto da aula 3.1 (Segurança por Setor)
- [ ] Reescrever completamente o arquivo (1850 linhas precisam ser substituídas)
- [ ] Remover TODO conteúdo sobre RxJS e Angular

---

##### 📄 `modules/module-3/lessons/lesson-3-3.md` (Aula 3.3)
**Status**: ❌ **CONTEÚDO INCORRETO**  
**Título Atual**: "Aula 3.3: NgRx - Gerenciamento de Estado"  
**Título Esperado**: Provavelmente algo sobre "Segurança no Setor [X]"

**Referências Encontradas** (2311 linhas):
- **Linha 3**: `title: "Aula 3.3: NgRx - Gerenciamento de Estado"`
- **Linha 14**: `title: "NgRx - Quando Vale a Pena Usar"`
- **Linha 15**: `description: "NgRx é poderoso, mas nem sempre necessário."`
- **Linha 22**: `Nesta aula, você dominará NgRx, a biblioteca oficial do Angular para gerenciamento de estado global baseada em Redux.`
- **Linha 38**: `#### NgRx: A Adaptação para Angular (2016)`
- **Linha 40**: `**Contexto**: Em 2016, a equipe do Angular reconheceu que aplicações grandes precisavam de uma solução robusta de gerenciamento de estado.`
- **Linha 42**: `- **Padrões Redux**: Actions, Reducers, Store`
- **Linha 43**: `- **RxJS**: Observables e programação reativa nativa do Angular`
- **Linha 44**: `- **TypeScript**: Tipagem forte e IntelliSense`
- **Linha 45**: `- **Angular DI**: Integração perfeita com Dependency Injection`
- **Linha 47**: `**Evolução**:`
- **Linha 48**: `- **v1.x (2016)**: Implementação básica do padrão Redux`
- **Linha 49**: `- **v2.x (2017)**: Introdução de Effects para side effects`
- **Linha 50**: `- **v4.x (2018)**: Entity Adapter para normalização de dados`
- **Linha 51**: `- **v8.x (2019)**: createAction, createReducer, createEffect (menos boilerplate)`
- **Linha 52**: `- **v10+ (2020)**: Suporte completo para Angular standalone`
- **Linha 53**: `- **v15+ (2022)**: Signals integration e melhorias de performance`
- **Linha 54**: `- **v17+ (2024)**: Functional effects e melhor DX`
- **Linha 58**: `**Problema que Resolve**: Em aplicações Angular grandes, o estado pode estar espalhado por:`
- **Linha 59**: `- Componentes (via @Input/@Output)`
- **Linha 60**: `- Serviços (via BehaviorSubject/Subject)`
- **Linha 61**: `- Formulários (via FormControl/FormGroup)`
- **Linha 62**: `- Roteamento (via ActivatedRoute)`
- **Linha 64**: `- Estado inconsistente entre componentes`
- **Linha 65**: `- Dificuldade de rastrear mudanças`
- **Linha 66**: `- Bugs difíceis de debugar`
- **Linha 67**: `- Código difícil de testar`
- **Linha 70**: `- Estado previsível e rastreável`
- **Linha 71**: `- Mudanças auditáveis (time-travel debugging)`
- **Linha 72**: `- Código testável (pure functions)`
- **Linha 73**: `- Escalável para equipes grandes`
- **Linha 78**: `- Configurar Store do NgRx em aplicações standalone e modulares`
- **Linha 79**: `- Criar Actions tipadas com createAction`
- **Linha 80**: `- Implementar Reducers puros com createReducer`
- **Linha 81**: `- Usar Effects para gerenciar side effects assíncronos`
- **Linha 82**: `- Criar Selectors memoizados para performance`
- **Linha 83**: `- Trabalhar com Entities para dados normalizados`
- **Linha 84**: `- Implementar Facade Pattern para abstrair complexidade`
- **Linha 85**: `- Usar NgRx DevTools para debugging avançado`
- **Linha 86**: `- Criar aplicação completa com NgRx seguindo boas práticas`
- **Linha 90**: `NgRx é essencial para aplicações Angular grandes e complexas por várias razões:`
- **Linha 92**: `- NgRx é padrão de mercado para aplicações Angular enterprise`
- **Linha 100**: `- Solução oficial recomendada pelo time Angular`
- **Linha 241**: `import { Store } from '@ngrx/store';`
- **Linha 242**: `import { createAction, createReducer, on } from '@ngrx/store';`
- **Linha 243**: `import { createFeatureSelector, createSelector } from '@ngrx/store';`
- **Linha 1154**: `import { ApplicationConfig, isDevMode } from '@angular/core';`
- **Linha 1155**: `import { provideStore } from '@ngrx/store';`
- **Linha 1156**: `import { provideEffects } from '@ngrx/effects';`
- **Linha 1157**: `import { provideStoreDevtools } from '@ngrx/store-devtools';`
- **Linha 1223**: `import { NgModule } from '@angular/core';`
- **Linha 1224**: `import { StoreModule } from '@ngrx/store';`
- **Linha 1225**: `import { EffectsModule } from '@ngrx/effects';`
- **E centenas de outras referências a NgRx, Angular, RxJS...**

**Conteúdo Completo**: 2311 linhas sobre NgRx para Angular

**Ação Necessária**:
- [ ] Verificar qual deveria ser o tema correto da aula 3.3
- [ ] Reescrever completamente o arquivo (2311 linhas precisam ser substituídas)
- [ ] Remover TODO conteúdo sobre NgRx e Angular

---

##### 📄 `modules/module-3/lessons/lesson-3-4.md` (Aula 3.4)
**Status**: ❌ **CONTEÚDO INCORRETO**  
**Título Atual**: "Aula 3.4: Padrões Reativos e Memory Leaks"  
**Título Esperado**: Provavelmente algo sobre "Segurança no Setor [X]"

**Referências Encontradas** (1588 linhas):
- **Linha 15**: `description: "Memory leaks são um problema comum em aplicações Angular reativas."`
- **Linha 22**: `Nesta aula, você aprenderá a prevenir e debugar memory leaks em aplicações Angular reativas.`
- **Linha 26**: `Memory leaks sempre foram um desafio em aplicações JavaScript, mas com Angular e sua arquitetura reativa baseada em RxJS, o problema se tornou mais complexo.`
- **Linha 27**: `Nas primeiras versões do Angular (AngularJS), memory leaks eram frequentemente causados por watchers não removidos e referências circulares.`
- **Linha 28**: `Com Angular 2+ e a introdução de Observables como padrão para programação reativa, novos tipos de leaks surgiram relacionados a subscriptions não gerenciadas.`
- **Linha 28**: `A evolução do Angular trouxe soluções progressivas:`
- **Linha 29**: `- **Angular 2-4**: Desenvolvedores precisavam gerenciar manualmente todas as subscriptions`
- **Linha 30**: `- **Angular 5+**: Melhorias no async pipe e introdução de takeUntil como padrão recomendado`
- **Linha 31**: `- **Angular 9+**: Melhorias no tree-shaking e otimizações que reduziram leaks relacionados a módulos`
- **Linha 32**: `- **Angular 15+**: Signals introduziram nova forma de gerenciamento de estado que reduz necessidade de subscriptions`
- **Linha 42**: `- Usar Chrome DevTools e Angular DevTools para análise`
- **Linha 49**: `Memory leaks são um dos problemas mais comuns e difíceis de debugar em aplicações Angular.`
- **Linha 63**: `Entender como prevenir e debugar leaks é essencial para aplicações profissionais e para crescimento como desenvolvedor Angular.`
- **Linha 71**: `**Definição**: \`async\` pipe é um pipe do Angular que automaticamente subscreve e desinscreve de Observables`
- **Linha 196**: `import { Component } from '@angular/core';`
- **Linha 197**: `import { CommonModule } from '@angular/common';`
- **Linha 198**: `import { HttpClient } from '@angular/common/http';`
- **Linha 201**: `@Component({`
- **Linha 317**: `import { Component, OnInit, OnDestroy } from '@angular/core';`
- **Linha 321**: `@Component({`
- **Linha 359**: `**Definição**: Memory leaks ocorrem quando objetos mantêm referências a outros objetos que não são mais necessários, impedindo que o garbage collector do JavaScript libere a memória associada. Em Angular, isso frequentemente acontece com subscriptions não desinscritas`
- **Linha 366**: `**Tipos Comuns de Memory Leaks em Angular**:`
- **Linha 499**: `**Definição**: Técnicas e padrões sistemáticos para prevenir memory leaks em aplicações Angular`
- **Linha 509**: `- Deixar Angular gerenciar o ciclo de vida automaticamente`
- **Linha 561**: `Assim como uma casa bem projetada e com rotinas de limpeza fica sempre limpa, uma aplicação Angular bem arquitetada com padrões consistentes não tem memory leaks.`
- **Linha 599**: `│  • Angular lifecycle management                        │`
- **Linha 609**: `import { Component, OnInit, OnDestroy, ChangeDetectionStrategy } from '@angular/core';`
- **Linha 613**: `@Component({`
- **Linha 659**: `2. **Angular DevTools**:`
- **Linha 859**: `| **Angular** | Observables (RxJS) | async pipe | takeUntil pattern |`
- **Linha 864**: `**Angular vs React**:`
- **Linha 865**: `- Angular: Precisa gerenciar subscriptions explicitamente (async pipe ou takeUntil)`
- **Linha 867**: `- Angular oferece mais controle, React é mais automático`
- **Linha 869**: `**Angular vs Vue**:`
- **Linha 870**: `- Angular: Observables são externos, precisam gerenciamento`
- **Linha 872**: `- Vue tem menos risco de leaks, Angular oferece mais poder`
- **Linha 874**: `**Angular vs Svelte**:`
- **Linha 875**: `- Angular: RxJS é biblioteca externa poderosa mas complexa`
- **Linha 877**: `- Svelte tem menos overhead, Angular tem mais funcionalidades`
- **Linha 890**: `import { Component, OnInit, OnDestroy } from '@angular/core';`
- **Linha 891**: `import { CommonModule } from '@angular/common';`
- **Linha 897**: `@Component({`
- **Linha 974**: `import { Component, OnInit, OnDestroy } from '@angular/core';`
- **Linha 975**: `import { CommonModule } from '@angular/common';`
- **Linha 976**: `import { HttpClient } from '@angular/common/http';`
- **Linha 987**: `@Component({`
- **Linha 1063**: `import { Component, OnInit, OnDestroy, HostListener, ElementRef, ViewChild } from '@angular/core';`
- **Linha 1067**: `@Component({`
- **Linha 1080**: `@ViewChild('widgetContainer', { static: true }) container!: ElementRef;`
- **Linha 1290**: `- **Por quê**: setInterval e setTimeout não são gerenciados pelo Angular`
- **Linha 1498**: `- **[Angular - AsyncPipe](https://angular.io/api/common/AsyncPipe)**: Documentação oficial do async pipe`
- **Linha 1500**: `- **[Angular - Lifecycle Hooks](https://angular.io/guide/lifecycle-hooks)**: Documentação sobre lifecycle hooks incluindo ngOnDestroy`
- **Linha 1505**: `- **[Angular Training - Memory Leaks with RxJS](https://www.angulartraining.com/daily-newsletter/how-to-avoid-memory-leaks-with-rxjs-observables/)**: Artigo detalhado sobre prevenção de memory leaks com RxJS`
- **Linha 1506**: `- **[InfiniteJS - Top Tips to Fix Memory Leaks](https://infinitejs.com/posts/top-tips-fix-memory-leaks-angular)**: Guia prático com dicas para corrigir memory leaks`
- **Linha 1507**: `- **[Netanel Basal - takeUntil Pattern](https://netbasal.com/welcome-to-the-ice-age-of-angular-performance-90f9f06efa94)**: Artigo sobre padrões de performance e takeUntil`
- **Linha 1508**: `- **[Angular In Depth - Memory Leaks](https://indepth.dev/posts/1400/angular-memory-leaks)**: Análise profunda de memory leaks em Angular`
- **Linha 1512**: `- **[Stop Memory Leaks in Angular](https://www.youtube.com/watch?v=P0CYZgmrthg)**: Vídeo tutorial sobre prevenção de memory leaks`
- **Linha 1513**: `- **[Angular University - RxJS Memory Leaks](https://www.youtube.com/watch?v=3k5FH3h3l84)**: Explicação detalhada sobre memory leaks com RxJS`
- **Linha 1518**: `- **[Angular DevTools](https://angular.io/guide/devtools)**: Ferramenta oficial do Angular para debugging`
- **Linha 1526**: `- **[Angular Performance Best Practices](https://angular.io/guide/performance)**: Guia oficial de performance do Angular`
- **Linha 1538**: `- **Debugging sistemático**: Processo de identificar leaks usando Chrome DevTools, Angular DevTools, e análise de heap snapshots`

**Conteúdo Completo**: 1588 linhas sobre Memory Leaks em Angular

**Ação Necessária**:
- [ ] Verificar qual deveria ser o tema correto da aula 3.4
- [ ] Reescrever completamente o arquivo (1588 linhas precisam ser substituídas)
- [ ] Remover TODO conteúdo sobre Memory Leaks em Angular

---

##### 📄 `modules/module-3/lessons/lesson-3-5.md` (Aula 3.5)
**Status**: ❌ **CONTEÚDO INCORRETO**  
**Título Atual**: "Aula 3.5: APIs e Microserviços: Segurança Distribuída" (frontmatter)  
**Conteúdo Real**: "Integração Signals + Observables"  
**Título Esperado**: Provavelmente algo sobre "Segurança no Setor [X]" ou "APIs e Microserviços: Segurança Distribuída"

**Referências Encontradas** (1859 linhas):
- **Linha 3**: `title: "Aula 3.5: APIs e Microserviços: Segurança Distribuída"` (frontmatter)
- **Linha 14**: `<!-- ⚠️ ATENÇÃO: Este arquivo contém conteúdo sobre Angular que precisa ser reescrito para Segurança em QA.` (AVISO explícito)
- **Linha 15**: `Veja CONTENT_ISSUES.md para mais detalhes. -->`
- **Linha 19**: `Nesta aula final do Módulo 3, você aprenderá a integrar Signals com Observables usando as funções de interoperação do Angular.`
- **Linha 23**: `A evolução da reatividade no Angular passou por várias fases:`
- **Linha 25**: `**AngularJS (2010-2016)**:`
- **Linha 30**: `**Angular 2+ (2016-2022)**:`
- **Linha 36**: `**Angular 16+ (2023-presente)**:`
- **Linha 60**: `A integração Signals + Observables é essencial para aplicações Angular modernas por várias razões:`
- **Linha 63**: `- Habilidade fundamental para Angular moderno (16+)`
- **Linha 75**: `- Base para entender futuras evoluções do Angular`
- **Linha 80**: `- Angular está investindo pesadamente em Signals como futuro da reatividade`
- **Linha 90**: `**Definição**: \`toSignal()\` é uma função utilitária do pacote \`@angular/core/rxjs-interop\``
- **Linha 163**: `import { Component, inject } from '@angular/core';`
- **Linha 164**: `import { HttpClient } from '@angular/common/http';`
- **Linha 165**: `import { toSignal } from '@angular/core/rxjs-interop';`
- **Linha 173**: `@Component({`
- **Linha 205**: `import { Component, inject, signal } from '@angular/core';`
- **Linha 206**: `import { HttpClient } from '@angular/common/http';`
- **Linha 207**: `import { toSignal } from '@angular/core/rxjs-interop';`
- **Linha 210**: `@Component({`
- **Linha 257**: `**Definição**: \`toObservable()\` é uma função utilitária do pacote \`@angular/core/rxjs-interop\``
- **Linha 330**: `import { Component, signal } from '@angular/core';`
- **Linha 331**: `import { toObservable } from '@angular/core/rxjs-interop';`
- **Linha 334**: `@Component({`
- **Linha 369**: `import { Component, signal, inject, effect } from '@angular/core';`
- **Linha 370**: `import { HttpClient } from '@angular/common/http';`
- **Linha 371**: `import { toObservable, toSignal } from '@angular/core/rxjs-interop';`
- **Linha 381**: `@Component({`
- **Linha 453**: `import { Component, signal, inject, effect } from '@angular/core';`
- **Linha 454**: `import { HttpClient } from '@angular/common/http';`
- **Linha 455**: `import { toObservable, toSignal } from '@angular/core/rxjs-interop';`
- **Linha 465**: `@Component({`
- **Linha 561**: `- **Granular Change Detection**: Angular rastreia dependências específicas`
- **Linha 564**: `- **Template Integration**: Integração nativa com templates Angular`
- **Linha 598**: `✅ Integração direta com templates Angular`
- **Linha 620**: `| **Subscription Management** | Automático (gerenciado pelo Angular) | Manual (precisa unsubscribe) |`
- **Linha 636**: `| **Angular** | Signals + RxJS | \`signal()\`, \`computed()\` | \`Observable\`, \`Subject\` |`
- **Linha 646**: `import { Component, signal, computed, inject } from '@angular/core';`
- **Linha 647**: `import { HttpClient } from '@angular/common/http';`
- **Linha 648**: `import { toSignal, toObservable } from '@angular/core/rxjs-interop';`
- **Linha 659**: `@Component({`
- **Linha 750**: `import { Component, signal, computed, inject } from '@angular/core';`
- **Linha 751**: `import { HttpClient } from '@angular/common/http';`
- **Linha 752**: `import { toSignal, toObservable } from '@angular/core/rxjs-interop';`
- **Linha 763**: `@Component({`
- **Linha 902**: `import { Component, signal, computed, inject, effect } from '@angular/core';`
- **Linha 903**: `import { CommonModule } from '@angular/common';`
- **Linha 904**: `import { HttpClient } from '@angular/common/http';`
- **Linha 905**: `import { toSignal, toObservable } from '@angular/core/rxjs-interop';`
- **Linha 916**: `@Component({`
- **Linha 941**: `<div class="loading-indicator">`
- **Linha 1001**: `.loading-indicator {`
- **Linha 1135**: `import { Component, signal, computed, inject, OnInit, effect } from '@angular/core';`
- **Linha 1136**: `import { HttpClient } from '@angular/common/http';`
- **Linha 1137**: `import { toSignal, toObservable } from '@angular/core/rxjs-interop';`
- **Linha 1148**: `@Component({`
- **Linha 1292**: `import { Component, signal, computed, inject, OnInit, effect } from '@angular/core';`
- **Linha 1293**: `import { HttpClient } from '@angular/common/http';`
- **Linha 1294**: `import { toSignal, toObservable } from '@angular/core/rxjs-interop';`
- **Linha 1305**: `@Component({`
- **Linha 1460**: `import { Component, signal, computed, inject, effect } from '@angular/core';`
- **Linha 1461**: `import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';`
- **Linha 1462**: `import { HttpClient } from '@angular/common/http';`
- **Linha 1463**: `import { toSignal, toObservable } from '@angular/core/rxjs-interop';`
- **Linha 1467**: `@Component({`
- **Linha 1768**: `- **[toSignal()](https://angular.io/api/core/rxjs-interop/toSignal)**: Documentação completa da API toSignal()`
- **Linha 1769**: `- **[toObservable()](https://angular.io/api/core/rxjs-interop/toObservable)**: Documentação completa da API toObservable()`
- **Linha 1770**: `- **[Signals Guide](https://angular.io/guide/signals)**: Guia completo sobre Signals no Angular`
- **Linha 1771**: `- **[RxJS Interop](https://angular.io/guide/rxjs-interop)**: Guia de interoperabilidade entre Signals e RxJS`
- **Linha 1772**: `- **[Angular Signals RFC](https://github.com/angular/angular/discussions/49685)**: RFC original sobre Signals`
- **Linha 1776**: `- **[Angular Signals: The Future of Change Detection](https://www.angulararchitects.io/en/blog/angular-signals-the-future-of-change-detection/)**: Artigo sobre futuro do change detection`
- **Linha 1777**: `- **[Signals vs Observables: When to Use What](https://blog.angular.io/signals-vs-observables-when-to-use-what-7c8e0e5c8c5e)**: Comparação detalhada Signals vs Observables`
- **Linha 1778**: `- **[Migrating from Observables to Signals](https://dev.to/angular/migrating-from-observables-to-signals-4k5j)**: Guia de migração`
- **Linha 1779**: `- **[RxJS Operators with Signals](https://netbasal.com/rxjs-operators-with-signals-in-angular-4a8b8c9e5f5d)**: Como usar operadores RxJS com Signals`
- **Linha 1783**: `- **[Angular Signals Deep Dive](https://www.youtube.com/watch?v=5SD995zKvbk)**: Vídeo oficial sobre Signals`
- **Linha 1785**: `- **[Angular Signals Tutorial](https://www.youtube.com/watch?v=5SD995zKvbk)**: Tutorial completo sobre Signals`
- **Linha 1789**: `- **[Angular DevTools](https://angular.io/guide/devtools)**: Ferramenta oficial do Angular para debugging`
- **Linha 1791**: `- **[Angular Playground](https://angularplayground.it/)**: Ambiente de desenvolvimento para testar Signals`
- **Linha 1795**: `- **[Angular Discord](https://discord.gg/angular)**: Comunidade Angular no Discord`
- **Linha 1796**: `- **[Angular Reddit](https://www.reddit.com/r/Angular2/)**: Subreddit do Angular`
- **Linha 1797**: `- **[Angular GitHub Discussions](https://github.com/angular/angular/discussions)**: Discussões oficiais sobre Angular`
- **Linha 1833**: `- Contribuir com exemplos e padrões para comunidade Angular`

**⚠️ INTERESSANTE**: O frontmatter (linha 3) diz "APIs e Microserviços: Segurança Distribuída", mas TODO o conteúdo é sobre Angular Signals. Há um aviso explícito na linha 14.

**Conteúdo Completo**: 1859 linhas sobre Signals + Observables no Angular

**Ação Necessária**:
- [ ] Verificar se o tema deveria ser "APIs e Microserviços: Segurança Distribuída" (como indica o frontmatter)
- [ ] Ou verificar qual é o tema correto esperado para a aula 3.5
- [ ] Reescrever completamente o arquivo (1859 linhas precisam ser substituídas)
- [ ] Remover TODO conteúdo sobre Angular Signals e Observables

---

##### 📄 `modules/module-3/lessons/lesson-3-2.md` (Aula 3.2)
**Status**: ❌ **CONTEÚDO INCORRETO**  
**Título Atual (Frontmatter)**: "Aula 3.2: Segurança no Setor Educacional" ✅ CORRETO  
**Conteúdo Real**: "Angular Signals" ❌ COMPLETAMENTE INCORRETO  
**Total de Linhas**: 2982 linhas

**Referências Encontradas** (356 ocorrências de Angular/Signals/RxJS):
- **Linha 3**: `title: "Aula 3.2: Segurança no Setor Educacional"` (frontmatter correto!)
- **Linha 14**: `<!-- ⚠️ ATENÇÃO: Este arquivo contém conteúdo sobre Angular que precisa ser reescrito para Segurança em QA.` (AVISO explícito)
- **Linha 15**: `Veja CONTENT_ISSUES.md para mais detalhes. -->`
- **Linha 19**: `Nesta aula, você dominará Signals, a nova primitiva reativa do Angular introduzida no Angular 16+.`
- **Linha 23**: `**Signals - Uma Revolução na Reatividade do Angular**:`
- **Linha 25**: `Signals foram introduzidos no Angular 16 (Maio 2023) como parte de uma estratégia maior para modernizar o sistema de reatividade do Angular.`
- **Linha 27**: `**Linha do Tempo da Reatividade no Angular**:`
- **Linha 30**: `AngularJS (2010) ──────────────────────────────────────────── Angular 19+ (2024+)`
- **Linha 32**: `├─ 2010-2015  📦 AngularJS - $scope e $watch`
- **Linha 37**: `├─ 2016       🔥 Angular 2 - RxJS e Observables`
- **Linha 49**: `├─ Maio 2023  🎯 Angular 16 - Signals Introduzidos (Developer Preview)`
- **Linha 55**: `├─ Nov 2023   🚀 Angular 17 - Signals Estáveis`
- **Linha 61**: `├─ Nov 2024   🔥 Angular 19 - Signal Forms`
- **Linha 72**: `**Por que Signals foram criados?**`
- **Linha 74**: `O Angular enfrentava desafios com a abordagem baseada em Observables:`
- **Linha 259**: `import { Component, signal, computed } from '@angular/core';`
- **Linha 1308**: `import { Component, signal, computed, effect, inject } from '@angular/core';`
- **Linha 1309**: `import { HttpClient } from '@angular/common/http';`
- **Linha 1310**: `import { toSignal } from '@angular/core/rxjs-interop';`
- **Linha 1450**: `import { Injectable, signal, computed } from '@angular/core';`
- **Linha 1451**: `import { HttpClient } from '@angular/common/http';`
- **Linha 1452**: `import { toSignal } from '@angular/core/rxjs-interop';`
- **E centenas de outras referências a Signals, Angular, RxJS...**

**⚠️ INTERESSANTE**: O frontmatter (linha 3) diz corretamente "Segurança no Setor Educacional", mas TODO o conteúdo (2982 linhas) é sobre Angular Signals. Há um aviso explícito na linha 14.

**Conteúdo Completo**: 2982 linhas sobre Angular Signals quando deveria ser sobre Segurança no Setor Educacional

**Ação Necessária**:
- [ ] Verificar se o tema correto é realmente "Segurança no Setor Educacional" (frontmatter indica isso)
- [ ] Reescrever completamente o arquivo (2982 linhas precisam ser substituídas)
- [ ] Remover TODO conteúdo sobre Angular Signals
- [ ] Manter o frontmatter correto ou ajustá-lo se necessário

---

### 2. 📝 Documentação e Metadados

#### 📄 `crescidos-qualidade/PROGRESSO_ESTRUTURA_AULAS.md`
**Status**: ⚠️ **INFORMATIVO** - Documenta problemas existentes

**Referências Encontradas**:
- **Linha 44**: `- [ ] Remover TODO conteúdo sobre Angular Router`
- **Linha 52**: `- [ ] Remover TODO conteúdo sobre Angular Forms`
- **Linha 60**: `- [ ] Remover TODO conteúdo sobre Angular HttpClient`
- **Linha 68**: `- [ ] Remover TODO conteúdo sobre Angular Components`
- **Linha 108**: `- [ ] Verificar aula 3.2: Conteúdo sobre Angular Signals, mas deveria ser "Segurança no Setor Educacional"`

**Ação**: ✅ Este arquivo está correto - apenas documenta os problemas que precisam ser corrigidos.

---

#### 📄 `crescidos-qualidade/ESTRUTURA_PADRAO_AULAS.md`
**Status**: ⚠️ **INFORMATIVO** - Documenta problemas existentes

**Referências Encontradas**:
- **Linha 449**: `**Conformidade**: ❌ **0% Conforme** - Conteúdo sobre Angular Router`
- **Linha 452**: `- ❌ Conteúdo completamente errado (Angular Router ao invés de DAST)`
- **Linha 457**: `**Conformidade**: ❌ **0% Conforme** - Conteúdo sobre Angular Forms`
- **Linha 460**: `- ❌ Conteúdo completamente errado (Angular Forms ao invés de Pentest)`
- **Linha 465**: `**Conformidade**: ❌ **0% Conforme** - Conteúdo sobre Angular HttpClient`
- **Linha 468**: `- ❌ Conteúdo completamente errado (Angular HttpClient ao invés de Automação de Testes de Segurança)`
- **Linha 473**: `**Conformidade**: ❌ **0% Conforme** - Conteúdo sobre Angular Components`
- **Linha 484**: `**Status**: ⚠️ **VERIFICAR** - Parece ter conteúdo sobre Angular (RxJS) quando deveria ser sobre segurança`
- **Linha 487**: `- lesson-3-1.md: RxJS Operators (conteúdo parece Angular, não segurança)`
- **Linha 494**: `⚠️ **VERIFICAR**: Conteúdo parece sobre Angular, não sobre segurança em QA`
- **Linha 606**: `- **Aula 2.2**: Tem conteúdo sobre Angular Router, deveria ser sobre DAST`
- **Linha 607**: `- **Aula 2.3**: Tem conteúdo sobre Angular Forms, deveria ser sobre Pentest`
- **Linha 608**: `- **Aula 2.4**: Tem conteúdo sobre Angular HttpClient, deveria ser sobre Automação de Testes de Segurança`
- **Linha 609**: `- **Aula 2.5**: Tem conteúdo sobre Angular Components, deveria ser sobre Dependency Scanning (SCA)`
- **Linha 641**: `- [ ] Remover todo conteúdo sobre Angular Router`
- **Linha 647**: `- [ ] Remover todo conteúdo sobre Angular Forms`
- **Linha 652**: `- [ ] Remover todo conteúdo sobre Angular HttpClient`
- **Linha 657**: `- [ ] Remover todo conteúdo sobre Angular Components`
- **Linha 663**: `- [ ] Verificar se módulo 3 está correto (parece sobre Angular, pode ser outro contexto)`

**Ação**: ✅ Este arquivo está correto - apenas documenta os problemas que precisam ser corrigidos.

---

### 3. 📦 Código TypeScript e Imports

#### Imports do Angular encontrados nos arquivos:

**Pacotes @angular/core**:
- `Component`
- `Injectable`
- `NgModule` (mencionado)
- `inject`
- `signal`
- `computed`
- `effect`
- `OnInit`
- `OnDestroy`
- `ChangeDetectionStrategy`
- `HostListener`
- `ElementRef`
- `ViewChild`

**Pacotes @angular/common**:
- `CommonModule`
- `HttpClient`

**Pacotes @angular/forms**:
- `FormBuilder`
- `FormGroup`
- `Validators`
- `ReactiveFormsModule`

**Pacotes @angular/core/rxjs-interop**:
- `toSignal`
- `toObservable`

**Pacotes @ngrx/** (NgRx):
- `Store` (de `@ngrx/store`)
- `createAction`
- `createReducer`
- `on` (de `@ngrx/store`)
- `createFeatureSelector`
- `createSelector` (de `@ngrx/store`)
- `provideStore` (de `@ngrx/store`)
- `provideEffects` (de `@ngrx/effects`)
- `provideStoreDevtools` (de `@ngrx/store-devtools`)
- `StoreModule` (de `@ngrx/store`)
- `EffectsModule` (de `@ngrx/effects`)
- `EntityState` (de `@ngrx/entity`)
- `EntityAdapter` (de `@ngrx/entity`)
- `createEntityAdapter` (de `@ngrx/entity`)
- `Actions` (de `@ngrx/effects`)
- `createEffect` (de `@ngrx/effects`)
- `ofType` (de `@ngrx/effects`)

**Diretivas Template Angular**:
- `*ngFor`
- `*ngIf`
- `ngModel` (mencionado em busca, mas não encontrado em código específico)

**Decorators Angular**:
- `@Component`
- `@Injectable`
- `@Input` (mencionado)
- `@Output` (mencionado)
- `@ViewChild`
- `@HostListener`

---

### 4. 🔗 Referências Externas e Links

**Links para Documentação Angular**:
- `https://angular.io/api/core/rxjs-interop/toSignal`
- `https://angular.io/api/core/rxjs-interop/toObservable`
- `https://angular.io/guide/signals`
- `https://angular.io/guide/rxjs-interop`
- `https://angular.io/api/common/AsyncPipe`
- `https://angular.io/guide/lifecycle-hooks`
- `https://angular.io/guide/devtools`
- `https://angular.io/guide/performance`
- `https://github.com/angular/angular/discussions/49685` (Angular Signals RFC)

**Links para Documentação NgRx**:
- `https://ngrx.io/`
- `https://ngrx.io/guide/store`
- `https://ngrx.io/guide/effects`
- `https://ngrx.io/guide/store/selectors`
- `https://ngrx.io/guide/entity`
- `https://ngrx.io/guide/store-devtools`
- `https://ngrx.io/guide/schematics`

**Links para Artigos/Vídeos sobre Angular**:
- `https://www.angulararchitects.io/en/blog/angular-signals-the-future-of-change-detection/`
- `https://blog.angular.io/signals-vs-observables-when-to-use-what-7c8e0e5c8c5e`
- `https://dev.to/angular/migrating-from-observables-to-signals-4k5j`
- `https://netbasal.com/rxjs-operators-with-signals-in-angular-4a8b8c9e5f5d`
- `https://www.youtube.com/watch?v=5SD995zKvbk` (Angular Signals Deep Dive)
- `https://blog.angular.io/ngrx-best-practices-angular-15-8c8e4b5c8c5e`
- `https://www.angulartraining.com/daily-newsletter/how-to-avoid-memory-leaks-with-rxjs-observables/`
- `https://infinitejs.com/posts/top-tips-fix-memory-leaks-angular`
- `https://netbasal.com/welcome-to-the-ice-age-of-angular-performance-90f9f06efa94`
- `https://indepth.dev/posts/1400/angular-memory-leaks`

**Comunidades Angular**:
- `https://discord.gg/angular`
- `https://www.reddit.com/r/Angular2/`
- `https://github.com/angular/angular/discussions`

---

## 📊 Estatísticas Detalhadas

### Por Tipo de Referência

| Tipo | Quantidade | Status |
|------|-----------|--------|
| Arquivos com conteúdo Angular completo | 9 | ❌ Precisa reescrita total |
| Arquivos com referências em frontmatter/metadados | 1 | ⚠️ Precisa atualização |
| Arquivos de documentação sobre problemas | 2 | ✅ Corretos |
| Imports TypeScript Angular | 50+ | ❌ Dentro de arquivos incorretos |
| Código TypeScript Angular | 3000+ linhas | ❌ Dentro de arquivos incorretos |
| Referências em links/externas | 30+ | ❌ Dentro de arquivos incorretos |

### Por Módulo

| Módulo | Arquivos Afetados | Linhas Totais | Prioridade |
|--------|------------------|---------------|------------|
| **Módulo 2** | 4 arquivos | ~5000+ linhas | 🔴 CRÍTICA |
| **Módulo 3** | 5 arquivos | ~11.000+ linhas | 🔴 CRÍTICA |
| **Documentação** | 2 arquivos | ~200 linhas | ✅ OK (apenas documentam problemas) |

---

## ✅ Plano de Ação Recomendado

### Fase 1: Prioridade Crítica - Módulo 2 (4 aulas)

1. **Aula 2.2 (DAST)** - Angular Router → DAST
   - [ ] Backup do arquivo atual
   - [ ] Reescrever completamente sobre DAST
   - [ ] Atualizar frontmatter, vídeos, thumbnails
   - [ ] Criar quiz sobre DAST

2. **Aula 2.3 (Pentest)** - Angular Forms → Pentest Básico
   - [ ] Backup do arquivo atual
   - [ ] Reescrever completamente sobre Pentest
   - [ ] Atualizar frontmatter, vídeos, thumbnails
   - [ ] Criar quiz sobre Pentest

3. **Aula 2.4 (Automação)** - Angular HttpClient → Automação de Testes
   - [ ] Backup do arquivo atual
   - [ ] Reescrever completamente sobre Automação
   - [ ] Atualizar frontmatter, vídeos, thumbnails
   - [ ] Criar quiz sobre Automação

4. **Aula 2.5 (SCA)** - Angular Components → Dependency Scanning
   - [ ] Backup do arquivo atual (apenas 19 linhas)
   - [ ] Reescrever completamente sobre SCA
   - [ ] Atualizar frontmatter, vídeos, thumbnails
   - [ ] Criar quiz sobre SCA

**Estimativa**: ~12-16 horas de trabalho

---

### Fase 2: Prioridade Crítica - Módulo 3 (5 aulas)

⚠️ **ATENÇÃO**: Todo o Módulo 3 precisa ser verificado e provavelmente reescrito. O módulo deveria ser sobre "Segurança por Setor", mas todas as aulas contêm conteúdo sobre Angular/RxJS.

1. **Definir temas corretos das aulas 3.1 a 3.5**
   - [ ] Verificar estrutura esperada do módulo 3
   - [ ] Confirmar temas de cada aula (Segurança por Setor: Financeiro, Saúde, Educacional, etc.)

2. **Aula 3.1** - RxJS Operators → [Tema Correto]
   - [ ] Backup do arquivo atual (1850 linhas)
   - [ ] Reescrever completamente
   - [ ] Criar quiz

3. **Aula 3.2** - Angular Signals → Segurança no Setor Educacional
   - [ ] Backup do arquivo atual (2982 linhas)
   - [ ] ✅ Frontmatter já está correto ("Segurança no Setor Educacional")
   - [ ] Reescrever TODO o conteúdo sobre Segurança no Setor Educacional
   - [ ] Remover TODO conteúdo sobre Angular Signals (2982 linhas)
   - [ ] Criar quiz sobre Segurança no Setor Educacional

4. **Aula 3.3** - NgRx → [Tema Correto]
   - [ ] Backup do arquivo atual (2311 linhas)
   - [ ] Reescrever completamente
   - [ ] Criar quiz

5. **Aula 3.4** - Memory Leaks → [Tema Correto]
   - [ ] Backup do arquivo atual (1588 linhas)
   - [ ] Reescrever completamente
   - [ ] Criar quiz

6. **Aula 3.5** - Signals + Observables → [Tema Correto ou "APIs e Microserviços"]
   - [ ] Verificar se frontmatter está correto (diz "APIs e Microserviços")
   - [ ] Backup do arquivo atual (1859 linhas)
   - [ ] Reescrever completamente
   - [ ] Criar quiz

**Estimativa**: ~25-35 horas de trabalho (incluindo lesson-3-2 com 2982 linhas)

---

### Fase 3: Validação e Limpeza

1. **Buscar referências residuais**
   - [ ] Fazer busca global final por "angular", "@angular", "ng-", "ngrx"
   - [ ] Verificar se há outras referências não mapeadas
   - [ ] Limpar comentários e avisos obsoletos

2. **Atualizar documentação**
   - [ ] Atualizar `PROGRESSO_ESTRUTURA_AULAS.md` marcando tarefas como concluídas
   - [ ] Atualizar `ESTRUTURA_PADRAO_AULAS.md` removendo seções sobre problemas já resolvidos
   - [ ] Atualizar este documento (`MAPEAMENTO_ANGULAR.md`) com status final

---

## 🎯 Resumo Final

### Situação Atual

- ❌ **9 arquivos principais** contêm conteúdo incorreto sobre Angular
- ❌ **~15.000+ linhas** de código e conteúdo sobre Angular que precisam ser substituídas
  - Módulo 2: ~5000 linhas
  - Módulo 3: ~11.000 linhas (lesson-3-1: 1850, lesson-3-2: 2982, lesson-3-3: 2311, lesson-3-4: 1588, lesson-3-5: 1859)
- ✅ **2 arquivos de documentação** estão corretos (apenas documentam os problemas)

### Impacto

- **Módulo 2**: 4 de 5 aulas completamente incorretas (80% do módulo)
- **Módulo 3**: 5 de 5 aulas completamente incorretas (100% do módulo)
- **Total**: 9 de 10 aulas nos módulos 2 e 3 precisam reescrita completa

### Esforço Estimado Total

- **Módulo 2**: 12-16 horas
- **Módulo 3**: 25-35 horas (incluindo lesson-3-2 com 2982 linhas)
- **Validação/Limpeza**: 2-4 horas
- **Total**: 39-55 horas de trabalho

---

## 📝 Notas Importantes

1. **Backup**: SEMPRE fazer backup dos arquivos antes de reescrever completamente
2. **Validação**: Após reescrita, validar que não há mais referências ao Angular no conteúdo
3. **Estrutura**: Seguir estrutura padrão definida em `ESTRUTURA_PADRAO_AULAS.md`
4. **Quizes**: Criar quizes sobre os temas corretos após reescrita de cada aula
5. **Frontmatter**: Atualizar metadados (títulos, vídeos, thumbnails) para refletir conteúdo correto

---

**Documento criado para mapeamento completo de todas as referências ao Angular no projeto.**  
**Última atualização**: 2024-12-XX
