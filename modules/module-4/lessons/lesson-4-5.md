---
layout: lesson
title: "Aula 4.5: Zone.js e Zoneless Apps"
slug: zonejs
module: module-4
lesson_id: lesson-4-5
duration: "60 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-4-4"
exercises:
  - 
  - "lesson-4-5-exercise-1"
  - "lesson-4-5-exercise-2"
  - "lesson-4-5-exercise-3"
podcast:
  file: "assets/podcasts/04.5-Zone.m4a"
  image: "assets/images/podcasts/04.5-Zone.png"
  title: "Zone.js e Zoneless Apps"
  description: "Zone.js é o motor da change detection tradicional do Angular."
  duration: "50-65 minutos"
permalink: /modules/performance-otimizacao/lessons/zonejs/
---

## Introdução

Nesta aula final do Módulo 4, você aprenderá sobre Zone.js e aplicações zoneless no Angular. Zoneless apps representam o futuro do Angular, oferecendo melhor performance e controle sobre change detection.

### O que você vai aprender

- Entender Zone.js e seu papel no Angular
- Usar NgZone e runOutsideAngular()
- Trabalhar com NoopNgZone
- Criar aplicações zoneless (Angular 18+)
- Migrar aplicações existentes para zoneless
- Entender benefícios e trade-offs

### Por que isso é importante

Aplicações zoneless são o futuro do Angular. Elas oferecem melhor performance, controle mais fino sobre change detection e são mais alinhadas com padrões modernos de desenvolvimento web. Entender Zone.js e zoneless é essencial para desenvolvedores Angular avançados.

---

## Conceitos Teóricos

### Zone.js

**Definição**: Zone.js é biblioteca que intercepta operações assíncronas para detectar mudanças automaticamente.

**Explicação Detalhada**:

Zone.js:
- Intercepta operações assíncronas
- Detecta mudanças automaticamente
- Dispara change detection
- Patches APIs nativas (setTimeout, Promise, etc.)
- Usado por padrão no Angular
- Pode ser removido em Angular 18+

**Analogia**:

Zone.js é como um assistente que observa tudo que acontece e avisa quando algo muda, permitindo que Angular atualize a interface automaticamente.

**Visualização**:

Async Operation ──Zone.js──→ Change Detection ──→ Update View
    │                              │
    ├── setTimeout                 │
    ├── Promise                    │
    ├── Event                      │
    └── HTTP                       │
Async Operation ──Zone.js──→ Change Detection ──→ Update View
    │                              │
    ├── setTimeout                 │
    ├── Promise                    │
    ├── Event                      │
    └── HTTP                       │
```
Async Operation ──Zone.js──→ Change Detection ──→ Update View
    │                              │
    ├── setTimeout                 │
    ├── Promise                    │
    ├── Event                      │
    └── HTTP                       │
```

**Exemplo Prático**:

import { Component } from '@angular/core';

@Component({
  selector: 'app-zone',
  standalone: true,
  template: `<p>{{ count }}</p>`
})
export class ZoneComponent {
  count = 0;
  
  constructor() {
    setTimeout(() => {
      this.count++;
    }, 1000);
  }
}
import { Component } from '@angular/core';

@Component({
  selector: 'app-zone',
  standalone: true,
  template: `<p>{{ count }}</p>`
})
export class ZoneComponent {
  count = 0;
  
  constructor() {
    setTimeout(() => {
      this.count++;
    }, 1000);
  }
}
```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-zone',
  standalone: true,
  template: `<p>{{ count }}</p>`
})
export class ZoneComponent {
  count = 0;
  
  constructor() {
    setTimeout(() => {
      this.count++;
    }, 1000);
  }
}
```

---

### NgZone e runOutsideAngular()

**Definição**: NgZone permite executar código fora do contexto do Zone.js, evitando change detection desnecessária.

**Explicação Detalhada**:

NgZone:
- Gerencia execução dentro/fora do Zone
- runOutsideAngular() executa sem trigger change detection
- run() executa dentro do Zone
- Útil para operações pesadas
- Melhora performance

**Analogia**:

runOutsideAngular() é como trabalhar em um escritório silencioso onde ninguém é interrompido, permitindo trabalho focado sem distrações.

**Exemplo Prático**:

import { Component, NgZone } from '@angular/core';

@Component({
  selector: 'app-ngzone',
  standalone: true,
  template: `<p>{{ count }}</p>`
})
export class NgZoneComponent {
  count = 0;
  
  constructor(private ngZone: NgZone) {}
  
  heavyOperation(): void {
    this.ngZone.runOutsideAngular(() => {
      for (let i = 0; i < 1000000; i++) {
        this.count = i;
      }
      this.ngZone.run(() => {
        this.count = 1000000;
      });
    });
  }
}
import { Component, NgZone } from '@angular/core';

@Component({
  selector: 'app-ngzone',
  standalone: true,
  template: `<p>{{ count }}</p>`
})
export class NgZoneComponent {
  count = 0;
  
  constructor(private ngZone: NgZone) {}
  
  heavyOperation(): void {
    this.ngZone.runOutsideAngular(() => {
      for (let i = 0; i < 1000000; i++) {
        this.count = i;
      }
      this.ngZone.run(() => {
        this.count = 1000000;
      });
    });
  }
}
```typescript
import { Component, NgZone } from '@angular/core';

@Component({
  selector: 'app-ngzone',
  standalone: true,
  template: `<p>{{ count }}</p>`
})
export class NgZoneComponent {
  count = 0;
  
  constructor(private ngZone: NgZone) {}
  
  heavyOperation(): void {
    this.ngZone.runOutsideAngular(() => {
      for (let i = 0; i < 1000000; i++) {
        this.count = i;
      }
      this.ngZone.run(() => {
        this.count = 1000000;
      });
    });
  }
}
```

---

### NoopNgZone

**Definição**: NoopNgZone desabilita Zone.js completamente, requerendo change detection manual.

**Explicação Detalhada**:

NoopNgZone:
- Desabilita Zone.js
- Requer change detection manual
- Melhor performance
- Mais controle
- Requer Signals ou change detection manual

**Exemplo Prático**:

import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';
import { AppComponent } from './app/app.component';

bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection()
  ]
});
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';
import { AppComponent } from './app/app.component';

bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection()
  ]
});
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';
import { AppComponent } from './app/app.component';

bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection()
  ]
});
```

---

### Zoneless Apps (Angular 18+)

**Definição**: Aplicações zoneless não usam Zone.js, dependendo de Signals e change detection manual.

**Explicação Detalhada**:

Zoneless Apps:
- Não usam Zone.js
- Dependem de Signals
- Change detection manual quando necessário
- Melhor performance
- Menor bundle size
- Futuro do Angular

**Analogia**:

Zoneless apps são como carros elétricos - mais eficientes, mais modernos, mas requerem uma abordagem diferente de "dirigir".

**Exemplo Prático**:

import { Component, signal, ChangeDetectorRef } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';

@Component({
  selector: 'app-zoneless',
  standalone: true,
  template: `
    <div>
{% raw %}

      <p>{{ count() }}</p>
{% endraw %}

      <button (click)="increment()">Increment</button>
    </div>
  `
})
export class ZonelessComponent {
  count = signal(0);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
}

bootstrapApplication(ZonelessComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection()
  ]
});
{% raw %}
import { Component, signal, ChangeDetectorRef } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';

@Component({
  selector: 'app-zoneless',
  standalone: true,
  template: `
    <div>
      <p>{{ count() }}</p>
      <button (click)="increment()">Increment</button>
    </div>
  `
})
export class ZonelessComponent {
  count = signal(0);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
}

bootstrapApplication(ZonelessComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection()
  ]
});
```typescript
import { Component, signal, ChangeDetectorRef } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';

@Component({
  selector: 'app-zoneless',
  standalone: true,
  template: `
    <div>
      <p>{{ count() }}</p>
      <button (click)="increment()">Increment</button>
    </div>
  `
})
export class ZonelessComponent {
  count = signal(0);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
}

bootstrapApplication(ZonelessComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection()
  ]
});
```
{% endraw %}

---

### Migração para Zoneless

**Definição**: Processo de migrar aplicação existente que usa Zone.js para zoneless.

**Explicação Detalhada**:

Migração:
- Converter para Signals
- Remover dependências de Zone.js
- Adicionar change detection manual quando necessário
- Testar extensivamente
- Gradual ou completa

**Exemplo Prático**:

import { Component, signal, computed, effect } from '@angular/core';

@Component({
  selector: 'app-migrated',
  standalone: true,
  template: `
    <div>
{% raw %}

      <p>{{ count() }}</p>
{% endraw %}
{% raw %}
      <p>{{ doubleCount() }}</p>
{% endraw %}

      <button (click)="increment()">Increment</button>
    </div>
  `
})
export class MigratedComponent {
  count = signal(0);
  doubleCount = computed(() => this.count() * 2);
  
  constructor() {
    effect(() => {
      console.log('Count changed:', this.count());
    });
  }
  
  increment(): void {
    this.count.update(v => v + 1);
  }
}
{% raw %}
import { Component, signal, computed, effect } from '@angular/core';

@Component({
  selector: 'app-migrated',
  standalone: true,
  template: `
    <div>
      <p>{{ count() }}</p>
      <p>{{ doubleCount() }}</p>
      <button (click)="increment()">Increment</button>
    </div>
  `
})
export class MigratedComponent {
  count = signal(0);
  doubleCount = computed(() => this.count() * 2);
  
  constructor() {
    effect(() => {
      console.log('Count changed:', this.count());
    });
  }
  
  increment(): void {
    this.count.update(v => v + 1);
  }
}
```typescript
import { Component, signal, computed, effect } from '@angular/core';

@Component({
  selector: 'app-migrated',
  standalone: true,
  template: `
    <div>
      <p>{{ count() }}</p>
      <p>{{ doubleCount() }}</p>
      <button (click)="increment()">Increment</button>
    </div>
  `
})
export class MigratedComponent {
  count = signal(0);
  doubleCount = computed(() => this.count() * 2);
  
  constructor() {
    effect(() => {
      console.log('Count changed:', this.count());
    });
  }
  
  increment(): void {
    this.count.update(v => v + 1);
  }
}
```
{% endraw %}

---

## Exemplos Práticos Completos

### Exemplo 1: Aplicação Zoneless Completa

**Contexto**: Criar aplicação completa usando zoneless change detection.

**Código**:

import { Component, signal, computed } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';

@Component({
  selector: 'app-root',
  standalone: true,
  template: `
    <div>
      <h1>Zoneless App</h1>
      <router-outlet></router-outlet>
    </div>
  `
})
export class AppComponent {}

bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection(),
    provideRouter(routes)
  ]
});
import { Component, signal, computed } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';

@Component({
  selector: 'app-root',
  standalone: true,
  template: `
    <div>
      <h1>Zoneless App</h1>
      <router-outlet></router-outlet>
    </div>
  `
})
export class AppComponent {}

bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection(),
    provideRouter(routes)
  ]
});
```typescript
import { Component, signal, computed } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideExperimentalZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';

@Component({
  selector: 'app-root',
  standalone: true,
  template: `
    <div>
      <h1>Zoneless App</h1>
      <router-outlet></router-outlet>
    </div>
  `
})
export class AppComponent {}

bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection(),
    provideRouter(routes)
  ]
});
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use Signals em aplicações zoneless**
   - **Por quê**: Signals são necessários para reatividade
   - **Exemplo**: `count = signal(0)`

2. **Use runOutsideAngular() para operações pesadas**
   - **Por quê**: Evita change detection desnecessária
   - **Exemplo**: Loops pesados, animações

3. **Migre gradualmente**
   - **Por quê**: Reduz riscos
   - **Exemplo**: Começar com componentes novos

4. **Teste extensivamente**
   - **Por quê**: Zoneless requer mudanças significativas
   - **Exemplo**: Testes unitários e E2E

### ❌ Anti-padrões Comuns

1. **Não usar Signals em zoneless**
   - **Problema**: Change detection não funciona
   - **Solução**: Sempre use Signals

2. **Não migrar tudo de uma vez**
   - **Problema**: Muitos pontos de falha
   - **Solução**: Migre gradualmente

3. **Não ignorar change detection manual**
   - **Problema**: Alguns casos precisam de detecção manual
   - **Solução**: Use markForCheck() quando necessário

---

## Exercícios Práticos

### Exercício 1: runOutsideAngular() (Intermediário)

**Objetivo**: Usar runOutsideAngular() para otimização

**Descrição**: 
Crie componente que usa runOutsideAngular() para operações pesadas.

**Arquivo**: `exercises/exercise-4-5-1-runoutside.md`

---

### Exercício 2: Aplicação Zoneless (Avançado)

**Objetivo**: Criar aplicação zoneless

**Descrição**:
Crie aplicação completa usando zoneless change detection.

**Arquivo**: `exercises/exercise-4-5-2-zoneless.md`

---

### Exercício 3: Migração para Zoneless (Avançado)

**Objetivo**: Migrar aplicação existente

**Descrição**:
Migre aplicação existente de Zone.js para zoneless.

**Arquivo**: `exercises/exercise-4-5-3-migracao.md`

---

## Referências Externas

### Documentação Oficial

- **[Zone.js](https://angular.io/guide/zone)**: Guia Zone.js
- **[Zoneless Change Detection](https://angular.io/guide/zoneless-change-detection)**: Guia zoneless
- **[NgZone](https://angular.io/api/core/NgZone)**: Documentação NgZone

---

## Resumo

### Principais Conceitos

- Zone.js intercepta operações assíncronas
- NgZone permite controle sobre Zone.js
- runOutsideAngular() evita change detection desnecessária
- Zoneless apps não usam Zone.js
- Signals são essenciais para zoneless
- Migração requer planejamento cuidadoso

### Pontos-Chave para Lembrar

- Use Signals em aplicações zoneless
- Use runOutsideAngular() para operações pesadas
- Migre gradualmente
- Teste extensivamente
- Zoneless é o futuro do Angular

### Próximos Passos

- Próximo módulo: Módulo 5 - Práticas Avançadas e Projeto Final
- Praticar zoneless em aplicações
- Explorar padrões avançados

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

**Aula Anterior**: [Aula 4.4: Profiling e Otimização](./lesson-4-4-profiling.md)  
**Próxima Aula**: [Aula 5.1: Testes Avançados](./lesson-5-1-testes.md)  
**Voltar ao Módulo**: [Módulo 4: Performance e Otimização](../modules/module-4-performance-otimizacao.md)

