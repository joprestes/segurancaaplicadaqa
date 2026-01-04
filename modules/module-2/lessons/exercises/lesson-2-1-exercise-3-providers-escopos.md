---
layout: exercise
title: "Exercício 2.1.3: Providers e Escopos"
slug: "providers-escopos"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **providers e escopos** através da **criação de serviços com diferentes escopos e demonstração de diferenças**.

Ao completar este exercício, você será capaz de:

- Configurar diferentes escopos de serviços
- Entender diferenças entre root, any, component
- Criar múltiplas instâncias quando necessário
- Escolher escopo apropriado

---

## Descrição

Você precisa criar três versões do mesmo serviço com diferentes escopos (root, any, component) e demonstrar como cada um se comporta.

### Contexto

Um sistema precisa entender quando usar diferentes escopos de serviços para otimizar performance e gerenciar estado corretamente.

### Tarefa

Crie três serviços idênticos com escopos diferentes:

1. **RootService**: providedIn: 'root'
2. **AnyService**: providedIn: 'any'
3. **ComponentService**: Fornecido no componente

Demonstre diferenças criando múltiplos componentes e módulos lazy-loaded.

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Três serviços criados com escopos diferentes
- [ ] Componentes que usam os serviços
- [ ] Módulo lazy-loaded para testar 'any'
- [ ] Logs mostram criação de instâncias
- [ ] Diferenças documentadas

### Critérios de Qualidade

- [ ] Código demonstra diferenças claramente
- [ ] Logs são informativos
- [ ] Estrutura é organizada

---

## Solução Esperada

### Abordagem Recomendada

**root.service.ts**
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class RootService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`[ROOT] RootService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getScope(): string {
    return 'root - Singleton global';
  }
}
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class RootService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`[ROOT] RootService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getScope(): string {
    return 'root - Singleton global';
  }
}
```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class RootService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`[ROOT] RootService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getScope(): string {
    return 'root - Singleton global';
  }
}
```

**any.service.ts**
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'any'
})
export class AnyService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`[ANY] AnyService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getScope(): string {
    return 'any - Nova instância por módulo lazy';
  }
}
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'any'
})
export class AnyService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`[ANY] AnyService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getScope(): string {
    return 'any - Nova instância por módulo lazy';
  }
}
```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'any'
})
export class AnyService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`[ANY] AnyService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getScope(): string {
    return 'any - Nova instância por módulo lazy';
  }
}
```

**component-scoped.service.ts**
import { Injectable } from '@angular/core';

@Injectable()
export class ComponentScopedService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`[COMPONENT] ComponentScopedService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getScope(): string {
    return 'component - Nova instância por componente';
  }
}
import { Injectable } from '@angular/core';

@Injectable()
export class ComponentScopedService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`[COMPONENT] ComponentScopedService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getScope(): string {
    return 'component - Nova instância por componente';
  }
}
```typescript
import { Injectable } from '@angular/core';

@Injectable()
export class ComponentScopedService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`[COMPONENT] ComponentScopedService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getScope(): string {
    return 'component - Nova instância por componente';
  }
}
```

**demo.component.ts**
import { Component } from '@angular/core';
import { RootService } from './root.service';
import { AnyService } from './any.service';
import { ComponentScopedService } from './component-scoped.service';

@Component({
  selector: 'app-demo',
  standalone: true,
  providers: [ComponentScopedService],
  template: `
    <div class="demo">
      <h2>Demonstração de Escopos</h2>
      
      <div class="service-info">
        <h3>RootService (providedIn: 'root')</h3>
{% raw %}

        <p>ID: {{ rootService.getInstanceId() }}</p>
{% endraw %}

        <p>{{ rootService.getScope() }}</p>

      </div>
      
      <div class="service-info">
        <h3>AnyService (providedIn: 'any')</h3>
{% raw %}

        <p>ID: {{ anyService.getInstanceId() }}</p>
{% endraw %}

        <p>{{ anyService.getScope() }}</p>

      </div>
      
      <div class="service-info">
        <h3>ComponentScopedService (component providers)</h3>
{% raw %}

        <p>ID: {{ componentService.getInstanceId() }}</p>
{% endraw %}

        <p>{{ componentService.getScope() }}</p>

      </div>
      
      <app-demo-child></app-demo-child>
    </div>
  `
})
export class DemoComponent {
  constructor(
    public rootService: RootService,
    public anyService: AnyService,
    public componentService: ComponentScopedService
  ) {}
}
{% raw %}
import { Component } from '@angular/core';
import { RootService } from './root.service';
import { AnyService } from './any.service';
import { ComponentScopedService } from './component-scoped.service';

@Component({
  selector: 'app-demo',
  standalone: true,
  providers: [ComponentScopedService],
  template: `
    <div class="demo">
      <h2>Demonstração de Escopos</h2>
      
      <div class="service-info">
        <h3>RootService (providedIn: 'root')</h3>
        <p>ID: {{ rootService.getInstanceId() }}</p>
        <p>{{ rootService.getScope() }}</p>
      </div>
      
      <div class="service-info">
        <h3>AnyService (providedIn: 'any')</h3>
        <p>ID: {{ anyService.getInstanceId() }}</p>
        <p>{{ anyService.getScope() }}</p>
      </div>
      
      <div class="service-info">
        <h3>ComponentScopedService (component providers)</h3>
        <p>ID: {{ componentService.getInstanceId() }}</p>
        <p>{{ componentService.getScope() }}</p>
      </div>
      
      <app-demo-child></app-demo-child>
    </div>
  `
})
export class DemoComponent {
  constructor(
    public rootService: RootService,
    public anyService: AnyService,
    public componentService: ComponentScopedService
  ) {}
}
```typescript
import { Component } from '@angular/core';
import { RootService } from './root.service';
import { AnyService } from './any.service';
import { ComponentScopedService } from './component-scoped.service';

@Component({
  selector: 'app-demo',
  standalone: true,
  providers: [ComponentScopedService],
  template: `
    <div class="demo">
      <h2>Demonstração de Escopos</h2>
      
      <div class="service-info">
        <h3>RootService (providedIn: 'root')</h3>
        <p>ID: {{ rootService.getInstanceId() }}</p>
        <p>{{ rootService.getScope() }}</p>
      </div>
      
      <div class="service-info">
        <h3>AnyService (providedIn: 'any')</h3>
        <p>ID: {{ anyService.getInstanceId() }}</p>
        <p>{{ anyService.getScope() }}</p>
      </div>
      
      <div class="service-info">
        <h3>ComponentScopedService (component providers)</h3>
        <p>ID: {{ componentService.getInstanceId() }}</p>
        <p>{{ componentService.getScope() }}</p>
      </div>
      
      <app-demo-child></app-demo-child>
    </div>
  `
})
export class DemoComponent {
  constructor(
    public rootService: RootService,
    public anyService: AnyService,
    public componentService: ComponentScopedService
  ) {}
}
```
{% endraw %}

**demo-child.component.ts**
import { Component } from '@angular/core';
import { RootService } from './root.service';
import { AnyService } from './any.service';
import { ComponentScopedService } from './component-scoped.service';

@Component({
  selector: 'app-demo-child',
  standalone: true,
  providers: [ComponentScopedService],
  template: `
    <div class="child-demo">
      <h3>Componente Filho</h3>
{% raw %}

      <p>RootService ID: {{ rootService.getInstanceId() }} (mesmo)</p>
{% endraw %}

      <p>AnyService ID: {{ anyService.getInstanceId() }} (mesmo se mesmo módulo)</p>

      <p>ComponentScopedService ID: {{ componentService.getInstanceId() }} (novo)</p>

    </div>
  `
})
export class DemoChildComponent {
  constructor(
    public rootService: RootService,
    public anyService: AnyService,
    public componentService: ComponentScopedService
  ) {}
}
{% raw %}
import { Component } from '@angular/core';
import { RootService } from './root.service';
import { AnyService } from './any.service';
import { ComponentScopedService } from './component-scoped.service';

@Component({
  selector: 'app-demo-child',
  standalone: true,
  providers: [ComponentScopedService],
  template: `
    <div class="child-demo">
      <h3>Componente Filho</h3>
      <p>RootService ID: {{ rootService.getInstanceId() }} (mesmo)</p>
      <p>AnyService ID: {{ anyService.getInstanceId() }} (mesmo se mesmo módulo)</p>
      <p>ComponentScopedService ID: {{ componentService.getInstanceId() }} (novo)</p>
    </div>
  `
})
export class DemoChildComponent {
  constructor(
    public rootService: RootService,
    public anyService: AnyService,
    public componentService: ComponentScopedService
  ) {}
}
```typescript
import { Component } from '@angular/core';
import { RootService } from './root.service';
import { AnyService } from './any.service';
import { ComponentScopedService } from './component-scoped.service';

@Component({
  selector: 'app-demo-child',
  standalone: true,
  providers: [ComponentScopedService],
  template: `
    <div class="child-demo">
      <h3>Componente Filho</h3>
      <p>RootService ID: {{ rootService.getInstanceId() }} (mesmo)</p>
      <p>AnyService ID: {{ anyService.getInstanceId() }} (mesmo se mesmo módulo)</p>
      <p>ComponentScopedService ID: {{ componentService.getInstanceId() }} (novo)</p>
    </div>
  `
})
export class DemoChildComponent {
  constructor(
    public rootService: RootService,
    public anyService: AnyService,
    public componentService: ComponentScopedService
  ) {}
}
```
{% endraw %}

**Explicação da Solução**:

1. RootService: Singleton em toda aplicação
2. AnyService: Nova instância por módulo lazy-loaded
3. ComponentScopedService: Nova instância por componente
4. Logs mostram quando instâncias são criadas
5. Demonstra diferenças práticas

---

## Testes

### Casos de Teste

**Teste 1**: RootService é singleton
- **Input**: Múltiplos componentes
- **Output Esperado**: Mesmo ID

**Teste 2**: ComponentScopedService cria nova instância
- **Input**: Múltiplos componentes
- **Output Esperado**: IDs diferentes

**Teste 3**: AnyService em módulos diferentes
- **Input**: Módulos lazy diferentes
- **Output Esperado**: IDs diferentes

---

## Extensões (Opcional)

1. **Módulo Lazy**: Crie módulo lazy para testar 'any'
2. **Performance**: Compare performance de cada escopo
3. **Memory**: Analise uso de memória

---

## Referências Úteis

- **[Provider Scopes](https://angular.io/guide/dependency-injection-providers#provider-scope)**: Escopos de providers
- **[providedIn](https://angular.io/api/core/Injectable#providedIn)**: Documentação providedIn

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

