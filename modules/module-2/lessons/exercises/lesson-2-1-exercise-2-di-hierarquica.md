---
layout: exercise
title: "Exercício 2.1.2: Injeção de Dependência Hierárquica"
slug: "di-hierarquica"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **hierarquia de injectors** através da **criação de serviços em diferentes níveis e observação de como Angular resolve dependências**.

Ao completar este exercício, você será capaz de:

- Entender hierarquia de injectors
- Criar serviços em diferentes níveis
- Observar resolução de dependências
- Usar providers em componentes

---

## Descrição

Você precisa criar serviços em diferentes níveis (root, componente) e demonstrar como Angular resolve dependências na hierarquia.

### Contexto

Um desenvolvedor precisa entender como Angular resolve dependências quando serviços são fornecidos em diferentes níveis da hierarquia.

### Tarefa

Crie uma estrutura com:

1. **Serviço Global**: `GlobalService` com providedIn: 'root'
2. **Serviço de Componente**: `ComponentService` fornecido no componente
3. **Componente Pai**: Fornece ComponentService
4. **Componente Filho**: Tenta injetar ambos os serviços
5. **Observação**: Logs para mostrar resolução

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Serviço global criado
- [ ] Serviço de componente criado
- [ ] Componente pai fornece serviço
- [ ] Componente filho injeta serviços
- [ ] Logs mostram resolução
- [ ] Hierarquia demonstrada

### Critérios de Qualidade

- [ ] Código demonstra hierarquia claramente
- [ ] Logs são informativos
- [ ] Estrutura é clara

---

## Solução Esperada

### Abordagem Recomendada

**global.service.ts**
```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class GlobalService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`GlobalService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getServiceName(): string {
    return 'GlobalService (root)';
  }
}
```

**component.service.ts**
```typescript
import { Injectable } from '@angular/core';

@Injectable()
export class ComponentService {
  private instanceId = Math.random().toString(36).substr(2, 9);
  
  constructor() {
    console.log(`ComponentService criado: ${this.instanceId}`);
  }
  
  getInstanceId(): string {
    return this.instanceId;
  }
  
  getServiceName(): string {
    return 'ComponentService (component level)';
  }
}
```

**parent.component.ts**
```typescript
import { Component } from '@angular/core';
import { GlobalService } from './global.service';
import { ComponentService } from './component.service';
import { ChildComponent } from './child.component';

@Component({
  selector: 'app-parent',
  standalone: true,
  imports: [ChildComponent],
  providers: [ComponentService],
  template: `
    <div class="parent">
      <h2>Componente Pai</h2>
      <p>GlobalService ID: {{ globalService.getInstanceId() }}</p>
      <p>ComponentService ID: {{ componentService.getInstanceId() }}</p>
      <app-child></app-child>
    </div>
  `
})
export class ParentComponent {
  constructor(
    public globalService: GlobalService,
    public componentService: ComponentService
  ) {
    console.log('ParentComponent - GlobalService:', this.globalService.getInstanceId());
    console.log('ParentComponent - ComponentService:', this.componentService.getInstanceId());
  }
}
```

**child.component.ts**
```typescript
import { Component } from '@angular/core';
import { GlobalService } from './global.service';
import { ComponentService } from './component.service';

@Component({
  selector: 'app-child',
  standalone: true,
  template: `
    <div class="child">
      <h3>Componente Filho</h3>
      <p>GlobalService ID: {{ globalService.getInstanceId() }}</p>
      <p>ComponentService ID: {{ componentService.getInstanceId() }}</p>
      <p class="note">
        GlobalService: Mesma instância (root)<br>
        ComponentService: Mesma instância do pai (herdado)
      </p>
    </div>
  `
})
export class ChildComponent {
  constructor(
    public globalService: GlobalService,
    public componentService: ComponentService
  ) {
    console.log('ChildComponent - GlobalService:', this.globalService.getInstanceId());
    console.log('ChildComponent - ComponentService:', this.componentService.getInstanceId());
  }
}
```

**Explicação da Solução**:

1. GlobalService com providedIn: 'root' cria singleton
2. ComponentService fornecido no componente pai
3. Filho herda ComponentService do pai
4. Logs mostram IDs de instância
5. Demonstra que ambos componentes compartilham instâncias

---

## Testes

### Casos de Teste

**Teste 1**: GlobalService é singleton
- **Input**: Criar múltiplos componentes
- **Output Esperado**: Mesmo ID de instância

**Teste 2**: ComponentService é compartilhado
- **Input**: Pai e filho usam ComponentService
- **Output Esperado**: Mesmo ID de instância

**Teste 3**: Logs mostram criação
- **Input**: Carregar componente
- **Output Esperado**: Logs no console mostram criação

---

## Extensões (Opcional)

1. **Múltiplos Filhos**: Crie múltiplos componentes filhos
2. **Serviço no Filho**: Forneça serviço também no filho
3. **Árvore Completa**: Crie árvore de componentes mais profunda

---

## Referências Úteis

- **[Dependency Injection](https://angular.io/guide/dependency-injection)**: Guia oficial
- **[Hierarchical Injectors](https://angular.io/guide/dependency-injection-in-action#hierarchical-dependency-injection)**: Hierarquia de injectors

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

