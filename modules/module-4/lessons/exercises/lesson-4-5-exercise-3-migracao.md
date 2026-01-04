---
layout: exercise
title: "Exercício 4.5.3: Migração para Zoneless"
slug: "migracao"
lesson_id: "lesson-4-5"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **migração para zoneless** através da **migração de aplicação existente de Zone.js para zoneless**.

Ao completar este exercício, você será capaz de:

- Planejar migração para zoneless
- Converter componentes para Signals
- Migrar gradualmente
- Lidar com desafios de migração
- Verificar migração completa

---

## Descrição

Você precisa migrar uma aplicação existente que usa Zone.js para zoneless change detection.

### Contexto

Uma aplicação existente precisa ser migrada para zoneless para melhor performance.

### Tarefa

Crie:

1. **Análise**: Analisar aplicação existente
2. **Planejamento**: Planejar estratégia de migração
3. **Migração**: Migrar componentes gradualmente
4. **Testes**: Testar migração
5. **Documentação**: Documentar processo

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Análise realizada
- [ ] Estratégia planejada
- [ ] Migração implementada
- [ ] Testes realizados
- [ ] Documentação criada

### Critérios de Qualidade

- [ ] Migração está completa
- [ ] Aplicação funciona corretamente
- [ ] Documentação é clara

---

## Solução Esperada

### Abordagem Recomendada

**migration-plan.md**
# Plano de Migração para Zoneless

## 1. Análise

### Componentes Identificados
- AppComponent (root)
- CounterComponent
- UserListComponent
- ProductListComponent
- CartComponent

### Dependências de Zone.js
- setTimeout/setInterval
- Event listeners
- HTTP requests
- Observables

## 2. Estratégia

### Fase 1: Preparação
- Converter para Signals onde possível
- Remover dependências explícitas de Zone.js
- Adicionar change detection manual quando necessário

### Fase 2: Migração Gradual
- Migrar componentes novos primeiro
- Migrar componentes simples
- Migrar componentes complexos

### Fase 3: Finalização
- Habilitar zoneless
- Testar extensivamente
- Corrigir problemas

## 3. Checklist

- [ ] Todos componentes usam Signals
- [ ] Observables convertidos para Signals
- [ ] Change detection manual adicionada quando necessário
- [ ] Testes atualizados
- [ ] Performance verificada
```markdown
# Plano de Migração para Zoneless

## 1. Análise

### Componentes Identificados
- AppComponent (root)
- CounterComponent
- UserListComponent
- ProductListComponent
- CartComponent

### Dependências de Zone.js
- setTimeout/setInterval
- Event listeners
- HTTP requests
- Observables

## 2. Estratégia

### Fase 1: Preparação
- Converter para Signals onde possível
- Remover dependências explícitas de Zone.js
- Adicionar change detection manual quando necessário

### Fase 2: Migração Gradual
- Migrar componentes novos primeiro
- Migrar componentes simples
- Migrar componentes complexos

### Fase 3: Finalização
- Habilitar zoneless
- Testar extensivamente
- Corrigir problemas

## 3. Checklist

- [ ] Todos componentes usam Signals
- [ ] Observables convertidos para Signals
- [ ] Change detection manual adicionada quando necessário
- [ ] Testes atualizados
- [ ] Performance verificada
```

**before-migration.component.ts** (ANTES)
{% raw %}
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Component({
  selector: 'app-before',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Antes da Migração</h2>
      <p>Count: {{ count }}</p>
      <ul>
        <li *ngFor="let user of users$ | async">{{ user.name }}</li>
      </ul>
    </div>
  `
{% endraw %}
})
export class BeforeComponent implements OnInit {
  count = 0;
  users$: Observable<any[]>;
  
  constructor(private http: HttpClient) {
    this.users$ = this.http.get<any[]>('/api/users');
  }
  
  ngOnInit(): void {
    setInterval(() => {
      this.count++;
    }, 1000);
  }
}
```

**after-migration.component.ts** (DEPOIS)
{% raw %}
```typescript
import { Component, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';
import { interval } from 'rxjs';

@Component({
  selector: 'app-after',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Depois da Migração</h2>
      <p>Count: {{ count() }}</p>
      <ul>
        @for (user of users(); track user.id) {
          <li>{{ user.name }}</li>
        }
      </ul>
    </div>
  `
})
export class AfterComponent {
  private http = inject(HttpClient);
  
  count = signal(0);
  
  users = toSignal(
    this.http.get<any[]>('/api/users'),
    { initialValue: [] }
  );
  
  constructor() {
    interval(1000).subscribe(() => {
      this.count.update(v => v + 1);
    });
  }
}
```
{% endraw %}

**migration-steps.md**
# Passos de Migração

## 1. Converter Propriedades para Signals

Antes:
```markdown
# Passos de Migração

## 1. Converter Propriedades para Signals

Antes:
```
count = 0;

Depois:
```

Depois:
```
count = signal(0);

## 2. Converter Observables para Signals

Antes:
```

## 2. Converter Observables para Signals

Antes:
```
users$ = this.http.get('/api/users');

Depois:
```

Depois:
```
users = toSignal(
  this.http.get('/api/users'),
  { initialValue: [] }
);

## 3. Atualizar Templates

Antes:
```

## 3. Atualizar Templates

Antes:
```
<p>{{ count }}</p>
<li *ngFor="let user of users$ | async">{{ user.name }}</li>

Depois:
```

Depois:
```
{% raw %}
<p>{{ count() }}</p>
{% endraw %}
@for (user of users(); track user.id) {
  <li>{{ user.name }}</li>
}

## 4. Habilitar Zoneless

```

## 4. Habilitar Zoneless

```
bootstrapApplication(AppComponent, {
  providers: [
    provideExperimentalZonelessChangeDetection()
  ]
});

## 5. Testar e Corrigir

- Testar todos componentes
- Verificar change detection
- Corrigir problemas encontrados
```

## 5. Testar e Corrigir

- Testar todos componentes
- Verificar change detection
- Corrigir problemas encontrados
```

**Explicação da Solução**:

1. Análise identifica componentes e dependências
2. Estratégia planejada para migração gradual
3. Componentes convertidos para Signals
4. Observables convertidos usando toSignal()
5. Templates atualizados para usar Signals
6. Zoneless habilitado e testado

---

## Testes

### Casos de Teste

**Teste 1**: Migração funciona
- **Input**: Usar aplicação migrada
- **Output Esperado**: Tudo funciona corretamente

**Teste 2**: Signals funcionam
- **Input**: Interagir com componentes
- **Output Esperado**: Reatividade funciona

**Teste 3**: Performance melhorada
- **Input**: Comparar performance
- **Output Esperado**: Melhor performance

---

## Extensões (Opcional)

1. **Automated Migration**: Crie script de migração automática
2. **Migration Tools**: Desenvolva ferramentas de migração
3. **Team Training**: Treine equipe no processo

---

## Referências Úteis

- **[Migration Guide](https://angular.io/guide/zoneless-change-detection#migration)**: Guia migração
- **[Signals](https://angular.io/guide/signals)**: Guia Signals

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

