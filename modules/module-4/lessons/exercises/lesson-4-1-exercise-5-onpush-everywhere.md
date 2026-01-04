---
layout: exercise
title: "Exercício 4.1.5: OnPush Everywhere"
slug: "onpush-everywhere"
lesson_id: "lesson-4-1"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **OnPush Everywhere pattern** através da **conversão de aplicação completa para OnPush**.

Ao completar este exercício, você será capaz de:

- Converter aplicação completa para OnPush
- Aplicar OnPush em todos componentes
- Garantir imutabilidade em toda aplicação
- Entender desafios de migração
- Aplicar padrão OnPush everywhere

---

## Descrição

Você precisa converter uma aplicação completa para usar OnPush em todos componentes.

### Contexto

Uma aplicação precisa ser otimizada aplicando OnPush em todos componentes.

### Tarefa

Crie:

1. **Auditoria**: Identificar todos componentes
2. **Conversão**: Converter cada componente para OnPush
3. **Imutabilidade**: Garantir imutabilidade
4. **Testes**: Testar aplicação completa
5. **Documentação**: Documentar mudanças

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Todos componentes convertidos para OnPush
- [ ] Imutabilidade garantida
- [ ] Aplicação funciona corretamente
- [ ] Performance melhorada
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] OnPush aplicado consistentemente
- [ ] Código é escalável

---

## Solução Esperada

### Abordagem Recomendada

**app.component.ts**
import { Component, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './header/header.component';
import { FooterComponent } from './footer/footer.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, HeaderComponent, FooterComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="app">
      <app-header></app-header>
      <main>
        <router-outlet></router-outlet>
      </main>
      <app-footer></app-footer>
    </div>
  `
})
export class AppComponent {}
```typescript
import { Component, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './header/header.component';
import { FooterComponent } from './footer/footer.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, HeaderComponent, FooterComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="app">
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

**header.component.ts**
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-header',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header>
      <h1>{{ title() }}</h1>
      <nav>
        <a routerLink="/home">Home</a>
        <a routerLink="/about">About</a>
      </nav>
    </header>
  `
})
export class HeaderComponent {
  title = signal('My App');
}
{% raw %}
```typescript
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-header',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header>
      <h1>{{ title() }}</h1>
      <nav>
        <a routerLink="/home">Home</a>
        <a routerLink="/about">About</a>
      </nav>
    </header>
  `
})
export class HeaderComponent {
  title = signal('My App');
}
```
{% endraw %}

**user-list.component.ts**
import { Component, ChangeDetectionStrategy, Input, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>{{ title() }}</h2>
      <ul>
        @for (user of users(); track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
    </div>
  `
})
export class UserListComponent {
  @Input() users = signal<User[]>([]);
  title = signal('Usuários');
}
{% raw %}
```typescript
import { Component, ChangeDetectionStrategy, Input, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

interface User {
  id: number;
  name: string;
  email: string;
}

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>{{ title() }}</h2>
      <ul>
        @for (user of users(); track user.id) {
          <li>{{ user.name }} - {{ user.email }}</li>
        }
      </ul>
    </div>
  `
})
export class UserListComponent {
  @Input() users = signal<User[]>([]);
  title = signal('Usuários');
}
```
{% endraw %}

**migration-checklist.md**
# Checklist de Migração para OnPush Everywhere

## 1. Auditoria
- [ ] Listar todos componentes
- [ ] Identificar componentes que podem usar OnPush
- [ ] Identificar dependências

## 2. Conversão
- [ ] Adicionar ChangeDetectionStrategy.OnPush
- [ ] Converter propriedades para Signals
- [ ] Garantir imutabilidade
- [ ] Usar trackBy em listas

## 3. Testes
- [ ] Testar cada componente
- [ ] Verificar change detection
- [ ] Validar funcionalidade

## 4. Otimização
- [ ] Usar markForCheck() quando necessário
- [ ] Otimizar operações de array
- [ ] Verificar performance

## 5. Documentação
- [ ] Documentar mudanças
- [ ] Criar guia de boas práticas
- [ ] Treinar equipe
```markdown
# Checklist de Migração para OnPush Everywhere

## 1. Auditoria
- [ ] Listar todos componentes
- [ ] Identificar componentes que podem usar OnPush
- [ ] Identificar dependências

## 2. Conversão
- [ ] Adicionar ChangeDetectionStrategy.OnPush
- [ ] Converter propriedades para Signals
- [ ] Garantir imutabilidade
- [ ] Usar trackBy em listas

## 3. Testes
- [ ] Testar cada componente
- [ ] Verificar change detection
- [ ] Validar funcionalidade

## 4. Otimização
- [ ] Usar markForCheck() quando necessário
- [ ] Otimizar operações de array
- [ ] Verificar performance

## 5. Documentação
- [ ] Documentar mudanças
- [ ] Criar guia de boas práticas
- [ ] Treinar equipe
```

**Explicação da Solução**:

1. Todos componentes usam OnPush
2. Signals usados para estado reativo
3. Imutabilidade garantida em todas operações
4. trackBy usado em todas listas
5. markForCheck() usado quando necessário
6. Aplicação completa otimizada

---

## Testes

### Casos de Teste

**Teste 1**: Todos componentes funcionam
- **Input**: Navegar pela aplicação
- **Output Esperado**: Tudo funciona corretamente

**Teste 2**: Performance melhorada
- **Input**: Comparar performance
- **Output Esperado**: Melhor performance

**Teste 3**: Change detection otimizada
- **Input**: Verificar change detection
- **Output Esperado**: Menos verificações

---

## Extensões (Opcional)

1. **Automated Migration**: Crie script de migração automática
2. **Performance Metrics**: Meça melhorias de performance
3. **Team Training**: Treine equipe no padrão

---

## Referências Úteis

- **[OnPush Everywhere](https://angular.io/guide/change-detection#optimize-change-detection)**: Guia OnPush
- **[Migration Guide](https://angular.io/guide/change-detection)**: Guia migração

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

