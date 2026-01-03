---
layout: exercise
title: "Exercício 1.3.1: Criar Primeiro Componente Standalone"
slug: "componente-standalone"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **criação de componentes standalone** através da **implementação de um componente de boas-vindas**.

Ao completar este exercício, você será capaz de:

- Criar componente standalone do zero
- Configurar decorator `@Component` corretamente
- Criar template HTML básico
- Adicionar estilos CSS ao componente
- Usar componente em outro componente

---

## Descrição

Você precisa criar um componente standalone `WelcomeComponent` que exibe uma mensagem de boas-vindas personalizada. O componente deve ser auto-suficiente e não depender de NgModules.

### Contexto

Uma aplicação precisa de um componente de boas-vindas que pode ser usado em diferentes partes da aplicação. O componente deve ser standalone para facilitar reutilização.

### Tarefa

Crie um componente `WelcomeComponent` com:

1. **Configuração Standalone**: `standalone: true` no decorator
2. **Template**: Exiba título, subtítulo e mensagem de boas-vindas
3. **Propriedades**: `title`, `subtitle`, `userName` (tipadas)
4. **Estilos**: Adicione estilos básicos para o componente
5. **Uso**: Importe e use o componente em `AppComponent`

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente criado com `standalone: true`
- [ ] Template HTML criado com título, subtítulo e mensagem
- [ ] Propriedades `title`, `subtitle`, `userName` definidas e tipadas
- [ ] Estilos CSS adicionados ao componente
- [ ] Componente importado e usado em `AppComponent`
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Template usa interpolação corretamente
- [ ] Estilos são encapsulados (ViewEncapsulation padrão)
- [ ] Componente é reutilizável
- [ ] Código é legível e bem organizado

---

## Dicas

### Dica 1: Estrutura Básica

```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-welcome',
  standalone: true,
  templateUrl: './welcome.component.html',
  styleUrls: ['./welcome.component.css']
})
export class WelcomeComponent {
  // propriedades aqui
}
```

### Dica 2: Gerar Componente com CLI

Use o Angular CLI para gerar o componente:
```bash
ng generate component welcome --standalone
```

### Dica 3: Template Básico

```html
<div class="welcome">
  <h1>{{ title }}</h1>
  <h2>{{ subtitle }}</h2>
  <p>Bem-vindo, {{ userName }}!</p>
</div>
```

### Dica 4: Importar em AppComponent

```typescript
import { WelcomeComponent } from './welcome/welcome.component';

@Component({
  imports: [WelcomeComponent],
  template: '<app-welcome></app-welcome>'
})
```

---

## Solução Esperada

### Abordagem Recomendada

**welcome.component.ts**
```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-welcome',
  standalone: true,
  templateUrl: './welcome.component.html',
  styleUrls: ['./welcome.component.css']
})
export class WelcomeComponent {
  title: string = 'Bem-vindo ao Angular Expert!';
  subtitle: string = 'Seu treinamento começa aqui';
  userName: string = 'Desenvolvedor';
}
```

**welcome.component.html**
```html
<div class="welcome-container">
  <div class="welcome-content">
    <h1 class="welcome-title">{{ title }}</h1>
    <h2 class="welcome-subtitle">{{ subtitle }}</h2>
    <p class="welcome-message">
      Olá, <strong>{{ userName }}</strong>! Estamos felizes em tê-lo aqui.
    </p>
    <div class="welcome-actions">
      <button class="btn-primary">Começar</button>
    </div>
  </div>
</div>
```

**welcome.component.css**
```css
.welcome-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 400px;
  padding: 2rem;
}

.welcome-content {
  text-align: center;
  max-width: 600px;
}

.welcome-title {
  font-size: 2.5rem;
  color: #1976d2;
  margin-bottom: 1rem;
}

.welcome-subtitle {
  font-size: 1.5rem;
  color: #666;
  margin-bottom: 1.5rem;
}

.welcome-message {
  font-size: 1.1rem;
  line-height: 1.6;
  margin-bottom: 2rem;
}

.btn-primary {
  background-color: #1976d2;
  color: white;
  border: none;
  padding: 12px 24px;
  font-size: 1rem;
  border-radius: 4px;
  cursor: pointer;
}

.btn-primary:hover {
  background-color: #1565c0;
}
```

**app.component.ts**
```typescript
import { Component } from '@angular/core';
import { WelcomeComponent } from './welcome/welcome.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [WelcomeComponent],
  template: '<app-welcome></app-welcome>'
})
export class AppComponent {}
```

**Explicação da Solução**:

1. Componente criado com `standalone: true`
2. Propriedades tipadas definidas na classe
3. Template usa interpolação para exibir dados
4. Estilos CSS organizados e encapsulados
5. Componente importado e usado em `AppComponent`

**Decisões de Design**:

- Template separado em arquivo para melhor organização
- Estilos encapsulados usando ViewEncapsulation padrão
- Propriedades com valores padrão para demonstração
- Estrutura HTML semântica e acessível

---

## Testes

### Casos de Teste

**Teste 1**: Componente renderiza corretamente
- **Input**: Componente carregado
- **Output Esperado**: Título, subtítulo e mensagem devem aparecer na tela

**Teste 2**: Propriedades são exibidas
- **Input**: Componente com propriedades definidas
- **Output Esperado**: Valores das propriedades devem aparecer no template

**Teste 3**: Estilos são aplicados
- **Input**: Componente renderizado
- **Output Esperado**: Estilos CSS devem ser aplicados ao componente

**Teste 4**: Componente pode ser usado em outros componentes
- **Input**: Importar `WelcomeComponent` em `AppComponent`
- **Output Esperado**: Componente deve funcionar sem erros

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Adicionar @Input**: Transforme `userName` em `@Input()` para receber valor externo
2. **Adicionar @Output**: Adicione evento quando botão "Começar" é clicado
3. **Adicionar Animação**: Use CSS animations para entrada do componente
4. **Responsividade**: Torne o componente responsivo com media queries

---

## Referências Úteis

- **[Standalone Components](https://angular.io/guide/standalone-components)**: Documentação oficial
- **[Component Overview](https://angular.io/guide/component-overview)**: Visão geral de componentes
- **[Angular CLI Generate](https://angular.io/cli/generate)**: Comandos do CLI

---

## Checklist de Qualidade

Antes de considerar este exercício completo:

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

