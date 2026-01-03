---
layout: exercise
title: "Exercício 1.3.4: ViewEncapsulation e Estilos"
slug: "view-encapsulation"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **ViewEncapsulation** através da **criação de três versões do mesmo componente com diferentes estratégias de encapsulação**.

Ao completar este exercício, você será capaz de:

- Entender diferentes modos de ViewEncapsulation
- Aplicar ViewEncapsulation.Emulated (padrão)
- Aplicar ViewEncapsulation.None
- Aplicar ViewEncapsulation.ShadowDom
- Observar diferenças práticas entre os modos

---

## Descrição

Você precisa criar três versões do mesmo componente `StyledBoxComponent`, cada uma com um modo diferente de ViewEncapsulation. Isso permitirá observar como os estilos são aplicados e isolados em cada caso.

### Contexto

Um desenvolvedor precisa entender como ViewEncapsulation funciona para escolher a estratégia correta em diferentes situações. Criar versões comparativas ajuda a visualizar as diferenças.

### Tarefa

Crie três componentes idênticos visualmente, mas com ViewEncapsulation diferentes:

1. **StyledBoxEmulatedComponent**: ViewEncapsulation.Emulated (padrão)
2. **StyledBoxNoneComponent**: ViewEncapsulation.None
3. **StyledBoxShadowComponent**: ViewEncapsulation.ShadowDom

Cada componente deve:
- Ter o mesmo template HTML
- Ter os mesmos estilos CSS
- Exibir um box estilizado com título e conteúdo
- Demonstrar como estilos são isolados ou não

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Três componentes criados com templates idênticos
- [ ] Cada componente usa ViewEncapsulation diferente
- [ ] Estilos CSS são os mesmos em todos
- [ ] Componente de demonstração mostra os três lado a lado
- [ ] Observações sobre diferenças documentadas

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Componentes são funcionais
- [ ] Diferenças são observáveis
- [ ] Código é bem organizado
- [ ] Comentários explicam diferenças

---

## Dicas

### Dica 1: Configurar ViewEncapsulation

```typescript
import { Component, ViewEncapsulation } from '@angular/core';

@Component({
  encapsulation: ViewEncapsulation.Emulated
})
```

### Dica 2: Emulated (Padrão)

Estilos são isolados usando atributos únicos gerados pelo Angular.

### Dica 3: None

Estilos são globais, sem isolamento. Podem afetar outros componentes.

### Dica 4: ShadowDom

Usa Shadow DOM nativo do navegador para isolamento completo.

### Dica 5: Observar no DevTools

Use Chrome DevTools para inspecionar como estilos são aplicados em cada modo.

---

## Solução Esperada

### Abordagem Recomendada

**styled-box-emulated.component.ts**
```typescript
import { Component, ViewEncapsulation } from '@angular/core';

@Component({
  selector: 'app-styled-box-emulated',
  standalone: true,
  templateUrl: './styled-box.component.html',
  styleUrls: ['./styled-box.component.css'],
  encapsulation: ViewEncapsulation.Emulated
})
export class StyledBoxEmulatedComponent {
  title: string = 'Emulated (Padrão)';
  content: string = 'Estilos isolados com atributos únicos';
}
```

**styled-box-none.component.ts**
```typescript
import { Component, ViewEncapsulation } from '@angular/core';

@Component({
  selector: 'app-styled-box-none',
  standalone: true,
  templateUrl: './styled-box.component.html',
  styleUrls: ['./styled-box.component.css'],
  encapsulation: ViewEncapsulation.None
})
export class StyledBoxNoneComponent {
  title: string = 'None (Global)';
  content: string = 'Estilos são globais, sem isolamento';
}
```

**styled-box-shadow.component.ts**
```typescript
import { Component, ViewEncapsulation } from '@angular/core';

@Component({
  selector: 'app-styled-box-shadow',
  standalone: true,
  templateUrl: './styled-box.component.html',
  styleUrls: ['./styled-box.component.css'],
  encapsulation: ViewEncapsulation.ShadowDom
})
export class StyledBoxShadowComponent {
  title: string = 'ShadowDom';
  content: string = 'Isolamento completo com Shadow DOM';
}
```

**styled-box.component.html** (compartilhado)
```html
<div class="styled-box">
  <h3 class="box-title">{{ title }}</h3>
  <p class="box-content">{{ content }}</p>
  <div class="box-footer">
    <span class="box-badge">ViewEncapsulation</span>
  </div>
</div>
```

**styled-box.component.css** (compartilhado)
```css
.styled-box {
  padding: 1.5rem;
  border: 2px solid #1976d2;
  border-radius: 8px;
  background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  margin: 1rem 0;
}

.box-title {
  color: #1976d2;
  font-size: 1.5rem;
  margin: 0 0 1rem 0;
  font-weight: 600;
}

.box-content {
  color: #424242;
  line-height: 1.6;
  margin: 0 0 1rem 0;
}

.box-footer {
  display: flex;
  justify-content: flex-end;
  margin-top: 1rem;
}

.box-badge {
  background-color: #1976d2;
  color: white;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 500;
}

/* Estilo global para teste */
.global-test {
  background-color: yellow !important;
  border: 3px solid red !important;
}
```

**demo.component.ts** (demonstração)
```typescript
import { Component } from '@angular/core';
import { StyledBoxEmulatedComponent } from './styled-box-emulated.component';
import { StyledBoxNoneComponent } from './styled-box-none.component';
import { StyledBoxShadowComponent } from './styled-box-shadow.component';

@Component({
  selector: 'app-demo',
  standalone: true,
  imports: [
    StyledBoxEmulatedComponent,
    StyledBoxNoneComponent,
    StyledBoxShadowComponent
  ],
  template: `
    <div class="demo-container">
      <h1>Comparação de ViewEncapsulation</h1>
      
      <app-styled-box-emulated></app-styled-box-emulated>
      <app-styled-box-none></app-styled-box-none>
      <app-styled-box-shadow></app-styled-box-shadow>
      
      <div class="global-test">
        <p>Este elemento tem classe global-test para testar vazamento de estilos</p>
      </div>
    </div>
  `,
  styles: [`
    .demo-container {
      max-width: 800px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    h1 {
      text-align: center;
      color: #333;
      margin-bottom: 2rem;
    }
  `]
})
export class DemoComponent {}
```

**Explicação da Solução**:

1. Três componentes idênticos com ViewEncapsulation diferentes
2. Template e estilos compartilhados para comparação justa
3. Classe `.global-test` demonstra vazamento de estilos
4. Componente de demonstração mostra os três lado a lado
5. Diferenças observáveis no navegador e DevTools

**Decisões de Design**:

- Mesmo template e estilos para comparação justa
- Estilos chamativos para facilitar observação
- Classe global para testar vazamento
- Estrutura clara para demonstração

**Observações Esperadas**:

- **Emulated**: Estilos isolados com atributos únicos (`_ngcontent-*`)
- **None**: Estilos podem vazar e afetar `.global-test`
- **ShadowDom**: Isolamento completo, estilos não vazam

---

## Testes

### Casos de Teste

**Teste 1**: Componentes renderizam corretamente
- **Input**: Três componentes carregados
- **Output Esperado**: Três boxes idênticos visualmente devem aparecer

**Teste 2**: Inspecionar no DevTools - Emulated
- **Input**: Abrir DevTools e inspecionar componente Emulated
- **Output Esperado**: Ver atributos `_ngcontent-*` nos elementos

**Teste 3**: Inspecionar no DevTools - None
- **Input**: Inspecionar componente None
- **Output Esperado**: Sem atributos de isolamento, estilos podem vazar

**Teste 4**: Inspecionar no DevTools - ShadowDom
- **Input**: Inspecionar componente ShadowDom
- **Output Esperado**: Ver `#shadow-root` no DevTools

**Teste 5**: Testar vazamento de estilos
- **Input**: Adicionar classe `.global-test` em elemento externo
- **Output Esperado**: Apenas componente None deve ser afetado

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Adicionar Estilos Globais**: Crie estilos globais e observe como afetam cada modo
2. **Testar Performance**: Compare performance de cada modo
3. **Criar Guia**: Documente quando usar cada modo
4. **Testar Compatibilidade**: Teste ShadowDom em diferentes navegadores

---

## Referências Úteis

- **[ViewEncapsulation](https://angular.io/api/core/ViewEncapsulation)**: Documentação oficial
- **[Component Styles](https://angular.io/guide/component-styles)**: Guia de estilos de componentes
- **[Shadow DOM](https://developer.mozilla.org/en-US/docs/Web/Web_Components/Using_shadow_DOM)**: Documentação MDN

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

