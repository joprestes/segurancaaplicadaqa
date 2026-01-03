---
layout: exercise
title: "Exercício 4.3.3: Triggers"
slug: "triggers"
lesson_id: "lesson-4-3"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **triggers** através da **criação de componente que demonstra diferentes triggers do @defer**.

Ao completar este exercício, você será capaz de:

- Usar on viewport trigger
- Usar on idle trigger
- Usar on timer trigger
- Usar on interaction trigger
- Combinar triggers quando necessário

---

## Descrição

Você precisa criar um componente que demonstra diferentes triggers do @defer.

### Contexto

Uma aplicação precisa carregar componentes em momentos diferentes usando triggers apropriados.

### Tarefa

Crie:

1. **on viewport**: Componente que carrega quando entra no viewport
2. **on idle**: Componente que carrega quando navegador está idle
3. **on timer**: Componente que carrega após tempo especificado
4. **on interaction**: Componente que carrega quando usuário interage
5. **Demonstração**: Componente completo demonstrando todos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] on viewport implementado
- [ ] on idle implementado
- [ ] on timer implementado
- [ ] on interaction implementado
- [ ] Todos triggers funcionam
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Triggers estão implementados corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**triggers-demo.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HeavyComponent } from './heavy.component';
import { AnalyticsComponent } from './analytics.component';
import { AdComponent } from './ad.component';
import { ModalComponent } from './modal.component';

@Component({
  selector: 'app-triggers-demo',
  standalone: true,
  imports: [CommonModule, HeavyComponent, AnalyticsComponent, AdComponent, ModalComponent],
  template: `
    <div>
      <h2>Demonstração de Triggers</h2>
      
      <section class="trigger-section">
        <h3>1. on viewport</h3>
        <p>Este componente carrega quando entra no viewport</p>
        <div style="height: 500px; overflow-y: auto; border: 1px solid #ccc; padding: 1rem;">
          <p>Role para baixo...</p>
          <div style="height: 800px;"></div>
          
          @defer (on viewport) {
            <app-heavy></app-heavy>
          } @placeholder {
            <div class="placeholder-box">
              <p>Componente será carregado quando visível</p>
            </div>
          }
        </div>
      </section>
      
      <section class="trigger-section">
        <h3>2. on idle</h3>
        <p>Este componente carrega quando navegador está idle</p>
        @defer (on idle) {
          <app-analytics></app-analytics>
        } @placeholder {
          <div class="placeholder-box">
            <p>Analytics será carregado quando navegador estiver idle</p>
          </div>
        }
      </section>
      
      <section class="trigger-section">
        <h3>3. on timer(3s)</h3>
        <p>Este componente carrega após 3 segundos</p>
        @defer (on timer(3s)) {
          <app-ad></app-ad>
        } @placeholder {
          <div class="placeholder-box">
            <p>Anúncio será carregado em 3 segundos</p>
          </div>
        }
      </section>
      
      <section class="trigger-section">
        <h3>4. on interaction</h3>
        <p>Este componente carrega quando você clica no botão</p>
        @defer (on interaction(button)) {
          <app-modal></app-modal>
        } @placeholder {
          <div class="placeholder-box">
            <button #button class="trigger-button">
              Clique para carregar modal
            </button>
          </div>
        }
      </section>
      
      <section class="trigger-section">
        <h3>5. on hover</h3>
        <p>Este componente carrega quando você passa o mouse</p>
        @defer (on hover(triggerElement)) {
          <app-heavy></app-heavy>
        } @placeholder {
          <div class="placeholder-box" #triggerElement>
            <p>Passe o mouse aqui para carregar</p>
          </div>
        }
      </section>
      
      <section class="trigger-section">
        <h3>6. Combined triggers</h3>
        <p>Este componente carrega quando viewport OU após 5 segundos</p>
        @defer (on viewport; on timer(5s)) {
          <app-heavy></app-heavy>
        } @placeholder {
          <div class="placeholder-box">
            <p>Carregará quando visível ou após 5 segundos</p>
          </div>
        }
      </section>
    </div>
  `,
  styles: [`
    .trigger-section {
      margin: 2rem 0;
      padding: 1rem;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
    }
    
    .placeholder-box {
      padding: 2rem;
      background: #f8f9fa;
      border: 2px dashed #dee2e6;
      border-radius: 4px;
      text-align: center;
    }
    
    .trigger-button {
      padding: 0.75rem 1.5rem;
      background: #3498db;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
    }
    
    .trigger-button:hover {
      background: #2980b9;
    }
  `]
})
export class TriggersDemoComponent {}
```

**Explicação da Solução**:

1. on viewport carrega quando elemento entra no viewport
2. on idle carrega quando navegador está idle
3. on timer carrega após tempo especificado
4. on interaction carrega quando usuário interage
5. on hover carrega quando mouse passa sobre
6. Triggers podem ser combinados com ;

---

## Testes

### Casos de Teste

**Teste 1**: on viewport funciona
- **Input**: Rolar até elemento
- **Output Esperado**: Componente carregado quando visível

**Teste 2**: on idle funciona
- **Input**: Aguardar navegador ficar idle
- **Output Esperado**: Componente carregado

**Teste 3**: on timer funciona
- **Input**: Aguardar tempo especificado
- **Output Esperado**: Componente carregado após timer

**Teste 4**: on interaction funciona
- **Input**: Clicar no botão
- **Output Esperado**: Componente carregado

---

## Extensões (Opcional)

1. **Custom Triggers**: Crie triggers customizados
2. **Performance Monitoring**: Monitore impacto de cada trigger
3. **A/B Testing**: Teste diferentes triggers

---

## Referências Úteis

- **[Triggers](https://angular.io/guide/defer#triggers)**: Guia triggers
- **[on viewport](https://angular.io/guide/defer#on-viewport)**: Documentação on viewport

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

