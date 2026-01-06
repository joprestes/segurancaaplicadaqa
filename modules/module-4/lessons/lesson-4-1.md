---
layout: lesson
title: "Aula 4.1: Change Detection Strategies"
slug: change-detection
module: module-4
lesson_id: lesson-4-1
duration: "120 minutos"
level: "Avançado"
prerequisites: []
exercises: []
podcast:
  file: "assets/podcasts/04.1-OnPush_Imutabilidade_e_Performance_de_Apps.m4a"
  image: "assets/images/podcasts/04.1-OnPush_Imutabilidade_e_Performance_de_Apps.png"
  title: "OnPush, Imutabilidade e Performance de Apps"
  description: "Change Detection é crítico para performance."
  duration: "60-75 minutos"
permalink: /modules/performance-otimizacao/lessons/change-detection/
---

## Introdução

Nesta aula, você dominará estratégias avançadas de change detection no Angular. Change detection é um dos aspectos mais importantes para performance em aplicações Angular, e entender como otimizá-la é essencial para criar aplicações rápidas e responsivas.

### Contexto Histórico e Evolução

A change detection no Angular passou por uma evolução significativa desde o AngularJS até o Angular moderno:

#### AngularJS (v1.x) - Two-Way Data Binding
- **Dirty Checking**: Verificava todas as expressões em cada ciclo usando `$digest()`
- **Problema**: Performance degradava drasticamente com muitos watchers
- **Solução**: `$apply()` manual e otimizações específicas

#### Angular 2+ (2016) - Zone.js e Change Detection Unidirecional
- **Zone.js**: Patcheamento automático de APIs assíncronas
- **Change Detection Tree**: Estrutura hierárquica otimizada
- **OnPush Strategy**: Introduzida para otimização seletiva
- **Melhoria**: Performance muito superior ao AngularJS

#### Angular 4+ - Otimizações Contínuas
- **Ivy Renderer**: Change detection mais eficiente
- **OnPush melhorado**: Melhor integração com observables e signals
- **Tree-shaking**: Redução de código não utilizado

#### Angular 17+ - Signals e Change Detection Moderna
- **Signals**: Sistema reativo nativo que otimiza change detection
- **OnPush + Signals**: Combinação poderosa para performance máxima
- **Zoneless Angular**: Possibilidade de usar Angular sem Zone.js

### O que você vai aprender

- Entender Default vs OnPush change detection em profundidade
- Compreender o papel do Zone.js no ciclo de change detection
- Implementar OnPush strategy em componentes de forma correta
- Trabalhar com imutabilidade e padrões imutáveis
- Usar ChangeDetectorRef para controle manual avançado
- Implementar trackBy functions para otimização de listas
- Aplicar padrão OnPush everywhere em aplicações reais
- Entender quando usar cada estratégia e suas implicações

### Por que isso é importante

Change detection pode ser um grande gargalo de performance em aplicações Angular. Em aplicações grandes com centenas de componentes, a estratégia Default pode executar milhares de verificações desnecessárias a cada ciclo, causando:

- **Lag perceptível**: Interface não responde imediatamente
- **Consumo excessivo de CPU**: Processamento desnecessário
- **Problemas de bateria**: Em dispositivos móveis
- **Experiência ruim**: Usuários percebem lentidão

OnPush strategy pode reduzir drasticamente o número de verificações de mudanças - de centenas para apenas algumas por ciclo - melhorando significativamente a performance. É uma das otimizações mais impactantes que você pode fazer, muitas vezes resultando em melhorias de 50-90% na performance de renderização.

**Impacto na Carreira**: Desenvolvedores que dominam change detection são capazes de:
- Criar aplicações Angular de alta performance
- Diagnosticar e resolver problemas de performance rapidamente
- Aplicar otimizações que fazem diferença real para usuários
- Entender profundamente como o Angular funciona internamente

---

## Conceitos Teóricos

### Default Strategy

**Definição**: Default strategy (ChangeDetectionStrategy.Default) verifica mudanças em todos os componentes da árvore de componentes em cada ciclo de change detection, independentemente de onde a mudança ocorreu.

**Explicação Detalhada**:

A Default Strategy funciona através de um processo sistemático:

1. **Trigger de Change Detection**: Zone.js detecta eventos assíncronos (cliques, timers, HTTP requests, etc.) e dispara o ciclo de change detection

2. **Verificação Hierárquica**: Angular percorre toda a árvore de componentes de cima para baixo (depth-first), verificando cada componente

3. **Comparação de Valores**: Para cada binding no template, Angular compara o valor atual com o valor anterior usando comparação de referência (`===`)

4. **Atualização da View**: Se uma diferença é detectada, Angular atualiza o DOM correspondente

5. **Propagação**: O processo continua para todos os componentes filhos

**Características**:
- Verifica todos componentes em cada ciclo, mesmo sem mudanças
- Executa após qualquer evento assíncrono detectado pelo Zone.js
- Compara valores usando `===` (comparação de referência)
- Não requer configuração especial - é o comportamento padrão
- Pode ser ineficiente em aplicações grandes (centenas de componentes)
- Fácil de usar mas pode causar problemas de performance significativos

**Quando usar Default Strategy**:
- Aplicações pequenas com poucos componentes
- Prototipagem rápida onde performance não é crítica
- Componentes que precisam detectar mudanças profundas em objetos (sem imutabilidade)
- Quando você não pode garantir imutabilidade dos dados

**Analogia Detalhada**:

Imagine que você é o segurança de um grande shopping center com 500 lojas. Com a Default Strategy, toda vez que qualquer coisa acontece (uma pessoa entra, um alarme toca, qualquer movimento), você precisa:

1. Verificar TODAS as 500 lojas, uma por uma
2. Conferir se cada porta está trancada
3. Verificar se cada vitrine está intacta
4. Checar se cada câmera está funcionando
5. Repetir isso mesmo que apenas uma loja tenha tido atividade

Isso funciona, mas é extremamente ineficiente. Você gasta 99% do seu tempo verificando lojas que não mudaram nada, quando poderia focar apenas nas que realmente precisam de atenção.

**Visualização Completa**:

```
┌─────────────────────────────────────────────────────────────────┐
│              Default Change Detection Cycle                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐                                              │
│  │   Evento     │  (click, timer, HTTP, etc.)                  │
│  │  Assíncrono  │                                              │
│  └──────┬───────┘                                              │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────┐                                              │
│  │   Zone.js    │  Detecta evento e notifica Angular            │
│  │  Patched API │                                              │
│  └──────┬───────┘                                              │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────┐                  │
│  │     Change Detection Cycle Iniciado      │                  │
│  └──────┬───────────────────────────────────┘                  │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────┐                  │
│  │   AppComponent (Root)                    │                  │
│  │   ✓ Verifica TODOS os bindings           │                  │
│  │   ✓ Compara valores com ===              │                  │
│  └──────┬───────────────────────────────────┘                  │
│         │                                                       │
│         ├───► ┌────────────────────────────┐                  │
│         │     │  HeaderComponent           │                  │
│         │     │  ✓ Verifica TODOS bindings │                  │
│         │     └──────┬─────────────────────┘                  │
│         │            │                                          │
│         │            └───► ┌─────────────────┐                 │
│         │                  │  NavComponent   │                 │
│         │                  │  ✓ Verifica...  │                 │
│         │                  └─────────────────┘                 │
│         │                                                       │
│         ├───► ┌────────────────────────────┐                  │
│         │     │  MainComponent             │                  │
│         │     │  ✓ Verifica TODOS bindings │                  │
│         │     └──────┬─────────────────────┘                  │
│         │            │                                          │
│         │            ├───► ┌─────────────────┐                 │
│         │            │     │  ListComponent  │                 │
│         │            │     │  ✓ Verifica...  │                 │
│         │            │     └──────┬──────────┘                 │
│         │            │            │                            │
│         │            │            └───► [100+ ItemComponents] │
│         │            │                  ✓ Cada um verificado   │
│         │            │                                          │
│         │            └───► ┌─────────────────┐                 │
│         │                  │  DetailComponent│                 │
│         │                  │  ✓ Verifica...  │                 │
│         │                  └─────────────────┘                 │
│         │                                                       │
│         └───► ┌────────────────────────────┐                  │
│               │  FooterComponent            │                  │
│               │  ✓ Verifica TODOS bindings │                  │
│               └─────────────────────────────┘                  │
│                                                                 │
│  ⚠️  TODOS os componentes verificados, mesmo sem mudanças!      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-default',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.Default,
  template: `
    <div>
      <p>{{ data }}</p>
      <p>{{ counter }}</p>
      <button (click)="increment()">Increment</button>
    </div>
  `
})
export class DefaultComponent {
  data = 'Hello';
  counter = 0;
  
  increment(): void {
    this.counter++;
  }
}
```

**Análise do Exemplo**:
- Sem `changeDetection` especificado, usa Default automaticamente
- Cada clique no botão dispara change detection em TODOS os componentes da aplicação
- Mesmo componentes que não usam `counter` ou `data` são verificados
- Em uma app com 200 componentes, isso significa 200 verificações por clique

---

### OnPush Strategy

**Definição**: OnPush strategy (ChangeDetectionStrategy.OnPush) verifica mudanças em um componente apenas quando uma de suas condições específicas é atendida: quando inputs mudam por referência, quando eventos ocorrem no próprio componente, ou quando change detection é explicitamente solicitada.

**Explicação Detalhada**:

A OnPush Strategy funciona de forma muito mais seletiva que a Default:

1. **Condições para Verificação**: Um componente OnPush só é verificado quando:
   - **Input Reference Change**: Um `@Input()` recebe uma nova referência (comparação `===`)
   - **Component Event**: Um evento ocorre no próprio componente (click, input, etc.)
   - **Async Pipe Update**: Um `async` pipe detecta nova emissão de Observable
   - **Manual Trigger**: `ChangeDetectorRef.markForCheck()` ou `detectChanges()` é chamado
   - **Signal Update**: Um signal usado no template é atualizado

2. **Verificação de Referência**: OnPush compara inputs por referência (`===`), não por valor profundo. Isso significa:
   - `{ name: 'John' } === { name: 'John' }` retorna `false` (objetos diferentes)
   - `array === array` retorna `true` apenas se for o mesmo objeto
   - Por isso, imutabilidade é essencial

3. **Propagação Limitada**: Quando um componente OnPush é verificado, seus filhos também são verificados, mas apenas se o componente pai foi marcado para verificação

4. **Performance**: Reduz drasticamente o número de verificações:
   - Em uma app com 200 componentes, apenas 2-5 podem ser verificados por ciclo
   - Redução de 95-98% nas verificações comparado à Default

**Características**:
- Verifica apenas quando condições específicas são atendidas
- Requer imutabilidade para funcionar corretamente
- Muito mais eficiente que Default (redução de 50-98% nas verificações)
- Reduz drasticamente verificações desnecessárias
- Requer disciplina de código (imutabilidade)
- Ideal para componentes que recebem dados via `@Input()`

**Quando usar OnPush Strategy**:
- Componentes que recebem dados via `@Input()`
- Componentes que usam signals ou observables
- Aplicações grandes onde performance é crítica
- Componentes "presentacionais" (dumb components)
- Quando você pode garantir imutabilidade dos dados

**Analogia Detalhada**:

Voltando à analogia do shopping center, com OnPush Strategy você é um segurança muito mais inteligente:

1. **Sistema de Notificação**: Cada loja tem um botão de "precisa verificação" que só é ativado quando algo realmente muda

2. **Verificação Seletiva**: Quando um evento acontece, você:
   - Verifica apenas as lojas que ativaram o botão de notificação
   - Ignora completamente as outras 495 lojas que não mudaram nada
   - Foca seu tempo onde realmente importa

3. **Eficiência**: Em vez de verificar 500 lojas toda vez, você verifica apenas 2-5 lojas que realmente precisam

4. **Requisito**: Para isso funcionar, as lojas precisam seguir um protocolo: quando algo muda, elas DEVEM criar uma nova "versão" da loja e ativar o botão. Se uma loja apenas modificar algo internamente sem criar nova versão, você não saberá.

Isso é exatamente como OnPush funciona: você precisa criar novos objetos (imutabilidade) para que Angular detecte mudanças.

**Visualização Completa**:

```
┌─────────────────────────────────────────────────────────────────┐
│              OnPush Change Detection Cycle                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐                                              │
│  │   Evento     │  (click em componente OnPush)                 │
│  │  no Component│                                              │
│  └──────┬───────┘                                              │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────┐                  │
│  │     Change Detection Cycle Iniciado      │                  │
│  └──────┬───────────────────────────────────┘                  │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────┐                  │
│  │   AppComponent (Root)                    │                  │
│  │   ⚠️  OnPush - Verifica inputs?          │                  │
│  │   ❌ Nenhum input mudou                  │                  │
│  │   ⏭️  PULA verificação                   │                  │
│  └──────────────────────────────────────────┘                  │
│         │                                                       │
│         ├───► ┌────────────────────────────┐                  │
│         │     │  HeaderComponent          │                  │
│         │     │  ⚠️  OnPush                │                  │
│         │     │  ❌ Nenhum input mudou     │                  │
│         │     │  ⏭️  PULA                 │                  │
│         │     └────────────────────────────┘                  │
│         │                                                       │
│         ├───► ┌────────────────────────────┐                  │
│         │     │  MainComponent            │                  │
│         │     │  ⚠️  OnPush                │                  │
│         │     │  ❌ Nenhum input mudou     │                  │
│         │     │  ⏭️  PULA                 │                  │
│         │     └──────┬────────────────────┘                  │
│         │            │                                          │
│         │            ├───► ┌─────────────────┐                 │
│         │            │     │  ListComponent   │                 │
│         │            │     │  ⚠️  OnPush      │                 │
│         │            │     │  ✅ Input mudou! │                 │
│         │            │     │  ✓ Verifica...  │                 │
│         │            │     └──────┬──────────┘                 │
│         │            │            │                            │
│         │            │            └───► ┌─────────────────┐     │
│         │            │                  │  ItemComponent │     │
│         │            │                  │  ⚠️  OnPush      │     │
│         │            │                  │  ✅ Input mudou! │     │
│         │            │                  │  ✓ Verifica...  │     │
│         │            │                  └─────────────────┘     │
│         │            │                                          │
│         │            └───► ┌─────────────────┐                 │
│         │                  │  DetailComponent│                 │
│         │                  │  ⚠️  OnPush      │                 │
│         │                  │  ❌ Input não    │                 │
│         │                  │     mudou       │                 │
│         │                  │  ⏭️  PULA       │                 │
│         │                  └─────────────────┘                 │
│         │                                                       │
│         └───► ┌────────────────────────────┐                  │
│               │  FooterComponent            │                  │
│               │  ⚠️  OnPush                │                  │
│               │  ❌ Nenhum input mudou      │                  │
│               │  ⏭️  PULA                  │                  │
│               └─────────────────────────────┘                  │
│                                                                 │
│  ✅ Apenas 2 componentes verificados (vs 200 na Default)!      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático**:

```typescript
@Component({
  selector: 'app-onpush',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <p>{{ user.name }}</p>
      <p>{{ user.email }}</p>
      <button (click)="handleClick()">Click me</button>
    </div>
  `
})
export class OnPushComponent {
  @Input() user: User = { name: '', email: '' };
  
  handleClick(): void {
    console.log('Clicked');
  }
}
```

**Análise do Exemplo**:
- Componente só será verificado quando `user` input mudar por referência
- Clique no botão dispara verificação apenas deste componente (evento local)
- Se `user` for mutado internamente (`user.name = 'New'`), mudança NÃO será detectada
- Para detectar mudanças, precisa passar novo objeto: `user = { ...user, name: 'New' }`

---

### Imutabilidade

**Definição**: Imutabilidade é o princípio de nunca modificar objetos ou arrays existentes diretamente, mas sempre criar novas instâncias quando mudanças são necessárias. Isso permite que comparações por referência (`===`) detectem mudanças de forma confiável.

**Explicação Detalhada**:

A imutabilidade é fundamental para o funcionamento correto da OnPush Strategy:

**Por que Imutabilidade é Necessária**:
- OnPush compara inputs por referência (`===`), não por valor profundo
- Se você modifica um objeto existente, a referência permanece a mesma
- Angular não detecta a mudança porque `oldObject === newObject` retorna `true`
- Criando novos objetos, a referência muda e Angular detecta a mudança

**Padrões de Imutabilidade**:

1. **Arrays**: Sempre criar novos arrays
   - ❌ `items.push(newItem)` - muta array existente
   - ✅ `items = [...items, newItem]` - cria novo array
   - ✅ `items = items.concat(newItem)` - cria novo array
   - ✅ `items = items.filter(...)` - cria novo array

2. **Objetos**: Sempre criar novos objetos
   - ❌ `user.name = 'New'` - muta objeto existente
   - ✅ `user = { ...user, name: 'New' }` - cria novo objeto
   - ✅ `user = Object.assign({}, user, { name: 'New' })` - cria novo objeto

3. **Objetos Aninhados**: Usar spread operator recursivo
   - ❌ `user.address.city = 'New'` - muta objeto aninhado
   - ✅ `user = { ...user, address: { ...user.address, city: 'New' } }`

**Benefícios da Imutabilidade**:
- Permite comparação por referência (`===`) funcionar corretamente
- Essencial para OnPush Strategy detectar mudanças
- Facilita debugging (histórico de estados)
- Torna código mais previsível e testável
- Previne bugs sutis de mutação acidental
- Compatível com Redux e padrões de estado imutável

**Desvantagens**:
- Pode criar mais objetos (overhead de memória)
- Requer disciplina de código
- Pode ser verboso para objetos profundamente aninhados

**Analogia Detalhada**:

Imagine que você está gerenciando versões de um documento importante:

**Abordagem Mutável (Ruim para OnPush)**:
- Você tem o documento "v1.0" em um arquivo
- Quando precisa fazer mudanças, você edita diretamente o arquivo
- O arquivo ainda se chama "v1.0", mas o conteúdo mudou
- Se alguém perguntar "o documento mudou?", você compara o nome do arquivo: "v1.0" === "v1.0" → não mudou (ERRADO!)

**Abordagem Imutável (Bom para OnPush)**:
- Você tem o documento "v1.0" em um arquivo
- Quando precisa fazer mudanças, você cria uma CÓPIA chamada "v1.1"
- Agora você tem dois arquivos: "v1.0" (original) e "v1.1" (novo)
- Se alguém perguntar "o documento mudou?", você compara os nomes: "v1.0" !== "v1.1" → mudou! (CORRETO!)

Angular funciona exatamente assim: ele compara "nomes de arquivo" (referências), não o conteúdo. Se você edita o arquivo sem mudar o nome, Angular não percebe. Se você cria um novo arquivo com novo nome, Angular detecta imediatamente.

**Visualização**:

```
┌─────────────────────────────────────────────────────────────┐
│              Mutação vs Imutabilidade                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         ABORDAGEM MUTÁVEL (❌ Ruim)                 │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │                                                     │   │
│  │  const user = { name: 'John', age: 30 };          │   │
│  │  const reference = user;                           │   │
│  │                                                     │   │
│  │  user.name = 'Jane';  // ← MUTA objeto existente   │   │
│  │                                                     │   │
│  │  user === reference  // true (mesma referência!)   │   │
│  │  // Angular OnPush: "Não mudou!" ❌                │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         ABORDAGEM IMUTÁVEL (✅ Bom)                  │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │                                                     │   │
│  │  const user = { name: 'John', age: 30 };          │   │
│  │  const oldReference = user;                       │   │
│  │                                                     │   │
│  │  const newUser = { ...user, name: 'Jane' };        │   │
│  │  // ← CRIA novo objeto                             │   │
│  │                                                     │   │
│  │  newUser === oldReference  // false (nova ref!)    │   │
│  │  // Angular OnPush: "Mudou!" ✅                    │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
interface User {
  id: number;
  name: string;
  email: string;
  preferences: {
    theme: string;
    notifications: boolean;
  };
}

@Component({
  selector: 'app-immutable',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>{{ user.name }}</h2>
      <p>{{ user.email }}</p>
      <p>Theme: {{ user.preferences.theme }}</p>
      <button (click)="updateName()">Update Name</button>
      <button (click)="updateTheme()">Update Theme</button>
    </div>
  `
})
export class ImmutableComponent {
  @Input() user: User = {
    id: 1,
    name: 'John',
    email: 'john@example.com',
    preferences: {
      theme: 'light',
      notifications: true
    }
  };
  
  updateName(): void {
    this.user = {
      ...this.user,
      name: 'Jane'
    };
  }
  
  updateTheme(): void {
    this.user = {
      ...this.user,
      preferences: {
        ...this.user.preferences,
        theme: this.user.preferences.theme === 'light' ? 'dark' : 'light'
      }
    };
  }
}
```

**Análise do Exemplo**:
- `updateName()` cria novo objeto `user` com spread operator
- `updateTheme()` cria novo objeto com spread aninhado para `preferences`
- Cada atualização cria nova referência, permitindo OnPush detectar mudanças
- Se mutássemos diretamente (`this.user.name = 'Jane'`), OnPush não detectaria

---

### ChangeDetectorRef

**Definição**: ChangeDetectorRef é uma classe injetável que fornece métodos para controlar change detection manualmente em um componente, permitindo otimizações avançadas e controle fino sobre quando verificações ocorrem.

**Explicação Detalhada**:

ChangeDetectorRef oferece controle programático sobre change detection através de métodos específicos:

**Métodos Principais**:

1. **`detectChanges()`**: Força uma verificação imediata de change detection no componente e seus filhos
   - Executa sincronamente, não espera o próximo ciclo
   - Útil quando você sabe que mudanças ocorreram fora do ciclo normal
   - Use com cuidado: pode causar verificações desnecessárias

2. **`markForCheck()`**: Marca o componente e seus ancestrais para verificação no próximo ciclo
   - Não executa imediatamente, apenas marca para o próximo ciclo
   - Útil em componentes OnPush quando mudanças ocorrem fora do ciclo normal
   - Mais eficiente que `detectChanges()` porque não força verificação imediata

3. **`detach()`**: Desconecta o componente do ciclo de change detection
   - Componente não será mais verificado automaticamente
   - Útil para componentes que raramente mudam ou quando você quer controle total
   - Você precisa chamar `detectChanges()` manualmente quando necessário

4. **`reattach()`**: Reconecta um componente desconectado ao ciclo de change detection
   - Reverte o efeito de `detach()`
   - Componente volta a ser verificado automaticamente

**Quando Usar Cada Método**:

- **`markForCheck()`**: Quando usar Observables ou callbacks assíncronos em componentes OnPush
- **`detectChanges()`**: Quando você precisa de verificação imediata e sabe exatamente quando chamar
- **`detach()`**: Para componentes que raramente mudam e você quer controle total
- **`reattach()`**: Para reconectar componentes desconectados dinamicamente

**Analogia Detalhada**:

ChangeDetectorRef é como um controle remoto universal para um sistema de segurança:

**`markForCheck()`** - Botão "Verificar na Próxima Ronda":
- Você pressiona o botão quando sabe que algo mudou
- O sistema não verifica imediatamente, mas marca para verificar na próxima ronda de inspeção
- Eficiente porque agrupa verificações

**`detectChanges()`** - Botão "Verificar AGORA":
- Você pressiona quando precisa de verificação imediata
- O sistema para tudo e verifica imediatamente
- Pode ser ineficiente se usado demais

**`detach()`** - Botão "Desligar Sistema":
- Desliga completamente o sistema de verificação automática
- Você assume controle total
- Útil quando você sabe exatamente quando verificar manualmente

**`reattach()`** - Botão "Religar Sistema":
- Religa o sistema de verificação automática
- Volta ao comportamento normal

**Visualização**:

```
┌─────────────────────────────────────────────────────────────┐
│           ChangeDetectorRef Methods                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Component (OnPush)                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                                                     │   │
│  │  ┌───────────────────────────────────────────────┐ │   │
│  │  │  markForCheck()                               │ │   │
│  │  │  ┌─────────────────────────────────────────┐ │ │   │
│  │  │  │ Marca para verificação no próximo ciclo │ │ │   │
│  │  │  │ Não executa imediatamente               │ │ │   │
│  │  │  │ Eficiente - agrupa verificações         │ │ │   │
│  │  │  └─────────────────────────────────────────┘ │ │   │
│  │  └───────────────────────────────────────────────┘ │   │
│  │                                                     │   │
│  │  ┌───────────────────────────────────────────────┐ │   │
│  │  │  detectChanges()                              │ │   │
│  │  │  ┌─────────────────────────────────────────┐ │ │   │
│  │  │  │ Força verificação IMEDIATA              │ │ │   │
│  │  │  │ Executa sincronamente                   │ │ │   │
│  │  │  │ Pode ser ineficiente se usado demais   │ │ │   │
│  │  │  └─────────────────────────────────────────┘ │ │   │
│  │  └───────────────────────────────────────────────┘ │   │
│  │                                                     │   │
│  │  ┌───────────────────────────────────────────────┐ │   │
│  │  │  detach()                                     │ │   │
│  │  │  ┌─────────────────────────────────────────┐ │ │   │
│  │  │  │ Desconecta do ciclo automático          │ │ │   │
│  │  │  │ Você assume controle total              │ │ │   │
│  │  │  │ Deve chamar detectChanges() manualmente │ │ │   │
│  │  │  └─────────────────────────────────────────┘ │ │   │
│  │  └───────────────────────────────────────────────┘ │   │
│  │                                                     │   │
│  │  ┌───────────────────────────────────────────────┐ │   │
│  │  │  reattach()                                   │ │   │
│  │  │  ┌─────────────────────────────────────────┐ │ │   │
│  │  │  │ Reconecta ao ciclo automático          │ │ │   │
│  │  │  │ Volta ao comportamento normal          │ │ │   │
│  │  │  └─────────────────────────────────────────┘ │ │   │
│  │  └───────────────────────────────────────────────┘ │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { Component, ChangeDetectionStrategy, ChangeDetectorRef, OnInit, OnDestroy } from '@angular/core';
import { Observable, interval } from 'rxjs';

@Component({
  selector: 'app-manual',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <p>Counter: {{ counter }}</p>
      <p>Status: {{ status }}</p>
      <button (click)="startTimer()">Start Timer</button>
      <button (click)="stopTimer()">Stop Timer</button>
      <button (click)="detachComponent()">Detach</button>
      <button (click)="reattachComponent()">Reattach</button>
    </div>
  `
})
export class ManualComponent implements OnInit, OnDestroy {
  counter = 0;
  status = 'Stopped';
  private timer?: Observable<number>;
  private subscription?: any;
  
  constructor(private cdr: ChangeDetectorRef) {}
  
  ngOnInit(): void {
    this.startTimer();
  }
  
  startTimer(): void {
    this.status = 'Running';
    this.timer = interval(1000);
    this.subscription = this.timer.subscribe(() => {
      this.counter++;
      this.cdr.markForCheck();
    });
  }
  
  stopTimer(): void {
    this.status = 'Stopped';
    this.subscription?.unsubscribe();
  }
  
  detachComponent(): void {
    this.cdr.detach();
    this.status = 'Detached';
  }
  
  reattachComponent(): void {
    this.cdr.reattach();
    this.status = 'Reattached';
    this.cdr.markForCheck();
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }
}
```

**Análise do Exemplo**:
- Componente OnPush que atualiza `counter` via Observable
- `markForCheck()` necessário porque Observable não dispara change detection automaticamente em OnPush
- `detach()` e `reattach()` demonstram controle manual completo
- Sem `markForCheck()`, o componente não atualizaria mesmo com timer rodando

---

### trackBy Functions

**Definição**: trackBy functions são funções que ajudam Angular a identificar de forma única cada item em uma lista renderizada com `@for` ou `*ngFor`, permitindo que Angular reutilize componentes DOM existentes ao invés de destruir e recriar quando a lista muda.

**Explicação Detalhada**:

**Problema sem trackBy**:
Quando uma lista muda, Angular por padrão:
1. Destrói todos os componentes DOM da lista
2. Cria novos componentes DOM para cada item
3. Mesmo itens que não mudaram são recriados
4. Isso é extremamente ineficiente para listas grandes

**Solução com trackBy**:
Com trackBy, Angular:
1. Compara o valor retornado por trackBy para cada item
2. Se o valor é o mesmo, reutiliza o componente DOM existente
3. Se o valor mudou ou é novo, cria novo componente
4. Reduz drasticamente criação/destruição de componentes

**Como Funciona**:
- trackBy recebe `(index, item)` e retorna um valor único (geralmente `id`)
- Angular usa esse valor para identificar itens
- Quando lista muda, Angular compara valores trackBy ao invés de comparar objetos inteiros
- Componentes com mesmo trackBy são reutilizados

**Benefícios**:
- Evita re-renderização desnecessária de componentes
- Melhora performance significativamente em listas grandes
- Reduz trabalho do change detection
- Preserva estado de componentes (scroll position, focus, etc.)
- Essencial para listas com 50+ itens

**Quando Usar**:
- Listas grandes (50+ itens)
- Listas que mudam frequentemente
- Quando performance é crítica
- Quando componentes têm estado interno importante

**Analogia Detalhada**:

Imagine que você é um professor corrigindo provas de uma turma de 100 alunos:

**Sem trackBy (Abordagem Ineficiente)**:
- Você recebe uma nova lista de provas
- Mesmo que apenas 2 alunos tenham refeito a prova, você:
  - Joga TODAS as 100 provas antigas no lixo
  - Pega 100 provas novas em branco
  - Reescreve TODAS as correções do zero
  - Mesmo as 98 provas que não mudaram são recriadas completamente

**Com trackBy (Abordagem Eficiente)**:
- Você recebe uma nova lista de provas
- Cada prova tem um número único (ID do aluno)
- Você compara os números:
  - Prova #42 ainda é do aluno #42? → Reutiliza correção existente
  - Prova #43 é nova (número diferente)? → Cria nova correção
  - Prova #44 foi removida? → Descarta correção antiga
- Você só trabalha nas provas que realmente mudaram

Angular funciona exatamente assim: trackBy fornece o "número único" (ID) que permite identificar quais itens são os mesmos e podem ser reutilizados.

**Visualização**:

```
┌─────────────────────────────────────────────────────────────┐
│           Lista SEM trackBy (❌ Ineficiente)                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Lista Antiga: [A, B, C, D, E]                            │
│  Lista Nova:   [A, B, X, D, E]  (C → X)                   │
│                                                             │
│  Angular:                                                    │
│  ❌ Destrói componente A (mesmo não mudou!)                │
│  ❌ Destrói componente B (mesmo não mudou!)                │
│  ❌ Destrói componente C                                    │
│  ❌ Destrói componente D (mesmo não mudou!)                │
│  ❌ Destrói componente E (mesmo não mudou!)                │
│                                                             │
│  ✅ Cria novo componente A                                  │
│  ✅ Cria novo componente B                                  │
│  ✅ Cria novo componente X                                  │
│  ✅ Cria novo componente D                                  │
│  ✅ Cria novo componente E                                  │
│                                                             │
│  Resultado: 5 destruições + 5 criações = 10 operações      │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│           Lista COM trackBy (✅ Eficiente)                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Lista Antiga: [A(id:1), B(id:2), C(id:3), D(id:4), E(id:5)]│
│  Lista Nova:   [A(id:1), B(id:2), X(id:6), D(id:4), E(id:5)]│
│                                                             │
│  Angular (com trackBy):                                     │
│  ✅ Reutiliza componente A (id:1 igual)                     │
│  ✅ Reutiliza componente B (id:2 igual)                     │
│  ❌ Destrói componente C (id:3 não existe mais)             │
│  ✅ Reutiliza componente D (id:4 igual)                     │
│  ✅ Reutiliza componente E (id:5 igual)                     │
│                                                             │
│  ✅ Cria novo componente X (id:6 novo)                       │
│                                                             │
│  Resultado: 1 destruição + 1 criação = 2 operações          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

{% raw %}
```typescript
interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
}

@Component({
  selector: 'app-trackby',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>Products ({{ products().length }})</h2>
      <button (click)="refreshProducts()">Refresh</button>
      <button (click)="addProduct()">Add Product</button>
      <ul>
        @for (product of products(); track trackByProductId($index, product)) {
          <li>
            <strong>{{ product.name }}</strong> - 
            {{ product.price | currency }} - 
            {{ product.category }}
          </li>
        }
      </ul>
    </div>
  `
})
export class TrackByComponent {
  products = signal<Product[]>([]);
  
  constructor() {
    this.loadProducts();
  }
  
  trackByProductId(index: number, product: Product): number {
    return product.id;
  }
  
  loadProducts(): void {
    this.products.set([
      { id: 1, name: 'Laptop', price: 999, category: 'Electronics' },
      { id: 2, name: 'Mouse', price: 25, category: 'Accessories' },
      { id: 3, name: 'Keyboard', price: 75, category: 'Accessories' }
    ]);
  }
  
  refreshProducts(): void {
    this.products.update(products => [...products]);
  }
  
  addProduct(): void {
    this.products.update(products => [
      ...products,
      { 
        id: Date.now(), 
        name: `Product ${products.length + 1}`, 
        price: Math.random() * 100,
        category: 'New'
      }
    ]);
  }
}
```
{% raw %}
interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
}

@Component({
  selector: 'app-trackby',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>Products ({{ products().length }})</h2>
      <button (click)="refreshProducts()">Refresh</button>
      <button (click)="addProduct()">Add Product</button>
      <ul>
        @for (product of products(); track trackByProductId($index, product)) {
          <li>
            <strong>{{ product.name }}</strong> - 
            {{ product.price | currency }} - 
            {{ product.category }}
          </li>
        }
      </ul>
    </div>
  `
})
export class TrackByComponent {
  products = signal<Product[]>([]);
  
  constructor() {
    this.loadProducts();
  }
  
  trackByProductId(index: number, product: Product): number {
    return product.id;
  }
  
  loadProducts(): void {
    this.products.set([
      { id: 1, name: 'Laptop', price: 999, category: 'Electronics' },
      { id: 2, name: 'Mouse', price: 25, category: 'Accessories' },
      { id: 3, name: 'Keyboard', price: 75, category: 'Accessories' }
    ]);
  }
  
  refreshProducts(): void {
    this.products.update(products => [...products]);
  }
  
  addProduct(): void {
    this.products.update(products => [
      ...products,
      { 
        id: Date.now(), 
        name: `Product ${products.length + 1}`, 
        price: Math.random() * 100,
        category: 'New'
      }
    ]);
  }
}
```
{% endraw %}

**Análise do Exemplo**:
- `trackByProductId` retorna `product.id` como identificador único
- Quando lista muda, Angular compara IDs ao invés de objetos inteiros
- Componentes com mesmo ID são reutilizados (preserva estado, scroll, etc.)
- Apenas itens novos ou removidos causam criação/destruição
- Em lista com 1000 produtos, mudar 1 produto causa apenas 1 operação DOM ao invés de 1000

---

## Comparação com Outros Frameworks

### Tabela Comparativa: Change Detection Strategies

| Framework | Estratégia Padrão | Estratégia Otimizada | Mecanismo | Performance | Complexidade |
|-----------|-------------------|---------------------|-----------|-------------|--------------|
| **Angular** | Default (verifica tudo) | OnPush (verificação seletiva) | Zone.js + Change Detection Tree | Alta com OnPush | Média-Alta |
| **React** | Re-render quando state/props mudam | React.memo, useMemo, useCallback | Virtual DOM + Reconciliation | Alta (otimizada) | Média |
| **Vue 3** | Re-render quando reactive data muda | v-memo, computed, watch | Proxy-based Reactivity | Muito Alta | Baixa-Média |
| **Svelte** | Compile-time optimization | N/A (otimizado em build) | Compile-time reactivity | Muito Alta | Baixa |

### Análise Detalhada por Framework

#### Angular vs React

**Angular (Default Strategy)**:
- Verifica todos componentes em cada ciclo
- Zone.js detecta eventos assíncronos automaticamente
- Comparação por referência (`===`)
- Pode ser ineficiente sem OnPush

**Angular (OnPush Strategy)**:
- Verifica apenas quando inputs mudam
- Requer imutabilidade
- Performance similar ao React.memo
- Mais controle manual necessário

**React**:
- Re-render apenas quando state/props mudam
- Comparação por referência nativa
- React.memo para otimização similar ao OnPush
- Não precisa de Zone.js (não tem)

**Vantagens Angular**:
- Zone.js detecta automaticamente eventos assíncronos
- OnPush oferece controle fino
- ChangeDetectorRef permite controle manual avançado

**Vantagens React**:
- Otimização mais simples (React.memo)
- Não precisa Zone.js (menor bundle)
- Re-render mais previsível

#### Angular vs Vue 3

**Angular (OnPush)**:
- Verificação seletiva baseada em referência
- Requer imutabilidade explícita
- Controle manual com ChangeDetectorRef

**Vue 3**:
- Reatividade baseada em Proxy
- Detecta mudanças profundas automaticamente
- Não precisa imutabilidade explícita
- v-memo para otimização de listas

**Vantagens Angular**:
- Controle mais explícito
- OnPush pode ser mais eficiente em casos específicos
- Melhor para aplicações muito grandes

**Vantagens Vue 3**:
- Mais simples de usar (não precisa imutabilidade)
- Reatividade automática mais poderosa
- Menos código boilerplate

#### Angular vs Svelte

**Angular**:
- Runtime change detection
- Zone.js necessário
- Bundle maior

**Svelte**:
- Compile-time optimization
- Sem runtime change detection
- Bundle menor
- Performance superior em muitos casos

**Vantagens Angular**:
- Mais flexível em runtime
- Ecossistema maior
- Mais recursos e ferramentas

**Vantagens Svelte**:
- Performance superior
- Bundle menor
- Código mais simples

### Quando Escolher Cada Abordagem

**Use Angular OnPush quando**:
- Você precisa de controle fino sobre change detection
- Aplicação grande com muitos componentes
- Você pode garantir imutabilidade
- Performance é crítica e você quer otimizar manualmente

**Use React.memo quando**:
- Você quer otimização simples
- Não quer lidar com Zone.js
- Prefere abordagem mais funcional

**Use Vue 3 quando**:
- Você quer reatividade automática poderosa
- Não quer se preocupar com imutabilidade
- Quer simplicidade sem perder performance

**Use Svelte quando**:
- Performance é prioridade máxima
- Bundle size é crítico
- Você quer código mais simples

---

## Exemplos Práticos Completos

### Exemplo 1: Componente OnPush Completo com Signals

**Contexto**: Criar componente completo usando OnPush strategy com imutabilidade e signals, demonstrando todas as práticas recomendadas.

**Código**:

{% raw %}
```typescript
import { Component, Input, ChangeDetectionStrategy, signal, computed, effect } from '@angular/core';
import { CommonModule } from '@angular/common';

interface User {
  id: number;
  name: string;
  email: string;
  role: 'admin' | 'user' | 'guest';
  lastLogin?: Date;
}

@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="user-list">
      <div class="header">
        <h2>Usuários (OnPush Strategy)</h2>
        <div class="stats">
          <p>Total: {{ userCount() }}</p>
          <p>Admins: {{ adminCount() }}</p>
          <p>Active: {{ activeUsers().length }}</p>
        </div>
      </div>
      
      <div class="actions">
        <button (click)="addUser()">Adicionar Usuário</button>
        <button (click)="refreshUsers()">Atualizar Lista</button>
        <button (click)="clearUsers()">Limpar</button>
      </div>
      
      <div class="filter">
        <label>
          Filtrar por role:
          <select [value]="filterRole()" (change)="setFilterRole($event)">
            <option value="">Todos</option>
            <option value="admin">Admin</option>
            <option value="user">User</option>
            <option value="guest">Guest</option>
          </select>
        </label>
      </div>
      
      <ul class="user-list-items">
        @for (user of filteredUsers(); track trackByUserId($index, user)) {
          <li class="user-item">
            <div class="user-info">
              <strong>{{ user.name }}</strong>
              <span class="email">{{ user.email }}</span>
              <span class="role" [class]="'role-' + user.role">{{ user.role }}</span>
            </div>
            <div class="user-actions">
              <button (click)="updateUser(user.id, { role: 'admin' })">Make Admin</button>
              <button (click)="removeUser(user.id)">Remover</button>
            </div>
          </li>
        } @empty {
          <li class="empty">Nenhum usuário encontrado</li>
        }
      </ul>
    </div>
  `,
  styles: [`
    .user-list { padding: 20px; }
    .header { display: flex; justify-content: space-between; margin-bottom: 20px; }
    .stats { display: flex; gap: 20px; }
    .actions { display: flex; gap: 10px; margin-bottom: 20px; }
    .user-list-items { list-style: none; padding: 0; }
    .user-item { 
      display: flex; 
      justify-content: space-between; 
      padding: 10px; 
      border-bottom: 1px solid #eee; 
    }
    .role { padding: 4px 8px; border-radius: 4px; }
    .role-admin { background: #ff6b6b; }
    .role-user { background: #4ecdc4; }
    .role-guest { background: #ffe66d; }
  `]
})
export class UserListComponent {
  users = signal<User[]>([]);
  filterRole = signal<string>('');
  
  userCount = computed(() => this.users().length);
  
  adminCount = computed(() => 
    this.users().filter(u => u.role === 'admin').length
  );
  
  activeUsers = computed(() =>
    this.users().filter(u => u.lastLogin && 
      new Date(u.lastLogin).getTime() > Date.now() - 7 * 24 * 60 * 60 * 1000
    )
  );
  
  filteredUsers = computed(() => {
    const role = this.filterRole();
    if (!role) return this.users();
    return this.users().filter(u => u.role === role);
  });
  
  constructor() {
    this.loadInitialUsers();
    
    effect(() => {
      console.log(`Users updated: ${this.users().length} total`);
    });
  }
  
  trackByUserId(index: number, user: User): number {
    return user.id;
  }
  
  loadInitialUsers(): void {
    this.users.set([
      { id: 1, name: 'John Doe', email: 'john@example.com', role: 'admin', lastLogin: new Date() },
      { id: 2, name: 'Jane Smith', email: 'jane@example.com', role: 'user', lastLogin: new Date() },
      { id: 3, name: 'Bob Johnson', email: 'bob@example.com', role: 'guest' }
    ]);
  }
  
  addUser(): void {
    const newUser: User = {
      id: Date.now(),
      name: `User ${this.users().length + 1}`,
      email: `user${this.users().length + 1}@example.com`,
      role: 'user',
      lastLogin: new Date()
    };
    
    this.users.update(users => [...users, newUser]);
  }
  
  updateUser(id: number, changes: Partial<User>): void {
    this.users.update(users =>
      users.map(user => 
        user.id === id 
          ? { ...user, ...changes }
          : user
      )
    );
  }
  
  removeUser(id: number): void {
    this.users.update(users => 
      users.filter(user => user.id !== id)
    );
  }
  
  refreshUsers(): void {
    this.users.update(users => [...users]);
  }
  
  clearUsers(): void {
    this.users.set([]);
  }
  
  setFilterRole(event: Event): void {
    const select = event.target as HTMLSelectElement;
    this.filterRole.set(select.value);
  }
}
```
{% endraw %}

**Explicação**:
- Usa OnPush strategy para performance otimizada
- Signals para estado reativo e imutável
- Computed signals para valores derivados
- trackBy para otimização de lista
- Todas as operações criam novos objetos (imutabilidade)
- Effect para side effects (logging)

---

### Exemplo 2: Componente com ChangeDetectorRef e Observables

**Contexto**: Demonstrar uso de ChangeDetectorRef com Observables em componente OnPush.

**Código**:

{% raw %}
```typescript
import { Component, ChangeDetectionStrategy, ChangeDetectorRef, OnInit, OnDestroy, Input, signal } from '@angular/core';
import { Observable, interval, Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

interface StockPrice {
  symbol: string;
  price: number;
  change: number;
  timestamp: Date;
}

@Component({
  selector: 'app-stock-tracker',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="stock-tracker">
      <h2>Stock Tracker (OnPush + Observables)</h2>
      
      <div class="controls">
        <button (click)="startTracking()" [disabled]="isTracking()">
          Start Tracking
        </button>
        <button (click)="stopTracking()" [disabled]="!isTracking()">
          Stop Tracking
        </button>
        <button (click)="toggleDetached()">
          {{ isDetached() ? 'Reattach' : 'Detach' }}
        </button>
      </div>
      
      <div class="status">
        <p>Status: {{ isTracking() ? 'Tracking' : 'Stopped' }}</p>
        <p>Detached: {{ isDetached() ? 'Yes' : 'No' }}</p>
        <p>Updates: {{ updateCount() }}</p>
      </div>
      
      <div class="stocks">
        @for (stock of stocks(); track stock.symbol) {
          <div class="stock-item">
            <span class="symbol">{{ stock.symbol }}</span>
            <span class="price" [class.positive]="stock.change > 0" 
                              [class.negative]="stock.change < 0">
              ${{ stock.price.toFixed(2) }}
            </span>
            <span class="change">
              {{ stock.change > 0 ? '+' : '' }}{{ stock.change.toFixed(2) }}
            </span>
            <span class="timestamp">
              {{ stock.timestamp | date:'HH:mm:ss' }}
            </span>
          </div>
        }
      </div>
    </div>
  `,
  styles: [`
    .stock-tracker { padding: 20px; }
    .controls { display: flex; gap: 10px; margin-bottom: 20px; }
    .status { margin-bottom: 20px; }
    .stocks { display: flex; flex-direction: column; gap: 10px; }
    .stock-item { 
      display: flex; 
      gap: 20px; 
      padding: 10px; 
      border: 1px solid #ddd; 
      border-radius: 4px;
    }
    .symbol { font-weight: bold; min-width: 80px; }
    .price { min-width: 100px; }
    .positive { color: green; }
    .negative { color: red; }
  `]
})
export class StockTrackerComponent implements OnInit, OnDestroy {
  stocks = signal<StockPrice[]>([]);
  isTracking = signal<boolean>(false);
  isDetached = signal<boolean>(false);
  updateCount = signal<number>(0);
  
  private destroy$ = new Subject<void>();
  private stockSymbols = ['AAPL', 'GOOGL', 'MSFT', 'AMZN', 'TSLA'];
  
  constructor(private cdr: ChangeDetectorRef) {}
  
  ngOnInit(): void {
    this.initializeStocks();
  }
  
  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }
  
  initializeStocks(): void {
    const initialStocks: StockPrice[] = this.stockSymbols.map(symbol => ({
      symbol,
      price: Math.random() * 1000,
      change: 0,
      timestamp: new Date()
    }));
    this.stocks.set(initialStocks);
  }
  
  startTracking(): void {
    if (this.isTracking()) return;
    
    this.isTracking.set(true);
    
    interval(1000)
      .pipe(takeUntil(this.destroy$))
      .subscribe(() => {
        this.updateStocks();
        
        if (this.isDetached()) {
          this.cdr.detectChanges();
        } else {
          this.cdr.markForCheck();
        }
        
        this.updateCount.update(count => count + 1);
      });
  }
  
  stopTracking(): void {
    this.isTracking.set(false);
    this.destroy$.next();
  }
  
  updateStocks(): void {
    this.stocks.update(stocks =>
      stocks.map(stock => {
        const change = (Math.random() - 0.5) * 10;
        const newPrice = Math.max(0, stock.price + change);
        
        return {
          ...stock,
          price: newPrice,
          change: change,
          timestamp: new Date()
        };
      })
    );
  }
  
  toggleDetached(): void {
    if (this.isDetached()) {
      this.cdr.reattach();
      this.isDetached.set(false);
    } else {
      this.cdr.detach();
      this.isDetached.set(true);
    }
  }
}
```
{% raw %}
import { Component, ChangeDetectionStrategy, ChangeDetectorRef, OnInit, OnDestroy, Input, signal } from '@angular/core';
import { Observable, interval, Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

interface StockPrice {
  symbol: string;
  price: number;
  change: number;
  timestamp: Date;
}

@Component({
  selector: 'app-stock-tracker',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="stock-tracker">
      <h2>Stock Tracker (OnPush + Observables)</h2>
      
      <div class="controls">
        <button (click)="startTracking()" [disabled]="isTracking()">
          Start Tracking
        </button>
        <button (click)="stopTracking()" [disabled]="!isTracking()">
          Stop Tracking
        </button>
        <button (click)="toggleDetached()">
          {{ isDetached() ? 'Reattach' : 'Detach' }}
        </button>
      </div>
      
      <div class="status">
        <p>Status: {{ isTracking() ? 'Tracking' : 'Stopped' }}</p>
        <p>Detached: {{ isDetached() ? 'Yes' : 'No' }}</p>
        <p>Updates: {{ updateCount() }}</p>
      </div>
      
      <div class="stocks">
        @for (stock of stocks(); track stock.symbol) {
          <div class="stock-item">
            <span class="symbol">{{ stock.symbol }}</span>
            <span class="price" [class.positive]="stock.change > 0" 
                              [class.negative]="stock.change < 0">
              ${{ stock.price.toFixed(2) }}
            </span>
            <span class="change">
              {{ stock.change > 0 ? '+' : '' }}{{ stock.change.toFixed(2) }}
            </span>
            <span class="timestamp">
              {{ stock.timestamp | date:'HH:mm:ss' }}
            </span>
          </div>
        }
      </div>
    </div>
  `,
  styles: [`
    .stock-tracker { padding: 20px; }
    .controls { display: flex; gap: 10px; margin-bottom: 20px; }
    .status { margin-bottom: 20px; }
    .stocks { display: flex; flex-direction: column; gap: 10px; }
    .stock-item { 
      display: flex; 
      gap: 20px; 
      padding: 10px; 
      border: 1px solid #ddd; 
      border-radius: 4px;
    }
    .symbol { font-weight: bold; min-width: 80px; }
    .price { min-width: 100px; }
    .positive { color: green; }
    .negative { color: red; }
  `]
})
export class StockTrackerComponent implements OnInit, OnDestroy {
  stocks = signal<StockPrice[]>([]);
  isTracking = signal<boolean>(false);
  isDetached = signal<boolean>(false);
  updateCount = signal<number>(0);
  
  private destroy$ = new Subject<void>();
  private stockSymbols = ['AAPL', 'GOOGL', 'MSFT', 'AMZN', 'TSLA'];
  
  constructor(private cdr: ChangeDetectorRef) {}
  
  ngOnInit(): void {
    this.initializeStocks();
  }
  
  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }
  
  initializeStocks(): void {
    const initialStocks: StockPrice[] = this.stockSymbols.map(symbol => ({
      symbol,
      price: Math.random() * 1000,
      change: 0,
      timestamp: new Date()
    }));
    this.stocks.set(initialStocks);
  }
  
  startTracking(): void {
    if (this.isTracking()) return;
    
    this.isTracking.set(true);
    
    interval(1000)
      .pipe(takeUntil(this.destroy$))
      .subscribe(() => {
        this.updateStocks();
        
        if (this.isDetached()) {
          this.cdr.detectChanges();
        } else {
          this.cdr.markForCheck();
        }
        
        this.updateCount.update(count => count + 1);
      });
  }
  
  stopTracking(): void {
    this.isTracking.set(false);
    this.destroy$.next();
  }
  
  updateStocks(): void {
    this.stocks.update(stocks =>
      stocks.map(stock => {
        const change = (Math.random() - 0.5) * 10;
        const newPrice = Math.max(0, stock.price + change);
        
        return {
          ...stock,
          price: newPrice,
          change: change,
          timestamp: new Date()
        };
      })
    );
  }
  
  toggleDetached(): void {
    if (this.isDetached()) {
      this.cdr.reattach();
      this.isDetached.set(false);
    } else {
      this.cdr.detach();
      this.isDetached.set(true);
    }
  }
}
```
{% endraw %}

**Explicação**:
- Componente OnPush que atualiza via Observable
- `markForCheck()` necessário porque Observable não dispara change detection automaticamente
- `detach()` e `reattach()` demonstram controle manual
- `detectChanges()` usado quando componente está detached
- Todas as atualizações são imutáveis

---

### Exemplo 3: Performance Comparison - Default vs OnPush

**Contexto**: Demonstrar diferença de performance entre Default e OnPush strategies.

**Código**:

{% raw %}
```typescript
import { Component, ChangeDetectionStrategy, Input, signal } from '@angular/core';

@Component({
  selector: 'app-performance-demo',
  standalone: true,
  template: `
    <div class="performance-demo">
      <h2>Performance Comparison</h2>
      
      <div class="controls">
        <button (click)="triggerChangeDetection()">
          Trigger Change Detection
        </button>
        <button (click)="addComponent()">Add Component</button>
        <button (click)="clearComponents()">Clear</button>
      </div>
      
      <div class="stats">
        <p>Total Components: {{ componentCount() }}</p>
        <p>Change Detection Cycles: {{ cycles() }}</p>
        <p>Last Update: {{ lastUpdate() | date:'HH:mm:ss.SSS' }}</p>
      </div>
      
      <div class="components">
        @for (id of componentIds(); track id) {
          <app-dummy-component [id]="id" [data]="sharedData()" />
        }
      </div>
    </div>
  `
})
export class PerformanceDemoComponent {
  componentIds = signal<number[]>([]);
  sharedData = signal<string>('Initial Data');
  cycles = signal<number>(0);
  lastUpdate = signal<Date>(new Date());
  
  componentCount = signal<number>(0);
  
  constructor() {
    setInterval(() => {
      this.cycles.update(c => c + 1);
      this.lastUpdate.set(new Date());
    }, 100);
  }
  
  triggerChangeDetection(): void {
    this.sharedData.update(data => `Updated: ${Date.now()}`);
  }
  
  addComponent(): void {
    this.componentIds.update(ids => [...ids, Date.now()]);
    this.componentCount.set(this.componentIds().length);
  }
  
  clearComponents(): void {
    this.componentIds.set([]);
    this.componentCount.set(0);
  }
}

@Component({
  selector: 'app-dummy-component',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.Default,
  template: `
    <div class="dummy">
      <span>Component {{ id }}</span>
      <span>{{ data }}</span>
    </div>
  `
})
export class DummyComponentDefault {
  @Input() id!: number;
  @Input() data!: string;
}

@Component({
  selector: 'app-dummy-component-onpush',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="dummy">
      <span>Component {{ id }}</span>
      <span>{{ data }}</span>
    </div>
  `
})
export class DummyComponentOnPush {
  @Input() id!: number;
  @Input() data!: string;
}
```
{% raw %}
import { Component, ChangeDetectionStrategy, Input, signal } from '@angular/core';

@Component({
  selector: 'app-performance-demo',
  standalone: true,
  template: `
    <div class="performance-demo">
      <h2>Performance Comparison</h2>
      
      <div class="controls">
        <button (click)="triggerChangeDetection()">
          Trigger Change Detection
        </button>
        <button (click)="addComponent()">Add Component</button>
        <button (click)="clearComponents()">Clear</button>
      </div>
      
      <div class="stats">
        <p>Total Components: {{ componentCount() }}</p>
        <p>Change Detection Cycles: {{ cycles() }}</p>
        <p>Last Update: {{ lastUpdate() | date:'HH:mm:ss.SSS' }}</p>
      </div>
      
      <div class="components">
        @for (id of componentIds(); track id) {
          <app-dummy-component [id]="id" [data]="sharedData()" />
        }
      </div>
    </div>
  `
})
export class PerformanceDemoComponent {
  componentIds = signal<number[]>([]);
  sharedData = signal<string>('Initial Data');
  cycles = signal<number>(0);
  lastUpdate = signal<Date>(new Date());
  
  componentCount = signal<number>(0);
  
  constructor() {
    setInterval(() => {
      this.cycles.update(c => c + 1);
      this.lastUpdate.set(new Date());
    }, 100);
  }
  
  triggerChangeDetection(): void {
    this.sharedData.update(data => `Updated: ${Date.now()}`);
  }
  
  addComponent(): void {
    this.componentIds.update(ids => [...ids, Date.now()]);
    this.componentCount.set(this.componentIds().length);
  }
  
  clearComponents(): void {
    this.componentIds.set([]);
    this.componentCount.set(0);
  }
}

@Component({
  selector: 'app-dummy-component',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.Default,
  template: `
    <div class="dummy">
      <span>Component {{ id }}</span>
      <span>{{ data }}</span>
    </div>
  `
})
export class DummyComponentDefault {
  @Input() id!: number;
  @Input() data!: string;
}

@Component({
  selector: 'app-dummy-component-onpush',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="dummy">
      <span>Component {{ id }}</span>
      <span>{{ data }}</span>
    </div>
  `
})
export class DummyComponentOnPush {
  @Input() id!: number;
  @Input() data!: string;
}
```
{% endraw %}

**Explicação**:
- Demonstra diferença visual de performance
- Default: todos componentes verificados sempre
- OnPush: apenas componentes com input mudado são verificados
- Use DevTools Performance para medir diferença real

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

#### 1. Use OnPush sempre que possível

**Por quê**: OnPush pode reduzir verificações de change detection em 50-98%, melhorando significativamente a performance, especialmente em aplicações grandes.

**Quando usar**:
- Componentes que recebem dados via `@Input()`
- Componentes "presentacionais" (dumb components)
- Componentes que usam signals ou observables
- Qualquer componente onde performance é importante

**Exemplo**:
```typescript
@Component({
  selector: 'app-user-card',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `...`
})
export class UserCardComponent {
  @Input() user!: User;
}
```

**Benefícios**:
- Redução drástica de verificações desnecessárias
- Melhor performance em aplicações grandes
- Código mais previsível e testável

---

#### 2. Mantenha imutabilidade rigorosamente

**Por quê**: OnPush compara inputs por referência (`===`). Se você muta objetos, a referência não muda e Angular não detecta mudanças.

**Padrões de Imutabilidade**:

**Arrays**:
```typescript
// ❌ Ruim - muta array existente
this.items.push(newItem);

// ✅ Bom - cria novo array
this.items = [...this.items, newItem];
this.items = this.items.concat(newItem);
this.items = this.items.filter(item => item.id !== id);
```

**Objetos**:
```typescript
// ❌ Ruim - muta objeto existente
this.user.name = 'New Name';

// ✅ Bom - cria novo objeto
this.user = { ...this.user, name: 'New Name' };
```

**Objetos Aninhados**:
```typescript
// ❌ Ruim - muta objeto aninhado
this.user.address.city = 'New City';

// ✅ Bom - cria novos objetos em todos os níveis
this.user = {
  ...this.user,
  address: {
    ...this.user.address,
    city: 'New City'
  }
};
```

**Com Signals**:
```typescript
// ✅ Excelente - signals garantem imutabilidade
this.users.update(users => [...users, newUser]);
this.users.update(users => 
  users.map(u => u.id === id ? { ...u, ...changes } : u)
);
```

---

#### 3. Use trackBy em todas as listas

**Por quê**: trackBy permite Angular reutilizar componentes DOM existentes ao invés de destruir e recriar, melhorando drasticamente performance em listas grandes.

**Quando usar**:
- Qualquer lista com `@for` ou `*ngFor`
- Especialmente importante para listas com 50+ itens
- Listas que mudam frequentemente
- Quando componentes têm estado interno importante

**Exemplo**:
```typescript
@Component({
  template: `
    <ul>
      @for (item of items(); track trackById($index, item)) {
        <li>{{ item.name }}</li>
      }
    </ul>
  `
})
export class ListComponent {
  items = signal<Item[]>([]);
  
  trackById(index: number, item: Item): number {
    return item.id;
  }
}
```

**Benefícios**:
- Reduz criação/destruição de componentes DOM
- Preserva estado de componentes (scroll, focus, etc.)
- Melhora performance significativamente em listas grandes

---

#### 4. Use markForCheck() com Observables em OnPush

**Por quê**: Observables não disparam change detection automaticamente em componentes OnPush. Você precisa marcar manualmente.

**Quando usar**:
- Quando usar Observables em componentes OnPush
- Após callbacks assíncronos que atualizam estado
- Quando mudanças ocorrem fora do ciclo normal

**Exemplo**:
```typescript
@Component({
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class ObservableComponent {
  data = signal<string>('');
  
  constructor(private cdr: ChangeDetectorRef) {}
  
  ngOnInit(): void {
    this.service.getData().subscribe(data => {
      this.data.set(data);
      this.cdr.markForCheck();
    });
  }
}
```

**Alternativa com async pipe**:
{% raw %}
```typescript
@Component({
  template: `{{ data$ | async }}`
})
export class AsyncComponent {
  data$ = this.service.getData();
}
```
{% raw %}
@Component({
  template: `{{ data$ | async }}`
})
export class AsyncComponent {
  data$ = this.service.getData();
}
```
{% endraw %}

---

#### 5. Prefira Signals sobre propriedades mutáveis

**Por quê**: Signals garantem imutabilidade automaticamente e integram perfeitamente com OnPush.

**Exemplo**:
```typescript
// ❌ Ruim - propriedade mutável
export class BadComponent {
  items: Item[] = [];
  
  addItem(item: Item): void {
    this.items.push(item);
  }
}

// ✅ Bom - signal imutável
export class GoodComponent {
  items = signal<Item[]>([]);
  
  addItem(item: Item): void {
    this.items.update(items => [...items, item]);
  }
}
```

---

#### 6. Use detach() para componentes raramente atualizados

**Por quê**: Se um componente raramente muda, você pode desconectá-lo completamente e controlar manualmente quando verificar.

**Quando usar**:
- Componentes que mudam muito raramente
- Quando você quer controle total sobre quando verificar
- Componentes com lógica complexa que não precisa de atualização frequente

**Exemplo**:
```typescript
@Component({
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class RarelyUpdatedComponent {
  constructor(private cdr: ChangeDetectorRef) {
    this.cdr.detach();
  }
  
  updateManually(): void {
    this.cdr.detach();
    this.cdr.detectChanges();
  }
}
```

---

#### 7. Use computed signals para valores derivados

**Por quê**: Computed signals são otimizados automaticamente e só recalculam quando dependências mudam.

**Exemplo**:
```typescript
export class Component {
  users = signal<User[]>([]);
  
  activeUsers = computed(() => 
    this.users().filter(u => u.active)
  );
  
  userCount = computed(() => this.users().length);
}
```

---

### ❌ Anti-padrões Comuns

#### 1. Mutar objetos diretamente em componentes OnPush

**Problema**: Change detection não detecta mudanças porque referência não muda.

**Exemplo Ruim**:
```typescript
@Component({
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class BadComponent {
  @Input() user!: User;
  
  updateName(): void {
    this.user.name = 'New Name';
  }
}
```

**Solução**:
```typescript
@Component({
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class GoodComponent {
  @Input() user!: User;
  
  updateName(): void {
    this.user = { ...this.user, name: 'New Name' };
  }
}
```

**Impacto**: Componente não atualiza visualmente, causando bugs difíceis de debugar.

---

#### 2. Esquecer trackBy em listas grandes

**Problema**: Performance degrada drasticamente. Cada mudança na lista causa destruição e recriação de todos os componentes.

**Exemplo Ruim**:
```typescript
@Component({
  template: `
    <ul>
      @for (item of items(); track $index) {
        <li>{{ item.name }}</li>
      }
    </ul>
  `
})
```

**Solução**:
```typescript
@Component({
  template: `
    <ul>
      @for (item of items(); track trackById($index, item)) {
        <li>{{ item.name }}</li>
      }
    </ul>
  `
})
export class GoodComponent {
  trackById(index: number, item: Item): number {
    return item.id;
  }
}
```

**Impacto**: Em lista com 1000 itens, mudar 1 item causa 1000 operações DOM ao invés de 1.

---

#### 3. Usar Default quando OnPush é possível

**Problema**: Performance desnecessariamente ruim. Todos os componentes são verificados sempre.

**Exemplo Ruim**:
```typescript
@Component({
  changeDetection: ChangeDetectionStrategy.Default
})
export class BadComponent {
  @Input() data!: string;
}
```

**Solução**:
```typescript
@Component({
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class GoodComponent {
  @Input() data!: string;
}
```

**Impacto**: Em app com 200 componentes, cada evento causa 200 verificações ao invés de 2-5.

---

#### 4. Não usar markForCheck() com Observables em OnPush

**Problema**: Componente não atualiza quando Observable emite novos valores.

**Exemplo Ruim**:
```typescript
@Component({
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class BadComponent {
  data = '';
  
  ngOnInit(): void {
    this.service.getData().subscribe(data => {
      this.data = data;
    });
  }
}
```

**Solução**:
```typescript
@Component({
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class GoodComponent {
  data = '';
  
  constructor(private cdr: ChangeDetectorRef) {}
  
  ngOnInit(): void {
    this.service.getData().subscribe(data => {
      this.data = data;
      this.cdr.markForCheck();
    });
  }
}
```

**Impacto**: UI não reflete mudanças de dados, causando experiência ruim para usuário.

---

#### 5. Usar detectChanges() excessivamente

**Problema**: `detectChanges()` força verificação imediata, que pode ser ineficiente se usado demais.

**Exemplo Ruim**:
```typescript
updateData(): void {
  this.data1 = 'new';
  this.cdr.detectChanges();
  this.data2 = 'new';
  this.cdr.detectChanges();
  this.data3 = 'new';
  this.cdr.detectChanges();
}
```

**Solução**:
```typescript
updateData(): void {
  this.data1 = 'new';
  this.data2 = 'new';
  this.data3 = 'new';
  this.cdr.markForCheck();
}
```

**Impacto**: Múltiplas verificações desnecessárias, degradando performance.

---

#### 6. Misturar estratégias inconsistentemente

**Problema**: Alguns componentes OnPush, outros Default, causa comportamento imprevisível.

**Solução**: Padronize estratégia em toda aplicação. Prefira OnPush everywhere.

**Impacto**: Dificulta debugging e causa problemas de performance inconsistentes.

---

#### 7. Não cancelar subscriptions em componentes OnPush

**Problema**: Memory leaks e verificações desnecessárias continuam após componente ser destruído.

**Exemplo Ruim**:
```typescript
ngOnInit(): void {
  this.service.getData().subscribe(data => {
    this.data = data;
    this.cdr.markForCheck();
  });
}
```

**Solução**:
```typescript
private destroy$ = new Subject<void>();

ngOnInit(): void {
  this.service.getData()
    .pipe(takeUntil(this.destroy$))
    .subscribe(data => {
      this.data = data;
      this.cdr.markForCheck();
    });
}

ngOnDestroy(): void {
  this.destroy$.next();
  this.destroy$.complete();
}
```

**Impacto**: Memory leaks, performance degradada, bugs difíceis de identificar.

---

## Exercícios Práticos

### Exercício 1: Implementar OnPush Básico (Básico)

**Objetivo**: Converter componente para OnPush

**Descrição**: 
Converta componente de Default para OnPush strategy.

**Arquivo**: `exercises/exercise-4-1-1-onpush-basico.md`

---

### Exercício 2: Imutabilidade e OnPush (Intermediário)

**Objetivo**: Implementar imutabilidade com OnPush

**Descrição**:
Crie componente OnPush que usa imutabilidade para atualizar estado.

**Arquivo**: `exercises/exercise-4-1-2-imutabilidade.md`

---

### Exercício 3: ChangeDetectorRef Manual (Intermediário)

**Objetivo**: Usar ChangeDetectorRef para controle manual

**Descrição**:
Crie componente que usa ChangeDetectorRef para controle manual de change detection.

**Arquivo**: `exercises/exercise-4-1-3-changedetectorref.md`

---

### Exercício 4: trackBy Functions (Intermediário)

**Objetivo**: Implementar trackBy functions

**Descrição**:
Crie componente com lista grande usando trackBy para otimização.

**Arquivo**: `exercises/exercise-4-1-4-trackby.md`

---

### Exercício 5: OnPush Everywhere (Avançado)

**Objetivo**: Aplicar OnPush em toda aplicação

**Descrição**:
Converta aplicação completa para usar OnPush em todos componentes.

**Arquivo**: `exercises/exercise-4-1-5-onpush-everywhere.md`

---

### Exercício 6: Otimização Completa (Avançado)

**Objetivo**: Otimizar aplicação completa

**Descrição**:
Aplique todas técnicas de otimização de change detection em aplicação real.

**Arquivo**: `exercises/exercise-4-1-6-otimizacao-completa.md`

---

## Referências Externas

### Documentação Oficial

- **[Change Detection Guide](https://angular.io/guide/change-detection)**: Guia completo oficial sobre change detection no Angular
- **[ChangeDetectionStrategy API](https://angular.io/api/core/ChangeDetectionStrategy)**: Documentação da API OnPush e Default strategies
- **[ChangeDetectorRef API](https://angular.io/api/core/ChangeDetectorRef)**: Documentação completa dos métodos de controle manual
- **[Signals Guide](https://angular.io/guide/signals)**: Como signals funcionam com change detection
- **[Zone.js Documentation](https://angular.io/guide/zone)**: Entendendo Zone.js e seu papel na change detection

### Artigos Técnicos e Tutoriais

- **[Angular Change Detection Explained](https://www.toptal.com/angular/angular-change-detection)**: Artigo detalhado sobre change detection strategies
- **[Angular Change Detection Infographic](https://christiankohler.net/angular-change-detection-infographic/)**: Infográfico visual explicando o processo
- **[OnPush Change Detection Strategy](https://www.angularminds.com/blog/the-key-strategies-of-angular-change-detection)**: Estratégias avançadas de change detection
- **[Understanding Angular Change Detection](https://howik.com/angular-change-detection-explained)**: Explicação detalhada com exemplos práticos
- **[Angular Performance: OnPush Change Detection](https://netbasal.com/angular-performance-onpush-change-detection-strategy-explained)**: Foco em performance e otimização

### Vídeos Educacionais

- **[Angular Change Detection Explained in 5 Minutes](https://www.youtube.com/live/eNuMUslF8Bw)**: Explicação rápida e visual
- **[Change Detection Strategy Angular Explained](https://www.youtube.com/watch?v=FgBLcQ4c8XU)**: Tutorial completo com exemplos
- **[Angular OnPush Change Detection](https://www.youtube.com/watch?v=3q3w6jqJ2nI)**: Foco específico em OnPush strategy

### Ferramentas e Recursos

- **[Angular DevTools](https://angular.io/guide/devtools)**: Ferramenta para debugar change detection
- **[Angular Performance Profiler](https://angular.io/guide/performance)**: Guia de profiling de performance
- **[Zone.js GitHub](https://github.com/angular/angular/tree/main/packages/zone.js)**: Código fonte e documentação do Zone.js

### Comparações e Benchmarks

- **[Angular vs React Performance](https://krausefx.com/blog/angular-vs-react-performance)**: Comparação de performance entre frameworks
- **[Change Detection Comparison](https://blog.angular-university.io/angular-2-change-detection/)**: Comparação detalhada de estratégias

---

## Resumo

### Principais Conceitos

- Default strategy verifica todos componentes
- OnPush strategy verifica apenas quando necessário
- Imutabilidade é essencial para OnPush
- ChangeDetectorRef permite controle manual
- trackBy functions melhoram performance de listas

### Pontos-Chave para Lembrar

- Use OnPush sempre que possível
- Mantenha imutabilidade
- Use trackBy em listas
- Use markForCheck() quando necessário
- Prefira OnPush sobre Default

### Próximos Passos

- Próxima aula: Lazy Loading e Code Splitting
- Praticar OnPush em componentes
- Explorar otimizações avançadas

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

**Aula Anterior**: [Aula 3.5: Integração Signals + Observables](./lesson-3-5-signals-observables.md)  
**Próxima Aula**: [Aula 4.2: Lazy Loading e Code Splitting](./lesson-4-2-lazy-loading.md)  
**Voltar ao Módulo**: [Módulo 4: Performance e Otimização](../modules/module-4-performance-otimizacao.md)
