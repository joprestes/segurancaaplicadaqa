---
layout: lesson
title: "Aula 1.5: Control Flow e Pipes"
slug: control-flow-pipes
module: module-1
lesson_id: lesson-1-5
duration: "90 minutos"
level: "Intermediário"
prerequisites: []
exercises: []
permalink: /modules/fundamentos-acelerados/lessons/control-flow-pipes/
---

## Introdução

Nesta aula, você aprenderá sobre Control Flow moderno do Angular (Angular 17+) e Pipes para transformação de dados. Control Flow substitui as diretivas estruturais tradicionais com sintaxe mais moderna e performática, enquanto Pipes permitem transformar dados para exibição de forma elegante e reutilizável.

### Contexto Histórico

**Control Flow - Uma Revolução no Angular**:

Control Flow foi uma das mudanças mais significativas introduzidas no Angular 17 (Novembro 2023). Representa uma evolução natural das diretivas estruturais tradicionais:

**Linha do Tempo**:

```
Angular 2 (2016) ──────────────────────────────────────────── Angular 17+ (2023+)
 │                                                                  │
 ├─ 2016    📦 Diretivas Estruturais Introduzidas                  │
 │          *ngIf, *ngFor, *ngSwitch                               │
 │          Sintaxe baseada em microsyntax                          │
 │          Performance boa mas não otimizada                      │
 │                                                                  │
 ├─ 2017-2022 📈 Melhorias Incrementais                            │
 │          Otimizações de *ngFor com trackBy                     │
 │          Melhorias de compilação                                │
 │          Performance melhorada                                  │
 │                                                                  │
 ├─ Nov 2023 🔥 Angular 17 - Control Flow Introduzido             │
 │          @if, @for, @switch                                     │
 │          Sintaxe moderna e intuitiva                            │
 │          Performance significativamente melhor                  │
 │          Type safety melhorado                                  │
 │          Tracking integrado em @for                             │
 │                                                                  │
 └─ 2024+    🎯 Control Flow como Padrão                           │
            Migração gradual de projetos                            │
            Suporte completo                                        │
```

**Por que Control Flow foi criado?**

As diretivas estruturais tradicionais tinham limitações:
- **Microsyntax complexa**: `*ngFor="let item of items; let i = index; trackBy: trackFn"` era verbosa
- **Performance**: Requeria otimizações manuais (trackBy)
- **Type Safety**: Limitado, especialmente em templates
- **Legibilidade**: Sintaxe não intuitiva para desenvolvedores novos

Control Flow resolve todos esses problemas com sintaxe moderna inspirada em linguagens como Rust e Swift.

**Pipes - História e Evolução**:

Pipes existem desde Angular 2 e são fundamentais para transformação de dados:

- **Angular 2**: Pipes introduzidos como forma de transformar dados no template
- **Angular 4+**: Melhorias de performance, pipes pure por padrão
- **Angular 6+**: AsyncPipe melhorado, novos pipes embutidos
- **Angular Moderno**: Pipes standalone, melhor integração com TypeScript

### O que você vai aprender

- **Control Flow Moderno**: `@if`, `@for`, `@switch` com sintaxe intuitiva
- **Migração**: Como migrar de diretivas estruturais para Control Flow
- **Pipes Embutidos**: DatePipe, CurrencyPipe, DecimalPipe, AsyncPipe e mais
- **Pipes Customizados**: Criar seus próprios pipes para transformações específicas
- **Pure vs Impure**: Entender quando usar cada tipo e impacto na performance
- **Performance**: Otimizações e melhores práticas para Control Flow e Pipes
- **AsyncPipe**: Gerenciamento automático de Observables e Promises

### Por que isso é importante

**Para Desenvolvimento**:
- **Sintaxe Moderna**: Control Flow é mais intuitivo e fácil de aprender
- **Performance**: Melhor performance nativa, especialmente em listas grandes
- **Type Safety**: Melhor suporte TypeScript em templates
- **Produtividade**: Código mais limpo e fácil de manter

**Para Projetos**:
- **Futuro do Angular**: Control Flow é o padrão recomendado
- **Performance**: Melhor performance em aplicações grandes
- **Manutenibilidade**: Código mais legível e consistente
- **Migração**: Caminho claro para modernizar projetos legados

**Para Carreira**:
- **Habilidade Essencial**: Conhecimento necessário para Angular moderno
- **Diferencial**: Entendimento de recursos mais recentes do framework
- **Relevância**: Alinhado com direção futura do Angular
- **Base Sólida**: Fundamental para desenvolvimento profissional

---

## Conceitos Teóricos

### Control Flow Moderno (@if, @for, @switch)

**Definição**: Control Flow é a nova sintaxe do Angular 17+ que substitui diretivas estruturais (*ngIf, *ngFor, *ngSwitch) com sintaxe mais moderna, performática e type-safe. É compilado diretamente para JavaScript otimizado, resultando em melhor performance.

**Explicação Detalhada**:

Control Flow oferece três construções principais:

1. **@if/@else**: Renderização condicional com sintaxe de bloco
2. **@for**: Iteração com tracking integrado e melhor performance
3. **@switch**: Seleção múltipla com sintaxe mais limpa

**Vantagens sobre Diretivas Estruturais**:

| Aspecto | Diretivas Estruturais | Control Flow |
|---------|----------------------|--------------|
| **Sintaxe** | Microsyntax complexa | Sintaxe de bloco intuitiva |
| **Performance** | Boa (com otimizações) | Excelente (nativa) |
| **Type Safety** | Limitado | Completo |
| **Tracking** | Manual (trackBy) | Integrado (@for) |
| **Legibilidade** | Média | Alta |
| **Compilação** | Diretivas runtime | Compilado para JS |

**Como Funciona**:

Control Flow é compilado diretamente para JavaScript durante o build, ao invés de usar diretivas runtime. Isso resulta em:
- Menos código gerado
- Melhor tree-shaking
- Performance superior
- Type checking em compile-time

**Analogia Detalhada**:

Control Flow é como ter um **tradutor profissional** ao invés de um dicionário:

- **Diretivas Estruturais (Antigo)**: É como usar um dicionário - você precisa procurar cada palavra, entender a gramática complexa, e ainda pode cometer erros. Funciona, mas é trabalhoso.

- **Control Flow (Novo)**: É como ter um tradutor profissional que entende perfeitamente o contexto, traduz de forma natural e eficiente, e garante que tudo está correto. Faz o mesmo trabalho, mas de forma muito mais eficiente e intuitiva.

**Visualização Detalhada**:

```
┌─────────────────────────────────────────────────────────────┐
│        Diretivas Estruturais (Antigo)                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  <div *ngIf="condition; else elseBlock">                   │
│    Conteúdo                                                 │
│  </div>                                                     │
│  <ng-template #elseBlock>                                   │
│    Alternativo                                              │
│  </ng-template>                                             │
│                                                              │
│  <div *ngFor="let item of items; let i = index;            │
│            trackBy: trackFn">                               │
│    {{ item }}                                               │
│  </div>                                                     │
│                                                              │
│  Problemas:                                                 │
│  • Sintaxe verbosa                                          │
│  • Microsyntax complexa                                     │
│  • Tracking manual                                          │
│  • Type safety limitado                                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              Control Flow (Novo)                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  @if (condition) {                                          │
│    <div>Conteúdo</div>                                      │
│  } @else {                                                  │
│    <div>Alternativo</div>                                   │
│  }                                                           │
│                                                              │
│  @for (item of items; track item.id) {                     │
│    <div>{{ item }}</div>                                    │
│  } @empty {                                                 │
│    <div>Lista vazia</div>                                   │
│  }                                                           │
│                                                              │
│  Benefícios:                                                │
│  • Sintaxe intuitiva                                        │
│  • Blocos claros                                            │
│  • Tracking integrado                                       │
│  • Type safety completo                                     │
│  • Performance superior                                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Fluxo de Compilação Detalhado:

```
┌─────────────────────────────────────────────────────────────────┐
│         Template com Control Flow (@if, @for, @switch)         │
└────────────────────┬──────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              Angular Compiler (AOT - Ahead of Time)             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Fase 1: Parsing e Análise                               │  │
│  │  ├─ Parse template HTML                                   │  │
│  │  ├─ Identificar blocos @if, @for, @switch                │  │
│  │  └─ Validar sintaxe                                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Fase 2: Type Checking (compile-time)                    │  │
│  │  ├─ Verificar tipos de variáveis                          │  │
│  │  ├─ Validar expressões condicionais                       │  │
│  │  ├─ Checar tipos em @for (track expressions)              │  │
│  │  └─ Validar casos em @switch                              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Fase 3: Otimização                                      │  │
│  │  ├─ Inline de expressões simples                          │  │
│  │  ├─ Otimização de loops (@for)                            │  │
│  │  ├─ Tree-shaking de código não usado                     │  │
│  │  └─ Minificação de código gerado                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Fase 4: Geração de Código                               │  │
│  │  ├─ Converter @if → if/else JavaScript                   │  │
│  │  ├─ Converter @for → for loop otimizado                  │  │
│  │  ├─ Converter @switch → switch/case                      │  │
│  │  └─ Gerar código com tracking integrado                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
└─────────────────────┼──────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              JavaScript Otimizado (Bundle Final)                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Benefícios:                                                    │
│  ✓ Menos código gerado (sem diretivas runtime)                 │
│  ✓ Type safety garantido em compile-time                       │
│  ✓ Performance superior (código otimizado)                     │
│  ✓ Bundle size menor (tree-shaking eficiente)                 │
│  ✓ Melhor tree-shaking (código estático)                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Runtime (Browser)                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Execução direta do JavaScript otimizado                       │
│  Sem overhead de diretivas estruturais                         │
│  Change detection mais eficiente                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático**:

```
export class ControlFlowComponent {
  isLoggedIn: boolean = true;
  items: string[] = ['Item 1', 'Item 2', 'Item 3'];
  status: 'active' | 'pending' | 'inactive' = 'active';
}
```

```
@if (isLoggedIn) {
  <p>Bem-vindo!</p>
} @else {
  <p>Por favor, faça login</p>
}

@for (item of items; track item) {
  <div>{{ item }}</div>
} @empty {
  <p>Nenhum item encontrado</p>
}

@switch (status) {
  @case ('active') {
    <span>Ativo</span>
  }
  @case ('pending') {
    <span>Pendente</span>
  }
  @default {
    <span>Inativo</span>
  }
}
```

---

### @if e @else

**Definição**: `@if` é a nova sintaxe para renderização condicional que substitui `*ngIf`.

**Explicação Detalhada**:

Sintaxe `@if`:
- `@if (condition) { ... }`: Renderiza se condição verdadeira
- `@else { ... }`: Bloco alternativo
- `@else if (condition) { ... }`: Condições adicionais

**Analogia**:

`@if` é como uma porta que só abre se você tiver a chave certa (condição verdadeira). Se não tiver, pode usar a porta dos fundos (`@else`).

**Exemplo Prático**:

```
@if (user) {
  <div class="user-profile">
    <h2>{{ user.name }}</h2>
    <p>{{ user.email }}</p>
  </div>
} @else if (loading) {
  <p>Carregando...</p>
} @else {
  <p>Usuário não encontrado</p>
}
```

---

### @for com trackBy

**Definição**: `@for` é a nova sintaxe para iteração que substitui `*ngFor` com melhor performance nativa e tracking obrigatório integrado.

**Explicação Detalhada**:

Sintaxe `@for`:
- `@for (item of items; track item.id) { ... }`: Itera com tracking obrigatório
- `@for (item of items; track $index) { ... }`: Tracking por índice (menos eficiente)
- `@empty { ... }`: Bloco quando lista vazia
- Tracking é obrigatório e integrado (não pode ser omitido)

**Como o Tracking Funciona Internamente**:

```
┌─────────────────────────────────────────────────────────────────┐
│              @for com Tracking - Processo Interno               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Estado Inicial:                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  items = [A(id:1), B(id:2), C(id:3)]                    │  │
│  │  Track Map: { 1: A, 2: B, 3: C }                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│  Nova Lista Chega:                                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  items = [A(id:1), D(id:4), C(id:3)]                    │  │
│  │  (B removido, D adicionado, ordem mudou)                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Processo de Diff Inteligente                            │  │
│  │                                                           │  │
│  │  1. Identificar itens existentes pelo track:             │  │
│  │     ✓ A(id:1) → já existe, reutilizar                   │  │
│  │     ✓ C(id:3) → já existe, reutilizar                   │  │
│  │                                                           │  │
│  │  2. Identificar novos itens:                             │  │
│  │     ✗ D(id:4) → novo, criar                              │  │
│  │                                                           │  │
│  │  3. Identificar removidos:                               │  │
│  │     ✗ B(id:2) → removido, destruir                      │  │
│  │                                                           │  │
│  │  4. Reordenar apenas o necessário:                       │  │
│  │     A → posição 0 (mantém)                               │  │
│  │     D → posição 1 (novo)                                 │  │
│  │     C → posição 2 (move de 2 para 2)                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Resultado: Renderização Otimizada                       │  │
│  │                                                           │  │
│  │  ✓ A reutilizado (sem re-render)                         │  │
│  │  ✓ C reutilizado (sem re-render)                         │  │
│  │  ✓ D criado (novo)                                       │  │
│  │  ✓ B destruído (removido)                                │  │
│  │                                                           │  │
│  │  Performance:                                             │  │
│  │  • Apenas 1 componente criado (D)                         │  │
│  │  • Apenas 1 componente destruído (B)                     │  │
│  │  • 2 componentes reutilizados (A, C)                     │  │
│  │  • 0 re-renderizações desnecessárias                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Comparação de Performance**:

| Cenário | *ngFor (sem trackBy) | *ngFor (com trackBy) | @for (track integrado) |
|---------|---------------------|---------------------|----------------------|
| **Lista 1000 itens, 1 novo** | 1000 re-renders | 1 create | 1 create |
| **Lista 1000 itens, reordenar** | 1000 re-renders | ~500 re-renders | ~0 re-renders |
| **Lista 1000 itens, remover 1** | 1000 re-renders | 1 destroy | 1 destroy |
| **Bundle Size** | Maior | Maior | Menor |
| **Type Safety** | Limitado | Limitado | Completo |

**Variáveis Especiais Disponíveis em @for**:

- `$index`: Índice atual do item (0-based)
- `$first`: `true` se é o primeiro item
- `$last`: `true` se é o último item
- `$even`: `true` se índice é par
- `$odd`: `true` se índice é ímpar
- `$count`: Total de itens na lista

**Exemplo com Variáveis Especiais**:

```
@for (item of items; track item.id; let i = $index; let isFirst = $first) {
  <div [class.first]="isFirst">
{% raw %}
    Item {{ i + 1 }}: {{ item.name }}
{% endraw %}
  </div>
}
```

Vantagens sobre *ngFor:
- Performance significativamente melhor (tracking integrado e otimizado)
- Tracking obrigatório (não pode esquecer)
- Sintaxe mais clara e intuitiva
- Type safety completo em compile-time
- Variáveis especiais mais intuitivas
- Menos código gerado (melhor bundle size)

**Analogia Detalhada**:

`@for` é como uma linha de produção moderna com sistema RFID integrado:

- ***ngFor sem trackBy**: É como uma linha de produção onde você precisa contar manualmente cada item toda vez que algo muda. Se um item é removido, você precisa recontar tudo do zero.

- ***ngFor com trackBy**: É como ter códigos de barras, mas você precisa escanear manualmente cada código toda vez. Funciona, mas ainda é trabalhoso.

- **@for com track**: É como ter RFID integrado na linha de produção. Cada item tem um identificador único que é automaticamente detectado. Quando algo muda, o sistema sabe instantaneamente quais itens são novos, quais foram removidos, e quais podem ser reutilizados - tudo automaticamente, sem trabalho manual.

**Exemplo Prático**:

```
@for (product of products; track product.id) {
  <div class="product-card">
    <h3>{{ product.name }}</h3>
{% raw %}
    <p>{{ product.price | currency }}</p>
{% endraw %}
  </div>
} @empty {
  <p>Nenhum produto disponível</p>
}
```

---

### @switch

**Definição**: `@switch` é a nova sintaxe para seleção múltipla que substitui `*ngSwitch`.

**Explicação Detalhada**:

Sintaxe `@switch`:
- `@switch (value) { ... }`: Inicia switch
- `@case (option) { ... }`: Caso específico
- `@default { ... }`: Caso padrão

**Analogia**:

`@switch` é como um seletor de canais de TV. Você escolhe um número (caso) e vê o canal correspondente.

**Exemplo Prático**:

```
@switch (userRole) {
  @case ('admin') {
    <button>Gerenciar Usuários</button>
    <button>Configurações</button>
  }
  @case ('editor') {
    <button>Criar Conteúdo</button>
  }
  @default {
    <button>Ver Conteúdo</button>
  }
}
{% raw %}
```

---

### Pipes Embutidos

**Definição**: Pipes são funções que transformam dados para exibição no template usando a sintaxe `{{ value | pipe }}`.

**Explicação Detalhada**:

Pipes embutidos principais:
- **DatePipe**: Formata datas (`{{ date | date:'short' }}`)
- **CurrencyPipe**: Formata moedas (`{{ price | currency:'BRL' }}`)
- **DecimalPipe**: Formata números (`{{ number | number:'1.2-2' }}`)
- **PercentPipe**: Formata percentuais (`{{ ratio | percent }}`)
- **AsyncPipe**: Subscribe automaticamente em Observables
- **UpperCasePipe / LowerCasePipe**: Transforma texto
- **JsonPipe**: Converte para JSON (útil para debug)

**Analogia**:

Pipes são como filtros de água. Você coloca água suja (dados brutos) e sai água limpa (dados formatados). Cada pipe é um tipo diferente de filtro.

**Visualização**:

```
{% raw %}

---

### Pipes Embutidos

**Definição**: Pipes são funções que transformam dados para exibição no template usando a sintaxe `{{ value | pipe }}`.

**Explicação Detalhada**:

Pipes embutidos principais:
- **DatePipe**: Formata datas (`{{ date | date:'short' }}`)
- **CurrencyPipe**: Formata moedas (`{{ price | currency:'BRL' }}`)
- **DecimalPipe**: Formata números (`{{ number | number:'1.2-2' }}`)
- **PercentPipe**: Formata percentuais (`{{ ratio | percent }}`)
- **AsyncPipe**: Subscribe automaticamente em Observables
- **UpperCasePipe / LowerCasePipe**: Transforma texto
- **JsonPipe**: Converte para JSON (útil para debug)

**Analogia**:

Pipes são como filtros de água. Você coloca água suja (dados brutos) e sai água limpa (dados formatados). Cada pipe é um tipo diferente de filtro.

**Visualização**:

```
{% endraw %}
Dados Brutos          Pipe              Dados Formatados
┌──────────┐         ┌──────────┐         ┌──────────────┐
│ 1234.56  │  ────→  │currenc   │  ────→  │ R$ 1.234,56  │
│ new Date │  ────→  │ date     │  ────→  │ 03/01/2026   │
│ 0.75     │  ────→  │percent   │  ────→  │ 75%          │
└──────────┘         └──────────┘         └──────────────┘
```

**Exemplo Prático**:

```
export class PipesComponent {
  price: number = 1234.56;
  date: Date = new Date();
  percentage: number = 0.75;
  userName: string = 'joão silva';
  userData: any = { name: 'João', age: 30 };
}
```

```
{% raw %}
<p>Preço: {{ price | currency:'BRL':'symbol':'1.2-2' }}</p>
<p>Data: {{ date | date:'dd/MM/yyyy' }}</p>
<p>Percentual: {{ percentage | percent:'1.0-2' }}</p>
<p>Nome: {{ userName | titlecase }}</p>
<p>Debug: {{ userData | json }}</p>
{% endraw %}
```

---

### Pipes Customizados

**Definição**: Você pode criar seus próprios pipes para transformações específicas de dados que não estão disponíveis nos pipes embutidos do Angular.

**Explicação Detalhada**:

Pipes customizados são criados com:
- Decorator `@Pipe` com metadados (name, standalone, pure)
- Método `transform(value, ...args)` obrigatório que implementa `PipeTransform`
- Pode ser `pure` (padrão) ou `impure` (use com cuidado)

**Arquitetura de um Pipe Customizado**:

```
┌─────────────────────────────────────────────────────────────────┐
│              Pipe Customizado - Estrutura Interna                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  @Pipe Decorator                                        │  │
│  │  ├─ name: 'pipeName' (usado no template)                │  │
│  │  ├─ standalone: true (Angular 14+)                      │  │
│  │  └─ pure: true/false (padrão: true)                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Class implements PipeTransform                          │  │
│  │                                                           │  │
│  │  transform(value: any, ...args: any[]): any {            │  │
│  │    // Lógica de transformação                            │  │
│  │    return transformedValue;                               │  │
│  │  }                                                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Uso no Template                                         │  │
{% raw %}
│  │  {{ value | pipeName:arg1:arg2 }}                       │  │
{% endraw %}
│  │                    │                                       │  │
│  │                    ▼                                       │  │
│  │  transform(value, arg1, arg2) é chamado                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Pure vs Impure - Comparação Detalhada**:

```
┌─────────────────────────────────────────────────────────────────┐
│          Pure Pipe vs Impure Pipe - Comportamento              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Pure Pipe (padrão: pure: true)                         │  │
│  │                                                           │  │
│  │  Change Detection Cycle:                                  │  │
│  │                                                           │  │
│  │  1. Angular verifica se value mudou                     │  │
│  │     ├─ Comparação por referência (===)                   │  │
│  │     └─ Se igual → retorna valor em cache                │  │
│  │                                                           │  │
│  │  2. Se value mudou:                                      │  │
│  │     ├─ Chama transform()                                 │  │
│  │     ├─ Armazena resultado em cache                       │  │
│  │     └─ Retorna novo valor                                │  │
│  │                                                           │  │
│  │  Benefícios:                                             │  │
│  │  ✓ Performance excelente                                 │  │
│  │  ✓ Recalcula apenas quando necessário                    │  │
│  │  ✓ Cache automático                                      │  │
│  │                                                           │  │
│  │  Limitação:                                              │  │
│  │  ✗ Não detecta mudanças dentro de objetos/arrays        │  │
│  │    (mudanças por referência)                             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Impure Pipe (pure: false)                              │  │
│  │                                                           │  │
│  │  Change Detection Cycle:                                  │  │
│  │                                                           │  │
│  │  1. A cada change detection:                             │  │
│  │     ├─ Chama transform() SEMPRE                          │  │
│  │     ├─ Sem cache                                         │  │
│  │     └─ Recalcula mesmo se value não mudou               │  │
│  │                                                           │  │
│  │  Benefícios:                                             │  │
│  │  ✓ Detecta mudanças profundas em objetos                │  │
│  │  ✓ Sempre atualizado                                    │  │
│  │                                                           │  │
│  │  Desvantagens:                                           │  │
│  │  ✗ Performance ruim (recalcula sempre)                  │  │
│  │  ✗ Pode causar lentidão em listas grandes               │  │
│  │  ✗ Sem cache                                             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo: Pure Pipe (Recomendado)**:

```
@Pipe({
  name: 'truncate',
  standalone: true,
  pure: true
})
export class TruncatePipe implements PipeTransform {
  transform(value: string, limit: number = 20, trail: string = '...'): string {
    if (!value) return '';
    if (value.length <= limit) return value;
    return value.substring(0, limit) + trail;
  }
}
```

**Exemplo: Impure Pipe (Use com Cuidado)**:

```
@Pipe({
  name: 'filter',
  standalone: true,
  pure: false
})
export class FilterPipe implements PipeTransform {
  transform<T>(items: T[], filterFn: (item: T) => boolean): T[] {
    if (!items || !filterFn) return items;
    return items.filter(filterFn);
  }
}
```

**⚠️ Aviso sobre Impure Pipes**:

Impure pipes devem ser evitados quando possível. Se você precisa filtrar uma lista, considere:

1. **Melhor Abordagem**: Filtrar no componente antes de passar para o template
```
get filteredItems() {
  return this.items.filter(item => item.active);
}
```

2. **Alternativa**: Usar computed signals (Angular 16+)
```
filteredItems = computed(() => 
  this.items().filter(item => item.active)
);
```

**Quando Usar Impure Pipes**:

- Apenas quando você realmente precisa detectar mudanças profundas em objetos
- Quando a transformação é muito simples e rápida
- Quando você não tem controle sobre a fonte de dados
- Como último recurso, não como primeira opção

**Analogia Detalhada**:

Pipes customizados são como ferramentas personalizadas em uma oficina:

- **Pipes Embutidos**: São como ferramentas padrão (martelo, chave de fenda) - sempre disponíveis e funcionam bem para tarefas comuns.

- **Pure Pipes Customizados**: São como ferramentas especializadas que você cria (ex: cortador de fios específico). Elas são eficientes porque:
  - Você só as usa quando realmente precisa (quando entrada muda)
  - Elas têm memória (cache) - se você cortar o mesmo fio novamente, ela lembra como fazer
  - São rápidas e não desperdiçam recursos

- **Impure Pipes**: São como ferramentas que você precisa recalibrar toda vez que usa, mesmo que seja para a mesma tarefa. Funcionam, mas são ineficientes porque:
  - Você recalibra mesmo quando não precisa (a cada change detection)
  - Não têm memória (sem cache)
  - Podem tornar a oficina lenta se usadas muito frequentemente

**Melhor Prática**: Crie ferramentas especializadas (pure pipes) para tarefas específicas, mas mantenha-as eficientes. Evite ferramentas que precisam recalibrar constantemente (impure pipes) a menos que absolutamente necessário.

**Exemplo Prático**:

```
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'truncate',
  standalone: true
})
export class TruncatePipe implements PipeTransform {
  transform(value: string, limit: number = 20, trail: string = '...'): string {
    if (!value) return '';
    if (value.length <= limit) return value;
    return value.substring(0, limit) + trail;
  }
}

@Pipe({
  name: 'filter',
  standalone: true,
  pure: false
})
export class FilterPipe implements PipeTransform {
  transform<T>(items: T[], filterFn: (item: T) => boolean): T[] {
    if (!items || !filterFn) return items;
    return items.filter(filterFn);
  }
}
```

```
{% raw %}
<p>{{ longText | truncate:50 }}</p>
{% endraw %}
<div *ngFor="let item of items | filter:isActive">
  {{ item.name }}
</div>
```

---

### AsyncPipe

**Definição**: AsyncPipe é um pipe especial que automaticamente gerencia o ciclo de vida completo de Observables e Promises, fazendo subscribe/unsubscribe e atualizando o template quando valores mudam.

**Explicação Detalhada**:

AsyncPipe funciona como um gerenciador automático de assinaturas:

**Ciclo de Vida do AsyncPipe**:

```
┌─────────────────────────────────────────────────────────────────┐
│            AsyncPipe - Ciclo de Vida Completo                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  1. Inicialização (ngOnInit)                            │  │
│  │                                                           │  │
{% raw %}
│  │  Template: {{ data$ | async }}                           │  │
{% endraw %}
│  │                    │                                       │  │
│  │                    ▼                                       │  │
│  │  AsyncPipe detecta Observable/Promise                     │  │
│  │                    │                                       │  │
│  │                    ▼                                       │  │
│  │  ┌─────────────────────────────────────┐                 │  │
│  │  │  AsyncPipe.subscribe(data$)        │                 │  │
│  │  │  ├─ Cria subscription              │                 │  │
│  │  │  ├─ Armazena referência            │                 │  │
│  │  │  └─ Aguarda primeiro valor         │                 │  │
│  │  └─────────────────────────────────────┘                 │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  2. Durante Execução (Change Detection)                  │  │
│  │                                                           │  │
│  │  Observable emite novo valor                             │  │
│  │                    │                                       │  │
│  │                    ▼                                       │  │
│  │  ┌─────────────────────────────────────┐                 │  │
│  │  │  AsyncPipe.onNext(newValue)        │                 │  │
│  │  │  ├─ Atualiza valor interno          │                 │  │
│  │  │  ├─ Marca para change detection    │                 │  │
│  │  │  └─ Template atualiza automaticamente│                │  │
│  │  └─────────────────────────────────────┘                 │  │
│  │                                                           │  │
│  │  Observable emite erro                                  │  │
│  │                    │                                       │  │
│  │                    ▼                                       │  │
│  │  ┌─────────────────────────────────────┐                 │  │
│  │  │  AsyncPipe.onError(error)           │                 │  │
│  │  │  ├─ Propaga erro (pode usar @if)   │                 │  │
│  │  │  └─ Template mostra estado de erro │                 │  │
│  │  └─────────────────────────────────────┘                 │  │
│  │                                                           │  │
│  │  Observable completa                                    │  │
│  │                    │                                       │  │
│  │                    ▼                                       │  │
│  │  ┌─────────────────────────────────────┐                 │  │
│  │  │  AsyncPipe.onComplete()             │                 │  │
│  │  │  ├─ Limpa subscription              │                 │  │
│  │  │  └─ Mantém último valor             │                 │  │
│  │  └─────────────────────────────────────┘                 │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  3. Destruição (ngOnDestroy)                             │  │
│  │                                                           │  │
│  │  Componente sendo destruído                              │  │
│  │                    │                                       │  │
│  │                    ▼                                       │  │
│  │  ┌─────────────────────────────────────┐                 │  │
│  │  │  AsyncPipe.ngOnDestroy()           │                 │  │
│  │  │  ├─ unsubscribe() automático        │                 │  │
│  │  │  ├─ Limpa referências              │                 │  │
│  │  │  └─ Previne memory leaks            │                 │  │
│  │  └─────────────────────────────────────┘                 │  │
│  │                                                           │  │
│  │  ✓ Sem memory leaks                                     │  │
│  │  ✓ Sem subscriptions órfãs                             │  │
│  │  ✓ Limpeza automática                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Comparação: AsyncPipe vs Subscribe Manual**:

| Aspecto | Subscribe Manual | AsyncPipe |
|---------|-----------------|-----------|
| **Subscribe** | Manual no ngOnInit | Automático |
| **Unsubscribe** | Manual no ngOnDestroy | Automático |
| **Memory Leaks** | Risco alto se esquecer | Prevenido automaticamente |
| **Change Detection** | Precisa marcar manualmente | Automático |
| **Código** | Verboso (try/catch/finally) | Declarativo |
| **Erros** | Precisa tratar manualmente | Pode usar @if para tratar |
| **Manutenção** | Mais propenso a erros | Menos erros |

**Exemplo: Tratamento de Estados com AsyncPipe**:

```
export class UserComponent {
  user$ = this.userService.getUser().pipe(
    catchError(error => {
      console.error('Erro ao carregar usuário:', error);
      return of(null);
    })
  );
  
  loading$ = this.user$.pipe(
    map(() => false),
    startWith(true)
  );
}
```

```
@if (loading$ | async) {
  <p>Carregando usuário...</p>
} @else if (user$ | async; as user) {
  <div class="user-profile">
    <h2>{{ user.name }}</h2>
    <p>{{ user.email }}</p>
  </div>
} @else {
  <p>Erro ao carregar usuário</p>
}
```

**Uso com Múltiplos Observables**:

```
export class DashboardComponent {
  stats$ = combineLatest([
    this.userService.getUsers(),
    this.orderService.getOrders(),
    this.productService.getProducts()
  ]).pipe(
    map(([users, orders, products]) => ({
      totalUsers: users.length,
      totalOrders: orders.length,
      totalProducts: products.length
    }))
  );
}
```

```
@if (stats$ | async; as stats) {
  <div class="dashboard">
    <div>Usuários: {{ stats.totalUsers }}</div>
    <div>Pedidos: {{ stats.totalOrders }}</div>
    <div>Produtos: {{ stats.totalProducts }}</div>
  </div>
}
{% raw %}
```

**Vantagens do AsyncPipe**:

1. **Prevenção de Memory Leaks**: Unsubscribe automático quando componente é destruído
2. **Código Mais Limpo**: Não precisa gerenciar subscriptions manualmente
3. **Change Detection Automático**: Atualiza template automaticamente quando valores mudam
4. **Type Safety**: Melhor suporte TypeScript com `as` syntax
5. **Menos Erros**: Impossível esquecer unsubscribe

**Analogia Detalhada**:

AsyncPipe é como um assistente pessoal inteligente que monitora múltiplas caixas de correio:

- **Subscribe Manual**: É como você mesmo checando a caixa de correio manualmente. Você precisa lembrar de checar, precisa lembrar de parar de checar quando não precisa mais, e se esquecer, as cartas se acumulam (memory leaks).

- **AsyncPipe**: É como ter um assistente que:
  - Monitora automaticamente todas as caixas de correio (Observables)
  - Te avisa imediatamente quando chega algo novo (onNext)
  - Organiza tudo para você (atualiza template)
  - Para de monitorar automaticamente quando você não precisa mais (unsubscribe no ngOnDestroy)
  - Nunca esquece de limpar (prevenção de memory leaks)
  - Funciona mesmo se você tiver múltiplas caixas (múltiplos Observables)

Você só precisa dizer "monitore esta caixa" (`{{ data$ | async }}`) e o assistente cuida de tudo automaticamente.

**Exemplo Prático**:

```
{% raw %}

**Vantagens do AsyncPipe**:

1. **Prevenção de Memory Leaks**: Unsubscribe automático quando componente é destruído
2. **Código Mais Limpo**: Não precisa gerenciar subscriptions manualmente
3. **Change Detection Automático**: Atualiza template automaticamente quando valores mudam
4. **Type Safety**: Melhor suporte TypeScript com `as` syntax
5. **Menos Erros**: Impossível esquecer unsubscribe

**Analogia Detalhada**:

AsyncPipe é como um assistente pessoal inteligente que monitora múltiplas caixas de correio:

- **Subscribe Manual**: É como você mesmo checando a caixa de correio manualmente. Você precisa lembrar de checar, precisa lembrar de parar de checar quando não precisa mais, e se esquecer, as cartas se acumulam (memory leaks).

- **AsyncPipe**: É como ter um assistente que:
  - Monitora automaticamente todas as caixas de correio (Observables)
  - Te avisa imediatamente quando chega algo novo (onNext)
  - Organiza tudo para você (atualiza template)
  - Para de monitorar automaticamente quando você não precisa mais (unsubscribe no ngOnDestroy)
  - Nunca esquece de limpar (prevenção de memory leaks)
  - Funciona mesmo se você tiver múltiplas caixas (múltiplos Observables)

Você só precisa dizer "monitore esta caixa" (`{{ data$ | async }}`) e o assistente cuida de tudo automaticamente.

**Exemplo Prático**:

```
{% endraw %}
import { Component, OnInit } from '@angular/core';
import { Observable, interval } from 'rxjs';
import { map } from 'rxjs/operators';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-async-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
{% raw %}
    <p>Timer: {{ timer$ | async }}</p>
    <p>Data: {{ date$ | async | date:'medium' }}</p>
{% endraw %}
  `
})
export class AsyncDemoComponent implements OnInit {
  timer$!: Observable<number>;
  date$!: Observable<Date>;
  
  ngOnInit(): void {
    this.timer$ = interval(1000).pipe(map(() => Date.now()));
    this.date$ = interval(1000).pipe(map(() => new Date()));
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Componente com Control Flow Completo

**Contexto**: Criar componente que demonstra todos os tipos de Control Flow.

**Código**:

```
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

interface Task {
  id: number;
  title: string;
  completed: boolean;
  priority: 'high' | 'medium' | 'low';
}

@Component({
  selector: 'app-task-manager',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="task-manager">
      <h2>Gerenciador de Tarefas</h2>
      
      @if (tasks.length === 0) {
        <p class="empty">Nenhuma tarefa cadastrada</p>
      } @else {
        <div class="tasks">
          @for (task of tasks; track task.id) {
            <div class="task-card" [class.completed]="task.completed">
              <h3>{{ task.title }}</h3>
              
              @switch (task.priority) {
                @case ('high') {
                  <span class="priority high">Alta Prioridade</span>
                }
                @case ('medium') {
                  <span class="priority medium">Média Prioridade</span>
                }
                @default {
                  <span class="priority low">Baixa Prioridade</span>
                }
              }
              
              @if (task.completed) {
                <span class="status">✓ Concluída</span>
              } @else {
                <button (click)="completeTask(task.id)">Marcar como Concluída</button>
              }
            </div>
          }
        </div>
      }
    </div>
  `
})
export class TaskManagerComponent {
  tasks: Task[] = [
    { id: 1, title: 'Tarefa Urgente', completed: false, priority: 'high' },
    { id: 2, title: 'Tarefa Normal', completed: true, priority: 'medium' },
    { id: 3, title: 'Tarefa Baixa', completed: false, priority: 'low' }
  ];
  
  completeTask(id: number): void {
    const task = this.tasks.find(t => t.id === id);
    if (task) {
      task.completed = true;
    }
  }
}
```

---

### Exemplo 2: Pipes Customizados Avançados

**Contexto**: Criar conjunto de pipes customizados úteis para aplicações reais.

**Código Completo**:

```
import { Pipe, PipeTransform } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Pipe({
  name: 'initials',
  standalone: true
})
export class InitialsPipe implements PipeTransform {
  transform(name: string): string {
    if (!name) return '';
    const parts = name.trim().split(' ').filter(p => p.length > 0);
    if (parts.length === 0) return '';
    if (parts.length === 1) return parts[0][0].toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }
}

@Pipe({
  name: 'timeAgo',
  standalone: true
})
export class TimeAgoPipe implements PipeTransform {
  transform(date: Date | string | number): string {
    if (!date) return '';
    
    const now = new Date();
    const past = new Date(date);
    const diff = now.getTime() - past.getTime();
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    const weeks = Math.floor(days / 7);
    const months = Math.floor(days / 30);
    const years = Math.floor(days / 365);
    
    if (years > 0) return `${years} ano${years > 1 ? 's' : ''} atrás`;
    if (months > 0) return `${months} mês${months > 1 ? 'es' : ''} atrás`;
    if (weeks > 0) return `${weeks} semana${weeks > 1 ? 's' : ''} atrás`;
    if (days > 0) return `${days} dia${days > 1 ? 's' : ''} atrás`;
    if (hours > 0) return `${hours} hora${hours > 1 ? 's' : ''} atrás`;
    if (minutes > 0) return `${minutes} minuto${minutes > 1 ? 's' : ''} atrás`;
    if (seconds > 0) return `${seconds} segundo${seconds > 1 ? 's' : ''} atrás`;
    return 'Agora mesmo';
  }
}

@Pipe({
  name: 'highlight',
  standalone: true
})
export class HighlightPipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}
  
  transform(text: string, search: string): SafeHtml {
    if (!search || !text) return text;
    
    const escapedSearch = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escapedSearch})`, 'gi');
    const highlighted = text.replace(regex, '<mark>$1</mark>');
    
    return this.sanitizer.sanitize(1, highlighted) || text;
  }
}

@Pipe({
  name: 'fileSize',
  standalone: true
})
export class FileSizePipe implements PipeTransform {
  transform(bytes: number, decimals: number = 2): string {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }
}

@Pipe({
  name: 'pluralize',
  standalone: true
})
export class PluralizePipe implements PipeTransform {
  transform(count: number, singular: string, plural?: string): string {
    if (count === 1) return `${count} ${singular}`;
    const pluralForm = plural || `${singular}s`;
    return `${count} ${pluralForm}`;
  }
}

@Pipe({
  name: 'mask',
  standalone: true
})
export class MaskPipe implements PipeTransform {
  transform(value: string, visibleChars: number = 4, maskChar: string = '*'): string {
    if (!value || value.length <= visibleChars) return value;
    
    const visible = value.slice(-visibleChars);
    const masked = maskChar.repeat(value.length - visibleChars);
    
    return masked + visible;
  }
}
```

**Uso no Template**:

```
<div class="user-card">
{% raw %}
  <div class="avatar">{{ user.name | initials }}</div>
{% endraw %}
  <h3>{{ user.name }}</h3>
{% raw %}
  <p>Membro desde {{ user.joinDate | timeAgo }}</p>
  <p>Arquivo: {{ file.size | fileSize }}</p>
  <p>{{ itemCount | pluralize:'item':'itens' }}</p>
  <p>Cartão: {{ creditCard | mask:4 }}</p>
{% endraw %}
  <div [innerHTML]="description | highlight:searchTerm"></div>
</div>
```

**Exemplo de Uso Avançado - Pipe com Múltiplos Parâmetros**:

```
@Pipe({
  name: 'formatCurrency',
  standalone: true
})
export class FormatCurrencyPipe implements PipeTransform {
  transform(
    value: number,
    currency: string = 'BRL',
    locale: string = 'pt-BR',
    minimumFractionDigits: number = 2,
    maximumFractionDigits: number = 2
  ): string {
    return new Intl.NumberFormat(locale, {
      style: 'currency',
      currency: currency,
      minimumFractionDigits,
      maximumFractionDigits
    }).format(value);
  }
}
```

```
{% raw %}
<p>Preço: {{ price | formatCurrency:'USD':'en-US' }}</p>
<p>Preço BR: {{ price | formatCurrency:'BRL':'pt-BR':2:2 }}</p>
{% endraw %}
```

---

## Comparação com Outras Abordagens

### Control Flow vs Diretivas Estruturais

**Tabela Comparativa Detalhada**:

| Aspecto | Diretivas Estruturais | Control Flow |
|---------|----------------------|--------------|
| **Sintaxe** | Microsyntax (`*ngIf="condition"`) | Blocos (`@if (condition) {}`) |
| **Performance** | Boa (com otimizações) | Excelente (nativa) |
| **Type Safety** | Limitado | Completo |
| **Tracking** | Manual (`trackBy: fn`) | Integrado (`track item.id`) |
| **Empty State** | Precisa `*ngIf` separado | `@empty {}` integrado |
| **Legibilidade** | Média | Alta |
| **Compilação** | Runtime directives | Compilado para JS |
| **Bundle Size** | Maior | Menor |
| **Angular Version** | Angular 2-16 | Angular 17+ |

**Exemplos Comparativos**:

```
<!-- Diretivas Estruturais (Antigo) -->
<div *ngIf="user; else loading">
  {{ user.name }}
</div>
<ng-template #loading>Carregando...</ng-template>

<div *ngFor="let item of items; let i = index; trackBy: trackFn">
  {{ i }}: {{ item }}
</div>

<!-- Control Flow (Novo) -->
@if (user) {
  <div>{{ user.name }}</div>
} @else {
  <div>Carregando...</div>
}

@for (item of items; track item.id) {
{% raw %}
  <div>{{ $index }}: {{ item }}</div>
{% endraw %}
} @empty {
  <div>Lista vazia</div>
}
```

### Angular vs React vs Vue: Control Flow

**Tabela Comparativa Detalhada**:

| Framework | Sintaxe Condicional | Sintaxe de Loop | Type Safety | Performance | Bundle Size | Curva Aprendizado |
|-----------|-------------------|-----------------|-------------|------------|-------------|------------------|
| **Angular (Control Flow)** | `@if {} @else {}` | `@for (item of items; track id) {}` | Completo (compile-time) | Excelente (compilado) | Menor (tree-shaking) | Média |
| **Angular (Diretivas)** | `*ngIf` | `*ngFor` | Limitado | Boa (runtime) | Maior | Baixa |
| **React** | `{condition && <div>}` ou `{condition ? <A /> : <B />}` | `{items.map(item => <div key={id}>)}` | Opcional (TypeScript) | Excelente (Virtual DOM) | Médio | Baixa |
| **Vue 3** | `v-if` / `v-else-if` / `v-else` | `v-for="(item, index) in items" :key="id"` | Opcional (TypeScript) | Excelente (compilado) | Menor | Baixa |
| **Svelte** | `{#if condition}` | `{#each items as item (item.id)}` | Completo (compile-time) | Excelente (compilado) | Menor | Baixa |

**Comparação Detalhada de Sintaxe**:

**Renderização Condicional**:

```
<!-- Angular Control Flow -->
@if (user) {
  <div>{{ user.name }}</div>
} @else {
  <div>Sem usuário</div>
}

<!-- React -->
{user ? <div>{user.name}</div> : <div>Sem usuário</div>}
{user && <div>{user.name}</div>}

<!-- Vue -->
<div v-if="user">{{ user.name }}</div>
<div v-else>Sem usuário</div>

<!-- Svelte -->
{#if user}
  <div>{user.name}</div>
{:else}
  <div>Sem usuário</div>
{/if}
```

**Iteração**:

```
<!-- Angular Control Flow -->
@for (item of items; track item.id) {
  <div>{{ item.name }}</div>
} @empty {
  <div>Lista vazia</div>
}

<!-- React -->
{items.map(item => <div key={item.id}>{item.name}</div>)}
{items.length === 0 && <div>Lista vazia</div>}

<!-- Vue -->
<div v-for="item in items" :key="item.id">{{ item.name }}</div>
<div v-if="items.length === 0">Lista vazia</div>

<!-- Svelte -->
{#each items as item (item.id)}
  <div>{item.name}</div>
{:else}
  <div>Lista vazia</div>
{/each}
```

**Análise de Trade-offs**:

| Aspecto | Angular Control Flow | React | Vue 3 | Svelte |
|---------|---------------------|-------|-------|--------|
| **Compilação** | AOT (Ahead of Time) | Runtime + Babel | AOT + Runtime | AOT completo |
| **Type Safety** | Completo (compile-time) | Opcional (TypeScript) | Opcional (TypeScript) | Completo (compile-time) |
| **Performance** | Excelente (código otimizado) | Excelente (Virtual DOM) | Excelente (compilado) | Excelente (código mínimo) |
| **Bundle Size** | Menor (tree-shaking eficiente) | Médio | Menor | Menor |
| **Tracking** | Obrigatório e integrado | Manual (key prop) | Manual (key prop) | Obrigatório |
| **Empty State** | Integrado (@empty) | Manual | Manual | Integrado (:else) |
| **Legibilidade** | Alta (sintaxe de bloco) | Média (JSX misturado) | Alta (diretivas claras) | Alta (sintaxe de bloco) |
| **Curva Aprendizado** | Média (novo conceito) | Baixa (JavaScript puro) | Baixa (similar HTML) | Baixa (sintaxe intuitiva) |

**Quando Usar Cada Abordagem**:

- **Angular Control Flow**: Projetos Angular 17+, quando type safety e performance são críticos
- **React**: Quando você já conhece React, precisa de flexibilidade máxima, ou trabalha com equipe React
- **Vue 3**: Quando você quer sintaxe similar a HTML, boa performance, e curva de aprendizado suave
- **Svelte**: Quando você quer bundle size mínimo e performance máxima, com sintaxe moderna

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use Control Flow em novos projetos**
   - **Por quê**: Melhor performance, sintaxe mais limpa, type safety completo
   - **Exemplo Bom**: `@if (condition) { ... } @else { ... }`
   - **Exemplo Ruim**: `*ngIf="condition"`
   - **Benefícios**: Performance superior, código mais legível, melhor type safety

2. **Sempre use track em @for**
   - **Por quê**: Melhora performance significativamente, evita re-renderizações
   - **Exemplo Bom**: `@for (item of items; track item.id) { ... }`
   - **Exemplo Ruim**: `@for (item of items) { ... }` (sem track)
   - **Benefícios**: Performance muito melhor em listas grandes

3. **Use @empty para estados vazios**
   - **Por quê**: Sintaxe mais clara e integrada
   - **Exemplo Bom**: 
```
     @for (item of items; track item.id) {
       <div>{{ item }}</div>
     } @empty {
       <p>Nenhum item encontrado</p>
     }
{% raw %}
```
   - **Benefícios**: Código mais limpo, sem necessidade de `*ngIf` separado

4. **Use AsyncPipe para Observables**
   - **Por quê**: Previne memory leaks automaticamente, gerencia subscribe/unsubscribe
   - **Exemplo Bom**: `{{ data$ | async }}`
   - **Exemplo Ruim**: Subscribe manual no componente
   - **Benefícios**: Sem memory leaks, código mais limpo

5. **Mantenha pipes pure quando possível**
   - **Por quê**: Melhor performance, recalcula apenas quando entrada muda
   - **Exemplo Bom**: `pure: true` (padrão)
   - **Exemplo Ruim**: `pure: false` sem necessidade
   - **Benefícios**: Performance muito melhor, menos recálculos

6. **Use pipes para transformação, não para lógica complexa**
   - **Por quê**: Pipes devem ser simples e reutilizáveis
   - **Exemplo Bom**: `{{ price | currency }}` (transformação simples)
   - **Exemplo Ruim**: Pipe com lógica de negócio complexa
   - **Benefícios**: Código mais testável, pipes reutilizáveis

7. **Combine pipes quando necessário**
   - **Por quê**: Permite transformações em cascata
   - **Exemplo Bom**: `{{ date$ | async | date:'short' }}`
   - **Benefícios**: Flexibilidade, código declarativo

8. **Migre gradualmente de diretivas para Control Flow**
   - **Por quê**: Permite migração incremental sem quebrar código existente
   - **Estratégia**: Migre componente por componente
   - **Benefícios**: Migração segura, sem riscos

### ❌ Anti-padrões Comuns

1. **Não misture Control Flow com diretivas estruturais no mesmo componente**
   - **Problema**: Pode causar confusão, inconsistência, problemas de performance
   - **Exemplo Ruim**: Misturar `@if` com `*ngIf` no mesmo componente
   - **Solução**: Escolha um padrão e mantenha consistente em todo componente
   - **Impacto**: Código confuso, difícil manutenção

2. **Não use pipes impure desnecessariamente**
   - **Problema**: Performance ruim, recalcula a cada change detection
   - **Exemplo Ruim**: `pure: false` quando pipe é determinístico
   - **Solução**: Use pure pipes sempre que possível, apenas use impure quando realmente necessário
   - **Impacto**: Performance degradada, aplicação lenta

3. **Não faça subscribe manual em Observables no template**
   - **Problema**: Memory leaks, código verboso, difícil manutenção
   - **Exemplo Ruim**: 
```
{% raw %}
   - **Benefícios**: Código mais limpo, sem necessidade de `*ngIf` separado

4. **Use AsyncPipe para Observables**
   - **Por quê**: Previne memory leaks automaticamente, gerencia subscribe/unsubscribe
   - **Exemplo Bom**: `{{ data$ | async }}`
   - **Exemplo Ruim**: Subscribe manual no componente
   - **Benefícios**: Sem memory leaks, código mais limpo

5. **Mantenha pipes pure quando possível**
   - **Por quê**: Melhor performance, recalcula apenas quando entrada muda
   - **Exemplo Bom**: `pure: true` (padrão)
   - **Exemplo Ruim**: `pure: false` sem necessidade
   - **Benefícios**: Performance muito melhor, menos recálculos

6. **Use pipes para transformação, não para lógica complexa**
   - **Por quê**: Pipes devem ser simples e reutilizáveis
   - **Exemplo Bom**: `{{ price | currency }}` (transformação simples)
   - **Exemplo Ruim**: Pipe com lógica de negócio complexa
   - **Benefícios**: Código mais testável, pipes reutilizáveis

7. **Combine pipes quando necessário**
   - **Por quê**: Permite transformações em cascata
   - **Exemplo Bom**: `{{ date$ | async | date:'short' }}`
   - **Benefícios**: Flexibilidade, código declarativo

8. **Migre gradualmente de diretivas para Control Flow**
   - **Por quê**: Permite migração incremental sem quebrar código existente
   - **Estratégia**: Migre componente por componente
   - **Benefícios**: Migração segura, sem riscos

### ❌ Anti-padrões Comuns

1. **Não misture Control Flow com diretivas estruturais no mesmo componente**
   - **Problema**: Pode causar confusão, inconsistência, problemas de performance
   - **Exemplo Ruim**: Misturar `@if` com `*ngIf` no mesmo componente
   - **Solução**: Escolha um padrão e mantenha consistente em todo componente
   - **Impacto**: Código confuso, difícil manutenção

2. **Não use pipes impure desnecessariamente**
   - **Problema**: Performance ruim, recalcula a cada change detection
   - **Exemplo Ruim**: `pure: false` quando pipe é determinístico
   - **Solução**: Use pure pipes sempre que possível, apenas use impure quando realmente necessário
   - **Impacto**: Performance degradada, aplicação lenta

3. **Não faça subscribe manual em Observables no template**
   - **Problema**: Memory leaks, código verboso, difícil manutenção
   - **Exemplo Ruim**: 
```
{% endraw %}
     ngOnInit() {
       this.data$.subscribe(value => this.data = value);
     }
{% raw %}
```
   - **Solução**: Use AsyncPipe `{{ data$ | async }}`
   - **Impacto**: Memory leaks, bugs difíceis de rastrear

4. **Não esqueça track em @for**
   - **Problema**: Performance ruim, re-renderizações desnecessárias
   - **Exemplo Ruim**: `@for (item of items) { ... }` (sem track)
   - **Solução**: Sempre use track: `@for (item of items; track item.id)`
   - **Impacto**: Performance muito ruim em listas grandes

5. **Não use pipes para lógica de negócio**
   - **Problema**: Pipes devem ser para transformação, não lógica complexa
   - **Exemplo Ruim**: Pipe que faz chamadas HTTP ou lógica complexa
   - **Solução**: Mova lógica para serviços ou métodos do componente
   - **Impacto**: Código difícil de testar, pipes não reutilizáveis

6. **Não use Control Flow em versões antigas do Angular**
   - **Problema**: Control Flow requer Angular 17+
   - **Exemplo Ruim**: Tentar usar `@if` no Angular 16 ou anterior
   - **Solução**: Use diretivas estruturais ou atualize Angular
   - **Impacto**: Código não compila

7. **Não ignore o @empty em @for**
   - **Problema**: UX ruim quando lista está vazia
   - **Exemplo Ruim**: `@for (item of items; track item.id) { ... }` (sem @empty)
   - **Solução**: Sempre forneça estado vazio: `@empty { <p>Vazio</p> }`
   - **Impacto**: Interface confusa para usuário

---

## Exercícios Práticos

### Exercício 1: Migrar para Control Flow (Básico)

**Objetivo**: Migrar componente de diretivas estruturais para Control Flow

**Descrição**: 
Pegue um componente existente que usa *ngIf, *ngFor e *ngSwitch e migre para @if, @for e @switch.

**Arquivo**: `exercises/exercise-1-5-1-migrar-control-flow.md`

---

### Exercício 2: Lista com @for e Pipes (Básico)

**Objetivo**: Usar @for com pipes para formatação

**Descrição**:
Crie uma lista de produtos usando @for e formate preços, datas e números usando pipes embutidos.

**Arquivo**: `exercises/exercise-1-5-2-for-pipes.md`

---

### Exercício 3: Pipe Customizado Simples (Intermediário)

**Objetivo**: Criar pipe customizado básico

**Descrição**:
Crie um pipe `capitalize` que capitaliza primeira letra de cada palavra.

**Arquivo**: `exercises/exercise-1-5-3-pipe-simples.md`

---

### Exercício 4: Pipe Customizado Avançado (Avançado)

**Objetivo**: Criar pipe customizado complexo

**Descrição**:
Crie um pipe `filter` que filtra arrays baseado em função predicado. Use com cuidado (pode ser impure).

**Arquivo**: `exercises/exercise-1-5-4-pipe-avancado.md`

---

### Exercício 5: Componente Completo com Control Flow e Pipes (Avançado)

**Objetivo**: Combinar Control Flow e Pipes em um componente real

**Descrição**:
Crie um componente de lista de transações financeiras que usa @for, @if, @switch, pipes embutidos e customizados para exibir dados formatados.

**Código Completo**:

```
{% endraw %}
import { Component, computed, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { TimeAgoPipe } from './pipes/time-ago.pipe';
import { FormatCurrencyPipe } from './pipes/format-currency.pipe';

interface Transaction {
  id: number;
  description: string;
  amount: number;
  type: 'income' | 'expense' | 'transfer';
  category: string;
  date: Date;
  status: 'pending' | 'completed' | 'failed';
}

@Component({
  selector: 'app-transactions',
  standalone: true,
  imports: [CommonModule, TimeAgoPipe, FormatCurrencyPipe],
  template: `
    <div class="transactions-container">
      <h2>Transações Financeiras</h2>
      
      @if (loading()) {
        <div class="loading">Carregando transações...</div>
      } @else if (transactions().length === 0) {
        <div class="empty-state">
          <p>Nenhuma transação encontrada</p>
        </div>
      } @else {
        <div class="summary">
          <div class="summary-item">
            <span>Total:</span>
            <span [class.positive]="total() >= 0" [class.negative]="total() < 0">
{% raw %}
              {{ total() | formatCurrency }}
{% endraw %}
            </span>
          </div>
          <div class="summary-item">
            <span>Receitas:</span>
{% raw %}
            <span class="positive">{{ income() | formatCurrency }}</span>
{% endraw %}
          </div>
          <div class="summary-item">
            <span>Despesas:</span>
{% raw %}
            <span class="negative">{{ expenses() | formatCurrency }}</span>
{% endraw %}
          </div>
        </div>
        
        <div class="filters">
          <select [value]="filterType()" (change)="filterType.set($any($event.target).value)">
            <option value="all">Todas</option>
            <option value="income">Receitas</option>
            <option value="expense">Despesas</option>
            <option value="transfer">Transferências</option>
          </select>
        </div>
        
        <div class="transactions-list">
          @for (transaction of filteredTransactions(); track transaction.id) {
            <div class="transaction-card" [class.pending]="transaction.status === 'pending'">
              <div class="transaction-header">
                <h3>{{ transaction.description }}</h3>
                
                @switch (transaction.status) {
                  @case ('pending') {
                    <span class="badge pending">Pendente</span>
                  }
                  @case ('completed') {
                    <span class="badge completed">Concluída</span>
                  }
                  @case ('failed') {
                    <span class="badge failed">Falhou</span>
                  }
                }
              </div>
              
              <div class="transaction-body">
                <div class="amount" 
                     [class.income]="transaction.type === 'income'"
                     [class.expense]="transaction.type === 'expense'">
                  @if (transaction.type === 'income') {
                    <span>+</span>
                  } @else if (transaction.type === 'expense') {
                    <span>-</span>
                  }
{% raw %}
                  {{ transaction.amount | formatCurrency }}
{% endraw %}
                </div>
                
                <div class="details">
                  <span class="category">{{ transaction.category }}</span>
{% raw %}
                  <span class="date">{{ transaction.date | timeAgo }}</span>
{% endraw %}
                </div>
              </div>
              
              @if (transaction.status === 'failed') {
                <div class="error-message">
                  Esta transação falhou. Tente novamente.
                </div>
              }
            </div>
          } @empty {
            <div class="empty-filtered">
              Nenhuma transação encontrada com os filtros selecionados
            </div>
          }
        </div>
      }
    </div>
  `,
  styles: [`
    .transactions-container {
      padding: 20px;
    }
    
    .loading, .empty-state {
      text-align: center;
      padding: 40px;
      color: #666;
    }
    
    .summary {
      display: flex;
      gap: 20px;
      margin-bottom: 20px;
      padding: 15px;
      background: #f5f5f5;
      border-radius: 8px;
    }
    
    .summary-item {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }
    
    .positive { color: #28a745; }
    .negative { color: #dc3545; }
    
    .transactions-list {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }
    
    .transaction-card {
      padding: 15px;
      border: 1px solid #ddd;
      border-radius: 8px;
      background: white;
    }
    
    .transaction-card.pending {
      border-left: 4px solid #ffc107;
    }
    
    .transaction-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    
    .badge {
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
    }
    
    .badge.pending { background: #ffc107; color: #000; }
    .badge.completed { background: #28a745; color: white; }
    .badge.failed { background: #dc3545; color: white; }
    
    .amount {
      font-size: 24px;
      font-weight: bold;
      margin-bottom: 10px;
    }
    
    .amount.income { color: #28a745; }
    .amount.expense { color: #dc3545; }
    
    .details {
      display: flex;
      justify-content: space-between;
      color: #666;
      font-size: 14px;
    }
    
    .error-message {
      margin-top: 10px;
      padding: 10px;
      background: #f8d7da;
      color: #721c24;
      border-radius: 4px;
    }
  `]
})
export class TransactionsComponent {
  loading = signal(false);
  filterType = signal<'all' | 'income' | 'expense' | 'transfer'>('all');
  
  transactions = signal<Transaction[]>([
    {
      id: 1,
      description: 'Salário',
      amount: 5000,
      type: 'income',
      category: 'Trabalho',
      date: new Date('2024-01-01'),
      status: 'completed'
    },
    {
      id: 2,
      description: 'Aluguel',
      amount: 1500,
      type: 'expense',
      category: 'Moradia',
      date: new Date('2024-01-05'),
      status: 'pending'
    },
    {
      id: 3,
      description: 'Transferência para Poupança',
      amount: 1000,
      type: 'transfer',
      category: 'Investimentos',
      date: new Date('2024-01-10'),
      status: 'completed'
    }
  ]);
  
  filteredTransactions = computed(() => {
    const type = this.filterType();
    if (type === 'all') return this.transactions();
    return this.transactions().filter(t => t.type === type);
  });
  
  income = computed(() => 
    this.transactions()
      .filter(t => t.type === 'income' && t.status === 'completed')
      .reduce((sum, t) => sum + t.amount, 0)
  );
  
  expenses = computed(() => 
    this.transactions()
      .filter(t => t.type === 'expense' && t.status === 'completed')
      .reduce((sum, t) => sum + t.amount, 0)
  );
  
  total = computed(() => this.income() - this.expenses());
}
```

**Explicação**:

Este exemplo demonstra:
- **@if/@else**: Para estados de loading e empty
- **@for com track**: Para iterar transações com tracking por ID
- **@switch**: Para diferentes status de transação
- **@empty**: Para quando filtros não retornam resultados
- **Pipes Customizados**: `timeAgo` e `formatCurrency`
- **Signals**: Para estado reativo
- **Computed Signals**: Para valores derivados

**Arquivo**: `exercises/exercise-1-5-5-componente-completo.md`

---

## Referências Externas

### Documentação Oficial

- **[Control Flow](https://angular.io/guide/control-flow)**: Guia oficial de Control Flow
- **[Pipes](https://angular.io/guide/pipes)**: Guia oficial de Pipes
- **[Built-in Pipes](https://angular.io/api/common#pipes)**: Lista de pipes embutidos
- **[AsyncPipe](https://angular.io/api/common/AsyncPipe)**: Documentação AsyncPipe

---

## Resumo

### Principais Conceitos

- Control Flow (@if, @for, @switch) substitui diretivas estruturais
- Pipes transformam dados para exibição
- AsyncPipe gerencia Observables automaticamente
- Pipes customizados criam transformações reutilizáveis
- Pure vs Impure afeta performance

### Pontos-Chave para Lembrar

- Use Control Flow em novos projetos
- Sempre use track em @for
- Use AsyncPipe para Observables
- Mantenha pipes pure quando possível
- Pipes são para transformação, não para lógica complexa

### Próximos Passos

- Próximo módulo: Desenvolvimento Intermediário
- Praticar migração para Control Flow
- Criar pipes customizados úteis

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

**Aula Anterior**: [Aula 1.4: Data Binding e Diretivas Modernas](./lesson-1-4-data-binding.md)  
**Próximo Módulo**: [Módulo 2: Desenvolvimento Intermediário](../modules/module-2-desenvolvimento-intermediario.md)  
**Voltar ao Módulo**: [Módulo 1: Fundamentos Acelerados](../modules/module-1-fundamentos-acelerados.md)

```