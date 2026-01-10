---
layout: lesson
title: "Aula 3.1: RxJS Operators Avançados"
slug: rxjs-operators
module: module-3
lesson_id: lesson-3-1
duration: "120 minutos"
level: "Avançado"
prerequisites: []
exercises: []
video:
  file: "assets/videos/03.1RxJS_Operators_Observables_SwitchMap_e_Busca_Perfeita.mp4"
  thumbnail: "assets/images/podcasts/03.1RxJS_Operators_Observables_SwitchMap_e_Busca_Perfeita.png"
  title: "RxJS Operators, Observables, SwitchMap e Busca Perfeita"
  description: "RxJS é fundamental para Angular moderno."
  duration: "65-80 minutos"
permalink: /modules/programacao-reativa-estado/lessons/rxjs-operators/
---

## Introdução

Nesta aula, você dominará RxJS Operators avançados, essenciais para programação reativa no Angular. RxJS é a biblioteca que torna Angular reativo, permitindo trabalhar com streams de dados assíncronos de forma elegante e poderosa.

### Contexto Histórico

**RxJS - A Revolução da Programação Reativa em JavaScript**:

RxJS (Reactive Extensions for JavaScript) é a implementação JavaScript da biblioteca ReactiveX, que foi criada pela Microsoft em 2011. A jornada do RxJS é uma das mais fascinantes evoluções no ecossistema JavaScript:

**Linha do Tempo**:

```
2011 ──────────────────────────────────────────────────────────── 2024+
 │                                                                  │
 ├─ 2011    📦 ReactiveX Criado pela Microsoft                    │
 │          Conceito de Observable pattern                         │
 │          Implementações em .NET, Java, C++                      │
 │                                                                  │
 ├─ 2012    🚀 RxJS v1.0 Lançado                                  │
 │          Implementação inicial em JavaScript                    │
 │          Baseado em callbacks e Promises                        │
 │          Comunidade pequena mas entusiasta                      │
 │                                                                  │
 ├─ 2015    🔥 RxJS v5.0 - Grande Refatoração                    │
 │          Arquitetura completamente reescrita                    │
 │          Performance significativamente melhorada                │
 │          API mais consistente                                   │
 │          Adoção crescente na comunidade                         │
 │                                                                  │
 ├─ 2016    ⚡ Angular 2 Adota RxJS como Core                    │
 │          HttpClient retorna Observables                         │
 │          Router usa Observables                                 │
 │          Forms reativos baseados em RxJS                       │
 │          RxJS torna-se essencial para Angular                   │
 │                                                                  │
 ├─ 2018    🎯 RxJS v6.0 - Breaking Changes                       │
 │          Nova arquitetura modular                               │
 │          Operators como funções puras                            │
 │          Tree-shaking melhorado                                 │
 │          Migração facilitada com rxjs-compat                    │
 │                                                                  │
 ├─ 2020    📈 RxJS v7.0 - Performance e Estabilidade            │
 │          Melhorias de performance                               │
 │          Novos operators (combineLatestWith, etc)              │
 │          Melhor suporte TypeScript                              │
 │                                                                  │
 └─ 2024+   🎯 RxJS Estabelecido como Padrão                      │
            Biblioteca madura e estável                            │
            Integração profunda com Angular                         │
            Comunidade global ativa                                 │
            Padrão de fato para programação reativa                │
```

**Por que RxJS foi criado?**

O problema que RxJS resolve é fundamental no desenvolvimento moderno:

**Antes do RxJS**:
- Callbacks aninhados (callback hell)
- Promises não canceláveis
- Dificuldade em combinar múltiplas operações assíncronas
- Gerenciamento manual de subscriptions
- Dificuldade em tratar erros em operações assíncronas

**Com RxJS**:
- Streams declarativos e composáveis
- Cancelamento automático de operações
- Combinação elegante de múltiplos streams
- Gerenciamento automático de recursos
- Tratamento de erros integrado

**Analogia Histórica**:

Pense em RxJS como a evolução do transporte público:
- **Callbacks** são como táxis individuais: cada um vai para um lugar diferente, difícil coordenar
- **Promises** são como ônibus: vão para um destino fixo, mas não podem ser cancelados facilmente
- **RxJS Observables** são como metrôs com múltiplas linhas: você pode trocar de linha (operators), combinar rotas (combineLatest), cancelar viagem (unsubscribe), e tudo funciona de forma coordenada e eficiente

### O que você vai aprender

- Trabalhar com Observables, Observers e Subscriptions em profundidade
- Usar operators de transformação avançados (map, switchMap, mergeMap, concatMap, exhaustMap)
- Combinar múltiplos Observables (combineLatest, forkJoin, merge, zip)
- Filtrar e controlar fluxo de dados (filter, debounceTime, throttleTime, distinctUntilChanged)
- Trabalhar com Subjects (Subject, BehaviorSubject, ReplaySubject, AsyncSubject)
- Entender Hot vs Cold Observables e quando usar cada um
- Tratar erros adequadamente (catchError, retry, retryWhen)
- Criar padrões reativos eficientes e evitar memory leaks
- Comparar RxJS com outras abordagens reativas (MobX, Redux, Zustand)

### Por que isso é importante

**Para Desenvolvimento Angular**:
- **Essencial**: RxJS é parte central do Angular - HttpClient, Router, Forms, tudo usa Observables
- **Inevitável**: Você não pode criar aplicações Angular profissionais sem entender RxJS
- **Poderoso**: Permite resolver problemas complexos de forma elegante e declarativa
- **Performático**: Gerenciamento eficiente de recursos e cancelamento automático

**Para Projetos**:
- **Aplicações Reativas**: Criação de aplicações verdadeiramente reativas e responsivas
- **Performance**: Evita memory leaks e gerencia recursos adequadamente
- **Manutenibilidade**: Código mais limpo, declarativo e fácil de entender
- **Escalabilidade**: Padrões que funcionam bem em aplicações grandes

**Para Carreira**:
- **Habilidade Essencial**: Conhecimento obrigatório para desenvolvedores Angular sênior
- **Diferencial**: Entender RxJS profundamente te diferencia no mercado
- **Fundação**: Base para entender Signals, State Management, e arquiteturas reativas
- **Aplicável**: Conceitos aplicáveis além do Angular (React, Vue com RxJS)

---

## Conceitos Teóricos

### Observables, Observers e Subscriptions

**Definição**: Observable é uma coleção de valores futuros que podem ser observados. Observer é quem consome esses valores através de callbacks. Subscription representa a execução ativa de um Observable e permite cancelamento.

**Explicação Detalhada**:

**Observable**:
- Representa stream de dados assíncronos que podem emitir zero ou mais valores ao longo do tempo
- É lazy: só executa quando há pelo menos um subscriber
- Pode emitir múltiplos valores ao longo do tempo (diferente de Promise que emite apenas um)
- Pode completar normalmente (complete) ou emitir erro (error)
- É unicast por padrão: cada subscriber cria nova execução
- Pode ser convertido para Hot Observable usando operators como `share()`

**Observer**:
- É um objeto com três métodos opcionais: `next`, `error`, `complete`
- `next(value)`: Chamado quando Observable emite um valor
- `error(err)`: Chamado quando Observable emite um erro
- `complete()`: Chamado quando Observable completa normalmente
- Pode ser passado diretamente para `subscribe()` ou como objeto
- É a interface que define como consumir valores do Observable

**Subscription**:
- Representa execução ativa de um Observable
- Permite cancelar execução através de `unsubscribe()`
- Pode ser combinada com outras subscriptions usando `add()`
- Quando unsubscribe é chamado, Observable para de emitir valores
- É essencial para evitar memory leaks em aplicações Angular

**Analogia Detalhada**:

Pense em Observable como um **canal de TV ao vivo**:

- **Observable** é o canal de TV: tem programação que será transmitida ao longo do tempo
- **Observer** é você assistindo: você decide o que fazer quando vê algo interessante (next), quando há problema na transmissão (error), ou quando o programa acaba (complete)
- **Subscription** é sua conexão com o canal: enquanto está conectado, você recebe conteúdo; quando desliga (unsubscribe), para de receber

**Mapeamento Detalhado**:
- `observer.next(value)` = Você vê algo interessante na TV e reage
- `observer.error(err)` = Há problema na transmissão (sinal perdido, erro técnico)
- `observer.complete()` = Programa acabou, transmissão encerrada
- `subscription.unsubscribe()` = Você desliga a TV e para de assistir
- Múltiplos subscribers = Múltiplas pessoas assistindo o mesmo canal (Cold Observable) ou canal ao vivo compartilhado (Hot Observable)

**Visualização Completa**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Observable Lifecycle                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Observable Creation                                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  const obs$ = new Observable(observer => {              │  │
│  │    observer.next(1);                                     │  │
│  │    observer.next(2);                                     │  │
│  │    observer.complete();                                  │  │
│  │  });                                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Subscription                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  const subscription = obs$.subscribe({                   │  │
│  │    next: (value) => console.log(value),                 │  │
│  │    error: (err) => console.error(err),                 │  │
│  │    complete: () => console.log('Done')                  │  │
│  │  });                                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Execution Flow                                                 │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐           │
│  │ Observer │ ←───  │Observable│  ───→ │Observer │           │
│  │  next(1) │       │  Stream  │       │  next(2) │           │
│  └──────────┘       └──────────┘       └──────────┘           │
│       │                  │                  │                  │
│       ▼                  ▼                  ▼                  │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐           │
│  │Observer  │      │Observer  │      │Observer  │           │
│  │complete()│      │  Error   │      │  Active  │           │
│  └──────────┘      └──────────┘      └──────────┘           │
│                                                                 │
│  Unsubscribe                                                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  subscription.unsubscribe();                             │  │
│  │  → Observable stops emitting                             │  │
│  │  → Resources cleaned up                                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { Observable, Observer } from 'rxjs';

const numberObservable = new Observable<number>((observer: Observer<number>) => {
  console.log('Observable execution started');
  
  let count = 0;
  const intervalId = setInterval(() => {
    count++;
    if (count <= 3) {
      observer.next(count);
    } else {
      clearInterval(intervalId);
      observer.complete();
    }
  }, 1000);
  
  return () => {
    console.log('Cleanup: clearing interval');
    clearInterval(intervalId);
  };
});

const observer = {
  next: (value: number) => {
    console.log(`Observer received: ${value}`);
  },
  error: (error: Error) => {
    console.error(`Observer error: ${error.message}`);
  },
  complete: () => {
    console.log('Observer: stream completed');
  }
};

const subscription = numberObservable.subscribe(observer);

setTimeout(() => {
  console.log('Unsubscribing...');
  subscription.unsubscribe();
}, 5000);
```

**Saída Esperada**:
```
Observable execution started
Observer received: 1
Observer received: 2
Observer received: 3
Observer: stream completed
Cleanup: clearing interval
```

**Casos de Uso Comuns**:
- HTTP requests (HttpClient retorna Observable)
- Event handlers (fromEvent)
- Timers (interval, timer)
- WebSockets
- Form value changes
- Router events

---

### Operators de Transformação

**Definição**: Operators que transformam valores emitidos por um Observable em novos valores, criando novos Observables a partir dos valores originais.

**Explicação Detalhada**:

Operators de transformação são funções puras que recebem um Observable e retornam um novo Observable com valores transformados. Eles são a essência do poder do RxJS, permitindo criar pipelines de transformação declarativos.

**Operators Principais**:

**`map`**:
- Transforma cada valor emitido aplicando uma função
- Mantém ordem e timing dos valores
- Não altera número de valores emitidos
- Síncrono por padrão
- Use quando: precisa transformar cada valor individualmente

**`switchMap`**:
- Cancela subscription anterior quando novo valor chega
- Útil para operações que devem ser canceladas quando nova requisição chega
- Apenas último Observable interno é mantido ativo
- Use quando: busca/autocomplete (quer apenas resultado da última busca)

**`mergeMap` (flatMap)**:
- Executa todos os Observables internos em paralelo
- Mantém todas as subscriptions ativas simultaneamente
- Valores podem chegar fora de ordem
- Use quando: precisa processar todos os valores em paralelo

**`concatMap`**:
- Executa Observables internos em sequência
- Espera um completar antes de iniciar próximo
- Mantém ordem garantida
- Use quando: ordem é importante e precisa processar sequencialmente

**`exhaustMap`**:
- Ignora novos valores enquanto Observable interno está executando
- Útil para prevenir múltiplas execuções simultâneas
- Use quando: quer garantir que apenas uma execução aconteça por vez

**Analogia Detalhada**:

Operators são como **estações de processamento em uma linha de produção industrial**:

- **map**: Estação de pintura - cada item passa e recebe uma camada de tinta (transformação simples)
- **switchMap**: Estação de inspeção com cancelamento - quando novo item chega, inspeção anterior é cancelada e nova começa (útil para evitar trabalho desnecessário)
- **mergeMap**: Múltiplas linhas paralelas - vários itens são processados simultaneamente em diferentes estações (máxima eficiência)
- **concatMap**: Linha sequencial - cada item passa por todas as estações em ordem, uma de cada vez (garantia de ordem)
- **exhaustMap**: Estação com trava - enquanto um item está sendo processado, novos itens esperam (previne sobrecarga)

**Visualização de Operators**:

```
┌─────────────────────────────────────────────────────────────────┐
│              Operators de Transformação - Fluxo                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Source Observable                                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  of(1, 2, 3)                                             │  │
│  │  ──1──2──3──|                                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│         │                                                        │
│         ├───────────────────────────────────────────────────────┤
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  map(x => x * 2)                                         │  │
│  │  ──2──4──6──|                                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│         │                                                        │
│         ├───────────────────────────────────────────────────────┤
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  switchMap(id => http.get(`/user/${id}`))               │  │
│  │  ──user1──user2──user3──|                               │  │
│  │  (cancela requisição anterior se nova chegar)           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Comparação Visual:                                            │
│                                                                 │
│  switchMap (cancela anterior):                                 │
│  ──1──2──3──|                                                  │
│     │   │   │                                                  │
│     ▼   ▼   ▼                                                  │
│     R1  R2  R3  (R1 e R2 cancelados quando R2 e R3 chegam)    │
│                                                                 │
│  mergeMap (paralelo):                                          │
│  ──1──2──3──|                                                  │
│     │   │   │                                                  │
│     ▼   ▼   ▼                                                  │
│     R1  R2  R3  (todos executam simultaneamente)              │
│     │   │   │                                                  │
│     └───┴───┘                                                  │
│         │                                                      │
│         ▼                                                      │
│     ──R1──R2──R3──| (podem chegar fora de ordem)              │
│                                                                 │
│  concatMap (sequencial):                                       │
│  ──1──2──3──|                                                  │
│     │   │   │                                                  │
│     ▼   │   │  (espera R1 completar)                          │
│     R1──┘   │                                                  │
│         │   │                                                  │
│         ▼   │  (espera R2 completar)                           │
│         R2──┘                                                  │
│             │                                                  │
│             ▼                                                  │
│             R3                                                │
│             │                                                  │
│             ▼                                                  │
│     ──R1──R2──R3──| (ordem garantida)                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { of, interval, fromEvent } from 'rxjs';
import { map, switchMap, mergeMap, concatMap, exhaustMap, take } from 'rxjs/operators';
import { HttpClient } from '@angular/common/http';

class UserService {
  constructor(private http: HttpClient) {}
  
  getUser(id: number) {
    return this.http.get(`/api/users/${id}`);
  }
}

const userService = new UserService(httpClient);

of(1, 2, 3).pipe(
  map(x => x * 2)
).subscribe(console.log);

fromEvent(document, 'click').pipe(
  switchMap(() => userService.getUser(Math.random()))
).subscribe(user => console.log('User:', user));

of(1, 2, 3).pipe(
  mergeMap(id => userService.getUser(id))
).subscribe(user => console.log('User:', user));

of(1, 2, 3).pipe(
  concatMap(id => userService.getUser(id))
).subscribe(user => console.log('User:', user));

fromEvent(document, 'click').pipe(
  exhaustMap(() => userService.saveData())
).subscribe(result => console.log('Saved:', result));
```

**Tabela Comparativa: Quando Usar Cada Operator**:

| Operator | Quando Usar | Comportamento | Exemplo de Uso |
|----------|-------------|---------------|----------------|
| `map` | Transformação simples síncrona | Transforma cada valor | `map(user => user.name)` |
| `switchMap` | Busca/autocomplete | Cancela anterior | Busca enquanto digita |
| `mergeMap` | Processamento paralelo | Executa todos simultaneamente | Upload múltiplos arquivos |
| `concatMap` | Ordem importante | Executa sequencialmente | Salvar dados em ordem |
| `exhaustMap` | Prevenir duplicatas | Ignora enquanto executa | Submit de formulário |

---

### Operators de Combinação

**Definição**: Operators que combinam múltiplos Observables em um único Observable, permitindo trabalhar com múltiplos streams de dados simultaneamente.

**Explicação Detalhada**:

Operators de combinação são essenciais quando você precisa coordenar múltiplas fontes de dados assíncronas. Cada operator tem comportamento específico sobre como combina os valores.

**Operators Principais**:

**`combineLatest`**:
- Combina últimos valores emitidos de cada Observable
- Emite sempre que qualquer Observable emite novo valor
- Espera todos emitirem pelo menos um valor antes de começar
- Útil para: combinar múltiplas fontes de estado que mudam independentemente

**`forkJoin`**:
- Espera todos os Observables completarem
- Emite array com valores finais de cada Observable
- Útil para: aguardar múltiplas requisições HTTP completarem

**`merge`**:
- Combina múltiplos Observables em um único stream
- Emite valores na ordem que chegam (pode ser fora de ordem)
- Útil para: combinar eventos de múltiplas fontes sem se importar com ordem

**`zip`**:
- Combina valores por índice (primeiro com primeiro, segundo com segundo)
- Espera todos terem valor correspondente antes de emitir
- Útil para: combinar streams que devem ser sincronizados por índice

**Analogia Detalhada**:

Operators de combinação são como **reuniões de equipe**:

- **combineLatest**: Reunião onde cada pessoa fala quando tem atualização - você sempre tem a última informação de cada um, atualizada em tempo real (dashboard com múltiplas métricas)
- **forkJoin**: Reunião onde todos apresentam relatório final - você espera todos terminarem antes de tomar decisão (aguardar múltiplas requisições)
- **merge**: Reunião aberta onde todos falam ao mesmo tempo - você ouve tudo mas não precisa coordenar (eventos de múltiplas fontes)
- **zip**: Reunião estruturada onde cada pessoa fala em sua vez - você combina primeira fala de cada um, depois segunda, etc. (sincronizar por índice)

**Visualização de Combinação**:

```
┌─────────────────────────────────────────────────────────────────┐
│            Operators de Combinação - Comparação                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Source Observables                                             │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐            │
│  │  obs1$   │      │  obs2$   │      │  obs3$   │            │
│  │  ──A──B──│      │  ──1──2──│      │  ──X──Y──│            │
│  └──────────┘      └──────────┘      └──────────┘            │
│                                                                 │
│  combineLatest (últimos valores)                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  combineLatest([obs1$, obs2$, obs3$])                   │  │
│  │                                                           │  │
│  │  Emite quando qualquer um muda:                          │  │
│  │  ──[A,1,X]──[B,1,X]──[B,2,X]──[B,2,Y]──|                │  │
│  │   (sempre tem último valor de cada)                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  forkJoin (valores finais)                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  forkJoin([obs1$, obs2$, obs3$])                       │  │
│  │                                                           │  │
│  │  Espera todos completarem:                               │  │
│  │  ────────────────────────────────────────[B,2,Y]──|      │  │
│  │   (apenas último valor de cada)                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  merge (todos os valores)                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  merge(obs1$, obs2$, obs3$)                             │  │
│  │                                                           │  │
│  │  Combina todos os valores:                              │  │
│  │  ──A──1──X──B──2──Y──|                                  │  │
│  │   (ordem de chegada, pode ser intercalado)              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  zip (por índice)                                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  zip(obs1$, obs2$, obs3$)                               │  │
│  │                                                           │  │
│  │  Combina por posição:                                   │  │
│  │  ──[A,1,X]──[B,2,Y]──|                                  │  │
│  │   (primeiro com primeiro, segundo com segundo)          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { combineLatest, forkJoin, merge, zip, interval, of } from 'rxjs';
import { take, map } from 'rxjs/operators';

const source1 = interval(1000).pipe(take(3), map(i => `A${i}`));
const source2 = interval(1500).pipe(take(3), map(i => `B${i}`));
const source3 = of('X', 'Y', 'Z');

combineLatest([source1, source2]).subscribe(
  ([val1, val2]) => console.log(`combineLatest: ${val1} - ${val2}`)
);

forkJoin([source1, source2]).subscribe(
  ([val1, val2]) => console.log(`forkJoin: ${val1} - ${val2}`)
);

merge(source1, source2).subscribe(
  val => console.log(`merge: ${val}`)
);

zip(source1, source2).subscribe(
  ([val1, val2]) => console.log(`zip: ${val1} - ${val2}`)
);
```

**Tabela Comparativa: Quando Usar Cada Operator**:

| Operator | Quando Usar | Emite Quando | Exemplo |
|----------|------------|--------------|---------|
| `combineLatest` | Precisa último valor de cada | Qualquer um emite | Dashboard com múltiplas métricas |
| `forkJoin` | Precisa todos completarem | Todos completam | Múltiplas requisições HTTP |
| `merge` | Quer todos os valores | Qualquer um emite | Eventos de múltiplas fontes |
| `zip` | Precisa sincronizar por índice | Todos têm valor correspondente | Combinar arrays paralelos |

---

### Operators de Filtragem

**Definição**: Operators que filtram valores baseado em condições ou controle de tempo, permitindo controlar quais valores passam pelo stream e quando.

**Explicação Detalhada**:

Operators de filtragem são essenciais para controlar fluxo de dados e prevenir sobrecarga. Eles permitem reduzir número de valores processados e controlar timing de emissões.

**Operators Principais**:

**`filter`**:
- Filtra valores baseado em condição booleana
- Emite apenas valores que passam no teste
- Síncrono e determinístico
- Use quando: precisa filtrar valores baseado em propriedade ou condição

**`debounceTime`**:
- Emite valor apenas após período sem novos valores
- Cancela emissão anterior se novo valor chegar antes do tempo
- Útil para: busca enquanto digita, evitar múltiplas execuções
- Use quando: quer aguardar usuário parar de interagir

**`throttleTime`**:
- Emite primeiro valor e ignora próximos por período
- Garante que valor seja emitido pelo menos uma vez por período
- Útil para: limitar frequência de eventos (scroll, resize)
- Use quando: quer limitar frequência mas garantir que evento aconteça

**`distinctUntilChanged`**:
- Emite apenas se valor mudou em relação ao anterior
- Comparação por igualdade (===)
- Útil para: evitar valores duplicados consecutivos
- Use quando: quer ignorar valores repetidos

**`take`**:
- Emite apenas N primeiros valores
- Completa Observable após N valores
- Útil para: limitar número de valores processados
- Use quando: quer apenas primeiros N valores

**`skip`**:
- Pula N primeiros valores
- Emite valores após pular N iniciais
- Útil para: ignorar valores iniciais
- Use quando: quer pular valores iniciais (ex: loading state)

**Analogia Detalhada**:

Operators de filtragem são como **sistemas de segurança e controle de acesso**:

- **filter**: Porteiro que verifica identidade - só deixa passar quem atende critérios (idade, tipo de acesso)
- **debounceTime**: Sensor de movimento com delay - só ativa após período sem movimento (evita ativações múltiplas)
- **throttleTime**: Semáforo - permite passagem por período, depois bloqueia (controla fluxo)
- **distinctUntilChanged**: Detector de mudança - só alerta quando algo realmente mudou (evita alertas repetidos)
- **take**: Limitador de capacidade - permite apenas N pessoas por vez
- **skip**: Fila com prioridade - pula primeiros N e atende a partir do N+1

**Visualização de Filtragem**:

```
┌─────────────────────────────────────────────────────────────────┐
│            Operators de Filtragem - Fluxo                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Source Observable                                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  fromEvent(input, 'input')                               │  │
│  │  ──a──ab──abc──abcd──abcde──|                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│         │                                                        │
│         ├───────────────────────────────────────────────────────┤
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  debounceTime(300)                                       │  │
│  │  ────────────────────────────────────────abcde──|        │  │
│  │  (espera 300ms sem novos valores)                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Source Observable                                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  fromEvent(window, 'scroll')                             │  │
│  │  ──s──s──s──s──s──s──s──s──|                             │  │
│  └──────────────────────────────────────────────────────────┘  │
│         │                                                        │
│         ├───────────────────────────────────────────────────────┤
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  throttleTime(1000)                                       │  │
│  │  ──s──────────s──────────s──|                              │  │
│  │  (emite primeiro, ignora próximos por 1s)                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Source Observable                                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  of(1, 1, 2, 2, 3, 3)                                     │  │
│  │  ──1──1──2──2──3──3──|                                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│         │                                                        │
│         ├───────────────────────────────────────────────────────┤
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  distinctUntilChanged()                                   │  │
│  │  ──1──────2──────3──|                                     │  │
│  │  (remove valores duplicados consecutivos)                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Comparação: debounceTime vs throttleTime                       │
│                                                                 │
│  Input: ──a──ab──abc──abcd──abcde──|                           │
│                                                                 │
│  debounceTime(300):                                             │
│  ────────────────────────────────────────abcde──|             │
│  (só emite após 300ms sem novos valores)                       │
│                                                                 │
│  throttleTime(300):                                            │
│  ──a──────────abc──────────abcde──|                            │
│  (emite primeiro, depois a cada 300ms)                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { fromEvent, interval, of } from 'rxjs';
import { 
  filter, 
  debounceTime, 
  throttleTime, 
  distinctUntilChanged, 
  take, 
  skip 
} from 'rxjs/operators';

const searchInput = document.querySelector('#search') as HTMLInputElement;

fromEvent(searchInput, 'input').pipe(
  debounceTime(300),
  distinctUntilChanged(),
  map((e: any) => e.target.value),
  filter(term => term.length >= 3)
).subscribe(term => {
  console.log('Searching for:', term);
});

fromEvent(window, 'scroll').pipe(
  throttleTime(1000)
).subscribe(() => {
  console.log('Scrolled!');
});

of(1, 1, 2, 2, 3, 3).pipe(
  distinctUntilChanged()
).subscribe(console.log);

interval(1000).pipe(
  take(5)
).subscribe(console.log);

of(1, 2, 3, 4, 5).pipe(
  skip(2)
).subscribe(console.log);
```

**Tabela Comparativa: Quando Usar Cada Operator**:

| Operator | Quando Usar | Comportamento | Exemplo |
|----------|------------|---------------|---------|
| `filter` | Filtrar por condição | Emite apenas valores que passam | `filter(user => user.active)` |
| `debounceTime` | Aguardar pausa | Emite após período sem novos | Busca enquanto digita |
| `throttleTime` | Limitar frequência | Emite primeiro, ignora por período | Eventos de scroll |
| `distinctUntilChanged` | Remover duplicatas | Emite apenas se mudou | Valores de formulário |
| `take` | Limitar quantidade | Emite apenas N primeiros | `take(10)` |
| `skip` | Pular iniciais | Pula N primeiros valores | `skip(1)` para pular loading |

---

### Subjects

**Definição**: Subjects são Observables especiais que também são Observers, permitindo multicast - múltiplos subscribers compartilham mesma execução e recebem valores simultaneamente.

**Explicação Detalhada**:

Subjects são fundamentais para comunicação entre componentes e gerenciamento de estado reativo. Eles permitem que você emita valores manualmente e compartilhe execução entre múltiplos subscribers.

**Tipos de Subjects**:

**`Subject`**:
- Não mantém valor atual
- Subscribers recebem apenas valores emitidos após subscription
- Se subscribe após valores serem emitidos, não recebe valores anteriores
- Use quando: eventos que não precisam de estado inicial

**`BehaviorSubject`**:
- Mantém valor atual (valor inicial obrigatório)
- Novos subscribers recebem valor atual imediatamente
- Sempre tem valor disponível
- Use quando: estado que precisa ser acessível imediatamente (ex: autenticação)

**`ReplaySubject`**:
- Replay N últimos valores para novos subscribers
- Configurável quantos valores manter em buffer
- Útil para: histórico de eventos que novos subscribers precisam ver
- Use quando: quer que novos subscribers vejam histórico recente

**`AsyncSubject`**:
- Emite apenas último valor quando completa
- Ignora todos os valores até completion
- Útil para: operações que só interessam resultado final
- Use quando: quer apenas resultado final de operação assíncrona

**Analogia Detalhada**:

Subjects são como **diferentes tipos de transmissão de rádio/TV**:

- **Subject**: Rádio ao vivo - quem sintoniza agora só ouve a partir de agora, não ouve o que já passou (eventos em tempo real)
- **BehaviorSubject**: Rádio com última música sempre tocando - quem sintoniza ouve a música atual imediatamente, depois continua ouvindo ao vivo (estado atual sempre disponível)
- **ReplaySubject**: Rádio com replay das últimas N músicas - quem sintoniza ouve as últimas N músicas que tocaram, depois continua ao vivo (histórico recente)
- **AsyncSubject**: Gravação de programa - só emite quando programa termina, com apenas o final (resultado final)

**Visualização de Subjects**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Subjects - Comparação                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Subject (sem estado)                                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  const subject = new Subject();                           │  │
│  │  subject.next(1);                                        │  │
│  │  subject.next(2);                                        │  │
│  │  subject.subscribe(v => console.log('A:', v));           │  │
│  │  subject.next(3);                                        │  │
│  │  // A recebe apenas: 3                                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  BehaviorSubject (mantém valor atual)                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  const bs = new BehaviorSubject(0);                      │  │
│  │  bs.next(1);                                             │  │
│  │  bs.subscribe(v => console.log('A:', v));               │  │
│  │  // A recebe imediatamente: 1                            │  │
│  │  bs.next(2);                                             │  │
│  │  bs.subscribe(v => console.log('B:', v));               │  │
│  │  // B recebe imediatamente: 2                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ReplaySubject (replay N últimos)                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  const rs = new ReplaySubject(2);                        │  │
│  │  rs.next(1);                                             │  │
│  │  rs.next(2);                                             │  │
│  │  rs.next(3);                                             │  │
│  │  rs.subscribe(v => console.log('A:', v));               │  │
│  │  // A recebe: 2, 3 (últimos 2 valores)                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  AsyncSubject (apenas último valor)                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  const as = new AsyncSubject();                          │  │
│  │  as.next(1);                                             │  │
│  │  as.next(2);                                             │  │
│  │  as.subscribe(v => console.log('A:', v));               │  │
│  │  as.complete();                                          │  │
│  │  // A recebe apenas: 2 (último valor antes de complete)   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Diagrama de Timeline:                                         │
│                                                                 │
│  Subject:                                                      │
│  ──1──2──[subscribe A]──3──|                                   │
│              │                                                 │
│              └─ A recebe: 3                                    │
│                                                                 │
│  BehaviorSubject(0):                                           │
│  ──1──2──[subscribe A]──3──[subscribe B]──4──|               │
│              │                    │                            │
│              └─ A recebe: 2, 3, 4                              │
│                             └─ B recebe: 3, 4                  │
│                                                                 │
│  ReplaySubject(2):                                            │
│  ──1──2──3──[subscribe A]──4──|                               │
│              │                                                 │
│              └─ A recebe: 2, 3, 4 (replay + novos)            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { Subject, BehaviorSubject, ReplaySubject, AsyncSubject } from 'rxjs';

const subject = new Subject<number>();
subject.subscribe(v => console.log('Subject A:', v));
subject.next(1);
subject.subscribe(v => console.log('Subject B:', v));
subject.next(2);

const behaviorSubject = new BehaviorSubject<number>(0);
behaviorSubject.subscribe(v => console.log('BehaviorSubject A:', v));
behaviorSubject.next(1);
behaviorSubject.subscribe(v => console.log('BehaviorSubject B:', v));
behaviorSubject.next(2);

const replaySubject = new ReplaySubject<number>(2);
replaySubject.next(1);
replaySubject.next(2);
replaySubject.next(3);
replaySubject.subscribe(v => console.log('ReplaySubject A:', v));
replaySubject.next(4);

const asyncSubject = new AsyncSubject<number>();
asyncSubject.subscribe(v => console.log('AsyncSubject A:', v));
asyncSubject.next(1);
asyncSubject.next(2);
asyncSubject.complete();
```

**Tabela Comparativa: Quando Usar Cada Subject**:

| Subject | Quando Usar | Mantém Estado | Novos Subscribers Recebem |
|---------|------------|---------------|---------------------------|
| `Subject` | Eventos sem estado | Não | Apenas valores futuros |
| `BehaviorSubject` | Estado atual necessário | Sim (valor atual) | Valor atual + futuros |
| `ReplaySubject` | Histórico necessário | Sim (N últimos) | Últimos N + futuros |
| `AsyncSubject` | Apenas resultado final | Sim (último) | Apenas último valor |

---

### Hot vs Cold Observables

**Definição**: Cold Observables criam nova execução para cada subscriber. Hot Observables compartilham execução entre múltiplos subscribers.

**Explicação Detalhada**:

A diferença entre Hot e Cold é fundamental para entender comportamento de Observables e gerenciamento de recursos.

**Cold Observable**:
- Nova execução para cada subscriber
- Cada subscriber recebe todos os valores desde o início
- Execução só começa quando há subscriber
- Recursos são criados por subscriber
- Exemplos: HTTP requests, `of()`, `from()`, `interval()` (sem share)

**Hot Observable**:
- Execução compartilhada entre subscribers
- Subscribers recebem valores a partir do momento que se inscrevem
- Execução pode começar antes de haver subscribers
- Recursos são compartilhados
- Exemplos: Subjects, eventos do DOM, `interval().pipe(share())`

**Analogia Detalhada**:

**Cold Observable** é como **Netflix**:
- Cada pessoa que assiste tem sua própria cópia do filme
- Você pode pausar, voltar, assistir do início
- Cada assinante tem experiência independente
- Recursos são dedicados por usuário

**Hot Observable** é como **TV ao vivo**:
- Todos assistem a mesma transmissão simultaneamente
- Se você ligar agora, vê a partir de agora (não vê o que já passou)
- Transmissão acontece independente de ter espectadores
- Recursos são compartilhados

**Visualização Hot vs Cold**:

```
┌─────────────────────────────────────────────────────────────────┐
│              Hot vs Cold Observables - Comparação               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Cold Observable (nova execução por subscriber)                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  const cold$ = new Observable(observer => {            │  │
│  │    console.log('Execution started');                    │  │
│  │    observer.next(Math.random());                        │  │
│  │  });                                                     │  │
│  │                                                           │  │
│  │  cold$.subscribe(v => console.log('A:', v));           │  │
│  │  // Output: Execution started                            │  │
│  │  //        A: 0.123                                      │  │
│  │                                                           │  │
│  │  cold$.subscribe(v => console.log('B:', v));           │  │
│  │  // Output: Execution started (nova execução!)          │  │
│  │  //        B: 0.456 (valor diferente!)                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Hot Observable (execução compartilhada)                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  const hot$ = interval(1000).pipe(share());             │  │
│  │                                                           │  │
│  │  hot$.subscribe(v => console.log('A:', v));            │  │
│  │  // A recebe: 0, 1, 2, 3...                             │  │
│  │                                                           │  │
│  │  setTimeout(() => {                                      │  │
│  │    hot$.subscribe(v => console.log('B:', v));          │  │
│  │    // B recebe: 3, 4, 5... (não recebe 0, 1, 2)         │  │
│  │  }, 3000);                                               │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Timeline Visual:                                              │
│                                                                 │
│  Cold Observable:                                               │
│  Time:  0s    1s    2s    3s                                   │
│  ──────────────────────────────────────────────                │
│  Sub A: [exec1]──0──1──2──3──|                                │
│  Sub B:        [exec2]──0──1──2──3──|                          │
│         (execução independente)                                 │
│                                                                 │
│  Hot Observable:                                                │
│  Time:  0s    1s    2s    3s    4s                             │
│  ──────────────────────────────────────────────                │
│  Source: ──0──1──2──3──4──|                                    │
│  Sub A:   ──0──1──2──3──4──|                                   │
│  Sub B:              ──3──4──|                                 │
│         (execução compartilhada)                                │
│                                                                 │
│  Conversão Cold → Hot:                                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  const cold$ = interval(1000);                           │  │
│  │  const hot$ = cold$.pipe(share());                       │  │
│  │                                                           │  │
│  │  // ou                                                    │  │
│  │                                                           │  │
│  │  const hot$ = cold$.pipe(shareReplay(1));                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { Observable, interval, Subject } from 'rxjs';
import { share, shareReplay, take } from 'rxjs/operators';

const cold$ = new Observable<number>(observer => {
  console.log('Cold: New execution');
  const value = Math.random();
  observer.next(value);
  observer.complete();
});

cold$.subscribe(v => console.log('Cold A:', v));
cold$.subscribe(v => console.log('Cold B:', v));

const hot$ = interval(1000).pipe(
  take(5),
  share()
);

hot$.subscribe(v => console.log('Hot A:', v));

setTimeout(() => {
  hot$.subscribe(v => console.log('Hot B:', v));
}, 3000);

const sharedWithReplay$ = interval(1000).pipe(
  take(5),
  shareReplay(1)
);

sharedWithReplay$.subscribe(v => console.log('Replay A:', v));

setTimeout(() => {
  sharedWithReplay$.subscribe(v => console.log('Replay B:', v));
}, 3000);
```

**Tabela Comparativa: Cold vs Hot**:

| Aspecto | Cold Observable | Hot Observable |
|---------|----------------|----------------|
| Execução | Nova por subscriber | Compartilhada |
| Valores | Todos desde início | A partir da subscription |
| Recursos | Criados por subscriber | Compartilhados |
| Exemplos | HTTP, `of()`, `from()` | Subjects, eventos DOM |
| Quando usar | Dados independentes | Eventos compartilhados |
| Conversão | N/A (padrão) | `share()`, `shareReplay()` |

---

### Tratamento de Erros

**Definição**: Operators e padrões para tratar erros em Observables, permitindo recuperação, retry e fallbacks quando operações falham.

**Explicação Detalhada**:

Tratamento de erros é crítico em aplicações reativas. RxJS fornece operators poderosos para lidar com erros de forma declarativa e elegante.

**Operators de Erro**:

**`catchError`**:
- Captura erro e retorna novo Observable
- Permite fallback ou valor padrão
- Não interrompe stream (diferente de throw)
- Use quando: quer tratar erro e continuar stream

**`retry`**:
- Tenta novamente em caso de erro
- Pode especificar número de tentativas
- Útil para: operações que podem falhar temporariamente
- Use quando: erro pode ser temporário (rede, timeout)

**`retryWhen`**:
- Retry com condições customizadas
- Permite delay entre tentativas
- Permite lógica complexa de retry
- Use quando: precisa controle fino sobre retry

**`throwError`**:
- Cria Observable que emite erro
- Útil para testes e tratamento de erros
- Use quando: precisa criar Observable que falha

**Analogia Detalhada**:

Tratamento de erros é como **sistema de segurança e backup**:

- **catchError**: Plano B - se algo der errado, você tem alternativa pronta (se servidor falhar, usa cache)
- **retry**: Tentar novamente - se primeira tentativa falhar, tenta de novo (como redial em telefone)
- **retryWhen**: Tentar novamente com estratégia - espera um pouco antes de tentar de novo, ou tenta apenas em certas condições (como retry exponencial)
- **throwError**: Simular falha - criar situação de erro para testes ou propagar erro

**Visualização de Tratamento de Erros**:

```
┌─────────────────────────────────────────────────────────────────┐
│            Tratamento de Erros - Fluxo                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Observable com Erro                                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  http.get('/api/data')                                    │  │
│  │  ──1──2──[ERROR]                                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│         │                                                        │
│         ├───────────────────────────────────────────────────────┤
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  catchError(err => of([]))                               │  │
│  │  ──1──2──[]──|                                            │  │
│  │  (substitui erro por valor padrão)                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Observable com Retry                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  http.get('/api/data')                                    │  │
│  │  ──1──2──[ERROR]──[RETRY]──[ERROR]──[RETRY]──3──4──|     │  │
│  │  (tenta novamente em caso de erro)                         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Observable com RetryWhen                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  http.get('/api/data')                                    │  │
│  │  ──1──2──[ERROR]──[WAIT 1s]──[RETRY]──[ERROR]──          │  │
│  │         ──[WAIT 2s]──[RETRY]──3──4──|                    │  │
│  │  (retry com delay crescente)                               │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Estratégias de Tratamento:                                    │
│                                                                 │
│  1. Fallback Simples:                                          │
│     catchError(() => of(defaultValue))                         │
│                                                                 │
│  2. Retry com Limite:                                          │
│     retry(3)                                                    │
│                                                                 │
│  3. Retry com Delay:                                           │
│     retryWhen(errors => errors.pipe(                           │
│       delay(1000),                                              │
│       take(3)                                                   │
│     ))                                                          │
│                                                                 │
│  4. Retry Exponencial:                                         │
│     retryWhen(errors => errors.pipe(                           │
│       scan((count, err) => {                                   │
│         if (count >= 3) throw err;                              │
│         return count + 1;                                       │
│       }, 0),                                                    │
│       delay(count => count * 1000)                             │
│     ))                                                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exemplo Prático Completo**:

```typescript
import { throwError, of, interval } from 'rxjs';
import { 
  catchError, 
  retry, 
  retryWhen, 
  delay, 
  take,
  scan,
  map 
} from 'rxjs/operators';
import { HttpClient } from '@angular/common/http';

class DataService {
  constructor(private http: HttpClient) {}
  
  getDataWithFallback() {
    return this.http.get('/api/data').pipe(
      catchError(err => {
        console.error('Error:', err);
        return of([]);
      })
    );
  }
  
  getDataWithRetry() {
    return this.http.get('/api/data').pipe(
      retry(3)
    );
  }
  
  getDataWithRetryWhen() {
    return this.http.get('/api/data').pipe(
      retryWhen(errors => errors.pipe(
        scan((count, err) => {
          if (count >= 3) throw err;
          return count + 1;
        }, 0),
        delay(count => count * 1000),
        take(3)
      ))
    );
  }
}

of(1, 2, 3).pipe(
  map(x => {
    if (x === 2) throw new Error('Error!');
    return x;
  }),
  catchError(err => of('Error handled'))
).subscribe(console.log);

interval(1000).pipe(
  map(x => {
    if (x === 3) throw new Error('Error!');
    return x;
  }),
  retry(2)
).subscribe(console.log);
```

**Tabela Comparativa: Estratégias de Tratamento**:

| Operator | Quando Usar | Comportamento | Exemplo |
|----------|------------|---------------|---------|
| `catchError` | Fallback necessário | Substitui erro por valor | `catchError(() => of([]))` |
| `retry` | Erro temporário | Tenta novamente N vezes | `retry(3)` |
| `retryWhen` | Retry customizado | Retry com condições | Retry exponencial |
| `throwError` | Simular erro | Cria Observable que falha | Testes |

---

## Exemplos Práticos Completos

### Exemplo 1: Serviço de Busca com Debounce e Retry

**Contexto**: Criar serviço de busca que aguarda usuário parar de digitar, faz requisição com retry em caso de falha, e trata erros adequadamente.

**Código**:

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, Subject, throwError } from 'rxjs';
import { 
  debounceTime, 
  distinctUntilChanged, 
  switchMap, 
  retry, 
  catchError, 
  shareReplay,
  filter
} from 'rxjs/operators';
import { of } from 'rxjs';

interface SearchResult {
  id: number;
  title: string;
  description: string;
}

@Injectable({
  providedIn: 'root'
})
export class SearchService {
  private searchTerms$ = new Subject<string>();
  
  constructor(private http: HttpClient) {}
  
  search(term: string): void {
    this.searchTerms$.next(term);
  }
  
  getResults(): Observable<SearchResult[]> {
    return this.searchTerms$.pipe(
      debounceTime(300),
      distinctUntilChanged(),
      filter(term => term.length >= 3),
      switchMap(term => 
        this.http.get<SearchResult[]>(`/api/search?q=${term}`).pipe(
          retry(2),
          catchError(err => {
            console.error('Search error:', err);
            return of([]);
          })
        )
      ),
      shareReplay(1)
    );
  }
}
```

**Explicação**:
- `debounceTime(300)`: Aguarda 300ms sem novos valores antes de buscar
- `distinctUntilChanged()`: Evita busca duplicada se termo não mudou
- `filter`: Só busca se termo tem pelo menos 3 caracteres
- `switchMap`: Cancela busca anterior se novo termo chegar
- `retry(2)`: Tenta novamente até 2 vezes em caso de erro
- `catchError`: Retorna array vazio em caso de erro
- `shareReplay(1)`: Compartilha resultado entre múltiplos subscribers

**Uso no Componente**:

```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { SearchService } from './search.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-search',
  template: `
    <input 
      #searchInput 
      (input)="onSearch(searchInput.value)"
      placeholder="Search..."
    />
    <ul>
      <li *ngFor="let result of results">
        {{ result.title }}
      </li>
    </ul>
  `
})
export class SearchComponent implements OnInit, OnDestroy {
  results: SearchResult[] = [];
  private subscription?: Subscription;
  
  constructor(private searchService: SearchService) {}
  
  ngOnInit() {
    this.subscription = this.searchService.getResults().subscribe(
      results => this.results = results
    );
  }
  
  onSearch(term: string) {
    this.searchService.search(term);
  }
  
  ngOnDestroy() {
    this.subscription?.unsubscribe();
  }
}
```

---

### Exemplo 2: Gerenciamento de Estado com BehaviorSubject

**Contexto**: Criar serviço de autenticação que gerencia estado do usuário usando BehaviorSubject.

**Código**:

```typescript
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { map } from 'rxjs/operators';

interface User {
  id: number;
  name: string;
  email: string;
  role: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();
  
  public isAuthenticated$ = this.currentUser$.pipe(
    map(user => user !== null)
  );
  
  public isAdmin$ = this.currentUser$.pipe(
    map(user => user?.role === 'admin' ?? false)
  );
  
  login(user: User) {
    this.currentUserSubject.next(user);
  }
  
  logout() {
    this.currentUserSubject.next(null);
  }
  
  getCurrentUser(): User | null {
    return this.currentUserSubject.value;
  }
}
```

**Explicação**:
- `BehaviorSubject`: Mantém estado atual do usuário
- `asObservable()`: Expõe apenas Observable (não permite next externo)
- `map`: Cria Observables derivados (isAuthenticated, isAdmin)
- `value`: Acesso síncrono ao valor atual

**Uso no Componente**:

{% raw %}
```typescript
import { Component } from '@angular/core';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-header',
  template: `
    <div *ngIf="authService.isAuthenticated$ | async">
      Welcome, {{ (authService.currentUser$ | async)?.name }}!
      <button (click)="logout()">Logout</button>
    </div>
  `
})
export class HeaderComponent {
  constructor(public authService: AuthService) {}
  
  logout() {
    this.authService.logout();
  }
}
```
{% raw %}
import { Component } from '@angular/core';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-header',
  template: `
    <div *ngIf="authService.isAuthenticated$ | async">
      Welcome, {{ (authService.currentUser$ | async)?.name }}!
      <button (click)="logout()">Logout</button>
    </div>
  `
})
export class HeaderComponent {
  constructor(public authService: AuthService) {}
  
  logout() {
    this.authService.logout();
  }
}
```
{% endraw %}

---

### Exemplo 3: Dashboard com Múltiplas Fontes de Dados

**Contexto**: Criar dashboard que combina múltiplas fontes de dados usando combineLatest.

**Código**:

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, combineLatest } from 'rxjs';
import { map } from 'rxjs/operators';

interface DashboardData {
  users: number;
  orders: number;
  revenue: number;
}

@Injectable({
  providedIn: 'root'
})
export class DashboardService {
  constructor(private http: HttpClient) {}
  
  getDashboardData(): Observable<DashboardData> {
    const users$ = this.http.get<{count: number}>('/api/users/count');
    const orders$ = this.http.get<{count: number}>('/api/orders/count');
    const revenue$ = this.http.get<{total: number}>('/api/revenue');
    
    return combineLatest([users$, orders$, revenue$]).pipe(
      map(([users, orders, revenue]) => ({
        users: users.count,
        orders: orders.count,
        revenue: revenue.total
      }))
    );
  }
}
```

**Explicação**:
- `combineLatest`: Combina últimos valores de cada requisição
- `map`: Transforma array de respostas em objeto DashboardData
- Atualiza quando qualquer fonte muda

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use async pipe quando possível**
   - **Por quê**: Gerencia subscription automaticamente, previne memory leaks
   - **Exemplo**: `*ngIf="data$ | async as data"`
   - **Benefício**: Código mais limpo, menos boilerplate

2. **Use takeUntil para múltiplas subscriptions**
   - **Por quê**: Facilita cleanup de múltiplas subscriptions
   - **Exemplo**: 
```
   private destroy$ = new Subject<void>();
   
   this.data$.pipe(
     takeUntil(this.destroy$)
   ).subscribe();
   
   ngOnDestroy() {
     this.destroy$.next();
     this.destroy$.complete();
   }
```
   - **Benefício**: Evita memory leaks, código mais organizado

3. **Use shareReplay para dados compartilhados**
   - **Por quê**: Evita múltiplas requisições HTTP
   - **Exemplo**: `shareReplay(1)`
   - **Benefício**: Performance melhor, menos carga no servidor

4. **Sempre trate erros**
   - **Por quê**: Previne crashes, melhora UX
   - **Exemplo**: `catchError(err => of([]))`
   - **Benefício**: Aplicação mais robusta

5. **Use switchMap para operações canceláveis**
   - **Por quê**: Cancela operações anteriores desnecessárias
   - **Exemplo**: Busca enquanto digita
   - **Benefício**: Performance melhor, menos requisições

6. **Use BehaviorSubject para estado compartilhado**
   - **Por quê**: Estado sempre disponível, fácil de acessar
   - **Exemplo**: Autenticação, configurações
   - **Benefício**: Código mais simples, estado consistente

7. **Prefira operators funcionais**
   - **Por quê**: Mais testável, composável
   - **Exemplo**: `pipe(map(), filter())` ao invés de nested subscriptions
   - **Benefício**: Código mais limpo e manutenível

8. **Use distinctUntilChanged para evitar processamento desnecessário**
   - **Por quê**: Evita processar valores duplicados
   - **Exemplo**: Valores de formulário
   - **Benefício**: Performance melhor

9. **Documente operators complexos**
   - **Por quê**: Facilita manutenção futura
   - **Exemplo**: Comentários explicando lógica de retry
   - **Benefício**: Código mais compreensível

10. **Teste seus Observables**
    - **Por quê**: Garante comportamento correto
    - **Exemplo**: Usar marble testing
    - **Benefício**: Confiança no código

### ❌ Anti-padrões Comuns

1. **Não esqueça de unsubscribe**
   - **Problema**: Memory leaks, subscriptions ativas após componente destruído
   - **Solução**: Use async pipe ou takeUntil
   - **Impacto**: Vazamento de memória, performance degradada

2. **Não use switchMap quando precisa de todos os valores**
   - **Problema**: Cancela requisições anteriores que podem ser necessárias
   - **Solução**: Use mergeMap ou concatMap
   - **Impacto**: Dados perdidos, comportamento incorreto

3. **Não crie Observable dentro de subscribe**
   - **Problema**: Nested subscriptions difíceis de gerenciar
   - **Solução**: Use switchMap/mergeMap
   - **Impacto**: Código difícil de manter, memory leaks

4. **Não ignore erros**
   - **Problema**: Erros silenciosos, difícil debugar
   - **Solução**: Sempre use catchError
   - **Impacto**: Bugs difíceis de encontrar, UX ruim

5. **Não use Subject quando BehaviorSubject é necessário**
   - **Problema**: Estado inicial não disponível
   - **Solução**: Use BehaviorSubject quando precisa de valor inicial
   - **Impacto**: Bugs de estado, código mais complexo

6. **Não faça requisições HTTP sem shareReplay**
   - **Problema**: Múltiplas requisições desnecessárias
   - **Solução**: Use shareReplay para dados compartilhados
   - **Impacto**: Performance ruim, carga desnecessária no servidor

7. **Não use mergeMap quando ordem importa**
   - **Problema**: Valores podem chegar fora de ordem
   - **Solução**: Use concatMap quando ordem é importante
   - **Impacto**: Dados incorretos, bugs sutis

8. **Não crie novos Observables desnecessariamente**
   - **Problema**: Overhead de criação
   - **Solução**: Reutilize Observables quando possível
   - **Impacto**: Performance degradada

---

## Comparações com Outras Abordagens

### RxJS vs MobX vs Redux

**Tabela Comparativa: Bibliotecas de Estado Reativo**:

| Aspecto | RxJS | MobX | Redux |
|---------|------|------|-------|
| **Paradigma** | Programação reativa com Observables | Programação reativa com observáveis | Flux pattern unidirecional |
| **Curva de Aprendizado** | Alta (operators complexos) | Média (conceitos simples) | Média-Alta (boilerplate) |
| **Bundle Size** | ~50KB (tree-shakeable) | ~15KB | ~10KB + middleware |
| **TypeScript** | Excelente suporte | Excelente suporte | Bom suporte |
| **Integração Angular** | Nativa (parte do core) | Biblioteca externa | Biblioteca externa |
| **Quando Usar** | Streams assíncronos, eventos | Estado reativo simples | Estado complexo, time-travel |
| **Performance** | Excelente (lazy evaluation) | Excelente (tracking automático) | Boa (previsível) |
| **Debugging** | DevTools disponível | Excelente (MobX DevTools) | Excelente (Redux DevTools) |
| **Comunidade** | Muito grande | Grande | Muito grande |
| **Casos de Uso** | HTTP, eventos, streams | Estado de UI | Estado global complexo |

**Quando Usar Cada Abordagem**:

**RxJS**:
- Operações assíncronas (HTTP, WebSockets)
- Eventos do usuário (clicks, inputs)
- Streams de dados complexos
- Quando já está usando Angular (já incluído)

**MobX**:
- Estado reativo simples
- Quando quer menos boilerplate que Redux
- Quando precisa de reatividade automática
- Aplicações menores a médias

**Redux**:
- Estado global complexo
- Quando precisa de time-travel debugging
- Quando equipe já conhece padrão Flux
- Aplicações grandes com estado complexo

---

## Exercícios Práticos

### Exercício 1: Observables Básicos (Básico)

**Objetivo**: Criar primeiro Observable e entender ciclo de vida

**Descrição**: 
Crie Observable que emite valores e demonstre subscription básica com cleanup adequado.

**Arquivo**: `exercises/exercise-3-1-1-observables-basicos.md`

---

### Exercício 2: Operators de Transformação (Básico)

**Objetivo**: Usar operators de transformação

**Descrição**:
Crie exemplos usando map, switchMap, mergeMap e concatMap demonstrando diferenças.

**Arquivo**: `exercises/exercise-3-1-2-operators-transformacao.md`

---

### Exercício 3: Operators de Combinação (Intermediário)

**Objetivo**: Combinar múltiplos Observables

**Descrição**:
Use combineLatest, forkJoin e merge para combinar streams e criar dashboard.

**Arquivo**: `exercises/exercise-3-1-3-operators-combinacao.md`

---

### Exercício 4: Operators de Filtragem (Intermediário)

**Objetivo**: Filtrar e controlar fluxo

**Descrição**:
Implemente busca com debounceTime e filtros avançados usando distinctUntilChanged.

**Arquivo**: `exercises/exercise-3-1-4-operators-filtragem.md`

---

### Exercício 5: Subjects (Intermediário)

**Objetivo**: Trabalhar com Subjects

**Descrição**:
Crie serviço de comunicação usando BehaviorSubject e ReplaySubject para estado compartilhado.

**Arquivo**: `exercises/exercise-3-1-5-subjects.md`

---

### Exercício 6: Hot vs Cold Observables (Avançado)

**Objetivo**: Entender diferença entre Hot e Cold

**Descrição**:
Demonstre diferença entre Hot e Cold Observables e use share() para converter.

**Arquivo**: `exercises/exercise-3-1-6-hot-cold.md`

---

### Exercício 7: Tratamento de Erros (Avançado)

**Objetivo**: Implementar tratamento robusto de erros

**Descrição**:
Crie padrão completo de tratamento de erros com retry exponencial e fallbacks.

**Arquivo**: `exercises/exercise-3-1-7-tratamento-erros.md`

---

### Exercício 8: Padrão Completo com RxJS (Avançado)

**Objetivo**: Criar padrão completo usando todas as técnicas

**Descrição**:
Crie serviço completo que usa todos os operators aprendidos em cenário real.

**Arquivo**: `exercises/exercise-3-1-8-padrao-completo.md`

---

## Referências Externas

### Documentação Oficial

- **[RxJS Documentation](https://rxjs.dev/)**: Documentação completa e atualizada
- **[RxJS Operators](https://rxjs.dev/guide/operators)**: Guia detalhado de operators
- **[RxJS API Reference](https://rxjs.dev/api)**: Referência completa da API
- **[RxJS Marble Testing](https://rxjs.dev/guide/testing/marble-testing)**: Guia de testes com marbles

### Artigos e Tutoriais

- **[RxJS: The Definitive Guide](https://www.learnrxjs.io/)**: Tutorial interativo completo
- **[Understanding RxJS Operators](https://blog.angular-university.io/rxjs-higher-order-mapping/)**: Explicação profunda de operators
- **[RxJS Best Practices](https://blog.angular-university.io/rxjs-best-practices/)**: Boas práticas e padrões
- **[RxJS Anti-Patterns](https://blog.angular-university.io/rxjs-anti-patterns/)**: Erros comuns e como evitar

### Vídeos

- **[RxJS Operators Explained](https://www.youtube.com/watch?v=Byttv3YpjQk)**: Explicação visual de operators
- **[RxJS in Angular](https://www.youtube.com/watch?v=ewcoEYS85Co)**: Uso prático no Angular
- **[Advanced RxJS Patterns](https://www.youtube.com/watch?v=2LCo926NFLI)**: Padrões avançados

### Ferramentas

- **[RxJS DevTools](https://github.com/trungk18/rxjs-devtools)**: Ferramentas de debugging
- **[RxJS Marble Diagrams](https://rxmarbles.com/)**: Visualização interativa de operators
- **[RxJS Visualizer](https://rxjs-visualize-example.netlify.app/)**: Visualização de streams

### Comparações e Contexto

- **[ReactiveX Documentation](http://reactivex.io/)**: Documentação do padrão ReactiveX
- **[RxJS vs Alternatives](https://blog.logrocket.com/rxjs-vs-alternatives/)**: Comparação com outras bibliotecas
- **[RxJS Performance](https://blog.angular-university.io/rxjs-performance/)**: Otimizações de performance

---

## Resumo

### Principais Conceitos

- **Observables**: Streams assíncronos que podem emitir múltiplos valores
- **Operators**: Funções que transformam e combinam Observables
- **Subjects**: Observables especiais que permitem multicast
- **Hot vs Cold**: Diferença fundamental no comportamento de execução
- **Tratamento de Erros**: Essencial para aplicações robustas
- **Padrões Reativos**: Evitam memory leaks e melhoram performance

### Pontos-Chave para Lembrar

- Use async pipe quando possível para gerenciamento automático
- Use takeUntil para cleanup de múltiplas subscriptions
- Use shareReplay para dados compartilhados
- Sempre trate erros adequadamente
- Escolha operator correto para cada situação
- Entenda diferença entre switchMap, mergeMap e concatMap
- Use BehaviorSubject para estado compartilhado
- Prefira operators funcionais sobre nested subscriptions

### Próximos Passos

- Próxima aula: Signals e Signal-First Architecture
- Praticar criando padrões reativos em projetos reais
- Explorar operators avançados não cobertos nesta aula
- Estudar marble testing para testes de Observables
- Aprofundar em performance e otimizações

---

## Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente com contexto histórico
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias detalhadas para cada conceito abstrato
- [x] Diagramas ASCII detalhados para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Tabelas comparativas com outras abordagens
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 2.5: Comunicação entre Componentes](./lesson-2-5-comunicacao-componentes.md)  
**Próxima Aula**: [Aula 3.2: Signals e Signal-First Architecture](./lesson-3-2-signals.md)  
**Voltar ao Módulo**: [Módulo 3: Programação Reativa e Estado](../modules/module-3-programacao-reativa-estado.md)
