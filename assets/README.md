# Estrutura de Assets

Esta pasta contém todos os assets (vídeos, imagens, infográficos) organizados por módulo.

## Estrutura

```
assets/
├── module-1/
│   ├── videos/              # Vídeos das aulas e exercícios do módulo 1
│   └── images/
│       ├── infograficos/    # Infográficos das aulas do módulo 1
│       └── podcasts/       # Imagens de podcasts do módulo 1
├── module-2/
│   ├── videos/              # Vídeos das aulas e exercícios do módulo 2
│   └── images/
│       ├── infograficos/    # Infográficos das aulas do módulo 2
│       └── podcasts/       # Imagens de podcasts do módulo 2
├── module-3/
│   ├── videos/              # Vídeos das aulas e exercícios do módulo 3
│   └── images/
│       ├── infograficos/    # Infográficos das aulas do módulo 3
│       └── podcasts/       # Imagens de podcasts do módulo 3
├── module-4/
│   ├── videos/              # Vídeos das aulas e exercícios do módulo 4
│   └── images/
│       ├── infograficos/    # Infográficos das aulas do módulo 4
│       └── podcasts/       # Imagens de podcasts do módulo 4
└── shared/
    └── images/              # Imagens compartilhadas (logo, infográficos gerais)
```

## Convenções de Nomenclatura

### Vídeos
- Aulas: `{numero-aula}-{titulo}.mp4` (ex: `1.1-Introducao_Seguranca_QA.mp4`)
- Exercícios: `Exercicios_{titulo}-{lesson-id}-exercises-intro.mp4`

### Infográficos
- Aulas: `infografico-lesson-{numero-aula}.png` (ex: `infografico-lesson-1-1.png`)
- Módulos: `infografico-introducao-modulo-{numero}.png`

### Podcasts
- `{numero-aula}-{titulo}.png` (ex: `2.1-SAST_Testes_Estaticos.png`)

## Como Adicionar Novos Assets

1. Identifique o módulo ao qual o asset pertence
2. Coloque o arquivo na pasta apropriada:
   - Vídeos → `assets/module-{N}/videos/`
   - Infográficos → `assets/module-{N}/images/infograficos/`
   - Podcasts → `assets/module-{N}/images/podcasts/`
3. Use a convenção de nomenclatura apropriada
4. Atualize as referências nos arquivos markdown correspondentes

## Assets Compartilhados

Assets que são usados em múltiplos módulos ou na página inicial devem ser colocados em `assets/shared/images/`.
