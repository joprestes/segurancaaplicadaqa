# ⚠️ Problemas de Conteúdo Identificados

Este arquivo documenta problemas de conteúdo encontrados durante a auditoria estrutural.

## 🚨 Conteúdo de Tema Incorreto

As seguintes aulas contêm conteúdo sobre **Angular** quando deveriam ser sobre **Segurança em QA**:

### Módulo 2: Testes de Segurança na Prática

- **lesson-2-1.md**: Contém conteúdo sobre "Serviços e Injeção de Dependência no Angular"
  - **Deveria ser**: "SAST: Static Application Security Testing"
  - **Arquivos de mídia incorretos**: 
    - `assets/podcasts/02.1-Servicos_e_Injecao_de_Dependencia_no_Angular.m4a`
    - `assets/videos/02.1-Serviços_e_Injeção_de_Dependência_no_Angular.mp4`

- **lesson-2-2.md**: Contém conteúdo sobre "Roteamento e Navegação Avançada no Angular"
  - **Deveria ser**: "DAST: Dynamic Application Security Testing"
  - **Arquivos de mídia incorretos**: 
    - `assets/podcasts/02.2-SilencioRouter_Guards_Resolvers_Lazy_Loading.m4a`
    - `assets/videos/02.2-SilencioRouter_Guards_Resolvers_Lazy_Loading.mp4`

- **lesson-2-3.md**: Contém conteúdo sobre "Formulários Reativos do Angular"
  - **Deveria ser**: "Testes de Penetração (Pentest) Básico"
  - **Arquivos de mídia incorretos**: 
    - `assets/podcasts/02.3-Dominando_os_Formularios_Reativos_do_Angular.m4a`
    - `assets/videos/02.3-Dominando_os_Formulários_Reativos_do_Angular.mp4`

- **lesson-2-4.md**: Contém conteúdo sobre "HTTP Client e Interceptors no Angular"
  - **Deveria ser**: "Automação de Testes de Segurança"
  - **Arquivos de mídia incorretos**: 
    - `assets/podcasts/02.4-HttpClient_e_Interceptors_no_Angular.m4a`
    - `assets/videos/02.4-HttpClient_e_Interceptors_no_Angular.mp4`

### Módulo 3: Segurança por Setor

- **lesson-3-2.md**: Contém conteúdo sobre "Angular Signals"
  - **Deveria ser**: "Segurança no Setor Educacional"
  - **Arquivos de mídia incorretos**: 
    - `assets/podcasts/03.2-Angular_Signals_O_Guia_Completo_e_Pratico.m4a`
    - `assets/videos/03.2-Angular_Signals__O_Guia_Completo_e_Prático.mp4`

- **lesson-3-5.md**: Contém conteúdo sobre "Integração Signals + Observables no Angular"
  - **Deveria ser**: "APIs e Microserviços: Segurança Distribuída"
  - **Arquivos de mídia incorretos**: 
    - `assets/podcasts/03.5-toSignal_e_toObservable_as_pontes_do_Angular.m4a`
    - `assets/videos/03.5-toSignal_e_toObservable_as_pontes_do_Angular.mp4`

## 📋 Ações Necessárias

1. **Reescrever conteúdo** das aulas listadas acima com conteúdo apropriado sobre Segurança em QA
2. **Remover ou substituir** arquivos de mídia (podcasts/vídeos) sobre Angular
3. **Atualizar front matter** dos arquivos `.md` para refletir o conteúdo correto
4. **Verificar** se há outros arquivos com conteúdo incorreto

## 📝 Nota

Os arquivos de mídia sobre Angular em `assets/videos/` e `assets/podcasts/` devem ser removidos ou movidos para outro repositório se pertencerem a outro projeto.
