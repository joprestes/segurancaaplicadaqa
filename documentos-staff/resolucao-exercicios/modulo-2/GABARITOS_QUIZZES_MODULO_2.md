# Gabaritos dos Quizzes - Módulo 2

Este documento consolida os gabaritos dos quizzes do Módulo 2. As respostas foram extraídas de `_data/quizzes.yml`.

---

## Aula 2.1 - SAST

1. q1 - C) Teste de segurança que analisa código-fonte sem executar a aplicação  
2. q2 - D) SAST analisa código estático, DAST analisa aplicação em execução  
3. q3 - A) Semgrep  
4. q4 - B) Taint Analysis  
5. q5 - D) SAST reporta vulnerabilidade que não existe na prática  
6. q6 - A) SAST: $50-200, Produção: $50,000-500,000+ (250-10,000x mais caro em produção)  
7. q7 - C) Critérios de qualidade que bloqueiam merge se não passarem (ex: 0 Critical vulnerabilities)  
8. q8 - D) Criar baseline (aceitar tudo que existe hoje) e focar apenas em novas vulnerabilities  
9. q9 - B) Bandit  
10. q10 - A) Priorizar por risco real: Critical + Em produção + Dados sensíveis = P1 (IMEDIATO), considerar contexto de negócio  

---

## Aula 2.2 - DAST

1. q1 - C) Teste de segurança que analisa aplicação em execução, simulando ataques reais  
2. q2 - A) Active Scanning envia payloads maliciosos e testa vulnerabilidades, Passive Scanning apenas observa tráfego sem atacar  
3. q3 - D) OWASP ZAP  
4. q4 - C) 60-80% das vulnerabilidades estão em áreas autenticadas que scans não-autenticados não conseguem ver  
5. q5 - A) Usuário consegue acessar dados de outros usuários via manipulação de IDs. DAST testa tentando acessar objetos de outros usuários  
6. q6 - B) DAST: 5-10%, SAST: 20-40%  
7. q7 - D) Active Scanning envia payloads maliciosos que podem danificar dados, causar DoS, gerar logs de ataque e comprometer estado da aplicação  
8. q8 - A) Baseline scan rápido em MRs (10-15 min), Full scan noturno (scan completo), Pre-production scan antes de deploy  
9. q9 - C) BOLA (Broken Object Level Authorization) - permite acesso a contas de outros usuários  
10. q10 - B) SAST em cada commit (shift-left) → DAST Baseline em cada MR → DAST Full Scan noturno → DAST Pre-Production antes de deploy → Pentest manual trimestral  

---

## Aula 2.3 - Pentest Básico

1. q1 - C) Pentest combina ferramentas automatizadas com análise manual criativa e pensamento como atacante, encontrando falhas que scanners não detectam  
2. q2 - A) OWASP Testing Guide  
3. q3 - D) Reconhecimento Passivo (OSINT)  
4. q4 - A) Porque não completa o TCP handshake (envia SYN, recebe SYN-ACK, mas não envia ACK final), deixando menos rastros  
5. q5 - C) Black Box (sem informações), Gray Box (credenciais de user), White Box (acesso completo + código-fonte)  
6. q6 - D) Meterpreter roda na memória (não toca disco), suporta pivoting, extensões dinâmicas, keystroke logging e é mais difícil de detectar  
7. q7 - A) Usuário consegue acessar recursos de outros usuários modificando IDs na URL/API. Exploração acessar /api/users/123 com token de user 456  
8. q8 - B) Binários com SUID rodam com privilégios do dono (geralmente root). Se exploráveis (ex find, vim, nmap), permitem executar comandos como root  
9. q9 - C) Executivo (para C-level/gestão) foca em impacto ao negócio e prioridades. Técnico (para dev/ops) tem steps to reproduce e recomendações detalhadas  
10. q10 - A) CVSS dá severidade técnica, mas contexto de negócio deve ajustar prioridade (XSS em checkout vale mais que XSS em admin interno)  

---

## Aula 2.4 - Automação de Testes de Segurança

1. q1 - A) Automação detecta vulnerabilidades conhecidas rapidamente (CVE, padrões), mas não substitui pensamento criativo humano para falhas de lógica e 0-days  
2. q2 - C) Porque com deploys múltiplos por dia, é impossível executar testes manuais antes de cada deploy. Automação permite shift-left e feedback contínuo  
3. q3 - D) SAST, SCA, Secret Scanning, IaC Security, Container Security - testes repetitivos com padrões conhecidos  
4. q4 - A) Porque cada aplicação tem lógica de negócio única. Ferramentas não sabem o que é comportamento esperado. Requer entendimento profundo do fluxo  
5. q5 - C) Detectar vulnerabilidades o mais cedo possível no ciclo de desenvolvimento (IDE, commit, MR), não apenas em produção  
6. q6 - D) Quality Gates bloqueiam build/deploy se vulnerabilidades críticas são encontradas, impedindo código inseguro em produção  
7. q7 - A) 60-80% do código moderno é dependências de terceiros. Novas CVEs são publicadas diariamente. SCA detecta dependências vulneráveis antes de merge  
8. q8 - C) Detectar automaticamente credenciais hardcoded (API keys, passwords, tokens) em código antes de commit. Credenciais vazadas = comprometimento imediato  
9. q9 - A) Baseline scan passivo em cada MR (10-15 min), Full scan noturno (completo), Pre-production scan final antes de deploy  
10. q10 - D) Configurar baselines, tuning de ferramentas, validar findings manualmente, implementar feedback loop (marcar false positives para refinar regras)  

---

## Aula 2.5 - Dependency Scanning e SCA

1. q1 - A) Análise automatizada de dependências de terceiros (libraries, packages) para detectar CVEs, licenças incompatíveis, dependências desatualizadas e malware  
2. q2 - C) Porque a maior parte do código (dependencies) não foi escrita pela equipe. Cada dependência é vetor de ataque potencial. Equifax breach: $1.4B por dependência não atualizada  
3. q3 - D) Dependência das suas dependências (você usa A, A usa B, B tem CVE). Você não sabe que B existe mas está vulnerável. SCA detecta toda a árvore  
4. q4 - C) 147 milhões de pessoas expostas, $1.4 bilhões em custos. Causa: Apache Struts não patcheado (CVE conhecida há 2 meses). SCA automatizado teria detectado  
5. q5 - C) Inventário completo de todas as dependências e versões na aplicação. Essencial para resposta a incidentes (Log4Shell: saber em 5 min se você usa log4j). Exigido por governo dos EUA  
6. q6 - D) Atacantes comprometem packages legítimos (typosquatting, malware, maintainer account takeover). SCA com malware detection e behavioral analysis detecta anomalias  
7. q7 - A) Usar dependência GPL em software proprietário pode custar milhões em processos. SCA mapeia todas as licenças e alerta sobre incompatibilidades  
8. q8 - C) Fixar versões exatas (package.json "1.2.3" vs "^1.2.3"). Evita breaking changes inesperados mas você não recebe security patches automaticamente  
9. q9 - D) Scan a cada commit (fast feedback), Quality Gate bloqueando merges com Critical/High CVEs, Daily full scan, Pre-production scan final  
10. q10 - A) 1) Verificar se CVE é exploitável no seu contexto, 2) Procurar dependência alternativa, 3) Isolar componente vulnerável, 4) Implementar WAF rules, 5) Monitorar para patch  
