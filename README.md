# 🛡️ ProcWatch

Monitor de processos em tempo real baseado em eventos do Sysmon, com foco em detecção de comportamento suspeito.

---

## Visão geral

O ProcWatch acompanha a criação de processos no Windows e aplica regras heurísticas para identificar possíveis atividades maliciosas.

A ideia é simples: observar o que está rodando, entender o contexto e atribuir risco.

---

## Como funciona

* Se inscreve no log do Sysmon (`Microsoft-Windows-Sysmon/Operational`)
* Captura eventos em tempo real
* Converte XML → estrutura manipulável
* Analisa eventos de criação de processos
* Aplica regras de detecção
* Gera um score de risco
* Registra tudo em um relatório

---

## O que ele analisa

### Execução de ferramentas suspeitas

Detecta uso de binários comuns em ataques (ex: shells, ferramentas de rede, etc).

### Command-line

Identifica flags associadas a comportamento ofensivo:

* execução remota
* download de payload
* abertura de portas

### Usuário

Verifica se o processo foi iniciado por grupos privilegiados.

### Relação pai-filho

Detecta cadeias anômalas, tipo:

```
winword.exe → powershell.exe
```

---

## Risk score

Cada evento recebe uma pontuação baseada no contexto:

* **1–3** → incomum
* **4–6** → suspeito
* **7–9** → malicioso
* **10+** → indicativo de ataque

---

## Saída

Os eventos relevantes são registrados em `report.md`, com:

* Informações do processo
* Motivos da detecção
* Classificação de risco

---

## Estrutura de regras

O comportamento do sistema é controlado por JSONs:

* `programs.json` → executáveis relevantes
* `flags.json` → argumentos suspeitos
* `parents.json` → relações anômalas
* `users_and_groups.json` → grupos privilegiados

---

## Stack

* Python
* Sysmon
* win32evtlog
* xmltodict

---

## Execução

```bash
python procwatch.py
```

---

## Objetivo

Projeto de estudo focado em:

* detecção comportamental
* análise de processos
* lógica de SOC
* visão prática de defesa
