# Holehe Custom GUI (OSINT Workbench)

Interface graphique (CustomTkinter) pour exécuter **Holehe** dans un cadre d’investigation plus structuré : import de wordlists, transparence sur les domaines ignorés, sauvegarde de dossiers (cases), exports et rapports.

> ⚠️ Utilisation responsable : n’exécute ce projet **que sur des comptes/adresses e‑mail pour lesquels tu as une autorisation explicite** (audit interne, test, consentement, mandat, etc.).

## Fonctionnalités

- **GUI** (CustomTkinter) pour lancer les vérifications Holehe
- **Import de wordlist** (`.txt` / `.rtf`) + inspection et diagnostics (lignes invalides/dupliquées/ignorées)
- **Exports** : résultats JSON, rapports HTML, diff entre runs, export métadonnées des pièces jointes (JSON/CSV)
- **Dossiers d’enquête** : sauvegarde/chargement d’un “case”, historique des exécutions, pièces jointes
- **Mode SAFE** (timeouts courts, périmètre limité, no password recovery)
- **Résilience** : retries, circuit breaker
- **Cache** des runs (évite de relancer la même analyse)
- **PDF (optionnel)** : export PDF si `reportlab` est installé, sinon fallback texte

## Prérequis

- macOS/Linux/Windows
- Python 3.12+ recommandé (3.14 fonctionne aussi selon l’environnement)

## Installation (venv)

Depuis la racine du dépôt :

```bash
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
pip install -U pip

# Dépendances GUI
pip install customtkinter

# Installer Holehe (version “vendored” dans ce dépôt)
pip install -e ./holehe
```

Optionnel (export PDF) :

```bash
pip install reportlab
```

## Lancer l’application

```bash
python gui_holehe.py
```

## Usage (résumé)

1. Renseigne l’e‑mail cible (autorisé)
2. (Optionnel) Choisis un fichier `.txt/.rtf` (wordlist)
3. Lance l’analyse
4. Filtre/tri via le dashboard, exporte un rapport (HTML/PDF) ou un diff entre runs

## Structure du dépôt

- `gui_holehe.py` : l’interface “OSINT Workbench”
- `holehe/` : code de Holehe (upstream) + nos adaptations côté `holehe/holehe/core.py`
- `investigations/` : données locales (cases, logs, cache, runs). Ignoré par git par défaut.

## Notes importantes

- Les wordlists contiennent souvent beaucoup d’entrées **non mappables** aux modules Holehe. L’outil d’inspection explique clairement ce qui est ignoré et pourquoi.
- Si tu vois un cache “bizarre” après une mise à jour, supprime `investigations/cache/`.

## Licence

- Le code “workbench” de ce dépôt est sous licence MIT (voir `LICENSE`).
- Le dossier `holehe/` contient un projet tiers sous licence **GPLv3** (voir `holehe/LICENSE.md`).

> Si tu redistribues ce dépôt/modifications, vérifie l’impact des licences (MIT + GPLv3) selon ton mode de distribution.
