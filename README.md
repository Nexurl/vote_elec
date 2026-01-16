# Vote électonique par Gaston PLOT

Ce dépôt est le résultat mon implémentation du système de vote selon le sujet de  [TD vote électronique](TD_vote_électronique_2025.pdf)

## Installation des packages

Créer un dossier ``.venv`` avec la commande :

```
python -m venv .venv
```

Activez l'environnement virtuel en exécutant un script d'activation adapté à votre OS:  
Windows -> activate.bat ou Activate.ps1  
Linux -> activate.sh

Les venv ont récemment changé, ces fichiers d'activation peuvent se situer dans ``.venv/bin`` ou ``.venv/Scripts`` si vous avez une version plus récente.

Installez ensuite les dépendances avec :

```
pip install flask
```

Vous pouvez ensuite exécuter le script ``app.py`` se situant à la racine du dépôt (avec le python exécutable du venv qui sera utilisé quand le script d'activation est exécuté)

## Désactivation du venv

Pensez bien à exécuter le script de désactivation pour retourner à votre état initial.  
Windows -> deactivate.bat  
Linux -> deactivate.sh