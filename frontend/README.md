# CYBERMORPH — interface SOC

React 19 + TypeScript + Vite 8, scène 3D avec three.js / React Three Fiber.
Voir le [README du projet](../README.md) pour le démarrage, la configuration et la sécurité.

```
src/
  api/          client REST unique (URL relatives) et types du backend
  state/        store minimal, flux temps réel /ws/live, état d'interface partagé avec la scène
  scene/        jumeau 3D : disposition (pure, testée), nœuds, liaisons, tracés, caméra
  components/   coque (navigation, barre d'état), inspecteur d'actif, primitives d'interface
  views/        Jumeau, Alertes, Incidents, Chemins, ATT&CK, Historique, Simulations
  styles/       jetons de design et feuille de style
tests/          tests unitaires (tsc + node --test)
```
