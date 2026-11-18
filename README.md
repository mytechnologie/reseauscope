# ReseauScope

**Utilitaire Windows d'inventaire et de diagnostic réseau** pour installateurs de
caméras, contrôle d'accès, alarme et domotique. Scanne un réseau, identifie les
équipements par leur fabricant (adresse MAC / OUI) et par leurs ports ouverts, et
regroupe tout dans un tableau filtrable et exportable.

Conçu pour un usage quotidien sur vos réseaux et ceux de vos clients (avec
autorisation). Fonctionne **sans droits administrateur**.

## Fonctions

| Onglet | Description |
|--------|-------------|
| **Scan réseau** | Détecte les hôtes actifs (ICMP, ARP, sondage TCP pour les équipements qui bloquent le ping), résout les noms (DNS / NetBIOS / mDNS), relève la MAC et le fabricant, scanne les ports clés et **classe chaque équipement** : caméra/NVR, contrôle d'accès, alarme, interphone, domotique, réseau, NAS, imprimante, ordinateur. Filtrage par type, code couleur, export CSV / HTML / JSON. |
| **Scan de ports** | Scan complet d'un hôte avec préréglages (caméras, accès/alarme, domotique, réseau, Windows) et lecture des bannières HTTP/HTTPS/RTSP (titre de page, serveur, certificat). |
| **Ping** | Ping continu avec graphe de latence, taux de perte, min/moy/max. |
| **Traceroute** | Traceroute ICMP natif (sans droits admin). |
| **Outils** | Interfaces locales, calculateur de sous-réseau, recherche de fabricant par MAC, Wake-on-LAN, mise à jour de la base IEEE et préfixes MAC personnalisés. |

## Identification des équipements

L'identification combine trois signaux :

1. **Fabricant MAC (OUI)** — base IEEE de ~35 000 fabricants embarquée, avec des
   règles pour les marques de sécurité (Hikvision, Dahua, Axis, Hanwha, HID,
   Mercury, Suprema, ZKTeco, Paxton, Paradox, DSC, Ajax, Bosch, 2N, Akuvox,
   Ubiquiti, Cisco, MikroTik…).
2. **Ports ouverts** — p. ex. 554 (RTSP → caméra), 37777 (Dahua), 34567 (DVR),
   4370 (ZKTeco contrôle d'accès), 4025 (EnvisaLink alarme), 8123 (Home Assistant).
3. **Noms d'hôte et bannières web** — mots-clés dans le nom NetBIOS/DNS ou le titre
   de l'interface web.

Vous pouvez enrichir la base avec vos propres préfixes (parc client) via le fichier
personnalisé accessible depuis l'onglet Outils.

## Construire l'exécutable Windows

### Automatique (recommandé) — GitHub Actions

À chaque `push` sur `main`, ou en lançant manuellement le workflow
**Build Windows EXE**, GitHub compile `ReseauScope.exe` et le publie comme
artefact téléchargeable. Un tag `vX.Y.Z` crée en plus une *release* avec l'exe joint.

### Manuel — sur une machine Windows

```bat
python -m pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm reseauscope.spec
```

L'exécutable est produit dans `dist\ReseauScope.exe` (un seul fichier, sans console).

## Lancer depuis les sources

```bash
pip install -r requirements.txt
python run.py
```

## Usage et responsabilité

Destiné à l'analyse de réseaux dont vous êtes responsable ou pour lesquels vous
disposez d'une autorisation. L'analyse de réseaux tiers sans autorisation peut être
illégale. Vous êtes seul responsable de l'usage de ce logiciel.
