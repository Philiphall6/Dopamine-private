# libarchive / CVE-2026-112522 — diagnostic iOS V5

Cette application est un banc de validation isolé pour iPhone14,2 sous iOS
26.0.1. Elle n'utilise pas Dopamine, ClearSword, Titan, IOKit, SPTM/PAPT ou
une primitive noyau.

Le dyld cache exact 23A355 exporte les symboles utilisés par le pont :
`archive_read_new`, `archive_read_support_filter_all`,
`archive_read_support_format_iso9660`, `archive_read_open_filename`,
`archive_read_next_header`, `archive_read_data_skip`, `archive_read_free`,
`archive_error_string`, `archive_format_name`, `archive_entry_pathname_utf8` et
`archive_entry_size`. Les mêmes exports sont présents dans le composant
27.0.1 24A446. L'application vérifie leur présence à l'exécution et retourne
`LIBARCHIVE_UNAVAILABLE` sans poursuivre si l'interface n'est pas disponible.

## Ce que l'application fait

- charge explicitement `/usr/lib/libarchive.2.dylib` avec `dlopen` ;
- active le lecteur ISO9660 de libarchive ;
- traite une ISO9660/Joliet normale embarquée comme contrôle ;
- permet de choisir manuellement un fichier ISO depuis Fichiers ;
- n'intègre aucun fichier malformé et n'en génère aucun ;
- limite chaque empreinte SHA-256 à un seul essai manuel dans une installation ;
- écrit un journal JSONL avant, pendant et après l'appel à libarchive ;
- conserve les chemins retournés par libarchive dans une capacité bornée et
  calcule leur longueur UTF-16BE ;
- conserve un marqueur `TEST_INTERRUPTED` avant le traitement manuel afin de
  corréler une fermeture avec un éventuel rapport `.ips`.

Le contrôle normal est `CONTROL_ARCHIVE_PASS`. Les classifications observées
par le pont sont `ARCHIVE_FORMAT_RECOGNIZED`,
`JOLIET_ENTRIES_OBSERVED`, `LONG_PATH_CONTROL_PASS` ou
`ARCHIVE_REJECTED`. L'application journalise toujours
`RUNTIME_FUNCTION_INVOCATION_NOT_PROVEN` : une API publique libarchive ne
permet pas d'attribuer une instruction interne précise à un chemin retourné.
Une simple absence de réponse ne constitue jamais un crash confirmé.

## Contrôles V5

Le générateur déterministe est `generate_v5_controls.py`. Il produit trois
ISO structurellement valides dans `Resources/v5-controls/` :

| Fichier | Objet | Octets UTF-16BE maximum | SHA-256 |
| --- | --- | ---: | --- |
| `V5-A-simple.iso` | contrôle simple | 24 | `6f763d448d0088fd2940e673a1f8e0f5582627f54516b74ca5ac2d7af6894ae8` |
| `V5-B-multilevel.iso` | plusieurs niveaux | 64 | `6a3123b3d8b959bd7edb594ca139f0f174c4bc8e57a29883c614e7b5bf166dd5` |
| `V5-C-long-safe-path.iso` | chemin long sous 1024 octets | 976 | `7f5bbd6f5873184b342c9cfc0c2eec62ca33b9ced3dcaa1e9707423ea0ed012b` |

La vérification hors ligne est sans dépendance Python externe :

```text
python3 generate_v5_controls.py
python3 verify_v5_controls.py
```

Elle vérifie les PVD/SVD, les tables de chemins little/big-endian, les
enregistrements de répertoire, le padding ISO9660, l'encodage Joliet, les
extents et les chemins attendus. `isovfy` est utilisé lorsqu'il est installé ;
son absence est signalée comme `isovfy_available=false`, jamais transformée en
succès silencieux.

## Compilation

Ouvrir `Libarchive-112522-Diagnostic.xcodeproj` avec Xcode 26.x et compiler la
cible `Libarchive-112522-Diagnostic` pour un iPhone. Le projet utilise
`IPHONEOS_DEPLOYMENT_TARGET=16.1` et `SDKROOT=iphoneos`.

Le workflow `.github/workflows/libarchive-112522-diagnostic.yml` effectue une
compilation non signée avec le SDK iPhoneOS installé par Xcode. Il ne lance
aucun fichier de test.

## Procédure manuelle

1. Installer l'application signée sur l'iPhone de test.
2. Lancer **Contrôle ISO normal** et vérifier `CONTROL_ARCHIVE_PASS`.
3. Exporter les journaux si le contrôle échoue.
4. Transférer `V5-A-simple.iso`, puis utiliser **Choisir un ISO (manuel)** et
   confirmer une seule fois.
5. Recommencer séparément avec `V5-B-multilevel.iso`, puis
   `V5-C-long-safe-path.iso`. Chaque fichier a une tentative manuelle par
   empreinte dans cette installation ; aucune relance automatique n'est
   effectuée après une fermeture.
6. Récupérer d'abord le journal et le rapport système avant toute autre action.

Les journaux sont dans le conteneur de l'application :

```text
Documents/CVE-2026-112522.jsonl
Documents/CVE-2026-112522.state
```

## Récupération des rapports `.ips`

Les rapports système peuvent être récupérés via Réglages → Confidentialité et
sécurité → Analyse et améliorations → Données d'analyse, Xcode Devices and
Simulators ou Console.app avec l'iPhone connecté.

Le script `classify_crash.py` est hors ligne :

```text
python3 classify_crash.py --ips /chemin/rapport.ips \
  --log /chemin/CVE-2026-112522.jsonl
```

Un rapport n'est attribué à libarchive que s'il contient une référence de
module ou de pile correspondante. Le marqueur `TEST_INTERRUPTED` seul ne suffit
pas.

## Limites

Un résultat `LONG_PATH_CONTROL_PASS` démontre seulement qu'un chemin Joliet
long, mais valide et sous la limite de contrôle, a été retourné par libarchive.
Il ne prouve pas l'appel de `_build_pathname_utf16be`, une corruption mémoire,
une exécution de code arbitraire, une lecture/écriture noyau, une écriture
physique ou un contournement SPTM/PAPT. Un crash attribué à libarchive doit
être confirmé par un rapport `.ips` et par sa pile d'appels.
