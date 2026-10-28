# Comparaison IPSW iOS 26.0.1 / iOS 27.0.1 sur iPhone14,2

Date : 2026-10-28
Cible : iPhone 13 Pro, modèle `iPhone14,2`, Apple A15
Objet : déterminer si les familles de vulnérabilités recensées par `duper-cves` sont propres à iOS 27 ou déjà présentes dans iOS 26.0.1.

## Conclusion

Les vulnérabilités ne sont pas exclusivement propres à iOS 27.

La comparaison des IPSW exacts démontre déjà deux familles de défauts présentes dans les deux versions :

1. ImageIO, chemin de décodage PDF avec multiplication de dimensions sans contrôle de capacité équivalent au correctif ultérieur.
2. `libarchive`, chemin Joliet/UTF-16 qui effectue des écritures avant le contrôle de capacité.

Cela ne permet pas d'étendre automatiquement toutes les CVE listées par `duper-cves` à iOS 26.0.1. La plupart des autres lignes ont été localisées par un diff iOS 27.0 RC → iOS 27.2 RC sur un autre modèle, et restent donc `UNKNOWN` pour 23A355 tant que la fonction correspondante n'a pas été comparée dans le kernelcache ou le dyld cache 26.

Cette analyse est statique. Aucun PoC n'a été exécuté sur l'iPhone et aucune capacité de jailbreak, d'écriture physique ou de contournement SPTM n'en découle.

## Corpus vérifié

| Version | Modèle | Build | IPSW SHA-256 |
| --- | --- | --- | --- |
| iOS 26.0.1 | iPhone14,2 | 23A355 | `5e2eaf57b3507f175969c1ee6faf35c2d6d10db6ded1f5cbe32bf89af3c5f8a3` |
| iOS 27.0.1 | iPhone14,2 | 24A446 | `84b70a15d9c1aee8f5830aefdcb4fc13dbdced3dde7289355d7598bdd13fb830` |

Les IPSW ont été extraits puis les dyld shared caches et kernelcaches ont été inspectés. Le kernelcache 26 extrait a le SHA-256 `8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`, identique à celui utilisé pour l'analyse V17. Le kernelcache 27 extrait a le SHA-256 `d99b7719ad4b367db264a7682806aecaf6e0621c6761d07325a58337319d4238`.

Versions de composants utiles :

| Composant | iOS 26.0.1 | iOS 27.0.1 |
| --- | --- | --- |
| ImageIO | `2773.0.1.2.0` | `2851.0.0.0.0` |
| `libarchive.2.dylib` | `158.0.0.0.0` | `182.0.1.0.0` |
| CoreMedia | `3255.79.1.8.0` | `3350.77.1.6.0` |
| libFontParser | `435.0.0.1.0` | `459.0.0.0.0` |
| libusd_ms | `23.1.31.0.0` | `24.1.30.0.0` |

## Preuves instructionnelles

### ImageIO : décodage PDF

Dans le binaire ImageIO exact de 26.0.1, `PDFReadPlugin::decodeImageData` se trouve à `0x185f36998`. Le chemin de calcul comprend :

```text
0x185f36a84: umull x1, w24, w23
```

Dans ImageIO 27.0.1, la même famille se trouve à `0x187aabf88` et comprend également :

```text
0x187aac074: umull x1, w24, w23
```

Le correctif documenté dans l'analyse iOS 27.2 ajoute une comparaison de la taille calculée avec la capacité de sortie avant le traitement. Cette barrière n'est pas présente dans le chemin correspondant des deux IPSW comparés.

**Verdict : présence dans 26.0.1 et 27.0.1 démontrée statiquement.** Le rattachement à un numéro CVE individuel reste une attribution par famille de correctif ; le dépôt public ne constitue pas une base Apple officielle de correspondance CVE/fonction.

### ImageIO : allocations TIFF

Le cache ImageIO 26.0.1 contient le symbole `__TIFFCheckMalloc`. Le cache 27.0.1 contient `__TIFFCheckMalloc_type`, associé à la nouvelle logique d'allocation vérifiée identifiée dans les travaux 27.2.

Cette différence indique que la branche 26 utilise une infrastructure plus ancienne. Elle constitue une indication forte pour la famille d'allocation TIFF, mais la présence ou l'absence d'un symbole ne suffit pas à prouver le comportement de chaque site d'allocation.

**Verdict : famille TIFF probablement concernée dès 26.0.1 ; preuve fonctionnelle site par site encore requise.**

### libarchive : chemin Joliet/UTF-16

Dans `libarchive.2.dylib` 26.0.1, `_build_pathname_utf16be` effectue des écritures avant le contrôle de longueur :

```text
add  x8, x8, x9
strb wzr, [x8]
strb w8, [x9]
...
contrôle de capacité seulement ensuite
```

Le même ordre d'opérations est présent dans la fonction correspondante de `libarchive.2.dylib` 27.0.1. L'analyse publique indique que le correctif 27.2 déplace le contrôle avant ces écritures.

**Verdict : famille Joliet/UTF-16 présente dans 26.0.1 et 27.0.1.**

### CoreMedia : Dolby Vision RPU

La fonction `_hevcbridgeParseVdrDmDataPayloadExMetadatatBlocks` est présente dans les deux caches :

```text
iOS 26.0.1 : 0x196c7277c
iOS 27.0.1 : 0x18eed3198
```

L'analyse publique identifie trois contrôles de compte ajoutés dans la branche 27.2. La présence de la fonction dans iOS 26.0.1 ne suffit cependant pas à prouver que les trois mêmes défauts existent dans cette version : le parser a changé de génération et doit être comparé instruction par instruction.

**Verdict : chemin présent dans les deux versions ; vulnérabilité 26.0.1 non démontrée.**

## Matrice de compatibilité des groupes `duper-cves`

| Groupe | CVE(s) listées par le dépôt | 26.0.1 exact | 27.0.1 exact | État |
| --- | --- | --- | --- | --- |
| ImageIO PDF/TIFF | 112633, 112614, 112488 et autres | PDF confirmé ; TIFF fortement indiqué | Familles présentes | `CONFIRMED_OVERLAP` |
| ImageIO JPEG/GPS/APNG/textures | 112634, 112629, 112561, 112627, 112632, 112630, 112571, 112625 | Non établi site par site | Localisé par l'analyse 27.0→27.2 | `UNKNOWN_26` |
| libarchive Joliet | 112522 | Confirmé | Confirmé | `CONFIRMED_OVERLAP` |
| libarchive LZX/vImage/ColorSync | 112621, 86971, 86988 | Non établi | Partiellement localisé | `UNKNOWN_26` |
| AudioToolbox | 112546, 113912, 113907, 86972, 86969 | Anciennes fonctions présentes, défaut non prouvé | Familles localisées en 27 | `UNKNOWN_26` |
| CoreMedia Dolby Vision | 112688 | Fonction présente, défaut non prouvé | Famille localisée en 27 | `UNKNOWN_26` |
| FontParser/CoreText | 112683, 86970, 112642, 112656 | Non établi pour ces CVE | Familles localisées en 27 | `UNKNOWN_26` |
| ModelIO/USD | 112565, 112449, 112413, 112485, 112461, 112486 | Non établi | `libusd_ms` 27.0 localisé | `UNKNOWN_26` |
| SceneKit | 112425, 112423, 112464, 86991 | Non établi | Localisé dans l'analyse 27 | `UNKNOWN_26` |
| IOHIDFamily | 112515 | Kernel non comparé au niveau instructionnel | Analyse publique sur un autre modèle | `NOT_ESTABLISHED` |
| USB | 112479 | Kernel non comparé au niveau instructionnel | Analyse publique sur un autre modèle | `NOT_ESTABLISHED` |
| AppleFSCompression | 113910 | Kernel non comparé au niveau instructionnel | Analyse publique sur kernelcache 27 | `NOT_ESTABLISHED` |

Les groupes kernel supplémentaires présents dans le dépôt sont exploratoires et ne doivent pas être assimilés à des vulnérabilités confirmées sur iPhone14,2 sans comparaison des kexts exacts.

## Distinction importante concernant les sources

Le dépôt `duper-cves` compare principalement iOS 27.0 RC `24A435` et iOS 27.2 RC `24B115`, sur un autre modèle d'iPhone. Ses résultats donnent des familles de correctifs et des hypothèses de correspondance CVE, mais ne prouvent pas automatiquement le statut d'iOS 26.0.1 `23A355`.

Les deux familles ImageIO PDF et libarchive Joliet ci-dessus ont été vérifiées directement dans les deux IPSW `iPhone14,2`, et non seulement déduites du dépôt public.

## Relation avec les bulletins Apple

Apple documente dans iOS 26.0.1 la correction de `CVE-2025-43400` dans FontParser. Cette CVE précise est donc corrigée dans 26.0.1 ; elle ne doit pas être confondue avec les lignes CVE 2026 du dépôt public.

L'absence d'une CVE dans le bulletin iOS 27.0.1 n'est pas une preuve d'absence : les bulletins Apple ne constituent pas toujours un inventaire complet de tous les défauts non divulgués. Les correctifs étudiés par `duper-cves` sont principalement associés à l'avis iOS 27.2.

## Verdict final

`NOT_IOS27_ONLY`

Le résultat techniquement défendable est :

- certaines familles sont déjà présentes dans iOS 26.0.1 et persistent dans iOS 27.0.1 ;
- beaucoup d'autres restent seulement démontrées pour la branche iOS 27 ;
- le statut exact des groupes kernel et de plusieurs parsers sur 23A355 demeure inconnu ;
- aucune vulnérabilité analysée ici ne constitue une preuve de primitive noyau, d'écriture physique, de contournement SPTM ou de jailbreak.

Références :

- [Apple — iOS 26.0.1 security content](https://support.apple.com/en-ca/125326)
- [Apple — iOS 27.2 security content](https://support.apple.com/en-us/149230)
- [Ping-2o/duper-cves](https://github.com/Ping-2o/duper-cves)
- [IPSW iPhone14,2 / iOS 26.0.1 / 23A355](https://ipsw.me/download/iPhone14%2C2/23A355/)
- [IPSW iPhone14,2 / iOS 27.0.1 / 24A446](https://ipsw.me/download/iPhone14%2C2/24A446/)
