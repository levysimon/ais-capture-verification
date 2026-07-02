# Registre de Vérification d'Intégrité - Captures AIS

Ce dépôt public sert de tiers de confiance pour l'ancrage cryptographique et l'horodatage de nos captures de données maritimes AIS.

## 🔑 Clé Publique de Signature
La clé `ed25519_public.pem` présente dans ce dépôt est la seule clé officielle utilisée pour signer les fichiers de base de données SQLite hebdomadaires (`ais_week_*.db`) et les exports.

## 🛠️ Comment vérifier l'intégrité d'un export ?
Si vous avez reçu un fichier de données et que vous souhaitez vérifier qu'il n'a pas été altéré, utilisez notre script de vérification `verify_chain.py` (ou `verify_export.py`) en lui fournissant la clé publique de ce dépôt :

```bash
python3 verify_chain.py --key ed25519_public.pem chemin/vers/le/fichier.db
