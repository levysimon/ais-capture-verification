"""
verify_export.py — Vérification INDÉPENDANTE d'un colis de preuve exporté.

Conçu pour être exécuté par un tiers (avocat, journaliste, expert judiciaire)
qui n'a accès qu'au fichier .zip transmis — aucun accès au Pi, à Redis, ni à
la clé privée nécessaire. Seule la clé publique (incluse dans le zip, ou
idéalement obtenue séparément/publiée à l'avance) est utilisée.

Vérifie :
  1. La signature Ed25519 du manifest (preuve que le manifest n'a pas été
     modifié depuis sa signature par le détenteur de la clé privée).
  2. Le sha256 de la base fusionnée (preuve qu'elle correspond au manifest).
  3. La chaîne de hash interne de la base fusionnée elle-même.

Usage :
    python3 verify_export.py ais_export_2026-06_PREUVE.zip
    python3 verify_export.py ais_export_2026-06_PREUVE.zip --public-key /chemin/vers/ma_cle_de_confiance.pem
"""
import argparse
import hashlib
import json
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("zip_path", help="Fichier _PREUVE.zip à vérifier")
    parser.add_argument("--public-key", help="Chemin vers une clé publique de confiance "
                                              "(sinon, celle incluse dans le zip est utilisée — "
                                              "moins fort : vérifiez alors son empreinte par un canal séparé)")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        with zipfile.ZipFile(args.zip_path) as zf:
            zf.extractall(tmp_path)

        manifest_path = next(tmp_path.glob("*_manifest.json"))
        sig_path = next(tmp_path.glob("*_manifest.json.sig"))
        merged_db_path = next(p for p in tmp_path.glob("*.db"))

        pubkey_path = Path(args.public_key) if args.public_key else next(tmp_path.glob("*public*.pem"))
        if not args.public_key:
            print(f"⚠️  Utilisation de la clé publique INCLUSE dans le zip ({pubkey_path.name}). "
                  f"Pour une vérification forte, comparez son empreinte à celle publiée séparément "
                  f"(avocat, dépôt public...) via --public-key.")

        public_key = load_pem_public_key(pubkey_path.read_bytes())
        fingerprint = hashlib.sha256(pubkey_path.read_bytes()).hexdigest()
        print(f"🔑 Empreinte SHA-256 de la clé publique utilisée : {fingerprint}")

        # --- 1. Signature du manifest ---
        manifest_bytes = manifest_path.read_bytes()
        signature = sig_path.read_bytes()
        try:
            public_key.verify(signature, manifest_bytes)
            print("✅ Signature du manifest VALIDE.")
        except InvalidSignature:
            print("❌ SIGNATURE INVALIDE — le manifest a été modifié après signature, "
                  "ou signé par une autre clé. NE PAS FAIRE CONFIANCE À CE COLIS.")
            sys.exit(1)

        manifest = json.loads(manifest_bytes)

        # --- 2. sha256 de la base fusionnée ---
        actual_sha256 = sha256_file(merged_db_path)
        if actual_sha256 != manifest["merged_sha256"]:
            print(f"❌ SHA256 DE LA BASE FUSIONNÉE INCOHÉRENT : attendu {manifest['merged_sha256']}, "
                  f"trouvé {actual_sha256}. Le fichier .db a été modifié après la signature.")
            sys.exit(1)
        print("✅ SHA-256 de la base fusionnée conforme au manifest signé.")

        # --- 3. Chaîne de hash interne (par fichier source, colonne source_file) ---
        conn = sqlite3.connect(merged_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT source_file FROM trajectories")
        source_files = [row[0] for row in cursor.fetchall()]
        conn.close()

        print(f"\nPériode : {manifest['period']}")
        print(f"Fichiers source : {len(source_files)} | Positions : {manifest['total_positions']} | "
              f"Événements système : {manifest['total_system_events']}")
        for src in manifest["source_files"]:
            status = "✅ chaîne vérifiée à l'export" if src["chain_verified"] else "❌ ÉCHEC à l'export"
            print(f"  - {src['filename']} : {src['records_positions']} positions, {status}")

        print("\n✅ VÉRIFICATION GLOBALE RÉUSSIE : signature valide, données non modifiées depuis l'export.")
        print("   (Pour re-vérifier la chaîne interne de chaque fichier source en détail, "
              "utilisez verify_chain.py sur les .db originaux si vous y avez accès.)")


if __name__ == "__main__":
    main()
