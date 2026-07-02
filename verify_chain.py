"""
verify_chain.py — Vérifie l'intégrité de la chaîne de hash d'un fichier .db AIS.

Recalcule chaque hash depuis le début du fichier et le compare à ce qui est
stocké : la moindre ligne modifiée, supprimée, ou insérée hors chaîne fait
échouer la vérification à l'endroit précis où ça casse.

Ne nécessite AUCUN accès à Redis ni au système d'origine — utilisable par
n'importe qui (avocat, journaliste, expert judiciaire) avec juste le fichier
.db en main.

Usage :
    python3 verify_chain.py ais_archive/ais_week_2026-W23.db
"""
import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64


def compute_record_hash(prev_hash: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + "|" + canonical).encode("utf-8")).hexdigest()


def verify(db_path: str) -> bool:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Reconstituer la séquence chronologique complète (positions + événements),
    # dans l'ordre d'insertion réel (id croissant par table, puis fusionnés par ts
    # comme au moment de l'archivage — id sert de tie-breaker stable).
    cursor.execute(
        "SELECT id, mmsi, zone, pi_timestamp, source_reported_time, time_delta_seconds, "
        "time_spoofing_suspected, lat, lon, source, notes, prev_hash, record_hash "
        "FROM trajectories ORDER BY id"
    )
    positions = cursor.fetchall()

    cursor.execute("SELECT id, event_type, ts, detail, prev_hash, record_hash FROM system_events ORDER BY id")
    events = cursor.fetchall()

    cursor.execute("SELECT last_hash FROM chain_state WHERE id = 1")
    row = cursor.fetchone()
    stored_final_hash = row[0] if row else None

    # On ne peut pas retrouver EXACTEMENT l'ordre d'interclassement chronologique
    # original (il dépend du moment de chaque archivage), mais chaque ligne porte
    # son propre prev_hash stocké : on vérifie donc localement, ligne par ligne,
    # que record_hash == SHA256(prev_hash_stocké + contenu), ET que la chaîne
    # est bien connectée bout à bout (le record_hash d'une ligne == le prev_hash
    # de la suivante dans l'ordre d'insertion réel), jusqu'au dernier hash stocké
    # dans chain_state.
    all_rows = []
    for p in positions:
        (id_, mmsi, zone, pi_ts, source_ts, delta, spoof, lat, lon, source, notes, prev_hash, record_hash) = p
        payload = {
            "type": "position", "mmsi": mmsi, "zone": zone, "pi_ts": pi_ts,
            "source_ts": source_ts, "delta": delta, "spoof": spoof,
            "lat": lat, "lon": lon, "source": source, "notes": notes,
        }
        all_rows.append({"table": "trajectories", "id": id_, "payload": payload,
                          "prev_hash": prev_hash, "record_hash": record_hash})
    for e in events:
        (id_, event_type, ts, detail, prev_hash, record_hash) = e
        payload = {"type": "event", "event_type": event_type, "ts": ts, "detail": detail}
        all_rows.append({"table": "system_events", "id": id_, "payload": payload,
                          "prev_hash": prev_hash, "record_hash": record_hash})

    if not all_rows:
        print("ℹ️  Fichier vide (aucune position ni événement) — rien à vérifier.")
        conn.close()
        return True

    # Reconstruire l'ordre d'insertion original : on trie par record_hash ==
    # prev_hash de la ligne suivante (chaînage réel), en partant de la genèse.
    by_prev_hash = {}
    for row_ in all_rows:
        by_prev_hash.setdefault(row_["prev_hash"], []).append(row_)

    ordered = []
    current = GENESIS_HASH
    remaining = len(all_rows)
    visited_hashes = set()
    while remaining > 0:
        candidates = by_prev_hash.get(current, [])
        if not candidates:
            print(f"❌ CHAÎNE ROMPUE : aucune ligne ne référence le hash {current[:16]}... "
                  f"comme prev_hash, alors que {remaining} ligne(s) restent à relier. "
                  f"Une ligne a été supprimée ou son prev_hash modifié.")
            conn.close()
            return False
        if len(candidates) > 1:
            print(f"⚠️  ATTENTION : {len(candidates)} lignes partagent le même prev_hash "
                  f"{current[:16]}... — possible duplication/falsification. Vérification arrêtée.")
            conn.close()
            return False
        row_ = candidates.pop(0)
        expected_hash = compute_record_hash(row_["prev_hash"], row_["payload"])
        if expected_hash != row_["record_hash"]:
            print(f"❌ HASH INVALIDE sur {row_['table']} id={row_['id']} : "
                  f"attendu {expected_hash[:16]}..., trouvé {row_['record_hash'][:16]}... "
                  f"-> cette ligne a été modifiée après coup.")
            conn.close()
            return False
        ordered.append(row_)
        current = row_["record_hash"]
        remaining -= 1

    if stored_final_hash and current != stored_final_hash:
        print(f"❌ INCOHÉRENCE FINALE : le dernier hash calculé ({current[:16]}...) ne correspond "
              f"pas à chain_state.last_hash ({stored_final_hash[:16]}...) — des lignes ont pu être "
              f"retirées à la fin de la chaîne.")
        conn.close()
        return False

    first_ts = min(r_["payload"].get("pi_ts") or r_["payload"].get("ts") for r_ in ordered)
    last_ts = max(r_["payload"].get("pi_ts") or r_["payload"].get("ts") for r_ in ordered)
    n_spoof = sum(1 for r_ in ordered if r_["payload"].get("spoof"))
    n_gaps = sum(1 for r_ in ordered if r_["payload"].get("type") == "event"
                 and "NON PLANIFIÉE" in r_["payload"].get("detail", ""))

    print(f"✅ Chaîne intègre : {len(ordered)} ligne(s) vérifiée(s), aucune altération détectée.")
    print(f"   Période couverte : {datetime.fromtimestamp(first_ts, tz=timezone.utc)} → "
          f"{datetime.fromtimestamp(last_ts, tz=timezone.utc)}")
    print(f"   Hash final de la chaîne : {current}")
    if n_spoof:
        print(f"   ⚠️ {n_spoof} position(s) avec écart temporel suspect (voir colonne notes).")
    if n_gaps:
        print(f"   ⚠️ {n_gaps} interruption(s) non planifiée(s) documentée(s) (coupure/crash suspecté).")

    conn.close()
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("db_path", help="Chemin vers le fichier .db à vérifier")
    args = parser.parse_args()
    ok = verify(args.db_path)
    sys.exit(0 if ok else 1)
