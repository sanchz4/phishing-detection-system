from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class ScanHistoryStore:
    def __init__(self, db_path: str = "data/scan_history.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id TEXT PRIMARY KEY,
                    input_value TEXT NOT NULL,
                    input_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    threat_category TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    confidence_level TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )

    def append(self, record: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO scan_history (
                    id, input_value, input_type, risk_score, threat_category,
                    confidence, confidence_level, explanation, scanned_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["input_value"],
                    record["input_type"],
                    int(record["risk_score"]),
                    record["threat_category"],
                    float(record["confidence"]),
                    record["confidence_level"],
                    record["explanation"],
                    record["scanned_at"],
                    json.dumps(record),
                ),
            )

    def list(self, risk_level: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT payload_json FROM scan_history"
        params: tuple[Any, ...] = ()
        if risk_level and risk_level.lower() != "all":
            query += " WHERE LOWER(threat_category) = LOWER(?)"
            params = (risk_level,)
        query += " ORDER BY scanned_at DESC"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [json.loads(row[0]) for row in rows]

    def clear(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM scan_history")

    def stats(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_scans,
                    SUM(CASE WHEN threat_category = 'dangerous' THEN 1 ELSE 0 END) AS dangerous_scans,
                    SUM(CASE WHEN threat_category = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_scans,
                    SUM(CASE WHEN threat_category = 'safe' THEN 1 ELSE 0 END) AS safe_scans,
                    AVG(risk_score) AS average_risk_score,
                    MAX(scanned_at) AS latest_scan_at
                FROM scan_history
                """
            ).fetchone()
        return {
            "total_scans": rows[0] or 0,
            "dangerous_scans": rows[1] or 0,
            "suspicious_scans": rows[2] or 0,
            "safe_scans": rows[3] or 0,
            "average_risk_score": round(rows[4] or 0, 2),
            "latest_scan_at": rows[5],
        }
