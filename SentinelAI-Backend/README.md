# SentinelAI Backend

API FastAPI para inferencia IDS con el autoencoder de `../SentinelAI-Model` y
persistencia de anomalías en PostgreSQL.

## Ejecución

```bash
cd SentinelAI-Backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL='postgresql://user:password@localhost/sentinel_db'
uvicorn main:app --host 0.0.0.0 --port 8000
```

La documentación interactiva queda disponible en `http://localhost:8000/docs`.

El scaler y el modelo incluidos esperan 78 entradas numéricas. Los CSV originales
de CIC-IDS2017 tienen 79 columnas porque agregan `Label`; por eso el endpoint acepta
78 entradas de inferencia o una fila de 79 valores y descarta el último valor
(`Label`). Para diccionarios con nombres, las columnas se ordenan usando
`scaler.feature_names_in_`.
