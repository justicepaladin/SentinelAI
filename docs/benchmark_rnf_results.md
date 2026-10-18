# Benchmark RNF-03, RNF-05 y RNF-06

**Medición:** 2026-10-18T15:31:51+00:00 · 500 peticiones POST /ingest en total (repartidas entre los tres modos), 500 inferencias puras y 5 calentamientos por fase.

| Medición | n | Media (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Máximo (ms) | Detecciones | Llamadas al firewall | Tasa por detección |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Inferencia pura (scaler + autoencoder) | 500 | 39.141 | 38.900 | 41.997 | 44.905 | 46.762 | — | — | — |
| POST /ingest · todos los modos | 500 | 43.573 | 42.679 | 46.916 | 53.502 | 183.190 | 500 | 167 | 33.4% |
| POST /ingest · respuesta activa | 167 | 42.281 | 42.055 | 44.062 | 46.362 | 50.496 | 167 | 167 | 100.0% |
| POST /ingest · enlace degradado | 167 | 43.880 | 42.538 | 44.872 | 62.122 | 183.190 | 167 | 0 | 0.0% |
| POST /ingest · modo informativo | 166 | 44.566 | 44.214 | 48.955 | 53.564 | 56.632 | 166 | 0 | 0.0% |

## Método y alcance

Se usaron el scaler y el autoencoder entrenados, sin reemplazar la inferencia. El vector de prueba fue sintético y determinista: 0.1 en cada una de las 78 entradas; su MSE fue 0.00228448189. Se eligió un vector que supera el umbral crítico para verificar la ruta de detección y las tres políticas de respuesta.

Cada POST pasó por el stack ASGI de FastAPI en el mismo proceso; la serialización del request se hizo antes del cronómetro. La inferencia pura incluye preparación del DataFrame, scaler, autoencoder y cálculo del MSE. Las latencias son de reloj monotónico y los percentiles usan interpolación lineal sobre las muestras medidas. El cliente ASGI revisa la finalización a intervalos de 1 ms; esa espera está incluida en el tiempo extremo a extremo.

Durante las mediciones, la autenticación se resolvió en memoria, los logs se contaron en memoria y PostgreSQL, Telegram e iptables fueron sustituidos por dobles. La columna de firewall cuenta invocaciones al punto de aplicación de reglas; no representa reglas instaladas en el host. El test falla si se pierde alguna detección, si el modo activo no invoca el firewall, o si los modos degradado e informativo lo invocan. Esta prueba no mide latencia de red, disco, PostgreSQL ni iptables reales.

La degradación se simuló con `link_degraded=true` en el payload; no se desconectó una interfaz física ni se introdujo pérdida de paquetes.

No se encontró en los archivos versionados un límite numérico de aceptación para RNF-03. Estos percentiles permiten compararlo con el valor pactado en la cátedra, pero el informe no declara cumplimiento sin ese criterio.

## Entorno

- Python 3.12.15; FastAPI 0.141.1; TensorFlow 2.21.0; scikit-learn 1.9.0.
- Linux-7.2.10-200.fc44.x86_64-x86_64-with-glibc2.43; CPU: 11th Gen Intel(R) Core(TM) i9-11950H @ 2.60GHz (16 CPU lógicas informadas).
- Modelo: `SentinelAI-Model/models/sentinel_model.h5`; scaler: `SentinelAI-Model/models/sentinel_scaler.save`.
- Comando: `SentinelAI-Backend/.venv/bin/python scripts/benchmark_rnf.py --requests 500 --warmup 5`.
