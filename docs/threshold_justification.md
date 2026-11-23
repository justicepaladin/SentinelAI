# Sensibilidad de las alertas y falsos positivos del bloqueo crítico

## Diseño de la evaluación

El autoencoder y el scaler congelados de SentinelAI reconstruyeron los flujos de CIC-IDS2017. Los percentiles y la regla μ + 3σ se calcularon exclusivamente con el MSE de los flujos benignos del lunes. El P99 desplegado conserva su valor histórico de `0.000308`. Los siete archivos de martes a viernes quedaron fuera de la calibración y aportan las etiquetas para medir detección y falsas alarmas.

- El lunes (`Monday-WorkingHours.pcap_ISCX.csv`) aportó 529,481 benignos válidos. Se excluyeron 0 ataques y 437 filas inválidas.
- La evaluación reunió 1,741,839 benignos y 556,556 ataques válidos. El número de filas inválidas descartadas fue 2,430. La prevalencia observada de ataques fue del 24.21 %.
- Las fracciones de muestreo fueron 1 en calibración y 1 en evaluación, con semilla 42.

## Distribución del MSE benigno del lunes

La prueba K² de D’Agostino-Pearson contrasta la hipótesis de normalidad con α = 0.05. Se usó la desviación estándar poblacional (ddof = 0) y la interpolación lineal de NumPy para los percentiles.

| n | Media MSE | σ | Asimetría | Curtosis excedente | K² | p | Decisión |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| 529,481 | 2.70260346e-05 | 0.000478096355 | 140.5309 | 26000.8454 | 2334799.7612 | < 1e-300 | Se rechaza H₀ |

La asimetría y la curtosis describen cuánto se aparta la forma de la distribución de la normal. Los percentiles estiman directamente la cola empírica. El significado probabilístico de μ + 3σ depende de la distribución del MSE.

## Candidatos de alerta informativa

Se cuenta una alerta cuando `MSE > umbral`. La sensibilidad es la fracción de ataques detectados, TP/(TP+FN). La precisión es la fracción de alertas que corresponden a ataques, TP/(TP+FP). La FPR es el porcentaje de benignos marcados, 100 × FP/(TN+FP). F1 = 2TP/(2TP+FP+FN). Los conteos suman los siete archivos antes de calcular las tasas.

| Método | Umbral MSE | TN | FP | FN | TP | Sensibilidad (Recall) | Precisión | FPR (%) | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| P80 | 2.00273735e-05 | 1,290,454 | 451,385 | 92,339 | 464,217 | 0.8341 | 0.5070 | 25.91 | 0.6307 |
| P85 | 2.76864648e-05 | 1,375,390 | 366,449 | 126,825 | 429,731 | 0.7721 | 0.5397 | 21.04 | 0.6354 |
| P90 | 4.12289519e-05 | 1,471,469 | 270,370 | 168,683 | 387,873 | 0.6969 | 0.5893 | 15.52 | 0.6386 |
| P95 | 7.79924667e-05 | 1,570,726 | 171,113 | 218,173 | 338,383 | 0.6080 | 0.6642 | 9.82 | 0.6348 |
| P97 | 0.000121420705 | 1,616,260 | 125,579 | 235,054 | 321,502 | 0.5777 | 0.7191 | 7.21 | 0.6407 |
| P98 | 0.000175376466 | 1,640,661 | 101,178 | 249,980 | 306,576 | 0.5508 | 0.7519 | 5.81 | 0.6358 |
| P99 recalculado | 0.000308054773 | 1,667,979 | 73,860 | 284,019 | 272,537 | 0.4897 | 0.7868 | 4.24 | 0.6037 |
| P99.5 | 0.0005076756 | 1,680,060 | 61,779 | 295,489 | 261,067 | 0.4691 | 0.8086 | 3.55 | 0.5937 |
| P99.9 | 0.00143483006 | 1,694,786 | 47,053 | 334,873 | 221,683 | 0.3983 | 0.8249 | 2.70 | 0.5372 |
| μ + 3σ | 0.0014613151 | 1,695,027 | 46,812 | 335,182 | 221,374 | 0.3978 | 0.8254 | 2.69 | 0.5368 |
| P99 desplegado | 0.000308 | 1,667,975 | 73,864 | 284,017 | 272,539 | 0.4897 | 0.7868 | 4.24 | 0.6037 |

La diferencia absoluta entre el P99 recalculado y el desplegado es 5.48e-08 MSE. A seis decimales reproduce el umbral histórico redondeado del notebook.

## Candidatos de bloqueo crítico reversible

Esta simulación cuenta un flujo como candidato al bloqueo cuando `MSE >= umbral crítico`. El umbral crítico de una pareja debe superar al de alerta para que todo bloqueo potencial sea también una alerta. Cada múltiplo 3 × P se calcula directamente sobre el percentil benigno del lunes, sin aplicar el piso de severidad del backend.

| Método | Umbral MSE | TN | FP | FN | TP | Sensibilidad (Recall) | Precisión | FPR (%) | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| P99.5 | 0.0005076756 | 1,680,060 | 61,779 | 295,489 | 261,067 | 0.4691 | 0.8086 | 3.55 | 0.5937 |
| P99.9 | 0.00143483006 | 1,694,786 | 47,053 | 334,873 | 221,683 | 0.3983 | 0.8249 | 2.70 | 0.5372 |
| μ + 3σ | 0.0014613151 | 1,695,027 | 46,812 | 335,182 | 221,374 | 0.3978 | 0.8254 | 2.69 | 0.5368 |
| 3 × P90 | 0.000123686856 | 1,617,639 | 124,200 | 235,441 | 321,115 | 0.5770 | 0.7211 | 7.13 | 0.6410 |
| 3 × P95 | 0.0002339774 | 1,656,754 | 85,085 | 272,304 | 284,252 | 0.5107 | 0.7696 | 4.88 | 0.6140 |
| 3 × P97 | 0.000364262114 | 1,673,960 | 67,879 | 289,210 | 267,346 | 0.4804 | 0.7975 | 3.90 | 0.5996 |

### Lectura de la pareja P90 / P99.9

Se ejemplifica la política con P90 para informar y P99.9 para bloquear. En la calibración benigna corresponden a colas nominales del 10 % y del 0.1 %, respectivamente.

- Con P90 se detectan 387,873 ataques (recall 69.69 %) y se marcan 270,370 benignos (FPR 15.52 %). Frente al P99 desplegado, con recall 48.97 %, el cambio es de +115,334 ataques detectados y +196,506 falsas alertas.
- Superan o igualan P99.9 221,683 ataques (39.83 % de todos los ataques) y 47,053 benignos (FPR crítica 2.70 %). De los falsos positivos de P90, la fracción que también alcanzaría el bloqueo es 17.40 %. Quedarían solo como informativos 166,190 ataques y 223,317 benignos.

La unidad de evaluación es el flujo. La política propuesta reserva el bloqueo para el corte crítico. En el backend actual, con la respuesta activa habilitada y sin suspensión, cualquier anomalía puede poner una IP en cuarentena. La severidad emplea el máximo entre el piso crítico configurado y tres veces el umbral del sitio. Los conteos de esta simulación miden flujos candidatos a la acción.

## Desglose por archivo y familia de ataque

Cada celda indica qué porcentaje de los flujos del grupo superó el umbral de alerta. En BENIGN se lee la FPR del archivo. En cada etiqueta de ataque se lee la sensibilidad para esa familia. La columna Flujos da el denominador de cada porcentaje. P99 es el percentil recalculado del lunes.

| Archivo | Grupo | Flujos | P90 (%) | P95 (%) | P97 (%) | P99 recalculado (%) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | BENIGN | 431,813 | 11.18 | 5.78 | 3.32 | 1.14 |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | FTP-Patator | 7,935 | 50.01 | 0.09 | 0.08 | 0.08 |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | SSH-Patator | 5,897 | 49.75 | 0.05 | 0.05 | 0.05 |
| `Wednesday-workingHours.pcap_ISCX.csv` | BENIGN | 439,683 | 12.69 | 7.44 | 4.49 | 2.05 |
| `Wednesday-workingHours.pcap_ISCX.csv` | DoS GoldenEye | 10,293 | 93.24 | 91.30 | 86.94 | 68.30 |
| `Wednesday-workingHours.pcap_ISCX.csv` | DoS Hulk | 230,124 | 67.92 | 67.77 | 67.59 | 66.10 |
| `Wednesday-workingHours.pcap_ISCX.csv` | DoS Slowhttptest | 5,499 | 98.29 | 98.13 | 95.84 | 45.08 |
| `Wednesday-workingHours.pcap_ISCX.csv` | DoS slowloris | 5,796 | 59.85 | 59.59 | 59.02 | 58.47 |
| `Wednesday-workingHours.pcap_ISCX.csv` | Heartbleed | 11 | 100.00 | 100.00 | 100.00 | 100.00 |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | BENIGN | 288,359 | 25.80 | 18.06 | 14.81 | 9.35 |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | Infiltration | 36 | 91.67 | 88.89 | 88.89 | 80.56 |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | BENIGN | 168,051 | 9.72 | 4.87 | 2.77 | 1.03 |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Web Attack – Brute Force | 1,507 | 7.37 | 4.98 | 4.91 | 0.20 |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Web Attack – Sql Injection | 21 | 4.76 | 4.76 | 4.76 | 0.00 |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Web Attack – XSS | 652 | 3.07 | 2.91 | 2.91 | 2.91 |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | BENIGN | 97,686 | 39.31 | 34.48 | 32.14 | 27.96 |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | DDoS | 128,025 | 76.03 | 64.03 | 63.71 | 59.30 |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | BENIGN | 127,292 | 12.98 | 6.83 | 4.64 | 1.33 |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | PortScan | 158,804 | 67.57 | 50.83 | 41.10 | 19.84 |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | BENIGN | 188,955 | 10.92 | 5.72 | 3.61 | 1.19 |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | Bot | 1,956 | 71.01 | 68.81 | 68.25 | 2.30 |

## Precisión esperada bajo distintas prevalencias

Para una prevalencia π se estima el valor predictivo positivo con `recall × π / (recall × π + FPR × (1 − π))`. Aquí la FPR se expresa como fracción. La proyección conserva la sensibilidad y la FPR observadas en los siete archivos y solo cambia la proporción de ataques. Un cambio en la mezcla de familias o en el tráfico benigno también puede modificar esas tasas.

| Acción | Método | 24,2 % | 10 % | 1 % | 0,1 % |
| :--- | :--- | ---: | ---: | ---: | ---: |
| Alerta | P80 | 50.68 | 26.34 | 3.15 | 0.32 |
| Alerta | P85 | 53.95 | 28.97 | 3.57 | 0.37 |
| Alerta | P90 | 58.91 | 33.28 | 4.34 | 0.45 |
| Alerta | P95 | 66.40 | 40.75 | 5.88 | 0.62 |
| Alerta | P97 | 71.89 | 47.10 | 7.49 | 0.80 |
| Alerta | P98 | 75.17 | 51.31 | 8.74 | 0.94 |
| Alerta | P99 recalculado | 78.66 | 56.20 | 10.45 | 1.14 |
| Alerta | P99.5 | 80.85 | 59.51 | 11.78 | 1.31 |
| Alerta | P99.9 | 82.48 | 62.10 | 12.96 | 1.45 |
| Alerta | μ + 3σ | 82.53 | 62.19 | 13.01 | 1.46 |
| Alerta | P99 desplegado | 78.66 | 56.20 | 10.45 | 1.14 |
| Bloqueo | P99.5 | 80.85 | 59.51 | 11.78 | 1.31 |
| Bloqueo | P99.9 | 82.48 | 62.10 | 12.96 | 1.45 |
| Bloqueo | μ + 3σ | 82.53 | 62.19 | 13.01 | 1.46 |
| Bloqueo | 3 × P90 | 72.09 | 47.34 | 7.56 | 0.80 |
| Bloqueo | 3 × P95 | 76.95 | 53.74 | 9.55 | 1.04 |
| Bloqueo | 3 × P97 | 79.74 | 57.80 | 11.07 | 1.22 |

El 24,2 % aproxima la prevalencia del conjunto completo. Cada celda expresa la precisión en porcentaje. N/D indica un denominador cero.

## Alcance y reproducción

El lunes se usó tanto para entrenar el autoencoder y ajustar el scaler como para calibrar los umbrales. La FPR de bloqueo cuantifica falsos positivos en estos días. Generalizarla a producción requiere una evaluación independiente con tráfico y prevalencias representativos. Una selección de umbrales basada en el desempeño observado de martes a viernes requiere un nuevo conjunto de prueba.

- SHA-256 del modelo: `f8083b15c70dd4a4fc098e53158eb5bf58d064f4ab191fa1f743e37e798de64d`.
- SHA-256 del scaler: `1af9b985d1e397d0501d722b01eaee30d3bbb1ee280e4a458bdb4a1529a03d79`.

| CSV | SHA-256 |
| :--- | :--- |
| `Monday-WorkingHours.pcap_ISCX.csv` | `852c4beb34eda186f32561fa79df7a0747e92e1a6535b01270820dd9ffe17f34` |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | `52b8692ae8c7d2ed04671fe2b98335693c0a92c7ab157d8c8b534d6523080851` |
| `Wednesday-workingHours.pcap_ISCX.csv` | `893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a` |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | `6bcda3857c2504676034e3ea57762d38393cc734cb377a726bd5cb153961b1b5` |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | `d67066211fb1689c78406f1506f4c44704ecb92088353d5c96d96d6474eb819d` |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | `6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee` |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | `ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b` |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | `53a41c24d570ea83b7ac55b2e94df94e7a8216aeb80a2af0246b6bc8bb543000` |

Desde la raíz del repositorio, el siguiente comando reproduce el análisis.

```bash
python SentinelAI-Model/threshold_analysis.py \
  --cic-dir SentinelAI-Model/data \
  --model SentinelAI-Model/models/sentinel_model.h5 --scaler SentinelAI-Model/models/sentinel_scaler.save \
  --chunksize 20000 --batch-size 4096 --seed 42 \
  --calibration-sample-fraction 1 --evaluation-sample-fraction 1 \
  --output docs/threshold_justification.md
```

El siguiente comando genera las matrices de alerta P90 y el resumen de bloqueo P99.9 con los valores completos de ambos umbrales.

```bash
python SentinelAI-Model/evaluate_ood.py \
  --cic-dir SentinelAI-Model/data \
  --model SentinelAI-Model/models/sentinel_model.h5 --scaler SentinelAI-Model/models/sentinel_scaler.save \
  --chunksize 20000 --batch-size 4096 --seed 42 \
  --sample-fraction 1 \
  --threshold 4.122895188629627e-05 --critical-threshold 0.0014348300639540836 \
  --output-dir SentinelAI-Model/reports/ood-p90-p999 \
  --plot-path docs/confusion_matrices.png
```
