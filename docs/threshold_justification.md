# Justificación estadística del umbral de MSE

## Diseño y procedencia

Se reconstruyeron los flujos CIC-IDS2017 con el autoencoder y el scaler congelados del proyecto. Los candidatos μ + 3σ, P99, P99.5 y P99.9 se calcularon **solo** con flujos benignos del lunes. El umbral desplegado `τ = 0.000308` se mantuvo fijo; se muestra aparte del P99 recalculado para verificar el redondeo y la reproducibilidad. FPR y F1 se midieron en los archivos de martes a viernes, sin escoger el umbral mirando esas etiquetas.

- Calibración: `Monday-WorkingHours.pcap_ISCX.csv`; 529,481 benignos válidos, 0 ataques excluidos, 437 filas inválidas.
- Evaluación: 7 archivos de martes a viernes; 1,741,839 benignos y 556,556 ataques válidos; 2,430 filas inválidas.
- Fracciones de muestreo: calibración 1, evaluación 1; semilla 42. Una fracción menor que 1 produce resultados exploratorios.
- Modelo SHA-256: `f8083b15c70dd4a4fc098e53158eb5bf58d064f4ab191fa1f743e37e798de64d`; scaler SHA-256: `1af9b985d1e397d0501d722b01eaee30d3bbb1ee280e4a458bdb4a1529a03d79`.
- Archivos de evaluación: `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`, `Friday-WorkingHours-Morning.pcap_ISCX.csv`, `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`, `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`, `Tuesday-WorkingHours.pcap_ISCX.csv`, `Wednesday-workingHours.pcap_ISCX.csv`.

## Forma de la distribución benigna

Se aplicó D'Agostino-Pearson K² sobre los MSE benignos del lunes (H₀: distribución normal; α = 0.05). La desviación estándar usa ddof = 0 y los percentiles usan interpolación lineal de NumPy.

| n | Media MSE | σ | Asimetría | Curtosis excedente | K² | p | Decisión |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| 529,481 | 2.70260346e-05 | 0.000478096355 | 140.5309 | 26000.8454 | 2334799.7612 | < 1e-300 | Se rechaza H₀ |

La asimetría y la curtosis cuantifican la forma de la cola; el p-valor por sí solo no mide el tamaño de la desviación, especialmente con muestras grandes. La regla μ + 3σ supone una cola aproximadamente normal si se interpreta como una garantía probabilística; P99 no necesita esa hipótesis.

## Comparación en días no usados para calibrar

Se marca anomalía cuando `MSE > umbral`. FPR = FP/(TN+FP) sobre benignos; F1 = 2TP/(2TP+FP+FN) para la clase ataque.

| Método | Umbral MSE | TN | FP | FN | TP | FPR | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| μ + 3σ | 0.0014613151 | 1,695,027 | 46,812 | 335,182 | 221,374 | 0.0269 | 0.5368 |
| P99 desplegado | 0.000308 | 1,667,975 | 73,864 | 284,017 | 272,539 | 0.0424 | 0.6037 |
| P99 recalculado | 0.000308054773 | 1,667,979 | 73,860 | 284,019 | 272,537 | 0.0424 | 0.6037 |
| P99.5 | 0.0005076756 | 1,680,060 | 61,779 | 295,489 | 261,067 | 0.0355 | 0.5937 |
| P99.9 | 0.00143483006 | 1,694,786 | 47,053 | 334,873 | 221,683 | 0.0270 | 0.5372 |

El P99 recalculado (0.000308054773) difiere del τ desplegado (0.000308) en 5.48e-08 MSE, compatible con el redondeo a seis decimales del notebook. En estos días, P99 desplegado obtuvo F1 = 0.6037 y FPR = 0.0424; μ + 3σ obtuvo F1 = 0.5368 y FPR = 0.0269. La elección implica un intercambio entre detección y falsas alarmas; rechazar normalidad no demuestra por sí solo que P99 sea óptimo. Tampoco debe interpretarse P99 como una FPR de 1 % en los días de prueba.

## Alcance de la conclusión

El lunes ya se utilizó para ajustar el scaler y entrenar el autoencoder original; por tanto, la calibración de estos candidatos es **dentro de muestra** y su FPR del 1 % nominal no está garantizado en producción. Los días restantes sí quedan fuera de la calibración de umbrales, aunque la elección final entre métodos después de ver esta tabla requeriría otra prueba independiente. Para afirmar una FPR calibrada sin contaminación, hay que volver a entrenar separando previamente entrenamiento y validación benigna, y reservar otros días para prueba.

La tabla compara umbrales; no modifica la configuración del backend. Los CSV y el `.h5` son artefactos locales ignorados por Git; sus hashes y el comando siguiente permiten identificar la ejecución.

| CSV | SHA-256 |
| :--- | :--- |
| `Monday-WorkingHours.pcap_ISCX.csv` | `852c4beb34eda186f32561fa79df7a0747e92e1a6535b01270820dd9ffe17f34` |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | `6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee` |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | `ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b` |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | `53a41c24d570ea83b7ac55b2e94df94e7a8216aeb80a2af0246b6bc8bb543000` |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | `6bcda3857c2504676034e3ea57762d38393cc734cb377a726bd5cb153961b1b5` |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | `d67066211fb1689c78406f1506f4c44704ecb92088353d5c96d96d6474eb819d` |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | `52b8692ae8c7d2ed04671fe2b98335693c0a92c7ab157d8c8b534d6523080851` |
| `Wednesday-workingHours.pcap_ISCX.csv` | `893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a` |

```bash
python SentinelAI-Model/threshold_analysis.py \
  --cic-dir SentinelAI-Model/data \
  --output docs/threshold_justification.md
```
