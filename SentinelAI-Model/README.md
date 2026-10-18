# Modelo de detección de SentinelAI

Este módulo contiene el notebook usado para explorar CIC-IDS2017, limpiar los
flujos, entrenar el autoencoder y calcular el umbral de detección. La guía general
de preparación y ejecución está en el [`README` principal](../README.md).

## Auditoría de generalización

`evaluate_ood.py` evalúa el **modelo y scaler ya entrenados**, sin volver a
ajustarlos. Lee los CSV por bloques, transforma las 78 columnas en el orden de
`scaler.feature_names_in_`, descarta flujos con valores no numéricos o infinitos
y aplica el umbral MSE fijo `0.000308` que usa el backend. Cada archivo produce
TN, FP, FN, TP, precisión, recall, F1 y tasa de falsos positivos. También
produce un agregado de los días de CIC que no participaron en el entrenamiento.
Cuando un archivo no contiene ataques evaluables, recall y F1 quedan vacíos
porque no se pueden estimar para esa muestra.

El notebook original ajustó `MinMaxScaler` y entrenó el autoencoder con **todo
el lunes**. Por eso el evaluador excluye ese día por defecto. Con
`--include-training-day` aparece como referencia contaminada, separada del
agregado de prueba. El umbral desplegado también se calculó con errores de
reconstrucción del lunes; el script nunca lo recalibra con los días de prueba.
Esto permite medir generalización de los artefactos actuales, pero no convierte
al lunes en validación independiente.

### Preparación y ejecución

Se necesitan los archivos locales `models/sentinel_model.h5` y
`models/sentinel_scaler.save`, además de los CSV de CIC-IDS2017 en `data/`.
El `.h5` y los datasets no se versionan en Git. Usá un entorno Python compatible
con TensorFlow, por ejemplo Python 3.11 o 3.12, e instalá:

```bash
python -m pip install -r SentinelAI-Model/requirements-validation.txt
```

El scaler local fue serializado con scikit-learn 1.9.0; la dependencia está
fijada a esa versión para evitar deserializaciones con versiones distintas.

Desde la raíz del repositorio:

```bash
python SentinelAI-Model/evaluate_ood.py \
  --cic-dir SentinelAI-Model/data \
  --output-dir SentinelAI-Model/reports/ood
```

El evaluador recorre todos los `*.csv` de `--cic-dir`, omite el lunes y prueba
martes a viernes. `--sample-fraction 0.02 --seed 42` acelera una exploración
reproducible, pero los resultados finales deben usar todas las filas. Se puede
pasar `--model`, `--scaler` y `--threshold` para probar otros artefactos; el
umbral debe quedar fijado **antes** de mirar los días de prueba.

### Prueba externa con UNSW-NB15

Un CSV tabular original de UNSW-NB15 **no es compatible directamente** con este
autoencoder: tiene un esquema de atributos diferente al de las 78 variables de
CIC-IDS2017. Renombrar unas pocas columnas, imputar ceros o volver a ajustar el
scaler sobre UNSW falsearía la comparación. Para una prueba válida, extraé de
los flujos externos las mismas 78 variables, con idénticas unidades, ventanas
y definiciones que el extractor usado para CIC. Conservá una columna binaria
`label` (`0` benigno, `1` ataque), cuya alineación con cada flujo debe verificarse.

Una fuente prometedora es el [CIC-UNSW-NB15 aumentado por la UNB](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html): sus autores volvieron a extraer flujos de UNSW-NB15 con CICFlowMeter. Publican `Data.csv` y `Label.csv` por separado; antes de evaluarlos hay que comprobar nombres, unidades y correspondencia de filas, y preparar un CSV con las 78 entradas requeridas y su `label` binaria. El enlace oficial de descarga pasa por un formulario. El [UNSW-NB15 original](https://research.unsw.edu.au/projects/unsw-nb15-dataset) usa características generadas con Argus y Bro-IDS, por lo que no sirve como entrada directa.

Si la extracción produjo otros nombres para variables **semánticamente
equivalentes**, pasá un JSON con un par por cada una de las 78 características:
clave = nombre esperado por el scaler, valor = columna del CSV externo. El mapa
solo alinea nombres; no calcula variables ausentes. El script falla e informa
las columnas faltantes cuando recibe UNSW crudo o un mapa incompleto.

```bash
python SentinelAI-Model/evaluate_ood.py \
  --cic-dir SentinelAI-Model/data \
  --external-csv /ruta/unsw_flows_cic_features.csv \
  --external-label label \
  --output-dir SentinelAI-Model/reports/ood
```

Si los nombres equivalentes difieren, agregá
`--external-feature-map /ruta/feature_map.json`. `--external-csv` puede
repetirse para varios archivos externos. El script no atribuye una caída de F1
antes de medirla: el tamaño y composición de los conjuntos se incluyen en la
salida para interpretar la comparación.

### Salidas

| Archivo | Contenido |
| --- | --- |
| `metrics.csv` | Métricas por día, agregado CIC y agregado externo, con filas evaluadas e inválidas. |
| `confusion_matrices.csv` | Cuatro celdas exactas de cada matriz: real/predicho benigno o ataque. |
| `confusion_matrices.png` | Panel de matrices para la presentación si `matplotlib` está disponible. |
| `evaluation.json` | Rutas de artefactos, umbral, esquema, muestreo y limitaciones. |

Para una futura evaluación sin contaminación de calibración, reentrená desde
cero con flujos benignos del lunes divididos **antes** de ajustar el scaler:
entrenamiento para `fit` y para el autoencoder, validación benigna separada
para fijar el percentil del MSE. Congelá artefactos y umbral, y recién entonces
evaluá días restantes y datos externos compatibles. No elijas umbral ni
hiperparámetros mirando los resultados de esos conjuntos.

Prueba rápida de la lógica del evaluador (modelo sintético, sin TensorFlow):

```bash
python -m unittest discover -s SentinelAI-Model/tests -v
```

## Comparación estadística de umbrales

`threshold_analysis.py` calcula los MSE benignos del lunes con el modelo y
scaler congelados, aplica D'Agostino-Pearson K², informa asimetría y curtosis,
y compara `μ + 3σ`, el `τ = 0.000308` desplegado, P99 recalculado, P99.5 y
P99.9. Las tasas FPR y F1 se miden sobre martes a viernes. El lunes **ya fue
usado para entrenar** el modelo y ajustar el scaler, así que esta calibración
es dentro de muestra; el reporte identifica esa limitación y no presenta el
P99 como garantía de FPR fuera de muestra.

```bash
python SentinelAI-Model/threshold_analysis.py \
  --cic-dir SentinelAI-Model/data \
  --output docs/threshold_justification.md
```

Por defecto usa todos los CSV. Para una prueba exploratoria se pueden indicar
`--calibration-sample-fraction` y `--evaluation-sample-fraction` menores que 1;
el reporte registra fracciones y semilla. Requiere `scipy`, incluido en
`requirements-validation.txt`.
