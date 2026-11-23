# VulnMiner

VulnMiner es el proyecto del Laboratorio 1 de Desarrollo de Software Seguro de la ESPE. La CLI analiza localmente código y configuraciones de microservicios con un clasificador supervisado. Cada hallazgo contiene su ubicación, evidencia y estado de revisión.

## Instalación y uso

Se requiere Python 3.9 o posterior. La CLI usa la biblioteca estándar de Python.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Desde la raíz del repositorio que se desee analizar:

```bash
vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes
```

La CLI empieza por los contextos locales de Compose, aplica detección por manifiestos y reconoce estructuras `services/`, `microservices/` y `apps/`. El análisis lee archivos de texto localmente. Python y JavaScript están demostrados. TypeScript recibe análisis léxico experimental. La herramienta también lee los formatos de configuración de la demostración y reconoce Dockerfiles, manifiestos y definiciones OpenAPI de texto.

## Probar el modelo entrenado

1. Abre una terminal en la carpeta de VulnMiner, donde están este README y `pyproject.toml`. Comprueba con `python3 --version` que tienes Python 3.9 o posterior.
2. Ejecuta el análisis del proyecto de ejemplo. Este comando funciona sin instalar la CLI y carga automáticamente [el modelo ya entrenado](vulnminer/model.json).

   ```bash
   python3 -m vulnminer scan examples/proyecto-reservado --standards owasp2025,api2023 --format json,html --output reportes/prueba-modelo
   ```

3. Comprueba que la consola indique **3 microservicios, 8 archivos analizados y 5 hallazgos potenciales**. Abre `reportes/prueba-modelo/analisis.html` en el navegador o consulta `reportes/prueba-modelo/analisis.json`. Los cinco hallazgos cubren cinco categorías OWASP web y cuatro de API.

Para analizar otro repositorio con el mismo modelo, sustituye `examples/proyecto-reservado` por su ruta. Puedes ejecutar las pruebas automatizadas desde la carpeta de VulnMiner con `python3 -m unittest discover -s tests -v`.

## Reproducir el entrenamiento y la evaluación

Ejecutar desde la raíz de VulnMiner:

```bash
python3 -m scripts.corpus
python3 -m scripts.train
python3 -m scripts.demo
python3 -m unittest discover -s tests -v
```

Los cinco notebooks de [SEMMA](notebooks/) incluyen código y salidas ejecutadas. Los scripts y los notebooks comparten el generador, el preprocesamiento y la evaluación.

Para regenerar las figuras, los notebooks con salidas guardadas y el informe, instalar ReportLab en el entorno de autoría y ejecutar:

```bash
python -m pip install -r docs/requirements-authoring.txt
python -m scripts.charts
python -m scripts.notebooks
python -m scripts.technical_report
```

## Evidencia y entregables

| Entregable | Ubicación |
|---|---|
| Corpus, diccionario y fuentes | [dataset.csv](data/dataset.csv), [diccionario](data/README.md), [CWE–OWASP](data/cwe_owasp.csv) |
| Fases SEMMA | [Notebooks](notebooks/), [scripts](scripts/) y [matriz de características](artifacts/features.csv) |
| Modelo y evaluación | [Modelo serializado](vulnminer/model.json), [métricas y matrices](artifacts/metrics.json) |
| Demostración reservada | [Proyecto](examples/proyecto-reservado/), [reporte JSON](artifacts/demo/reservado/analisis.json), [reporte HTML](artifacts/demo/reservado/analisis.html) |
| Proyecto de contraste | [Proyecto](examples/proyecto-contraste/), [reporte JSON](artifacts/demo/contraste/analisis.json), [reporte HTML](artifacts/demo/contraste/analisis.html) |
| Evaluación funcional | [Anotación manual](artifacts/demo_truth.json), [métricas por ubicación y categoría](artifacts/demo_metrics.json) |
| Informe técnico | [PDF](docs/Informe_tecnico_VulnMiner.pdf) |

## Alcance de los resultados

La cobertura demostrada comprende cinco categorías web (A01, A02, A04, A06 y A07) y cuatro de API (API1, API2, API4 y API8). El catálogo incluye los 20 códigos. La cobertura es por patrón controlado dentro de cada categoría. El puntaje de confianza es una salida sin calibrar. La severidad depende del impacto supuesto y cada alerta categorizada requiere verificación.

El corpus representa declaraciones individuales. El analizador trabaja por línea, con contexto de claves antecesoras en YAML, y reconoce un subconjunto de las declaraciones locales de Compose. Los resultados pueden omitir controles distribuidos entre archivos o expresados con otra sintaxis. En el contraste, el modelo omitió una política que declaraba el transporte mediante un valor de protocolo. Los dos proyectos locales son maquetas de revisión estática. La ejecución sobre el proyecto del docente requiere el repositorio que se proporcionará durante la demostración.
