# Dataset y diccionario de datos

`dataset.csv` contiene 800 declaraciones de código y configuración, con 400 casos vulnerables y 400 controles no vulnerables. Son casos controlados originales que representan el estado declarado de cinco controles. La etiqueta adversa se refiere al control en el escenario especificado. La etiqueta favorable indica que la declaración cumple ese criterio local.

## Procedencia y muestreo

`scripts/corpus.py` es el generador y fuente primaria. Los 20 dominios de proyecto son grupos sintéticos. Cada uno aporta 40 declaraciones construidas con pares de riesgo y control en cuatro formatos. Los pares conservan la forma y el contexto y cambian el estado del control. Hay 60 grupos de plantilla distribuidos entre las particiones. Cada partición tiene formulaciones propias de los nombres de control, con términos de seguridad compartidos para permitir aprendizaje léxico. No se incluyeron ejemplos de OWASP Benchmark ni de NIST SARD.

Las particiones de entrenamiento, validación y prueba contienen 560, 120 y 120 casos. Ningún identificador de proyecto ni de familia cruza particiones. La normalización valida consistencia y detecta textos duplicados después de normalizar espacios y mayúsculas. Esta comprobación no prueba independencia semántica entre las plantillas. Los ejemplos de ambos repositorios de demostración se encuentran fuera del CSV.

Las correspondencias web se apoyan en las listas CWE publicadas por OWASP. Las correspondencias API relacionan el patrón con la descripción de la categoría en un contexto de API y son criterios de etiquetado del proyecto. Se explicitan en `cwe_owasp.csv`.

## Columnas

| Campo | Tipo | Definición |
|---|---|---|
| `id` | texto | Identificador estable del caso. |
| `project` | texto | Grupo de procedencia sintético, usado para separar particiones. |
| `source` | texto | Procedencia de la declaración. |
| `path` | texto | Ruta representativa dentro del grupo sintético. |
| `family` | texto | Plantilla de formulación que agrupa casos relacionados dentro de una sola partición. |
| `language` | texto | Python, JavaScript, YAML o Properties. |
| `partition` | enum | `train`, `validation` o `test`. |
| `api_context` | entero | 1 cuando la anotación sitúa el control en una API, 0 en otro contexto. |
| `is_vulnerable` | entero | 1 para el caso de riesgo, 0 en el control emparejado. |
| `patterns` | texto | Identificadores internos separados por barra vertical. Vacío en casos no vulnerables. |
| `owasp` | texto | Identificadores OWASP separados por barra vertical. Vacío en casos no vulnerables. |
| `content` | texto | Línea de código o configuración que se transforma para entrenar. |

El modelo recibe características derivadas solo de `content`. Los campos de procedencia, la partición y las etiquetas se excluyen de la entrada. El indicador `api_context` se usa para evaluar la correspondencia de etiquetas. En la CLI se obtiene mediante una heurística de contexto a partir de la ruta y del texto del archivo.
