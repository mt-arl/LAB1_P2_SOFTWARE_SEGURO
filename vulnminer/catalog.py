"""Taxonomías versionadas y correspondencias para los patrones del laboratorio."""

from dataclasses import dataclass

WEB = {
    "A01:2025": "Control de acceso roto",
    "A02:2025": "Configuración de seguridad incorrecta",
    "A03:2025": "Fallas en la cadena de suministro de software",
    "A04:2025": "Fallas criptográficas",
    "A05:2025": "Inyección",
    "A06:2025": "Diseño inseguro",
    "A07:2025": "Fallas de autenticación",
    "A08:2025": "Fallas de integridad del software o los datos",
    "A09:2025": "Fallas en el registro y las alertas de seguridad",
    "A10:2025": "Manejo inadecuado de condiciones excepcionales",
}
API = {
    "API1:2023": "Autorización rota a nivel de objeto",
    "API2:2023": "Autenticación rota",
    "API3:2023": "Autorización rota a nivel de propiedades del objeto",
    "API4:2023": "Consumo de recursos sin restricciones",
    "API5:2023": "Autorización rota a nivel de función",
    "API6:2023": "Acceso sin restricciones a flujos de negocio sensibles",
    "API7:2023": "Falsificación de solicitudes del lado del servidor",
    "API8:2023": "Configuración de seguridad incorrecta",
    "API9:2023": "Inventario inadecuado de API",
    "API10:2023": "Consumo inseguro de API",
}
STANDARDS = {"owasp2025": WEB, "api2023": API}


@dataclass(frozen=True)
class Control:
    web: str
    api: str
    cwe: str
    description: str
    severity: str
    impact: str
    remediation: str


CONTROLS = {
    "ownership": Control(
        "A01:2025", "API1:2023", "CWE-283",
        "Posible desactivación de la comprobación de propiedad de objetos.",
        "alta", "Si se aplica a objetos privados, podría permitir acceso entre cuentas.",
        "Exigir autorización del lado del servidor para cada objeto y operación; "
        "revisar cómo se vincula el acceso a la identidad autenticada.",
    ),
    "debug": Control(
        "A02:2025", "API8:2023", "CWE-489",
        "Posible modo de depuración o diagnóstico detallado habilitado.",
        "media", "En un entorno expuesto, el diagnóstico puede revelar detalles internos.",
        "Desactivar la depuración en despliegues y enviar diagnósticos detallados "
        "a registros internos con control de acceso.",
    ),
    "transport": Control(
        "A04:2025", "", "CWE-319",
        "Posible política de transporte sin cifrado obligatorio.",
        "media", "Si el canal transporta información sensible, su confidencialidad puede verse afectada.",
        "Exigir HTTPS/TLS en la comunicación y comprobar la configuración efectiva "
        "en el proxy y en los servicios internos.",
    ),
    "rate_limit": Control(
        "A06:2025", "API4:2023", "CWE-799",
        "Posible desactivación o ausencia de un límite declarado de frecuencia.",
        "media", "Las operaciones costosas podrían afectar la disponibilidad del servicio.",
        "Definir límites por identidad y operación, aplicarlos de forma centralizada "
        "y revisar los límites efectivos del gateway.",
    ),
    "expiration": Control(
        "A07:2025", "API2:2023", "CWE-613",
        "Posible política que omite la expiración de sesión o token.",
        "alta", "Si controla sesiones activas, puede prolongar el uso de una sesión comprometida.",
        "Exigir expiración explícita, verificarla del lado del servidor y definir "
        "invalidación y renovación según el flujo de autenticación.",
    ),
}
LABELS = tuple(CONTROLS)


def categories(label, api_context):
    control = CONTROLS[label]
    codes = (control.web,)
    return codes + (control.api,) if api_context and control.api else codes
