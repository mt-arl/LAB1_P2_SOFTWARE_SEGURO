"""Declaraciones de política del servicio de identidad."""

require_api_token_expiration = False
identity_service_tls_required = False
identity_debug_output = False

def service_metadata():
    return {"service": "identity", "version": "v1"}
