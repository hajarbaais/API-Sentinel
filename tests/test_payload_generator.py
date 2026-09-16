"""
Tests unitaires cibles de PayloadGenerator.generate_multipart_for_request_body
(api_sentinel.fixtures.payload_generator) - capacite ajoutee pour
couvrir les endpoints d'upload de fichier (multipart/form-data), non
geres par generate_for_request_body (JSON uniquement). Benchmark
crapi-5 (crAPI /user/pictures, /user/videos).
"""

from api_sentinel.fixtures.payload_generator import (
    PLACEHOLDER_BINARY_FILE,
    PayloadGenerator,
)


def _operation_with_multipart_schema(schema: dict) -> dict:
    return {
        "requestBody": {
            "content": {
                "multipart/form-data": {"schema": schema},
            }
        }
    }


def test_binary_field_gets_a_valid_placeholder_file():
    generator = PayloadGenerator({})
    operation = _operation_with_multipart_schema(
        {"type": "object", "properties": {"file": {"type": "string", "format": "binary"}}}
    )
    files = generator.generate_multipart_for_request_body(operation)
    assert files["file"] == ("sentinel-test.gif", PLACEHOLDER_BINARY_FILE, "image/gif")


def test_non_binary_field_is_generated_as_a_string_tuple():
    generator = PayloadGenerator({})
    operation = _operation_with_multipart_schema(
        {"type": "object", "properties": {"caption": {"type": "string"}}}
    )
    files = generator.generate_multipart_for_request_body(operation)
    field_name, value = files["caption"]
    assert field_name is None
    assert isinstance(value, str)


def test_no_request_body_returns_none():
    generator = PayloadGenerator({})
    assert generator.generate_multipart_for_request_body({}) is None


def test_json_only_operation_returns_none():
    generator = PayloadGenerator({})
    operation = {
        "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}
    }
    assert generator.generate_multipart_for_request_body(operation) is None


def test_ref_schema_is_resolved(tmp_path):
    raw_spec = {
        "components": {
            "schemas": {
                "Upload": {
                    "type": "object",
                    "properties": {"file": {"type": "string", "format": "binary"}},
                }
            }
        }
    }
    generator = PayloadGenerator(raw_spec)
    operation = _operation_with_multipart_schema({"$ref": "#/components/schemas/Upload"})
    files = generator.generate_multipart_for_request_body(operation)
    assert "file" in files


def test_unresolvable_ref_returns_none():
    generator = PayloadGenerator({})
    operation = _operation_with_multipart_schema({"$ref": "#/components/schemas/Missing"})
    assert generator.generate_multipart_for_request_body(operation) is None


def test_empty_properties_returns_none():
    generator = PayloadGenerator({})
    operation = _operation_with_multipart_schema({"type": "object", "properties": {}})
    assert generator.generate_multipart_for_request_body(operation) is None
