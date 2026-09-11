"""
Tests unitaires du detecteur SSRF cloud
(api_sentinel.detectors.ssrf_cloud).

Deux aspects critiques a couvrir sans reseau :
  1. le reperage des champs de type URL dans une spec OpenAPI
     (query params et corps de requete) ;
  2. le filtre anti-faux-positif par echo : une signature qui serait
     une sous-chaine de l'URL injectee ne doit JAMAIS pouvoir
     declencher un finding, sinon un endpoint qui se contente de
     refleter l'URL soumise compterait a tort comme vulnerable.
"""

from api_sentinel.detectors.ssrf_cloud import (
    CloudMetadataTarget,
    URLFieldDiscovery,
    extract_role_name,
    summarize_credentials,
)


# --- CloudMetadataTarget : filtre anti-echo et detection de signature ---

def test_signature_that_is_a_substring_of_the_url_is_dropped():
    target = CloudMetadataTarget(
        provider="aws",
        url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        response_signatures=["security-credentials", "AccessKeyId"],
    )
    # "security-credentials" apparait litteralement dans l'URL : ecarte.
    assert "security-credentials" not in target.response_signatures
    assert "AccessKeyId" in target.response_signatures


def test_echo_of_the_injected_url_is_never_a_match():
    target = CloudMetadataTarget(
        provider="aws",
        url="http://169.254.169.254/latest/meta-data/",
        response_signatures=["ami-id", "instance-id"],
    )
    # L'endpoint se contente de renvoyer l'URL soumise (comportement
    # normal d'un champ "webhook_url" non vulnerable).
    echoed_response = '{"webhook_url": "http://169.254.169.254/latest/meta-data/"}'
    assert target.matches(echoed_response) == []


def test_real_metadata_content_is_detected():
    target = CloudMetadataTarget(
        provider="aws",
        url="http://169.254.169.254/latest/meta-data/",
        response_signatures=["ami-id", "instance-id", "local-ipv4"],
    )
    real_response = "ami-id\nami-launch-index\ninstance-id\nlocal-ipv4\nmac\n"
    matches = target.matches(real_response)
    assert set(matches) == {"ami-id", "instance-id", "local-ipv4"}


def test_matching_is_case_insensitive():
    target = CloudMetadataTarget(
        provider="azure",
        url="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        response_signatures=["subscriptionId", "vmId"],
    )
    response = '{"compute":{"SUBSCRIPTIONID":"abc-123","vmid":"xyz"}}'
    assert set(target.matches(response)) == {"subscriptionId", "vmId"}


def test_empty_response_never_matches():
    target = CloudMetadataTarget(
        provider="aws", url="http://169.254.169.254/latest/meta-data/",
        response_signatures=["ami-id"],
    )
    assert target.matches("") == []
    assert target.matches(None) == []


# --- URLFieldDiscovery : reperage des points d'injection ---

def _discovery(tmp_path, raw_spec):
    keywords_path = tmp_path / "keywords.yaml"
    keywords_path.write_text(
        "url_field_keywords:\n  - url\n  - webhook\n  - callback\n  - image\n",
        encoding="utf-8",
    )
    return URLFieldDiscovery(raw_spec, str(keywords_path))


def test_query_param_with_uri_format_is_detected(tmp_path):
    discovery = _discovery(tmp_path, {})
    endpoint = _fake_endpoint(parameters=[
        {"name": "target", "in": "query", "schema": {"type": "string", "format": "uri"}},
    ])
    assert discovery.find_query_params(endpoint) == ["target"]


def test_query_param_matched_by_keyword_is_detected(tmp_path):
    discovery = _discovery(tmp_path, {})
    endpoint = _fake_endpoint(parameters=[
        {"name": "callback_url", "in": "query", "schema": {"type": "string"}},
    ])
    assert discovery.find_query_params(endpoint) == ["callback_url"]


def test_non_string_query_param_is_never_flagged_even_with_matching_name(tmp_path):
    discovery = _discovery(tmp_path, {})
    endpoint = _fake_endpoint(parameters=[
        {"name": "webhook_id", "in": "query", "schema": {"type": "integer"}},
    ])
    assert discovery.find_query_params(endpoint) == []


def test_path_and_header_params_are_ignored(tmp_path):
    discovery = _discovery(tmp_path, {})
    endpoint = _fake_endpoint(parameters=[
        {"name": "url", "in": "path", "schema": {"type": "string"}},
        {"name": "url", "in": "header", "schema": {"type": "string"}},
    ])
    assert discovery.find_query_params(endpoint) == []


def test_body_field_with_uri_format_is_detected(tmp_path):
    raw_spec = {}
    discovery = _discovery(tmp_path, raw_spec)
    operation = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "avatar_url": {"type": "string", "format": "uri"},
                        },
                    }
                }
            }
        }
    }
    assert discovery.find_body_fields(operation) == ["avatar_url"]


def test_body_field_resolved_via_ref_is_detected(tmp_path):
    raw_spec = {
        "components": {
            "schemas": {
                "Profile": {
                    "type": "object",
                    "properties": {
                        "nickname": {"type": "string"},
                        "webhook": {"type": "string"},
                    },
                }
            }
        }
    }
    discovery = _discovery(tmp_path, raw_spec)
    operation = {
        "requestBody": {
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Profile"}}
            }
        }
    }
    assert discovery.find_body_fields(operation) == ["webhook"]


def test_operation_without_request_body_returns_nothing(tmp_path):
    discovery = _discovery(tmp_path, {})
    assert discovery.find_body_fields({}) == []


def test_body_field_detected_via_whole_body_example_despite_unrelated_name(tmp_path):
    # Reproduit le champ "mechanic_api" de crAPI : ni mot-cle dans le
    # nom, ni format: uri declare, mais l'exemple global du corps de
    # requete montre une vraie URL - c'est le vecteur SSRF documente
    # de crAPI, il ne doit pas passer inapercu.
    raw_spec = {}
    discovery = _discovery(tmp_path, raw_spec)
    operation = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "mechanic_code": {"type": "string"},
                            "mechanic_api": {"type": "string"},
                        },
                    },
                    "example": {
                        "mechanic_code": "TRAC_JHN",
                        "mechanic_api": "http://localhost:8000/workshop/api/mechanic/receive_report",
                    },
                }
            }
        }
    }
    assert discovery.find_body_fields(operation) == ["mechanic_api"]


def _fake_endpoint(parameters):
    class _Endpoint:
        pass

    ep = _Endpoint()
    ep.parameters = parameters
    return ep


# --- CloudMetadataTarget : chainage IAM (config) ---

def test_target_without_iam_urls_does_not_support_chaining():
    target = CloudMetadataTarget(
        provider="gcp", url="http://169.254.169.254/computeMetadata/v1/",
        response_signatures=["oslogin/"],
    )
    assert target.supports_iam_chaining() is False


def test_target_with_both_iam_urls_supports_chaining():
    target = CloudMetadataTarget(
        provider="aws", url="http://169.254.169.254/latest/meta-data/",
        response_signatures=["ami-id"],
        iam_role_list_url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        iam_credentials_url_template="http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
    )
    assert target.supports_iam_chaining() is True


# --- extract_role_name : reperage best-effort d'un nom de role ---

def test_extract_role_name_from_plain_text_response():
    assert extract_role_name("my-app-instance-role\n") == "my-app-instance-role"


def test_extract_role_name_skips_common_json_wrapper_keys():
    assert extract_role_name('{"data": "my-app-instance-role"}') == "my-app-instance-role"


def test_extract_role_name_returns_none_for_empty_response():
    assert extract_role_name("") is None
    assert extract_role_name(None) is None


def test_extract_role_name_skips_pure_numeric_tokens():
    assert extract_role_name("404 12345") is None


# --- summarize_credentials : preuve masquee, jamais le secret reel ---

def test_summarize_credentials_requires_both_access_key_and_secret():
    only_access_key = '{"AccessKeyId": "ASIAABCDEFGHIJKLMNOP"}'
    assert summarize_credentials(only_access_key) is None


def test_summarize_credentials_returns_none_without_access_key_pattern_match():
    # "AccessKeyId" et "SecretAccessKey" presents comme simples mots,
    # mais pas sous une forme cle:valeur exploitable.
    assert summarize_credentials("mentions AccessKeyId and SecretAccessKey only") is None


def test_summarize_credentials_masks_the_access_key_and_hides_the_secret():
    full_response = (
        '{"Code":"Success","AccessKeyId":"ASIAABCDEFGHIJKLMNOP",'
        '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",'
        '"Token":"FQoGZXIvYXdzE...","Expiration":"2026-09-12T00:00:00Z"}'
    )
    proof = summarize_credentials(full_response)

    assert proof["access_key_id_masked"] == "ASIA...MNOP"
    assert proof["secret_access_key_present"] is True
    assert proof["session_token_present"] is True
    assert proof["expiration"] == "2026-09-12T00:00:00Z"

    # La cle secrete et le jeton de session reels ne doivent jamais
    # apparaitre dans le resume (ENF5).
    proof_text = str(proof)
    assert "wJalrXUtnFEMI" not in proof_text
    assert "FQoGZXIvYXdzE" not in proof_text


def test_summarize_credentials_without_token_or_expiration():
    response = '{"AccessKeyId":"ASIAABCDEFGHIJKLMNOP","SecretAccessKey":"secretvalue"}'
    proof = summarize_credentials(response)

    assert proof["session_token_present"] is False
    assert proof["expiration"] is None
