
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# GIF 1x1 transparent minimal mais VALIDE (magic bytes GIF89a corrects) -
# pour satisfaire une eventuelle validation basique de type MIME cote
# serveur sur un endpoint d'upload d'image/video, sans avoir a generer
# un vrai fichier multimedia.
PLACEHOLDER_BINARY_FILE = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04"
    b"\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)


class SchemaResolutionError(Exception):

    pass


class PayloadGenerator:
    
    MAX_DEPTH = 6

    def __init__(self, raw_spec: dict):
        self.raw_spec = raw_spec
        self.components = raw_spec.get("components", {}).get("schemas", {})

    def generate_for_request_body(self, operation: dict) -> dict | None:
       
        request_body = operation.get("requestBody")
        if not request_body:
            return None

        content = request_body.get("content", {})
        json_content = content.get("application/json")
        if not json_content:
            logger.debug(
                "Pas de contenu application/json pour cet endpoint, "
                "generation de payload ignoree."
            )
            return None

        schema = json_content.get("schema")
        if not schema:
            return None

        try:
            return self._generate_value(schema, depth=0)
        except SchemaResolutionError as exc:
            logger.warning("Echec de generation de payload : %s", exc)
            return None

    def generate_multipart_for_request_body(self, operation: dict) -> Optional[dict]:
        """
        Genere les champs d'un formulaire `multipart/form-data` (upload
        de fichier), au format attendu par `requests` pour son parametre
        `files=` - pas `json=`. Complementaire de
        `generate_for_request_body` (qui ne gere que
        `application/json` et retourne None sur ce type de contenu) :
        les deux methodes restent separees pour ne rien changer au
        contrat des appelants existants qui n'ont besoin que du JSON.

        Un champ `format: binary` recoit un petit fichier image PLACEHOLDER
        valide (cf. PLACEHOLDER_BINARY_FILE) plutot que des octets
        arbitraires, pour maximiser les chances de passer une validation
        basique de type MIME cote serveur (upload de photo/video).
        """
        request_body = operation.get("requestBody")
        if not request_body:
            return None

        multipart_content = request_body.get("content", {}).get("multipart/form-data")
        if not multipart_content:
            return None

        schema = multipart_content.get("schema")
        if not schema:
            return None

        if "$ref" in schema:
            try:
                schema = self._resolve_ref(schema["$ref"])
            except SchemaResolutionError as exc:
                logger.warning("Echec de generation de payload multipart : %s", exc)
                return None

        properties = schema.get("properties", {})
        files: dict[str, Any] = {}

        for field_name, field_schema in properties.items():
            if field_schema.get("format") == "binary":
                files[field_name] = (
                    "sentinel-test.gif", PLACEHOLDER_BINARY_FILE, "image/gif",
                )
                continue
            try:
                value = self._generate_value(field_schema, depth=0)
            except SchemaResolutionError:
                logger.debug(
                    "Champ multipart '%s' ignore (generation impossible).",
                    field_name,
                )
                continue
            # Un champ texte multipart doit etre une chaine - `requests`
            # n'accepte pas un int/bool/dict tel quel dans `files=`.
            files[field_name] = (None, str(value))

        return files or None

    def _resolve_ref(self, ref: str) -> dict:
        
        if not ref.startswith("#/components/schemas/"):
            raise SchemaResolutionError(
                f"Reference non supportee (seules les references locales "
                f"vers components/schemas sont geres) : {ref}"
            )

        schema_name = ref.split("/")[-1]
        resolved = self.components.get(schema_name)

        if resolved is None:
            raise SchemaResolutionError(
                f"Schema reference introuvable : {schema_name}"
            )

        return resolved

    def _generate_value(self, schema: dict, depth: int) -> Any:
        
        if depth > self.MAX_DEPTH:
            raise SchemaResolutionError(
                "Profondeur d'imbrication maximale atteinte "
                "(schema probablement recursif)."
            )

       
        if "$ref" in schema:
            resolved = self._resolve_ref(schema["$ref"])
            return self._generate_value(resolved, depth + 1)

        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]

        if "enum" in schema and schema["enum"]:
            return schema["enum"][0]

        schema_type = schema.get("type", "object")

        if schema_type == "object":
            return self._generate_object(schema, depth)
        elif schema_type == "array":
            return self._generate_array(schema, depth)
        elif schema_type == "string":
            return self._generate_string(schema)
        elif schema_type == "integer":
            return self._generate_integer(schema)
        elif schema_type == "number":
            return self._generate_number(schema)
        elif schema_type == "boolean":
            return True

        logger.warning("Type de schema inconnu '%s', valeur None utilisee.", schema_type)
        return None

    def _generate_object(self, schema: dict, depth: int) -> dict:
        """
        Genere un objet JSON en remplissant en priorite les champs
        listes comme 'required'. Les champs optionnels sont aussi
        remplis par defaut, car les rendre absents systematiquement
        reduirait les chances que la creation reussisse sur certaines API.
        """
        properties = schema.get("properties", {})
        result = {}

        for field_name, field_schema in properties.items():
            try:
                result[field_name] = self._generate_value(field_schema, depth + 1)
            except SchemaResolutionError as exc:
                required_fields = schema.get("required", [])
                if field_name in required_fields:
                    
                    raise SchemaResolutionError(
                        f"Champ obligatoire '{field_name}' impossible a generer : {exc}"
                    ) from exc
                logger.debug(
                    "Champ optionnel '%s' ignore (generation impossible).",
                    field_name,
                )

        return result

    def _generate_array(self, schema: dict, depth: int) -> list:
       
        items_schema = schema.get("items")
        if not items_schema:
            return []
        return [self._generate_value(items_schema, depth + 1)]

    def _generate_string(self, schema: dict) -> str:
       
        fmt = schema.get("format")
        unique_suffix = uuid.uuid4().hex[:8]

        if fmt == "email":
            return f"sentinel.test.{unique_suffix}@example.com"
        elif fmt == "uuid":
            return str(uuid.uuid4())
        elif fmt == "date":
            return datetime.now(timezone.utc).date().isoformat()
        elif fmt == "date-time":
            return datetime.now(timezone.utc).isoformat()
        elif fmt == "uri":
            return f"https://example.com/{unique_suffix}"

        min_length = schema.get("minLength", 1)
        base = f"sentinel-test-{unique_suffix}"
        if len(base) < min_length:
            base = base.ljust(min_length, "x")
        return base

    def _generate_integer(self, schema: dict) -> int:
        minimum = schema.get("minimum", 1)
        maximum = schema.get("maximum", minimum + 100)
        return min(max(minimum, 1), maximum)

    def _generate_number(self, schema: dict) -> float:
        minimum = schema.get("minimum", 1.0)
        maximum = schema.get("maximum", minimum + 100.0)
        return float(min(max(minimum, 1.0), maximum))