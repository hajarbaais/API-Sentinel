

import json
import yaml
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Endpoint:
    
    path: str                         
    method: str                       
    parameters: list                   
    summary: str = ""                 
    has_path_param: bool = False       
    def __repr__(self):
        return f"{self.method} {self.path}"


class OpenAPIParser:
 
    HTTP_METHODS = ["get", "post", "put", "patch", "delete"]

    def __init__(self, spec_path: str):
        self.spec_path = Path(spec_path)
        self.raw_spec = self._load_spec()

    def _load_spec(self) -> dict:
        
        if not self.spec_path.exists():
            raise FileNotFoundError(f"Fichier introuvable : {self.spec_path}")

        content = self.spec_path.read_text(encoding="utf-8")

        if self.spec_path.suffix in [".yaml", ".yml"]:
            return yaml.safe_load(content)
        elif self.spec_path.suffix == ".json":
            return json.loads(content)
        else:
            raise ValueError(
                f"Extension non supportée : {self.spec_path.suffix}. "
                "Utilise un fichier .yaml, .yml ou .json"
            )

    def parse(self) -> list[Endpoint]:
       
        endpoints = []
        paths = self.raw_spec.get("paths", {})

        for path, path_item in paths.items():
            shared_params = path_item.get("parameters", [])

            for method in self.HTTP_METHODS:
                if method not in path_item:
                    continue

                operation = path_item[method]
                method_params = operation.get("parameters", [])
                all_params = shared_params + method_params

                endpoint = Endpoint(
                    path=path,
                    method=method.upper(),
                    parameters=all_params,
                    summary=operation.get("summary", ""),
                    has_path_param=self._has_path_parameter(path, all_params),
                )
                endpoints.append(endpoint)

        return endpoints

    def _has_path_parameter(self, path: str, parameters: list) -> bool:
      
        if "{" in path and "}" in path:
            return True
        return False


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage : python openapi_parser.py chemin/vers/openapi.yaml")
        sys.exit(1)

    parser = OpenAPIParser(sys.argv[1])
    endpoints = parser.parse()

    print(f"\n{len(endpoints)} endpoint(s) trouve(s) :\n")
    for ep in endpoints:
        marker = "[BOLA-CANDIDATE]" if ep.has_path_param else "                "
        print(f"{marker} {ep}")