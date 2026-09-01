
import uuid
from flask import Flask, request, jsonify

app = Flask(__name__)

KNOWN_USERS = {
    "admin@test.local": {"password": "TestPassword123!", "role": "admin"},
    "attacker1@test.local": {"password": "TestPassword123!", "role": "user"},
    "attacker2@test.local": {"password": "TestPassword123!", "role": "guest"},
}

TOKENS: dict[str, str] = {}

FACTURES: dict[str, dict] = {}


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = KNOWN_USERS.get(email)
    if user and user["password"] == password:
        fake_token = f"fake-jwt-token-for-{email}"
        TOKENS[fake_token] = email
        return jsonify({"token": fake_token}), 200

    return jsonify({"error": "Identifiants invalides"}), 401


def _current_user_from_request():
    
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.removeprefix("Bearer ")
    email = TOKENS.get(token)
    if not email:
        return None

    return {"email": email, "role": KNOWN_USERS[email]["role"]}


@app.route("/auth/me", methods=["GET"])
def me():
   
    user = _current_user_from_request()
    if not user:
        return jsonify({"error": "Non authentifie"}), 401

    return jsonify({"email": user["email"], "role": user["role"]}), 200

@app.route("/admin/users", methods=["GET"])
def admin_list_users():
    user = _current_user_from_request()
    if not user:
        return jsonify({"error": "Non authentifie"}), 401

    if user["role"] != "admin":
        return jsonify({"error": "Acces refuse"}), 403

    return jsonify({"users": list(KNOWN_USERS.keys())}), 200


@app.route("/factures", methods=["POST"])
def create_facture():
    user = _current_user_from_request()
    if not user:
        return jsonify({"error": "Non authentifie"}), 401

    data = request.get_json()
    if not data or "montant" not in data or "description" not in data:
        return jsonify({"error": "Champs requis manquants"}), 422

    facture_id = str(uuid.uuid4())
    facture = {
        "id": facture_id,
        "montant": data["montant"],
        "description": data["description"],
        "devise": data.get("devise", "EUR"),
        "dateEmission": data.get("dateEmission"),
        "owner_token": request.headers.get("Authorization", ""),
    }
    FACTURES[facture_id] = facture

    return jsonify(facture), 201


@app.route("/factures/<facture_id>", methods=["GET"])
def get_facture(facture_id):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Non authentifie"}), 401

    facture = FACTURES.get(facture_id)
    if not facture:
        return jsonify({"error": "Facture introuvable"}), 404

    if facture["owner_token"] != auth_header:
        return jsonify({"error": "Acces refuse"}), 403

    return jsonify(facture), 200


if __name__ == "__main__":
    app.run(host="localhost", port=8080)