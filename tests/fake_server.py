
import uuid
from flask import Flask, request, jsonify

app = Flask(__name__)

KNOWN_USERS = {
    "victim@test.local": "TestPassword123!",
    "attacker1@test.local": "TestPassword123!",
    "attacker2@test.local": "TestPassword123!",
}


FACTURES: dict[str, dict] = {}


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if email in KNOWN_USERS and KNOWN_USERS[email] == password:
        fake_token = f"fake-jwt-token-for-{email}"
        return jsonify({"token": fake_token}), 200

    return jsonify({"error": "Identifiants invalides"}), 401


@app.route("/factures", methods=["POST"])
def create_facture():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
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
        "owner_token": auth_header,  # utile plus tard pour simuler BOLA
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

    # Verification de propriete ajoutee : le token doit correspondre
    # exactement a celui utilise lors de la creation de la facture.
    if facture["owner_token"] != auth_header:
        return jsonify({"error": "Acces refuse"}), 403

    return jsonify(facture), 200


if __name__ == "__main__":
    app.run(host="localhost", port=8080)