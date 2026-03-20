from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

with open("server_public.pem", "rb") as f:
    PUBLIC_KEY = f.read()

@app.route("/api/v1/admin/users", methods=["GET"])
def admin_users():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "No token"}), 401

    token = auth.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"]
        )
        return jsonify({"users": ["admin", "user1", "user2"]}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 401

if __name__ == "__main__":
    app.run(port=5001)
