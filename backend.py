from flask import Flask, request, jsonify
import random, base64
from webauthn.helpers.structs import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    PublicKeyCredentialDescriptor,
    AuthenticatorAttachment,
    
)
from webauthn import (
    verify_registration_response,
    options_to_json,
    base64url_to_bytes
    
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

app = Flask(__name__)

# In-memory storage for simplicity
users = {}
def options_to_dict(options: PublicKeyCredentialCreationOptions) -> dict:
    """
    Function to help convert PublicKeyCredentialCreationOptions 
    to a dictionary
    """
    return {
        "rp": {
            "id": options.rp.id,
            "name": options.rp.name,
        },
        "user": {
            "id": base64.urlsafe_b64encode(options.user.id).decode("utf-8"),
            "name": options.user.name,
            "display_name": options.user.display_name,
        },
        "challenge":options.challenge,
        "authenticator_selection": {
            "authenticator_attachment": options.authenticator_selection.authenticator_attachment,
            "user_verification": options.authenticator_selection.user_verification,
        },
        "pub_key_cred_params": [
            {"type": param.type, "alg": param.alg} for param in options.pub_key_cred_params
        ],
        "timeout": options.timeout,
    }
    
def generate_challenge():
    challenge = base64.urlsafe_b64encode(random.randbytes(32)).decode("utf-8")
    return challenge

@app.route("/")
def index():
    return "Backend Server!!!"

@app.route("/challenge", methods=["POST"])
def send_challenge():
    print(">>>>>>>> Sending challenge to user")
    data = request.json
    email = data.get("email")
    
    if not email:
        return jsonify({"error": "Email is required"}), 400

    challenge = generate_challenge()
    users[email] = {
        "challenge": challenge,
    }
    return jsonify({"challenge": challenge})
    
@app.route("/register", methods=["POST"])
def register():
    # aleady sent challenge to user
    # just need to verify the response
    print(">>>>>>>> Registering user")
    res = request.json
    print(res)
    email: str = res.get("email")
    credential: str = res.get("credential")
    
    if not email or not credential:
        return jsonify({"error": "Email and credential are required"}), 400
    
    if email not in users:
        return jsonify({"error": "Email not found"}), 404
    
    _expected_challenge = users[email]["challenge"] 
    
    # verify registration
    print(">>>>>>>> Verifying registration")
    verified_registration: VerifiedRegistration = verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(_expected_challenge),
        expected_rp_id="localhost",
        expected_origin="https://localhost:8000",
        require_user_verification=True,
    )
    print(f"Verified Registration: {verified_registration}")
    valid = verified_registration.user_verified
    if not valid:
        return jsonify({"error": "User verification failed"}), 400
    return jsonify({"success": "User registered successfully"}), 200
    
if __name__ == "__main__":
    app.run(
        # host="0.0.0.0", 
        host="localhost",
        port=8000, 
        debug=True, 
        ssl_context=(
            "localhost.crt",
            "localhost.key"
        )
    )