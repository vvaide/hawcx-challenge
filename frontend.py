import flet as ft
from flet import (
    Page,
    Row,
    Column,
    TextField,
    Container,
    ControlEvent,
    Colors,
    app,
)
from webauthn import (
    options_to_json,
    base64url_to_bytes,
    options_to_json,
)
from webauthn.helpers.structs import (
    UserVerificationRequirement,
    AuthenticatorAttachment,
    RegistrationCredential,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialParameters,   
)
import httpx, json
import logging

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

BACKEND_URL = "https://localhost:8000"

class Login(Container):
    def __init__(self):
        super().__init__()
        self.width = 400
        self.height = 250
        self.email = TextField(
            label="Email",
            text_align=ft.TextAlign.LEFT,
            border_color=Colors.WHITE,
            on_submit=self.authenticate_user,
        )
        self.submit_button = ft.ElevatedButton(
            "Authenticate & Submit",
            on_click=self.authenticate_user,
            disabled=False
        )
        self.register_button = ft.ElevatedButton(
            "Register",
            on_click=self.register_user,
            disabled=False
        )
        self.status_text = ft.Text("", color=Colors.RED)
        self.content = Column(
            controls=[
                self.email, 
                Row(
                    controls=[self.register_button, self.submit_button],
                    alignment=ft.MainAxisAlignment.CENTER,
                ),
                self.status_text
            ],
            alignment=ft.MainAxisAlignment.CENTER,
        )

    async def get_challenge(self, email: str) -> str:
        async with httpx.AsyncClient(verify=False) as client:
            logger.warning(f"log >>> - Sending challenge request to {BACKEND_URL}/challenge")
            response = await client.post(f"{BACKEND_URL}/challenge", json={"email": email})
            logger.warning(f"log >>> - Response: {response.json()}")
            return response.json()["challenge"]

    async def send_registration(self, email: str, credential: str) -> None:
        logger.warning(f"log >>> - Sending registration request to {BACKEND_URL}/register")
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{BACKEND_URL}/register", 
                json={"email": email, "credential": credential}
            )
            logger.warning(f"log >>> - Response: {response.json()}")
            return response.json() 

    async def register_user(self, event: ControlEvent) -> None:
        logger.warning("log >>> - Registering user")
        if not self.email.value:
            logger.warning("log >>> - No email provided")
            self.status_text.value = "Please enter your email"
            self.status_text.color = Colors.RED
            self.update()
            logger.warning("log >>> - Exiting register_user")
            return
        
        self.status_text.value = "Starting biometric registration..."
        self.status_text.color = Colors.WHITE12
        self.update()
        
        # get challenge from server
        challenge = await self.get_challenge(self.email.value)
        logger.warning(f"log >>> - Challenge: {challenge}")

        # navigator.credentials.create
        pub_key = PublicKeyCredentialCreationOptions(
            challenge=challenge.encode("utf-8"),
            rp=PublicKeyCredentialRpEntity( # relying party
                id="localhost",
                name="Hawcx Challenge",
            ),
            user=PublicKeyCredentialUserEntity(
                id=self.email.value.encode("utf-8"), # not meant to be human readable
                name=self.email.value,
                display_name=self.email.value,
            ),
            pub_key_cred_params=[
                PublicKeyCredentialParameters(
                    type="public-key",
                    alg=-7,
                )
            ],
            timeout=30000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),            
        )
        reg_cred = RegistrationCredential(
            id=base64url_to_bytes(challenge),
            raw_id=base64url_to_bytes(challenge),
            response={
                
            },
            type="public-key",
        )
        pub_key.credentials.append(reg_cred)
        
        # convert to json
        pub_key_json = options_to_json(pub_key)
        logger.warning(f"log >>> - Options: {pub_key_json}")
        
        # send options to server
        res = await self.send_registration(self.email.value, pub_key_json)
        logger.warning(f"log >>> - Response: {res}")
        res = json.loads(res)
        if not res["success"]:
            self.status_text.value = "Registration failed"
            self.status_text.color = Colors.RED
            self.update()
            logger.warning("log >>> - Exiting register_user")
            return

        self.status_text.value = "Registration successful"
        self.status_text.color = Colors.GREEN
        self.update()
        logger.warning("log >>> - Exiting register_user")

    def authenticate_user(self, event: ControlEvent) -> None:
        if not self.email.value:
            self.status_text.value = "Please enter your email"
            self.status_text.color = Colors.RED
            self.update()
            return
        
        self.status_text.value = "Starting biometric authentication..."
        self.update()
        
def main(page: Page) -> None:
    logger.warning("log >>> - Starting app")
    page.title = "Hawcx Challenge"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.theme_mode = ft.ThemeMode.DARK
    logger.warning("log >>> - Adding login page")
    page.add(Login())
    logger.warning("log >>> - Exiting main")

if __name__ == "__main__":
    logger.warning("log >>> - Starting app")
    app(target=main, view=ft.AppView.WEB_BROWSER)