from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette_csrf import CSRFMiddleware
import httpx
import os
from typing import Optional

app = FastAPI(title="Portal")

# Session middleware debe ir primero
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "your-secret-key-change-in-production"))

# CSRF middleware
app.add_middleware(
    CSRFMiddleware,
    secret=os.getenv("SESSION_SECRET", "your-secret-key-change-in-production"),
    cookie_name="csrf_token",
    cookie_secure=False,  # Cambiar a True en producción con HTTPS
    cookie_samesite="lax",
    header_name="X-CSRF-Token"
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

KEYCLOAK_URL_PUBLIC = os.getenv("KEYCLOAK_URL_PUBLIC", "http://localhost:8080")
KEYCLOAK_URL_INTERNAL = os.getenv("KEYCLOAK_URL_INTERNAL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "portal")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "portal-client")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8100/callback")
BASE_PATH = os.getenv("BASE_PATH", "/portal")


def get_current_user(request: Request) -> Optional[dict]:
    return request.session.get("user")


def require_auth(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return user


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url=f"{BASE_PATH}/home")
    
    auth_url = (
        f"{KEYCLOAK_URL_PUBLIC}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
        f"?client_id={KEYCLOAK_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid profile email"
    )
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "auth_url": auth_url,
        "base_path": BASE_PATH,
        "authenticated": False,
        "user": None
    })


@app.get("/callback")
async def callback(request: Request, code: str):
    token_url = f"{KEYCLOAK_URL_INTERNAL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            token_response = await client.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "client_id": KEYCLOAK_CLIENT_ID,
                    "client_secret": KEYCLOAK_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": REDIRECT_URI
                }
            )
            
            if token_response.status_code != 200:
                error_detail = token_response.text
                raise HTTPException(status_code=400, detail=f"Token exchange failed: {error_detail}")
            
            tokens = token_response.json()
            access_token = tokens.get("access_token")
            
            if not access_token:
                raise HTTPException(status_code=400, detail="No access token received")
            
            userinfo_url = f"{KEYCLOAK_URL_INTERNAL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
            userinfo_response = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if userinfo_response.status_code != 200:
                error_detail = userinfo_response.text
                raise HTTPException(status_code=400, detail=f"Failed to get user info: {error_detail}")
            
            user_info = userinfo_response.json()
            request.session["user"] = user_info
            request.session["access_token"] = access_token
        
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Timeout connecting to Keycloak")
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Connection error: {str(e)}")
    
    return RedirectResponse(url=f"{BASE_PATH}/home")


@app.get("/home", response_class=HTMLResponse)
async def home(request: Request, user: dict = Depends(require_auth)):
    return templates.TemplateResponse("home.html", {
        "request": request,
        "user": user,
        "base_path": BASE_PATH,
        "authenticated": True
    })


@app.get("/logout")
async def logout(request: Request):
    access_token = request.session.get("access_token")
    request.session.clear()
    
    if access_token:
        redirect_base = REDIRECT_URI.rsplit('/callback', 1)[0]
        post_logout_redirect = f"{redirect_base}/"
        
        logout_url = (
            f"{KEYCLOAK_URL_PUBLIC}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
            f"?post_logout_redirect_uri={post_logout_redirect}"
            f"&client_id={KEYCLOAK_CLIENT_ID}"
        )
        return RedirectResponse(url=logout_url, status_code=302)
    
    return RedirectResponse(url=f"{BASE_PATH}/", status_code=302)


@app.get("/health")
async def health():
    return {"status": "healthy"}