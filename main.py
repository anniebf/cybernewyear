from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Table, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import os
import secrets

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./cyberpunk_missions.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Association table for many-to-many relationship
user_missions = Table('user_missions', Base.metadata,
                      Column('user_id', Integer, ForeignKey('users.id')),
                      Column('mission_id', Integer, ForeignKey('missions.id')),
                      Column('completed_at', DateTime, default=datetime.now)
                      )


# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    password = Column(String)  # Senha para login
    last_activity = Column(DateTime, default=datetime.now)
    session_token = Column(String, unique=True, index=True, nullable=True)
    completed_missions = relationship("Mission", secondary=user_missions, back_populates="completed_by")
    current_mission_id = Column(Integer, ForeignKey('missions.id'), nullable=True)
    current_mission = relationship("Mission", foreign_keys=[current_mission_id])


class Mission(Base):
    __tablename__ = "missions"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    order = Column(Integer, default=0)  # Ordem das missões
    completed_by = relationship("User", secondary=user_missions, back_populates="completed_missions")
    next_mission_id = Column(Integer, ForeignKey('missions.id'), nullable=True)  # Próxima missão na sequência


# Pydantic models
class UserCreate(BaseModel):
    name: str
    password: str


class UserLogin(BaseModel):
    name: str
    password: str


class MissionCreate(BaseModel):
    name: str
    description: str
    order: int = 0
    next_mission_id: Optional[int] = None


# Dependency para obter sessão do banco de dados
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Criar tabelas
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI(title="Cyberpunk Missions System")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Admin password (em produção, use hash e variáveis de ambiente)
ADMIN_PASSWORD = "netrunner2077"
SESSION_TIMEOUT = 300  # 5 minutos de inatividade


# Middleware para verificar sessão (somente para rotas de usuário específicas)
@app.middleware("http")
async def check_session(request: Request, call_next):
    # Rotas que NÃO precisam de autenticação (públicas)
    public_routes = [
        # Páginas HTML
        '/', '/ranking', '/admin', '/missions',

        # APIs públicas
        '/api/login', '/api/register', '/api/admin/login',
        '/api/ranking', '/api/missions', '/api/logout'
    ]

    # Rotas administrativas que precisam de sessão admin
    admin_routes = [
        '/api/admin/missions', '/api/admin/users',
        '/api/admin/missions/', '/api/admin/users/'
    ]

    # Rotas de usuário que PRECISAM de sessão (privadas)
    user_routes_need_session = [
        '/api/user/current',
        '/api/user/missions',
        '/api/user/complete-current'
    ]

    request_path = request.url.path

    # Verificar se é uma rota de usuário que precisa de sessão
    needs_session = any(request_path.startswith(route.replace('{user_id}', '').replace('{mission_id}', ''))
                        for route in user_routes_need_session)

    if needs_session:
        session_token = request.cookies.get("session_token")
        if session_token:
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.session_token == session_token).first()
                if user:
                    # Verificar timeout
                    if datetime.now() - user.last_activity > timedelta(seconds=SESSION_TIMEOUT):
                        # Sessão expirada
                        user.session_token = None
                        db.commit()
                        return Response(status_code=401, content="Sessão expirada")

                    # Atualizar última atividade
                    user.last_activity = datetime.now()
                    db.commit()

                    # Adicionar user ao request state
                    request.state.user = user
                    response = await call_next(request)
                    return response
            finally:
                db.close()

        # Sem sessão válida
        return Response(status_code=401, content="Sessão inválida ou expirada")

    # Para todas as outras rotas (públicas), permitir acesso
    response = await call_next(request)
    return response


# Função para obter usuário atual
def get_current_user(request: Request):
    if hasattr(request.state, 'user'):
        return request.state.user
    raise HTTPException(status_code=401, detail="Não autenticado")


# API Endpoints PÚBLICOS (não precisam de autenticação)

@app.get("/api/ranking")
def get_ranking(db: Session = Depends(get_db)):
    """Ranking público - todos podem ver"""
    users = db.query(User).all()
    ranking = []
    for user in users:
        ranking.append({
            "id": user.id,
            "name": user.name,
            "missions_completed": len(user.completed_missions),
            "current_mission": user.current_mission.name if user.current_mission else "Nenhuma"
        })
    ranking.sort(key=lambda x: x["missions_completed"], reverse=True)
    return ranking


@app.get("/api/missions")
def get_all_missions_public(db: Session = Depends(get_db)):
    """Lista de missões pública - todos podem ver"""
    missions = db.query(Mission).order_by(Mission.order).all()
    return [{
        "id": m.id,
        "name": m.name,
        "description": m.description,
        "order": m.order,
        "next_mission_id": m.next_mission_id
    } for m in missions]


@app.post("/api/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    # Verificar se usuário já existe
    existing_user = db.query(User).filter(User.name == user.name).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Nome já registrado")

    # Criar novo usuário
    db_user = User(name=user.name, password=user.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {"id": db_user.id, "name": db_user.name}


@app.post("/api/login")
def login(user: UserLogin, response: Response, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.name == user.name).first()

    if not db_user:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    if db_user.password != user.password:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    # Gerar token de sessão
    session_token = secrets.token_hex(32)
    db_user.session_token = session_token
    db_user.last_activity = datetime.now()

    # Definir primeira missão como atual (se houver)
    if not db_user.current_mission_id:
        first_mission = db.query(Mission).order_by(Mission.order).first()
        if first_mission:
            db_user.current_mission_id = first_mission.id

    db.commit()

    # Definir cookie
    response.set_cookie(key="session_token", value=session_token, httponly=True, max_age=1800)  # 30 minutos

    return {
        "id": db_user.id,
        "name": db_user.name,
        "current_mission_id": db_user.current_mission_id
    }


@app.post("/api/logout")
def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    """Logout público"""
    session_token = request.cookies.get("session_token")
    if session_token:
        user = db.query(User).filter(User.session_token == session_token).first()
        if user:
            user.session_token = None
            db.commit()

    response.delete_cookie(key="session_token")
    return {"success": True}


# API Endpoints PRIVADOS (precisam de sessão)

@app.get("/api/user/current")
def get_current_user_info(request: Request, db: Session = Depends(get_db)):
    session_token = request.cookies.get("session_token")
    if not session_token:
        raise HTTPException(status_code=401, detail="Não autenticado")

    user = db.query(User).filter(User.session_token == session_token).first()
    if not user:
        raise HTTPException(status_code=401, detail="Sessão inválida")

    # Verificar timeout
    if datetime.now() - user.last_activity > timedelta(seconds=SESSION_TIMEOUT):
        user.session_token = None
        db.commit()
        raise HTTPException(status_code=401, detail="Sessão expirada")

    # Atualizar última atividade
    user.last_activity = datetime.now()
    db.commit()

    missions_completed = len(user.completed_missions)

    # Pegar missão atual
    current_mission = None
    if user.current_mission:
        current_mission = {
            "id": user.current_mission.id,
            "name": user.current_mission.name,
            "description": user.current_mission.description
        }

    # Pegar próxima missão
    next_mission = None
    if user.current_mission and user.current_mission.next_mission_id:
        next_m = db.query(Mission).filter(Mission.id == user.current_mission.next_mission_id).first()
        if next_m:
            next_mission = {
                "id": next_m.id,
                "name": next_m.name
            }

    return {
        "id": user.id,
        "name": user.name,
        "missions_completed": missions_completed,
        "current_mission": current_mission,
        "next_mission": next_mission
    }


@app.get("/api/user/missions")
def get_user_missions_status(request: Request, db: Session = Depends(get_db)):
    session_token = request.cookies.get("session_token")
    if not session_token:
        raise HTTPException(status_code=401, detail="Não autenticado")

    user = db.query(User).filter(User.session_token == session_token).first()
    if not user:
        raise HTTPException(status_code=401, detail="Sessão inválida")

    # Verificar timeout
    if datetime.now() - user.last_activity > timedelta(seconds=SESSION_TIMEOUT):
        user.session_token = None
        db.commit()
        raise HTTPException(status_code=401, detail="Sessão expirada")

    # Atualizar última atividade
    user.last_activity = datetime.now()
    db.commit()

    missions = db.query(Mission).order_by(Mission.order).all()

    result = []
    for mission in missions:
        is_completed = mission in user.completed_missions
        result.append({
            "id": mission.id,
            "name": mission.name,
            "description": mission.description,
            "order": mission.order,
            "is_completed": is_completed,
            "is_current": user.current_mission_id == mission.id,
            "is_available": is_completed or mission.id == user.current_mission_id
        })

    return result


@app.post("/api/user/complete-current")
def complete_current_mission(request: Request, db: Session = Depends(get_db)):
    session_token = request.cookies.get("session_token")
    if not session_token:
        raise HTTPException(status_code=401, detail="Não autenticado")

    user = db.query(User).filter(User.session_token == session_token).first()
    if not user:
        raise HTTPException(status_code=401, detail="Sessão inválida")

    # Verificar timeout
    if datetime.now() - user.last_activity > timedelta(seconds=SESSION_TIMEOUT):
        user.session_token = None
        db.commit()
        raise HTTPException(status_code=401, detail="Sessão expirada")

    # Atualizar última atividade
    user.last_activity = datetime.now()

    if not user.current_mission:
        raise HTTPException(status_code=400, detail="Nenhuma missão atual")

    # Verificar se já completou
    if user.current_mission in user.completed_missions:
        raise HTTPException(status_code=400, detail="Missão já completada")

    # Marcar como completada
    user.completed_missions.append(user.current_mission)

    # Mover para próxima missão
    if user.current_mission.next_mission_id:
        next_mission = db.query(Mission).filter(Mission.id == user.current_mission.next_mission_id).first()
        if next_mission:
            user.current_mission_id = next_mission.id
    else:
        # Tentar pegar próxima por ordem
        next_mission = db.query(Mission).filter(
            Mission.order > user.current_mission.order
        ).order_by(Mission.order).first()

        if next_mission:
            user.current_mission_id = next_mission.id

    db.commit()

    return {
        "completed_mission": {
            "id": user.current_mission.id,
            "name": user.current_mission.name
        },
        "next_mission": {
            "id": user.current_mission_id,
            "name": next_mission.name if next_mission else None
        }
    }


# ROTA PARA TOGGLE DE MISSÕES DO USUÁRIO (para admin - precisa de proteção)
@app.post("/api/user/{user_id}/mission/{mission_id}/toggle")
def toggle_user_mission(user_id: int, mission_id: int, request: Request, db: Session = Depends(get_db)):
    # Verificar se é uma requisição do admin (simples verificação por agora)
    # Em produção, implemente um sistema de autenticação melhor para admin
    referer = request.headers.get("referer", "")
    if "/admin" not in referer:
        # Permitir apenas do painel admin
        raise HTTPException(status_code=403, detail="Acesso não autorizado")

    user = db.query(User).filter(User.id == user_id).first()
    mission = db.query(Mission).filter(Mission.id == mission_id).first()

    if not user or not mission:
        raise HTTPException(status_code=404, detail="Usuário ou missão não encontrada")

    # Verificar se a missão já está completada
    if mission in user.completed_missions:
        # Remover da lista de completadas
        user.completed_missions.remove(mission)
        completed = False
    else:
        # Adicionar à lista de completadas
        user.completed_missions.append(mission)
        completed = True

        # Se a missão completada for a atual, mover para próxima
        if user.current_mission_id == mission.id:
            # Tentar pegar próxima missão
            next_mission = db.query(Mission).filter(
                Mission.order > mission.order
            ).order_by(Mission.order).first()

            if next_mission:
                user.current_mission_id = next_mission.id

    db.commit()
    return {"completed": completed, "mission_id": mission_id, "user_id": user_id}


# Endpoints administrativos - agora sem proteção de sessão, mas com verificação simples
# Em produção, implemente autenticação JWT ou similar para admin
admin_sessions = {}  # Sessões simples em memória para admin


@app.post("/api/admin/login")
def admin_login(password: dict, response: Response):
    if password.get("password") != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Senha incorreta")

    # Criar token de sessão simples
    session_token = secrets.token_hex(32)
    admin_sessions[session_token] = datetime.now()

    # Definir cookie
    response.set_cookie(key="admin_token", value=session_token, httponly=True, max_age=3600)  # 1 hora

    return {"success": True, "token": session_token}


def verify_admin_session(request: Request):
    # Verificar token admin
    admin_token = request.cookies.get("admin_token")
    if not admin_token:
        raise HTTPException(status_code=401, detail="Não autenticado como admin")

    # Verificar se token existe e não expirou (1 hora)
    if admin_token in admin_sessions:
        session_time = admin_sessions[admin_token]
        if datetime.now() - session_time < timedelta(hours=1):
            # Atualizar tempo da sessão
            admin_sessions[admin_token] = datetime.now()
            return True

    # Sessão inválida ou expirada
    raise HTTPException(status_code=401, detail="Sessão admin expirada")


@app.get("/api/admin/missions")
def get_all_missions_admin(request: Request, db: Session = Depends(get_db)):
    # Verificar sessão admin
    verify_admin_session(request)

    missions = db.query(Mission).order_by(Mission.order).all()
    return [{
        "id": m.id,
        "name": m.name,
        "description": m.description,
        "order": m.order,
        "next_mission_id": m.next_mission_id
    } for m in missions]


@app.post("/api/admin/missions")
def create_mission(mission: MissionCreate, request: Request, db: Session = Depends(get_db)):
    # Verificar sessão admin
    verify_admin_session(request)

    # Determinar a ordem automaticamente se não for fornecida
    if mission.order == 0:
        last_mission = db.query(Mission).order_by(Mission.order.desc()).first()
        mission.order = last_mission.order + 1 if last_mission else 1

    db_mission = Mission(
        name=mission.name,
        description=mission.description,
        order=mission.order,
        next_mission_id=mission.next_mission_id
    )
    db.add(db_mission)
    db.commit()
    db.refresh(db_mission)
    return {
        "id": db_mission.id,
        "name": db_mission.name,
        "description": db_mission.description,
        "order": db_mission.order,
        "next_mission_id": db_mission.next_mission_id
    }


@app.put("/api/admin/missions/{mission_id}")
def update_mission(mission_id: int, mission: MissionCreate, request: Request, db: Session = Depends(get_db)):
    # Verificar sessão admin
    verify_admin_session(request)

    db_mission = db.query(Mission).filter(Mission.id == mission_id).first()
    if not db_mission:
        raise HTTPException(status_code=404, detail="Missão não encontrada")

    db_mission.name = mission.name
    db_mission.description = mission.description
    db_mission.order = mission.order
    db_mission.next_mission_id = mission.next_mission_id

    db.commit()
    db.refresh(db_mission)
    return {
        "id": db_mission.id,
        "name": db_mission.name,
        "description": db_mission.description,
        "order": db_mission.order,
        "next_mission_id": db_mission.next_mission_id
    }


@app.delete("/api/admin/missions/{mission_id}")
def delete_mission(mission_id: int, request: Request, db: Session = Depends(get_db)):
    # Verificar sessão admin
    verify_admin_session(request)

    mission = db.query(Mission).filter(Mission.id == mission_id).first()
    if not mission:
        raise HTTPException(status_code=404, detail="Missão não encontrada")

    # Atualizar referências de next_mission_id
    missions_to_update = db.query(Mission).filter(Mission.next_mission_id == mission_id).all()
    for m in missions_to_update:
        m.next_mission_id = None

    # Atualizar usuários com essa missão como atual
    users = db.query(User).filter(User.current_mission_id == mission_id).all()
    for user in users:
        # Tentar encontrar próxima missão
        next_mission = db.query(Mission).filter(
            Mission.order > mission.order
        ).order_by(Mission.order).first()
        user.current_mission_id = next_mission.id if next_mission else None

    db.delete(mission)
    db.commit()
    return {"success": True}


@app.get("/api/admin/users")
def get_all_users(request: Request, db: Session = Depends(get_db)):
    # Verificar sessão admin
    verify_admin_session(request)

    users = db.query(User).all()
    result = []
    for user in users:
        # Carregar todas as missões completadas
        completed_missions = []
        for mission in user.completed_missions:
            completed_missions.append({
                "id": mission.id,
                "name": mission.name
            })

        result.append({
            "id": user.id,
            "name": user.name,
            "completed_missions": completed_missions,
            "current_mission": user.current_mission.name if user.current_mission else None,
            "last_activity": user.last_activity
        })
    return result


# HTML Pages
@app.get("/", response_class=HTMLResponse)
def read_root():
    return FileResponse("static/login.html")


@app.get("/missions", response_class=HTMLResponse)
def missions_page():
    return FileResponse("static/missions.html")


@app.get("/ranking", response_class=HTMLResponse)
def ranking_page():
    return FileResponse("static/ranking.html")


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return FileResponse("static/admin.html")


# Criar algumas missões de exemplo
@app.on_event("startup")
def startup_event():
    db = SessionLocal()

    # Criar missões exemplo se não existirem
    if db.query(Mission).count() == 0:
        example_missions = [
            Mission(
                name="Phantom Liberty",
                description="Infiltrate the secret facility and retrieve the data chip from the main server. Beware of security turrets.",
                order=1
            ),
            Mission(
                name="The Pickup",
                description="Find the Flathead robot in the abandoned warehouse. Use stealth to avoid gang members.",
                order=2
            ),
            Mission(
                name="Chippin' In",
                description="Help Johnny Silverhand locate his lost memories in the cyberspace. Decrypt the memory fragments.",
                order=3
            ),
            Mission(
                name="Pyramid Song",
                description="Dive with Judy to explore the underwater ruins. Find the ancient neural interface.",
                order=4
            ),
            Mission(
                name="Beat on the Brat",
                description="Win all the fighting tournaments in Night City. Each opponent has unique combat patterns.",
                order=5
            ),
        ]

        # Configurar sequência
        for i in range(len(example_missions) - 1):
            example_missions[i].next_mission_id = example_missions[i + 1].id

        db.add_all(example_missions)
        db.commit()

    db.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)