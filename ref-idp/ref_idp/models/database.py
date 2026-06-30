"""SQLAlchemy async database setup and models."""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship

from ref_idp.config import settings


class Base(DeclarativeBase):
    pass


class Principal(Base):
    __tablename__ = "principals"

    id = Column(String, primary_key=True)
    type = Column(String, nullable=False)  # "human" or "org"
    external_id = Column(String, unique=True, nullable=False)  # e.g. "github:alice"
    name = Column(String, nullable=False)
    notification_endpoint = Column(String, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    agents = relationship("Agent", back_populates="principal")


class Agent(Base):
    __tablename__ = "agents"

    id = Column(String, primary_key=True)
    agent_id = Column(String, unique=True, nullable=False)  # aip:domain:unique
    name = Column(String, nullable=False)
    principal_id = Column(String, ForeignKey("principals.id"), nullable=False)
    metadata_json = Column(Text, nullable=True)
    # Bumped on key revocation. JWTs carry this value as a claim;
    # resource-server verifiers refuse JWTs below the agent's current
    # version — kills in-flight tokens that would otherwise remain
    # valid until TTL. See v0.5 spec §6.10.
    token_version = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    principal = relationship("Principal", back_populates="agents")
    keys = relationship("AgentKey", back_populates="agent")


class AgentKey(Base):
    __tablename__ = "agent_keys"

    id = Column(String, primary_key=True)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    kid = Column(String, nullable=False)
    public_key_bytes = Column(String, nullable=False)  # hex-encoded
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    agent = relationship("Agent", back_populates="keys")


class HubApp(Base):
    """A registered hub application (resource server) — ModelScope hub_app.

    The ``client_id`` is the audience the token endpoint can enforce against
    (see ``REF_AGENT_IDP_ENFORCE_AUDIENCE``).
    """

    __tablename__ = "hub_apps"

    client_id = Column(String, primary_key=True)  # hub_<6hex>
    app_name = Column(String, nullable=False)
    app_homepage = Column(String, nullable=False)
    app_logo = Column(String, nullable=True)
    owner = Column(String, nullable=False, default="dev-user")
    created_at = Column(DateTime, default=func.now(), nullable=False)


engine = create_async_engine(settings.database_url, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncSession:
    """Yield an async database session."""
    async with async_session() as session:
        yield session  # type: ignore[misc]


async def init_db() -> None:
    """Create all database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
