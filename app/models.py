"""
Database Models для VPS Manager

Все модели с полными type hints и документацией.
"""

from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app import db

# Вспомогательная таблица для связи many-to-many между Server и ServerCategory
server_category_association = db.Table(
    "server_category_association",
    db.Column(
        "server_id", db.Integer, db.ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True
    ),
    db.Column(
        "category_id",
        db.Integer,
        db.ForeignKey("server_categories.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column("created_at", db.TIMESTAMP, server_default=db.func.now()),
)


class User(UserMixin, db.Model):
    """Модель пользователя системы."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())

    # Relationships
    servers = db.relationship("Server", backref="user", lazy=True)
    ssh_keys = db.relationship("SSHKey", backref="user", lazy=True)
    logs = db.relationship("Log", backref="user", lazy=True)
    initiated_deployments = db.relationship(
        "KeyDeployment", foreign_keys="KeyDeployment.deployed_by", backref="deployer"
    )
    initiated_revokes = db.relationship(
        "KeyDeployment", foreign_keys="KeyDeployment.revoked_by", backref="revoker"
    )

    def set_password(self, password: str) -> None:
        """Устанавливает хэш пароля."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Проверяет пароль."""
        return check_password_hash(self.password_hash, password)


class ServerCategory(db.Model):
    """Модель категории сервера."""

    __tablename__ = "server_categories"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    color = db.Column(db.String(7), default="#6c757d", nullable=False)  # HEX color code
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())

    # Relationships
    servers = db.relationship(
        "Server", secondary=server_category_association, back_populates="categories", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return f"<ServerCategory {self.name}>"


class Server(db.Model):
    """Модель VPS сервера."""

    __tablename__ = "servers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    ssh_port = db.Column(db.Integer, default=22, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default="unknown", nullable=False)
    last_check = db.Column(db.TIMESTAMP)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    openssh_version = db.Column(db.String(20), nullable=True)
    requires_legacy_ssh = db.Column(db.Boolean, default=False, nullable=False)
    access_key_id = db.Column(db.Integer, db.ForeignKey("ssh_keys.id"), nullable=True)

    # Relationships
    access_key = db.relationship("SSHKey", foreign_keys=[access_key_id], backref="server_access")
    deployments = db.relationship(
        "KeyDeployment", back_populates="server", lazy="dynamic", cascade="all, delete-orphan"
    )
    categories = db.relationship(
        "ServerCategory",
        secondary=server_category_association,
        back_populates="servers",
        lazy="dynamic",
    )


class SSHKey(db.Model):
    """Модель SSH ключа."""

    __tablename__ = "ssh_keys"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key_encrypted = db.Column(db.LargeBinary, nullable=False)
    fingerprint = db.Column(db.String(100), unique=True, nullable=False)
    key_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Relationships
    deployments = db.relationship(
        "KeyDeployment", back_populates="ssh_key", lazy="dynamic", cascade="all, delete-orphan"
    )


class KeyDeployment(db.Model):
    """
    Модель для отслеживания развертывания SSH ключей на серверах.

    Атрибуты:
        id: Уникальный идентификатор записи.
        ssh_key_id: ID SSH ключа (внешний ключ).
        server_id: ID сервера (внешний ключ).
        deployed_at: Дата/время развертывания.
        deployed_by: ID пользователя, который развернул ключ.
        revoked_at: Дата/время отзыва (если был отозван).
        revoked_by: ID пользователя, который отозвал ключ.
    """

    __tablename__ = "key_deployments"

    id = db.Column(db.Integer, primary_key=True)
    ssh_key_id = db.Column(
        db.Integer, db.ForeignKey("ssh_keys.id", ondelete="CASCADE"), nullable=False, index=True
    )
    server_id = db.Column(
        db.Integer, db.ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    deployed_at = db.Column(db.TIMESTAMP, server_default=db.func.now(), nullable=False, index=True)
    deployed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    revoked_at = db.Column(db.TIMESTAMP, nullable=True, index=True)
    revoked_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Relationships
    ssh_key = db.relationship("SSHKey", back_populates="deployments")
    server = db.relationship("Server", back_populates="deployments")

    # Составной индекс для часто используемых фильтров
    __table_args__ = (db.Index("idx_key_server_revoked", "ssh_key_id", "server_id", "revoked_at"),)


class Log(db.Model):
    """Модель журнала событий."""

    __tablename__ = "logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)  # JSON string
    target = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.now)
