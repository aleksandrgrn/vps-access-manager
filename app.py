import ipaddress
import json
import os
from datetime import datetime, timezone

import click
import requests
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.exceptions import HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import (
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, NumberRange

import ssh_manager

# Загрузка переменных окружения
load_dotenv()

# Инициализация приложения
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32).hex()),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///vps_manager.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,  # 1 час
    SESSION_REFRESH_EACH_REQUEST=True,
    WTF_CSRF_TIME_LIMIT=3600,
    WTF_CSRF_CHECK_DEFAULT=True,
    WTF_CSRF_SSL_STRICT=False,
    JSON_AS_ASCII=False,
)

# Initialize CSRF Protection
csrf = CSRFProtect(app)


@app.after_request
def set_csrf_cookie(response):
    if "CSRF-TOKEN" not in request.cookies:
        response.set_cookie("CSRF-TOKEN", generate_csrf())
    return response


# --- НОВЫЕ НАСТРОЙКИ БЕЗОПАСНОСТИ ---
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Включаем Secure cookie только если приложение не в режиме разработки
if os.environ.get("FLASK_ENV") != "development":
    app.config["SESSION_COOKIE_SECURE"] = True

# Инициализация расширений
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Пожалуйста, войдите, чтобы получить доступ к этой странице."
login_manager.login_message_category = "info"

# --- Формы ---


class ServerForm(FlaskForm):
    name = StringField("Название сервера", validators=[DataRequired()])
    ip_address = StringField("IP-адрес", validators=[DataRequired()])
    ssh_port = IntegerField(
        "SSH ПорT", default=22, validators=[DataRequired(), NumberRange(min=1, max=65535)]
    )
    username = StringField("Имя пользователя", validators=[DataRequired()])
    submit = SubmitField("Сохранить")


class GenerateKeyForm(FlaskForm):
    name = StringField("Название ключа", validators=[DataRequired()])
    key_type = SelectField(
        "Тип ключа",
        choices=[("rsa", "RSA 4096"), ("ed25519", "Ed25519")],
        validators=[DataRequired()],
    )
    submit = SubmitField("Сгенерировать")


class UploadKeyForm(FlaskForm):
    name = StringField("Название ключа", validators=[DataRequired()])
    public_key = TextAreaField("Публичный ключ", validators=[DataRequired()])
    submit = SubmitField("Загрузить")


class LoginForm(FlaskForm):
    username = StringField(
        "Имя пользователя",
        validators=[DataRequired(message="Это поле обязательно для заполнения.")],
    )
    password = PasswordField(
        "Пароль", validators=[DataRequired(message="Это поле обязательно для заполнения.")]
    )
    submit = SubmitField("Войти")


# --- Модели Базы Данных ---


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Server(db.Model):
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

    user = db.relationship("User", backref=db.backref("servers", lazy=True))
    access_key_id = db.Column(db.Integer, db.ForeignKey("ssh_keys.id"), nullable=True)
    access_key = db.relationship("SSHKey", foreign_keys=[access_key_id], backref="server_access")
    deployments = db.relationship(
        "KeyDeployment", back_populates="server", lazy="dynamic", cascade="all, delete-orphan"
    )


class SSHKey(db.Model):
    __tablename__ = "ssh_keys"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key_encrypted = db.Column(db.LargeBinary, nullable=False)
    fingerprint = db.Column(db.String(100), unique=True, nullable=False)
    key_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    user = db.relationship("User", backref=db.backref("ssh_keys", lazy=True))
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

    ssh_key = db.relationship("SSHKey", back_populates="deployments")
    server = db.relationship("Server", back_populates="deployments")
    deployer = db.relationship("User", foreign_keys=[deployed_by], backref="initiated_deployments")
    revoker = db.relationship("User", foreign_keys=[revoked_by], backref="initiated_revokes")

    # Составной индекс для часто используемых фильтров
    __table_args__ = (db.Index("idx_key_server_revoked", "ssh_key_id", "server_id", "revoked_at"),)


class Log(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)  # JSON string
    target = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.TIMESTAMP, server_default=db.func.now())

    user = db.relationship("User", backref=db.backref("logs", lazy=True))


# --- Вспомогательные функции ---


def add_log(action, target=None, details=None):
    """Добавляет запись в журнал событий."""
    if not current_user.is_authenticated:
        return

    log_entry = Log(
        user_id=current_user.id,
        action=action,
        target=target,
        details=json.dumps(details) if details else None,
        ip_address=request.remote_addr,
    )
    db.session.add(log_entry)
    db.session.commit()


# --- Загрузчик пользователя для Flask-Login ---


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Маршруты (Routes) ---


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            add_log("login_success", target=user.username)
            # Перенаправление на следующую страницу, если она была указана
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        else:
            add_log("login_failed", target=form.username.data)
            flash("Неправильный логин или пароль.", "error")

    return render_template("login.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    servers_count = Server.query.filter_by(user_id=current_user.id).count()
    keys_count = SSHKey.query.filter_by(user_id=current_user.id).count()
    online_count = Server.query.filter_by(user_id=current_user.id, status="online").count()
    recent_logs = (
        Log.query.filter_by(user_id=current_user.id).order_by(Log.timestamp.desc()).limit(5).all()
    )

    return render_template(
        "dashboard.html",
        servers_count=servers_count,
        keys_count=keys_count,
        online_count=online_count,
        recent_logs=recent_logs,
    )


@app.route("/logout")
@login_required
def logout():
    add_log("logout", target=current_user.username)
    logout_user()
    flash("Вы успешно вышли из системы.", "success")
    return redirect(url_for("login"))


# --- Команды CLI для управления приложением ---


@app.cli.command("init-db")
def init_db_command():
    """Создает таблицы базы данных."""
    with app.app_context():
        db.create_all()
        print("Таблицы базы данных успешно созданы.")


@app.cli.command("generate-fernet-key")
def generate_fernet_key_command():
    """Генерирует ключ шифрования Fernet."""
    key = Fernet.generate_key()
    print("Ваш ключ шифрования (добавьте его в .env как ENCRYPTION_KEY):")
    print(key.decode())


@app.route("/servers/add", methods=["POST"])
@login_required
def add_server_with_password():
    form = ServerForm()
    if form.validate_on_submit():
        ip_address = form.ip_address.data
        port = form.ssh_port.data
        username = form.username.data
        password = request.form.get("password")

        if not password:
            flash("Пароль не может быть пустым.", "danger")
            return redirect(url_for("servers"))

        # 0. ИНИЦИАЛИЗИРОВАТЬ СЕРВЕР: определить версию OpenSSH
        try:
            app.logger.info(f"Инициализация сервера {ip_address}:{port}")
            init_result = ssh_manager.initialize_server(ip_address, port, username, password)

            if not init_result["success"]:
                flash(f'Ошибка инициализации сервера: {init_result["message"]}', "danger")
                return redirect(url_for("servers"))

            openssh_version = init_result["openssh_version"]
            requires_legacy_ssh = init_result["requires_legacy_ssh"]

            app.logger.info(
                f"Сервер инициализирован. OpenSSH версия: {openssh_version}, Legacy: {requires_legacy_ssh}"
            )
            flash(f"Сервер инициализирован. OpenSSH версия: {openssh_version}", "info")

        except Exception as e:
            flash(f"Ошибка при инициализации сервера: {e}", "danger")
            app.logger.error(f"Ошибка инициализации: {e}")
            return redirect(url_for("servers"))

        # 1. Сгенерировать уникальный ключ для этого сервера (root_domain.com)
        try:
            private_key_pem, public_key_ssh = ssh_manager.generate_ssh_key("rsa")
            fingerprint = ssh_manager.get_fingerprint(public_key_ssh)
            if not fingerprint or SSHKey.query.filter_by(fingerprint=fingerprint).first():
                flash("Не удалось сгенерировать уникальный ключ. Попробуйте еще раз.", "danger")
                return redirect(url_for("servers"))
        except Exception as e:
            flash(f"Ошибка при генерации ключа: {e}", "danger")
            return redirect(url_for("servers"))

        # 2. Сохранить уникальный ключ в БД
        try:
            encryption_key = os.environ.get("ENCRYPTION_KEY")
            encrypted_private_key = ssh_manager.encrypt_private_key(private_key_pem, encryption_key)

            # Создаем уникальное имя ключа: root_domain.com
            root_key_name = f"root_{form.name.data}"
            new_root_key = SSHKey(
                name=root_key_name,
                public_key=public_key_ssh,
                private_key_encrypted=encrypted_private_key,
                fingerprint=fingerprint,
                key_type="rsa",
                user_id=current_user.id,
            )
            db.session.add(new_root_key)
            db.session.flush()  # Получаем ID ключа
            app.logger.info(f"Создан уникальный ключ {root_key_name} (ID: {new_root_key.id})")
        except Exception as e:
            flash(f"Ошибка при сохранении ключа в БД: {e}", "danger")
            db.session.rollback()
            return redirect(url_for("servers"))

        # 3. Развернуть публичный ключ на сервере через пароль
        deploy_result = ssh_manager.deploy_key_with_password(
            ip_address, port, username, password, public_key_ssh
        )

        # Очистка пароля из памяти
        del password

        if not deploy_result["success"]:
            flash(f'Не удалось добавить ключ на сервер: {deploy_result["message"]}', "danger")
            db.session.rollback()
            return redirect(url_for("servers"))

        # 4. Сохранить сервер с информацией о версии OpenSSH
        try:
            new_server = Server(
                name=form.name.data,
                ip_address=ip_address,
                ssh_port=port,
                username=username,
                user_id=current_user.id,
                status="online",  # Считаем, что он онлайн, раз мы смогли добавить ключ
                openssh_version=openssh_version,
                requires_legacy_ssh=requires_legacy_ssh,
            )
            db.session.add(new_server)
            db.session.flush()  # Получаем ID сервера
            app.logger.info(f"Создан сервер {form.name.data} (ID: {new_server.id})")
        except Exception as e:
            flash(f"Ошибка при сохранении сервера в БД: {e}", "danger")
            db.session.rollback()
            return redirect(url_for("servers"))

        # 5. Создать KeyDeployment для уникального ключа
        try:
            deployment = KeyDeployment(
                ssh_key_id=new_root_key.id,
                server_id=new_server.id,
                deployed_by=current_user.id,
                deployed_at=datetime.now(timezone.utc),
            )
            db.session.add(deployment)
            db.session.commit()
            app.logger.info(
                f"Создан KeyDeployment: ключ {new_root_key.id} -> сервер {new_server.id}"
            )
        except Exception as e:
            flash(f"Ошибка при создании записи развертывания: {e}", "danger")
            db.session.rollback()
            return redirect(url_for("servers"))

        add_log(
            "add_server",
            target=new_server.name,
            details={
                "ip": new_server.ip_address,
                "key_id": new_root_key.id,
                "openssh_version": openssh_version,
            },
        )
        flash(f"Сервер успешно добавлен и настроен. OpenSSH версия: {openssh_version}", "success")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Ошибка в поле "{getattr(form, field).label.text}": {error}', "danger")

    return redirect(url_for("servers"))


@app.route("/servers", methods=["GET"])
@login_required
def servers():
    form = ServerForm()
    user_servers = Server.query.filter_by(user_id=current_user.id).all()
    status_colors = {"online": "success", "offline": "danger", "unknown": "secondary"}
    return render_template(
        "servers.html", form=form, servers=user_servers, status_colors=status_colors
    )


@app.route("/servers/edit/<int:server_id>", methods=["POST"])
@login_required
def edit_server(server_id):
    server = Server.query.get_or_404(server_id)
    if server.user_id != current_user.id:
        return jsonify({"success": False, "message": "Доступ запрещен"}), 403

    form = ServerForm()
    if form.validate_on_submit():
        server.name = form.name.data
        server.ip_address = form.ip_address.data
        server.ssh_port = form.ssh_port.data
        server.username = form.username.data
        db.session.commit()
        add_log("edit_server", target=server.name)
        flash("Данные сервера успешно обновлены.", "success")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Ошибка в поле "{getattr(form, field).label.text}": {error}', "danger")
    return redirect(url_for("servers"))


@app.route("/servers/delete/<int:server_id>", methods=["POST"])
@login_required
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    if server.user_id != current_user.id:
        return jsonify({"success": False, "message": "Доступ запрещен"}), 403

    db.session.delete(server)
    db.session.commit()
    add_log("delete_server", target=server.name)
    return jsonify({"success": True, "message": "Сервер успешно удален."})


@app.route("/api/bulk-import-servers", methods=["POST"])
@login_required
def bulk_import_servers():
    """
    Массовый импорт серверов из текстовых данных.
    Формат: domain username password ip-address ssh-port (5 полей через пробел)
    Для каждого сервера создается уникальный SSH ключ и развертывается на сервер.
    """
    try:
        data = request.get_json()
        if not data or "servers_data" not in data:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Отсутствуют данные для импорта",
                        "added": 0,
                        "skipped": 0,
                        "failed": 0,
                    }
                ),
                400,
            )

        servers_data = data["servers_data"].strip()
        if not servers_data:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Данные пусты",
                        "added": 0,
                        "skipped": 0,
                        "failed": 0,
                    }
                ),
                400,
            )

        lines = servers_data.split("\n")
        added = 0
        skipped = 0
        failed = 0

        encryption_key = os.environ.get("ENCRYPTION_KEY")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Парсим строку: domain username password ip-address ssh-port
            parts = line.split()

            # Проверяем, что ровно 5 полей
            if len(parts) != 5:
                app.logger.warning(f"Неверный формат строки (ожидается 5 полей): {line}")
                failed += 1
                continue

            domain, username, password, ip_address, ssh_port_str = parts

            # Валидируем IP адрес
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                app.logger.warning(f"Неверный IP адрес: {ip_address}")
                failed += 1
                continue

            # Валидируем SSH порт
            try:
                ssh_port = int(ssh_port_str)
                if ssh_port < 1 or ssh_port > 65535:
                    app.logger.warning(f"SSH порт вне диапазона: {ssh_port}")
                    failed += 1
                    continue
            except ValueError:
                app.logger.warning(f"Неверный SSH порт: {ssh_port_str}")
                failed += 1
                continue

            # Проверяем дубликаты по IP адресу
            existing_server = Server.query.filter_by(
                ip_address=ip_address, user_id=current_user.id
            ).first()

            if existing_server:
                app.logger.info(f"Сервер с IP {ip_address} уже существует, пропускаем")
                skipped += 1
                continue

            # 🔍 КРИТИЧНО: Инициализировать сервер - проверить OpenSSH версию!
            try:
                app.logger.info(f"🔍 Инициализация сервера {domain} ({ip_address}:{ssh_port})...")
                init_result = ssh_manager.initialize_server(
                    ip_address, ssh_port, username, password
                )

                if not init_result["success"]:
                    app.logger.warning(
                        f'⚠️ Ошибка инициализации {domain}: {init_result.get("message")}'
                    )
                    failed += 1
                    continue

                openssh_version = init_result.get("openssh_version", "unknown")
                requires_legacy_ssh = init_result.get("requires_legacy_ssh", False)
                app.logger.info(
                    f"✅ Сервер {domain}: OpenSSH {openssh_version}, legacy={requires_legacy_ssh}"
                )

            except Exception as e:
                app.logger.error(f"❌ Ошибка при инициализации {domain}: {str(e)}")
                failed += 1
                continue

            # Создаем УНИКАЛЬНЫЙ ключ для этого сервера
            try:
                app.logger.info(f"Генерирую уникальный ключ для {domain}")
                private_key_pem, public_key_ssh = ssh_manager.generate_ssh_key("rsa")
                fingerprint = ssh_manager.get_fingerprint(public_key_ssh)

                if not fingerprint or SSHKey.query.filter_by(fingerprint=fingerprint).first():
                    app.logger.error(f"Не удалось сгенерировать уникальный ключ для {domain}")
                    failed += 1
                    continue

                # Шифруем приватный ключ
                encrypted_private_key = ssh_manager.encrypt_private_key(
                    private_key_pem, encryption_key
                )

                # Создаем уникальное имя ключа: root_domain.com
                root_key_name = f"root_{domain}"
                new_root_key = SSHKey(
                    name=root_key_name,
                    public_key=public_key_ssh,
                    private_key_encrypted=encrypted_private_key,
                    fingerprint=fingerprint,
                    key_type="rsa",
                    user_id=current_user.id,
                )
                db.session.add(new_root_key)
                db.session.flush()  # Получаем ID ключа
                app.logger.info(f"Создан уникальный ключ {root_key_name} (ID: {new_root_key.id})")

            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Ошибка при генерации ключа для {domain}: {e}")
                failed += 1
                continue

            # Развертываем ключ на сервер через пароль
            try:
                app.logger.info(f"Развертываю ключ на {domain} ({ip_address}:{ssh_port})")
                success, message = ssh_manager.add_key_to_authorized_keys(
                    ip_address, ssh_port, username, password, public_key_ssh
                )

                if not success:
                    app.logger.error(f"Не удалось развернуть ключ на {domain}: {message}")
                    db.session.rollback()
                    failed += 1
                    continue

                app.logger.info(f"Ключ успешно развернут на {domain}")

            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Ошибка при развертывании ключа на {domain}: {e}")
                failed += 1
                continue

            # Создаем новый сервер
            try:
                new_server = Server(
                    name=domain,
                    ip_address=ip_address,
                    username=username,
                    ssh_port=ssh_port,
                    user_id=current_user.id,
                    status="online",  # Считаем онлайн, раз мы смогли развернуть ключ
                    openssh_version=openssh_version,
                    requires_legacy_ssh=requires_legacy_ssh,
                )
                db.session.add(new_server)
                db.session.flush()  # Получить ID сервера
                app.logger.info(
                    f"Создан сервер {domain} (ID: {new_server.id}), OpenSSH: {openssh_version}, Legacy: {requires_legacy_ssh}"
                )

            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Ошибка при добавлении сервера {domain}: {e}")
                failed += 1
                continue

            # Создаем KeyDeployment с УНИКАЛЬНЫМ ключом (не с access_key!)
            try:
                deployment = KeyDeployment(
                    ssh_key_id=new_root_key.id,  # УНИКАЛЬНЫЙ ключ для этого сервера
                    server_id=new_server.id,
                    deployed_by=current_user.id,
                    deployed_at=datetime.now(timezone.utc),
                )
                db.session.add(deployment)
                db.session.commit()
                app.logger.info(
                    f"Создан KeyDeployment: ключ {new_root_key.id} -> сервер {new_server.id}"
                )

            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Ошибка при создании KeyDeployment для {domain}: {e}")
                failed += 1
                continue

            add_log(
                "add_server",
                target=domain,
                details={"ip": ip_address, "port": ssh_port, "key_id": new_root_key.id},
            )
            added += 1

        return jsonify(
            {"success": True, "message": "OK", "added": added, "skipped": skipped, "failed": failed}
        )

    except Exception as e:
        app.logger.error(f"Ошибка в bulk_import_servers: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Ошибка сервера: {str(e)}",
                    "added": 0,
                    "skipped": 0,
                    "failed": 0,
                }
            ),
            500,
        )


@app.route("/keys")
@login_required
def keys():
    generate_form = GenerateKeyForm()
    upload_form = UploadKeyForm()
    user_keys = SSHKey.query.filter_by(user_id=current_user.id).all()
    user_servers = Server.query.filter_by(user_id=current_user.id).all()
    return render_template(
        "keys.html",
        generate_form=generate_form,
        upload_form=upload_form,
        keys=user_keys,
        servers=user_servers,
    )


@app.route("/keys/generate", methods=["POST"])
@login_required
def generate_key():
    form = GenerateKeyForm()
    if form.validate_on_submit():
        private_key, public_key = ssh_manager.generate_ssh_key(form.key_type.data)
        fingerprint = ssh_manager.get_fingerprint(public_key)

        if not fingerprint or SSHKey.query.filter_by(fingerprint=fingerprint).first():
            flash("Не удалось сгенерировать уникальный ключ. Попробуйте еще раз.", "danger")
            return redirect(url_for("keys"))

        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key:
            flash("Ошибка: ENCRYPTION_KEY не настроен в переменных окружения.", "danger")
            return redirect(url_for("keys"))
        encrypted_private_key = ssh_manager.encrypt_private_key(private_key, encryption_key)

        new_key = SSHKey(
            name=form.name.data,
            public_key=public_key,
            private_key_encrypted=encrypted_private_key,
            fingerprint=fingerprint,
            key_type=form.key_type.data,
            user_id=current_user.id,
        )
        db.session.add(new_key)
        db.session.commit()
        add_log("generate_key", target=new_key.name, details={"type": new_key.key_type})
        flash("SSH-ключ успешно сгенерирован.", "success")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Ошибка в поле "{getattr(form, field).label.text}": {error}', "danger")
    return redirect(url_for("keys"))


@app.route("/keys/delete/<int:key_id>", methods=["POST"])
@login_required
def delete_key(key_id):
    key = SSHKey.query.get_or_404(key_id)
    if key.user_id != current_user.id:
        return jsonify({"success": False, "message": "Доступ запрещен"}), 403

    db.session.delete(key)
    db.session.commit()
    add_log("delete_key", target=key.name)
    return jsonify({"success": True, "message": "Ключ успешно удален."})


@app.route("/keys/deploy", methods=["POST"])
@login_required
def deploy_key_route():
    """Deploy SSH key to server using unique root key"""
    app.logger.info("Получен запрос на развертывание ключа")

    if not request.is_json:
        app.logger.error("Ошибка: запрос не в формате JSON")
        return jsonify({"success": False, "message": "Неверный формат запроса"}), 400

    data = request.get_json()
    key_id = data.get("key_id")
    server_id = data.get("server_id")

    app.logger.debug(f"Получены данные: key_id={key_id}, server_id={server_id}")

    if not key_id or not server_id:
        app.logger.error("Отсутствуют обязательные параметры")
        return jsonify({"success": False, "message": "Не указаны обязательные параметры"}), 400

    try:
        key_to_deploy = SSHKey.query.get(key_id)
        server = Server.query.get(server_id)

        if not key_to_deploy or not server:
            app.logger.error(f"Ключ {key_id} или сервер {server_id} не найдены")
            return jsonify({"success": False, "message": "Ключ или сервер не найдены"}), 404

        if key_to_deploy.user_id != current_user.id or server.user_id != current_user.id:
            app.logger.warning(
                f"Попытка несанкционированного доступа к ключу {key_id} или серверу {server_id}"
            )
            return jsonify({"success": False, "message": "Доступ запрещен"}), 403

        # НАЙТИ УНИКАЛЬНЫЙ ключ для подключения: root_{server.name}
        root_key_name = f"root_{server.name}"
        access_key = SSHKey.query.filter_by(user_id=current_user.id, name=root_key_name).first()

        if not access_key:
            app.logger.error(f"Root ключ не найден для сервера {server.name}")
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Root ключ не найден для сервера {server.name}. Создайте ключ {root_key_name} перед развертыванием.",
                    }
                ),
                404,
            )

        # Расшифровать access key
        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key:
            app.logger.error("ENCRYPTION_KEY не установлен")
            return jsonify({"success": False, "message": "Ошибка конфигурации сервера"}), 500

        try:
            app.logger.info(f"Расшифровка ключа доступа {access_key.name}...")
            access_private_key = ssh_manager.decrypt_private_key(
                access_key.private_key_encrypted, encryption_key
            )

            if not access_private_key:
                app.logger.error("Расшифровка вернула None!")
                return jsonify({"success": False, "message": "Ошибка расшифровки ключа"}), 500

            app.logger.info(f"Ключ {access_key.name} успешно расшифрован")

        except Exception as e:
            app.logger.error(f"Ошибка при расшифровке ключа доступа: {str(e)}")
            return (
                jsonify({"success": False, "message": f"Ошибка расшифровки ключа: {str(e)}"}),
                500,
            )

        # Развернуть ключ на сервер с адаптивными алгоритмами
        try:
            app.logger.info(
                f"Развертывание {key_to_deploy.name} на {server.ip_address}:{server.ssh_port}"
            )

            success, message = ssh_manager.deploy_key(
                server.ip_address,
                server.ssh_port,
                server.username,
                access_private_key,
                key_to_deploy.public_key,
                server=server,  # Передаем объект server для адаптивных алгоритмов
            )

            if success:
                app.logger.info(f"Ключ {key_to_deploy.name} успешно развернут на {server.name}")
                add_log("deploy_key", target=key_to_deploy.name, details={"server": server.name})

                # Создать KeyDeployment запись
                existing = KeyDeployment.query.filter_by(
                    ssh_key_id=key_id, server_id=server_id, revoked_at=None
                ).first()

                if not existing:
                    deployment = KeyDeployment(
                        ssh_key_id=key_id,
                        server_id=server_id,
                        deployed_by=current_user.id,
                        deployed_at=datetime.now(timezone.utc),
                    )
                    db.session.add(deployment)
                    db.session.commit()
                    app.logger.info(
                        f"Запись KeyDeployment создана для ключа {key_id} на сервере {server_id}"
                    )
                else:
                    app.logger.info(
                        f"Запись KeyDeployment уже существует для ключа {key_id} на сервере {server_id}"
                    )

            else:
                app.logger.warning(f"Ошибка при развертывании ключа: {message}")

            return jsonify({"success": success, "message": message})

        except Exception as e:
            app.logger.exception(f"Ошибка при развертывании ключа: {str(e)}")
            return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500

    except Exception as e:
        error_msg = f"Внутренняя ошибка сервера: {str(e)}"
        app.logger.error(error_msg)
        return jsonify({"success": False, "message": "Внутренняя ошибка сервера"}), 500


@app.route("/servers/test/<int:server_id>", methods=["POST"])
@login_required
def test_server_connection(server_id):
    server = Server.query.get_or_404(server_id)
    if server.user_id != current_user.id:
        return jsonify({"success": False, "message": "Доступ запрещен"}), 403

    if not server.access_key:
        return jsonify(
            {
                "success": False,
                "message": "Для этого сервера не настроен ключ доступа. Пожалуйста, пересоздайте сервер.",
            }
        )

    access_key = server.access_key

    encryption_key = os.environ.get("ENCRYPTION_KEY")
    try:
        private_key = ssh_manager.decrypt_private_key(
            access_key.private_key_encrypted, encryption_key
        )
    except Exception:
        return jsonify(
            {"success": False, "message": "Не удалось дешифровать ключ доступа 'access_key'."}
        )

    success, message = ssh_manager.test_connection(
        server.ip_address, server.ssh_port, server.username, private_key
    )

    # Обновляем статус сервера в БД
    server.status = "online" if success else "offline"
    server.last_check = db.func.now()
    db.session.commit()

    add_log(
        "test_connection",
        target=server.name,
        details={"result": "success" if success else "failed"},
    )
    return jsonify({"success": success, "message": message, "status": server.status})


@app.route("/api/key-servers/<int:key_id>", methods=["GET"])
@login_required
def get_key_servers(key_id):
    """Получить список серверов где развернут ключ"""
    try:
        ssh_key = SSHKey.query.get(key_id)

        if not ssh_key:
            return jsonify({"success": False, "message": "Ключ не найден"}), 404

        if ssh_key.user_id != current_user.id:
            return jsonify({"success": False, "message": "Доступ запрещен"}), 403

        # Получаем все активные развертывания этого ключа
        deployments = KeyDeployment.query.filter_by(ssh_key_id=key_id, revoked_at=None).all()

        servers = []
        for deployment in deployments:
            server = Server.query.get(deployment.server_id)
            if server:
                servers.append(
                    {"id": server.id, "name": server.name, "ip_address": server.ip_address}
                )

        return jsonify({"success": True, "servers": servers})

    except Exception as e:
        app.logger.error(f"Ошибка при получении серверов для ключа: {str(e)}")
        return jsonify({"success": False, "message": "Ошибка сервера"}), 500


@app.route("/api/revoke-key", methods=["POST"])
@login_required
def revoke_key_api():
    """Отозвать развёрнутый ключ с сервера по ID развертывания с детальной диагностикой"""
    data = request.json
    deployment_id = data.get("deployment_id")

    if not deployment_id:
        return (
            jsonify(
                {
                    "success": False,
                    "error_code": "INVALID_INPUT",
                    "message": "deployment_id required",
                }
            ),
            400,
        )

    try:
        deployment = KeyDeployment.query.get(deployment_id)

        if not deployment:
            return (
                jsonify(
                    {"success": False, "error_code": "NOT_FOUND", "message": "Deployment not found"}
                ),
                404,
            )

        ssh_key = SSHKey.query.get(deployment.ssh_key_id)
        server = Server.query.get(deployment.server_id)

        if not ssh_key or not server:
            return (
                jsonify(
                    {
                        "success": False,
                        "error_code": "NOT_FOUND",
                        "message": "Key or server not found",
                    }
                ),
                404,
            )

        # Проверить доступ
        if server.user_id != current_user.id:
            return (
                jsonify(
                    {"success": False, "error_code": "ACCESS_DENIED", "message": "Access denied"}
                ),
                403,
            )

        app.logger.info(f"Starting revoke of key {ssh_key.id} from server {server.id}")

        # Получить access key для подключения
        access_key = server.access_key

        if not access_key:
            root_key = SSHKey.query.filter_by(
                name=f"root_{server.name}", user_id=current_user.id
            ).first()

            if not root_key:
                app.logger.error(f"No root key found for server {server.name}")
                return (
                    jsonify(
                        {
                            "success": False,
                            "error_code": "NO_ROOT_KEY",
                            "message": "Не найден root ключ для подключения к серверу",
                        }
                    ),
                    400,
                )

            try:
                # Расшифровать приватный ключ (root_key.private_key_encrypted хранит зашифрованные данные)
                encryption_key = os.getenv("ENCRYPTION_KEY", "default-key")
                private_key_decrypted = ssh_manager.decrypt_private_key(
                    root_key.private_key_encrypted, encryption_key
                )

                # Использовать root ключ для удаления пользовательского ключа со сервера
                success, message = ssh_manager.revoke_key(
                    server.ip_address,
                    server.ssh_port,
                    "root",
                    private_key_decrypted,
                    ssh_key.public_key,
                    server,
                )

                if success:
                    deployment.revoked_at = datetime.now(timezone.utc)
                    deployment.revoked_by = current_user.id
                    db.session.commit()

                    app.logger.info(f"Key {ssh_key.name} successfully revoked from {server.name}")
                    add_log(
                        "revoke_key",
                        target=ssh_key.name,
                        details={"server": server.name, "status": "revoked"},
                    )

                    return jsonify({"success": True, "message": "Ключ успешно удален"}), 200
                else:
                    app.logger.warning(f"Failed to revoke key from server: {message}")
                    return jsonify({"success": False, "error": message}), 500

            except Exception as e:
                app.logger.error(f"Error revoking key: {str(e)}")
                return (
                    jsonify({"success": False, "error": f"Ошибка при отзыве ключа: {str(e)}"}),
                    500,
                )

        # Расшифровать приватный ключ
        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key:
            return (
                jsonify(
                    {
                        "success": False,
                        "error_code": "ENCRYPTION_ERROR",
                        "message": "Server configuration error",
                        "details": {
                            "problem": "Ошибка конфигурации сервера",
                            "reasons": ["ENCRYPTION_KEY не установлен"],
                            "solution": "Свяжитесь с администратором",
                        },
                    }
                ),
                500,
            )

        try:
            access_private_key = ssh_manager.decrypt_private_key(
                access_key.private_key_encrypted, encryption_key
            )
        except Exception as e:
            app.logger.error(f"Failed to decrypt access key: {str(e)}")
            return (
                jsonify(
                    {
                        "success": False,
                        "error_code": "DECRYPT_ERROR",
                        "message": f"Failed to decrypt access key",
                        "details": {
                            "problem": "Не удалось расшифровать ключ доступа",
                            "reasons": [str(e)],
                            "solution": "Ключ доступа повреждён. Создайте новый ключ.",
                        },
                    }
                ),
                500,
            )

        # Удалить ключ с детальной диагностикой
        try:
            success, message, error_code = ssh_manager.revoke_key_detailed(
                server.ip_address,
                server.ssh_port,
                server.username,
                access_private_key,
                ssh_key.public_key,
            )

            if not success:
                # Вернуть ДЕТАЛИ ошибки
                error_details = {
                    "CONNECTION_TIMEOUT": {
                        "problem": "Сервер не отвечает на подключение",
                        "reasons": [
                            "Сервер выключен или перезагружается",
                            f"Неверный IP адрес ({server.ip_address})",
                            "SSH порт закрыт в firewall",
                            f"Неверный SSH порт (текущий: {server.ssh_port})",
                            "Сетевая проблема между вашим сервером и VPS",
                        ],
                        "solution": "Проверьте IP адрес и SSH порт, убедитесь что сервер доступен",
                    },
                    "CONNECTION_ERROR": {
                        "problem": "Ошибка подключения к серверу",
                        "reasons": [
                            "Сервер недоступен",
                            "Проблемы с сетевым соединением",
                            "Firewall блокирует подключение",
                        ],
                        "solution": "Проверьте доступность сервера и настройки firewall",
                    },
                    "AUTH_FAILED": {
                        "problem": "Ошибка аутентификации на сервере",
                        "reasons": [
                            f'Пользователь "{server.username}" не существует на сервере',
                            "SSH ключ не авторизован на сервере",
                            "Ключ повреждён или неправильно расшифрован",
                            "Проблемы с правами доступа на ~/.ssh",
                        ],
                        "solution": "Проверьте имя пользователя и убедитесь что access_key развёрнут на сервер",
                    },
                    "KEY_NOT_FOUND": {
                        "problem": "Ключ не найден в authorized_keys",
                        "reasons": [
                            "Ключ уже был удален",
                            "Ключ никогда не был развернут",
                            "Файл authorized_keys был изменен вручную",
                        ],
                        "solution": "Ключ уже отозван. Можно безопасно удалить запись.",
                    },
                    "SSH_ERROR": {
                        "problem": "Ошибка SSH команды",
                        "reasons": [
                            "Права доступа запрещают удаление файла",
                            "Файл ~/.ssh/authorized_keys повреждён",
                            "Недостаточно места на диске",
                            "Проблемы с правами доступа",
                        ],
                        "solution": "Подключитесь к серверу вручную и проверьте ~/.ssh/authorized_keys",
                    },
                }

                details = error_details.get(
                    error_code,
                    {
                        "problem": message,
                        "reasons": ["Неизвестная ошибка"],
                        "solution": "Проверьте логи сервера",
                    },
                )

                app.logger.warning(f"Failed to revoke key: {message} (error_code: {error_code})")

                return (
                    jsonify(
                        {
                            "success": False,
                            "error_code": error_code,
                            "message": message,
                            "details": details,
                            "server_info": {
                                "name": server.name,
                                "ip": server.ip_address,
                                "port": server.ssh_port,
                                "username": server.username,
                            },
                        }
                    ),
                    500,
                )

        except Exception as ssh_error:
            app.logger.error(f"SSH exception during key revoke: {str(ssh_error)}")
            return (
                jsonify(
                    {
                        "success": False,
                        "error_code": "SSH_EXCEPTION",
                        "message": str(ssh_error),
                        "details": {
                            "problem": "Критическая ошибка SSH соединения",
                            "reasons": [str(ssh_error)],
                            "solution": "Проверьте консоль приложения для полных логов ошибки",
                        },
                    }
                ),
                500,
            )

        # Успех - отметить как revoked в БД
        deployment.revoked_at = datetime.now(timezone.utc)
        deployment.revoked_by = current_user.id
        db.session.commit()

        add_log("revoke_key", target=ssh_key.name, details={"server": server.name})

        return jsonify(
            {
                "success": True,
                "message": f"✅ Key {ssh_key.name} successfully revoked from {server.name}",
            }
        )

    except Exception as e:
        app.logger.exception(f"Unexpected error in revoke_key_api: {str(e)}")
        return jsonify({"success": False, "error_code": "INTERNAL_ERROR", "message": str(e)}), 500


@app.route("/api/revoke-key-all", methods=["POST"])
@login_required
def revoke_key_all():
    """
    Отозвать SSH-ключ со ВСЕХ серверов сразу.

    Параметры:
        ssh_key_id: ID ключа для отзыва

    Возвращает:
        {
            'success': bool,
            'total': int,
            'completed': int,
            'failed': int,
            'servers': [{'name': str, 'status': 'success'|'failed', 'message': str}]
        }
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    try:
        data = request.get_json()
        ssh_key_id = data.get("ssh_key_id")

        if not ssh_key_id:
            return jsonify({"success": False, "message": "ssh_key_id обязателен"}), 400

        # Получаем ключ
        ssh_key = SSHKey.query.get(ssh_key_id)
        if not ssh_key:
            return jsonify({"success": False, "message": "Ключ не найден"}), 404

        # Проверяем доступ
        if ssh_key.user_id != current_user.id:
            return jsonify({"success": False, "message": "Доступ запрещен"}), 403

        # Получаем все активные развертывания этого ключа
        deployments = KeyDeployment.query.filter_by(ssh_key_id=ssh_key_id, revoked_at=None).all()

        if not deployments:
            return jsonify(
                {
                    "success": True,
                    "message": "Ключ не развернут ни на одном сервере",
                    "total": 0,
                    "completed": 0,
                    "failed": 0,
                    "servers": [],
                }
            )

        app.logger.info(f"Начинаем отзыв ключа {ssh_key.name} со {len(deployments)} серверов")

        # Получаем ключ шифрования
        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key:
            app.logger.error("ENCRYPTION_KEY не установлен")
            return jsonify({"success": False, "message": "Ошибка конфигурации сервера"}), 500

        # Сохраняем ID пользователя для использования в потоках
        user_id = current_user.id
        ssh_key_id = ssh_key.id
        ssh_key_name = ssh_key.name
        ssh_key_public = ssh_key.public_key

        # Обёртка для выполнения в контексте приложения
        def revoke_from_server_wrapper(deployment):
            """Обёртка для выполнения в контексте приложения"""
            with app.app_context():
                try:
                    # Получить данные развертывания
                    deployment = KeyDeployment.query.get(deployment.id)
                    if not deployment:
                        return {
                            "server_id": None,
                            "server_name": "Unknown",
                            "success": False,
                            "message": "Deployment not found",
                        }

                    ssh_key_obj = deployment.ssh_key
                    server = deployment.server

                    if not server:
                        return {
                            "server_id": deployment.server_id,
                            "server_name": "Unknown",
                            "success": False,
                            "message": "Сервер не найден",
                        }

                    # Поиск root ключа
                    root_key_name = f"root_{server.name}"
                    root_key = SSHKey.query.filter_by(name=root_key_name, user_id=user_id).first()

                    if not root_key:
                        app.logger.warning(f"Root ключ не найден для сервера {server.name}")
                        return {
                            "server_id": server.id,
                            "server_name": server.name,
                            "success": False,
                            "message": "Root ключ не найден",
                        }

                    # Расшифровка приватного ключа
                    try:
                        private_key_decrypted = ssh_manager.decrypt_private_key(
                            root_key.private_key_encrypted, encryption_key
                        )
                    except Exception as e:
                        app.logger.error(
                            f"Ошибка при расшифровке root ключа для {server.name}: {str(e)}"
                        )
                        return {
                            "server_id": server.id,
                            "server_name": server.name,
                            "success": False,
                            "message": "Ошибка расшифровки ключа",
                        }

                    # Отзыв ключа
                    try:
                        app.logger.info(f"Отзываем ключ {ssh_key_name} с сервера {server.name}")
                        result = ssh_manager.revoke_key(
                            server.ip_address,
                            server.ssh_port,
                            server.username,
                            private_key_decrypted,
                            ssh_key_public,
                            server,
                        )

                        success = result.get("success", False)
                        message = result.get("message", "Неизвестная ошибка")

                        if success:
                            # Обновляем deployment в БД
                            deployment.revoked_at = datetime.now(timezone.utc)
                            deployment.revoked_by = user_id
                            db.session.commit()

                            app.logger.info(f"Ключ {ssh_key_name} успешно отозван с {server.name}")
                            add_log(
                                "revoke_key_all",
                                target=ssh_key_name,
                                details={"server": server.name, "status": "success"},
                            )

                            return {
                                "server_id": server.id,
                                "server_name": server.name,
                                "success": True,
                                "message": "Успешно отозван",
                            }
                        else:
                            app.logger.warning(
                                f"Ошибка при отзыве ключа с {server.name}: {message}"
                            )
                            add_log(
                                "revoke_key_all_failed",
                                target=ssh_key_name,
                                details={"server": server.name, "error": message},
                            )

                            return {
                                "server_id": server.id,
                                "server_name": server.name,
                                "success": False,
                                "message": message,
                            }

                    except Exception as e:
                        app.logger.error(f"Исключение при отзыве ключа с {server.name}: {str(e)}")
                        return {
                            "server_id": server.id,
                            "server_name": server.name,
                            "success": False,
                            "message": f"Ошибка: {str(e)}",
                        }

                except Exception as e:
                    app.logger.error(f"Неожиданная ошибка в revoke_from_server_wrapper: {str(e)}")
                    return {
                        "server_id": None,
                        "server_name": "Unknown",
                        "success": False,
                        "message": f"Ошибка: {str(e)}",
                    }

        # Параллельно отзываем ключ со всех серверов (max 5 одновременно)
        results = []
        completed = 0
        failed = 0

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(revoke_from_server_wrapper, dep): dep for dep in deployments}

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=30)
                    results.append(result)

                    if result["success"]:
                        completed += 1
                    else:
                        failed += 1

                    app.logger.debug(f'Результат для {result["server_name"]}: {result["success"]}')

                except Exception as e:
                    app.logger.error(f"Ошибка при выполнении задачи: {str(e)}")
                    failed += 1
                    results.append(
                        {
                            "server_id": None,
                            "server_name": "Unknown",
                            "success": False,
                            "message": f"Ошибка выполнения: {str(e)}",
                        }
                    )

        app.logger.info(f"Отзыв ключа завершен. Успешно: {completed}, Ошибок: {failed}")

        return jsonify(
            {
                "success": True,
                "message": f"Отзыв завершен. Успешно: {completed}, Ошибок: {failed}",
                "total": len(deployments),
                "completed": completed,
                "failed": failed,
                "servers": results,
            }
        )

    except Exception as e:
        app.logger.exception(f"Ошибка в revoke_key_all: {str(e)}")
        return jsonify({"success": False, "message": f"Ошибка сервера: {str(e)}"}), 500


@app.route("/key-deployments/revoke", methods=["POST"])
@login_required
def revoke_key_deployment():
    data = request.get_json()
    key_id = data.get("key_id")
    server_id = data.get("server_id")

    key_to_revoke = SSHKey.query.get_or_404(key_id)
    if key_to_revoke.user_id != current_user.id:
        abort(403)

    # Сценарий 1: Отозвать со всех серверов
    if server_id is None:
        servers_with_key = (
            Server.query.join(KeyDeployment)
            .filter(
                KeyDeployment.ssh_key_id == key_id,
                KeyDeployment.revoked_at.is_(None),
                Server.user_id == current_user.id,
            )
            .all()
        )

        if not servers_with_key:
            return jsonify(
                {"success": True, "message": "Ключ не был развернут ни на одном сервере."}
            )

        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key:
            return jsonify({"success": False, "message": "Ключ шифрования не настроен."}), 500

        user_credentials = {"encryption_key": encryption_key}

        report = ssh_manager.revoke_key_from_all_servers(
            key_to_revoke.public_key, servers_with_key, user_credentials
        )

        # Обновляем БД для успешно отозванных ключей
        for sid in report["success"]:
            deployment = KeyDeployment.query.filter_by(
                ssh_key_id=key_id, server_id=sid, revoked_at=None
            ).first()
            if deployment:
                deployment.revoked_at = db.func.now()
                deployment.revoked_by = current_user.id
                add_log(
                    "revoke_key",
                    target=key_to_revoke.name,
                    details={"server_id": sid, "result": "success"},
                )
        db.session.commit()

        return jsonify({"success": True, **report})

    # Сценарий 2: Отозвать с одного сервера
    else:
        server = Server.query.get_or_404(server_id)
        if server.user_id != current_user.id:
            abort(403)

        deployment = KeyDeployment.query.filter_by(
            ssh_key_id=key_id, server_id=server_id, revoked_at=None
        ).first()

        if not deployment:
            return jsonify({"success": False, "message": "Активное развертывание не найдено."}), 404

        access_key = server.access_key
        if not access_key:
            return (
                jsonify({"success": False, "message": "Ключ доступа для сервера не найден."}),
                500,
            )

        try:
            encryption_key = os.environ.get("ENCRYPTION_KEY")
            private_key = ssh_manager.decrypt_private_key(
                access_key.private_key_encrypted, encryption_key
            )

            # Используем новую функцию revoke_key() с адаптивными алгоритмами
            # Передаем объект server для использования connect_with_adaptive_algorithms()
            result = ssh_manager.revoke_key(
                server.ip_address,
                server.ssh_port,
                server.username,
                private_key,
                key_to_revoke.public_key,
                server,  # Передаем объект server для адаптивных алгоритмов
            )

            if result["success"]:
                deployment.revoked_at = db.func.now()
                deployment.revoked_by = current_user.id
                db.session.commit()
                add_log(
                    "revoke_key",
                    target=key_to_revoke.name,
                    details={
                        "server": server.name,
                        "result": "success",
                        "openssh_version": server.openssh_version,
                    },
                )
                return jsonify({"success": True, "message": "Ключ успешно отозван."})
            else:
                add_log(
                    "revoke_key_failed",
                    target=key_to_revoke.name,
                    details={"server": server.name, "error": result["message"]},
                )
                return jsonify({"success": False, "message": result["message"]})

        except Exception as e:
            logger.error(f"Ошибка при отзыве ключа: {str(e)}")
            return jsonify({"success": False, "message": f"Внутренняя ошибка: {str(e)}"}), 500


@app.route("/key-deployments/track", methods=["POST"])
@login_required
def track_key_deployment():
    data = request.get_json()
    key_id = data.get("key_id")
    server_id = data.get("server_id")

    if not key_id or not server_id:
        return jsonify({"success": False, "message": "Отсутствуют ID ключа или сервера."}), 400

    # Проверяем, существует ли уже такая активная запись
    existing_deployment = KeyDeployment.query.filter_by(
        ssh_key_id=key_id, server_id=server_id, revoked_at=None
    ).first()

    if existing_deployment:
        return jsonify({"success": True, "message": "Развертывание уже отслеживается."})

    new_deployment = KeyDeployment(
        ssh_key_id=key_id, server_id=server_id, deployed_by=current_user.id
    )
    db.session.add(new_deployment)
    db.session.commit()

    add_log("track_deployment", target=f"key_{key_id}_on_server_{server_id}")
    return jsonify({"success": True, "message": "Развертывание успешно зарегистрировано."})


@app.route("/key-deployments")
@login_required
def key_deployments():
    deployments = KeyDeployment.query.filter_by(deployed_by=current_user.id).all()
    return render_template("key-deployments.html", deployments=deployments)


@app.route("/logs")
@login_required
def logs():
    page = request.args.get("page", 1, type=int)
    logs_pagination = (
        Log.query.filter_by(user_id=current_user.id)
        .order_by(Log.timestamp.desc())
        .paginate(page=page, per_page=50, error_out=False)
    )

    action_colors = {
        "login_success": "success",
        "login_failed": "warning",
        "logout": "secondary",
        "add_server": "info",
        "edit_server": "info",
        "delete_server": "danger",
        "generate_key": "primary",
        "delete_key": "danger",
        "deploy_key": "success",
        "test_connection": "secondary",
    }

    return render_template(
        "logs.html", logs_pagination=logs_pagination, action_colors=action_colors
    )


# --- Запуск приложения ---


@app.cli.command("create-admin")
@click.argument("username")
@click.argument("password")
def create_admin(username, password):
    """Создает нового пользователя-администратора."""
    with app.app_context():
        if User.query.filter_by(username=username).first():
            print(f"Пользователь с именем '{username}' уже существует.")
            return

        admin_user = User(username=username, is_admin=True)
        admin_user.set_password(password)

        db.session.add(admin_user)
        db.session.commit()
        print(f"Администратор '{username}' успешно создан.")


# Обработчики ошибок
@app.errorhandler(404)
def not_found_error(error):
    return render_template("error.html", error=error), 404


@app.errorhandler(403)
def forbidden_error(error):
    return render_template("error.html", error=error), 403


@app.errorhandler(500)
def internal_error(error):
    # Логируем ошибку
    app.logger.error(f"500 Error: {str(error)}")
    return render_template("error.html", error=error), 500


@app.errorhandler(Exception)
def handle_exception(error):
    # Передаем HTTP ошибки как есть
    if isinstance(error, HTTPException):
        return error

    # Логируем необработанное исключение
    app.logger.exception("Unhandled Exception: %s", (error))

    # Возвращаем 500 Internal Server Error
    return render_template("error.html", error=str(error)), 500


if __name__ == "__main__":
    # Включаем логирование
    import logging
    from logging.handlers import RotatingFileHandler

    # Настройка логирования
    if not os.path.exists("logs"):
        os.mkdir("logs")
    file_handler = RotatingFileHandler("logs/vps_manager.log", maxBytes=10240, backupCount=10)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]")
    )
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info("VPS Manager startup")

    app.run(debug=os.environ.get("FLASK_ENV") == "development")
