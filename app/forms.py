"""
WTForms для VPS Manager

Все формы с валидацией.
"""

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Length, NumberRange


class ServerForm(FlaskForm):
    """Форма добавления/редактирования сервера."""

    name = StringField("Название сервера", validators=[DataRequired()])
    ip_address = StringField("IP-адрес", validators=[DataRequired()])
    ssh_port = IntegerField(
        "SSH Порт", default=22, validators=[DataRequired(), NumberRange(min=1, max=65535)]
    )
    username = StringField("Имя пользователя", validators=[DataRequired()])
    requires_legacy_ssh = BooleanField("Legacy SSH (OpenSSH < 7.2)", default=False)
    submit = SubmitField("Сохранить")


class GenerateKeyForm(FlaskForm):
    """Форма генерации SSH ключа."""

    name = StringField("Название ключа", validators=[DataRequired()])
    key_type = SelectField(
        "Тип ключа",
        choices=[("rsa", "RSA 4096"), ("ed25519", "Ed25519")],
        validators=[DataRequired()],
    )
    description = TextAreaField("Описание (опционально)", validators=[Length(max=500)])
    submit = SubmitField("Сгенерировать")


class UploadKeyForm(FlaskForm):
    """Форма загрузки публичного SSH ключа."""

    name = StringField("Название ключа", validators=[DataRequired()])
    public_key = TextAreaField("Публичный ключ", validators=[DataRequired()])
    description = TextAreaField("Описание (опционально)", validators=[Length(max=500)])
    submit = SubmitField("Загрузить")


class LoginForm(FlaskForm):
    """Форма входа в систему."""

    username = StringField(
        "Имя пользователя",
        validators=[DataRequired(message="Это поле обязательно для заполнения.")],
    )
    password = PasswordField(
        "Пароль", validators=[DataRequired(message="Это поле обязательно для заполнения.")]
    )
    submit = SubmitField("Войти")
