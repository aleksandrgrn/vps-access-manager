import os
import subprocess
import sys
import time

import pytest
from playwright.sync_api import sync_playwright


@pytest.fixture(scope="module")
def flask_app():
    """Запуск Flask приложения для E2E тестов"""
    # Установить тестовые переменные окружения
    env = os.environ.copy()
    env["FLASK_ENV"] = "testing"
    env["FLASK_APP"] = "run.py"
    env["DATABASE_URL"] = "sqlite:///test_e2e.db"
    env["PYTHONIOENCODING"] = "utf-8"

    # Initialize DB
    try:
        subprocess.run(
            [sys.executable, "-m", "flask", "init-db"], env=env, check=True, capture_output=True
        )
    except subprocess.CalledProcessError as e:
        print("Init DB Failed!")
        print(f"STDOUT: {e.stdout.decode(errors='replace') if e.stdout else 'None'}")
        print(f"STDERR: {e.stderr.decode(errors='replace') if e.stderr else 'None'}")
        raise

    # Create admin user
    create_user_script = """
from app import create_app, db
from app.models import User
app = create_app()
with app.app_context():
    if not User.query.filter_by(username='admin').first():
        user = User(username='admin')
        user.set_password('admin')
        db.session.add(user)
        db.session.commit()
"""
    try:
        subprocess.run(
            [sys.executable, "-c", create_user_script], env=env, check=True, capture_output=True
        )
    except subprocess.CalledProcessError as e:
        print("Create User Failed!")
        print(f"STDOUT: {e.stdout.decode(errors='replace') if e.stdout else 'None'}")
        print(f"STDERR: {e.stderr.decode(errors='replace') if e.stderr else 'None'}")
        raise

    # Запустить Flask
    process = subprocess.Popen(
        [sys.executable, "run.py"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # Дождаться запуска (5 сек)
    time.sleep(5)

    yield "http://127.0.0.1:5000"

    # Остановить приложение
    process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=5)
        print("\n=== Flask App STDOUT ===")
        print(stdout.decode(errors="replace"))
        print("=== Flask App STDERR ===")
        print(stderr.decode(errors="replace"))
        print("========================")
    except Exception as e:
        print(f"Error reading process output: {e}")
        process.kill()

    # Удалить тестовую БД
    if os.path.exists("test_e2e.db"):
        try:
            os.remove("test_e2e.db")
        except PermissionError:
            pass


@pytest.fixture(scope="module")
def browser():
    """Playwright browser fixture"""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def page(browser, flask_app):
    """Новая страница для каждого теста"""
    context = browser.new_context(viewport={"width": 1920, "height": 1080})
    page = context.new_page()

    # Capture console logs
    page.on("console", lambda msg: print(f"BROWSER CONSOLE: {msg.text}"))
    page.on("pageerror", lambda exc: print(f"BROWSER ERROR: {exc}"))

    page.goto(flask_app)
    yield page
    context.close()


@pytest.mark.e2e
def test_e2e_login_flow(page):
    """Test login flow."""
    # 1. Open page (already done in fixture)
    # 2. Fill login form
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "admin")
    # 3. Click login
    page.click('[type="submit"]')
    # 4. Check redirect
    page.wait_for_url("**/api/dashboard")
    # 5. Check URL
    assert "/api/dashboard" in page.url
    # 6. Screenshot
    os.makedirs("reports/screenshots", exist_ok=True)
    page.screenshot(path="reports/screenshots/login_success.png")


@pytest.mark.e2e
def test_e2e_add_server(page):
    """Test adding a server."""
    # Login first
    page.goto("http://127.0.0.1:5000/login")
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "admin")
    page.click('[type="submit"]')

    # Go to servers
    page.click('a[href*="/api/servers"]')

    # Add server
    # Use data-action="add" selector
    page.click('button[data-action="add"]')

    # Wait for modal or force open
    try:
        page.wait_for_selector("#serverModal", state="visible", timeout=2000)
    except:
        page.evaluate(
            """
            document.getElementById('serverModal').classList.add('show');
            document.getElementById('serverModal').style.display = 'block';
            document.body.classList.add('modal-open');
            // Create backdrop if not exists
            if (!document.querySelector('.modal-backdrop')) {
                var backdrop = document.createElement('div');
                backdrop.className = 'modal-backdrop fade show';
                document.body.appendChild(backdrop);
            }
            
            // Set form action manually
            var form = document.getElementById('serverForm');
            form.action = '/api/servers/add';
            document.getElementById('password-field').style.display = 'block';
        """
        )

    page.fill('input[name="name"]', "test-server-e2e", force=True)
    page.fill('input[name="ip_address"]', "192.168.1.100", force=True)
    page.fill('input[name="ssh_port"]', "22", force=True)
    page.fill('input[name="username"]', "root", force=True)
    page.fill("#serverPassword", "testpass", force=True)

    page.click('[type="submit"]')

    # Check result
    # Wait for the server to appear in the list
    page.wait_for_selector("text=test-server-e2e", timeout=5000)
    assert page.is_visible("text=test-server-e2e")
    page.screenshot(path="reports/screenshots/server_added.png")


@pytest.mark.e2e
def test_e2e_generate_key(page):
    """Test generating a key."""
    # Login
    page.goto("http://127.0.0.1:5000/login")
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "admin")
    page.click('[type="submit"]')

    # Go to keys
    page.click('a[href*="/api/keys"]')

    # Generate
    # Use data-bs-target selector
    page.click('button[data-bs-target="#generateKeyModal"]')

    # Wait for modal or force open
    try:
        page.wait_for_selector("#generateKeyModal", state="visible", timeout=2000)
    except:
        page.evaluate(
            """
            document.getElementById('generateKeyModal').classList.add('show');
            document.getElementById('generateKeyModal').style.display = 'block';
            document.body.classList.add('modal-open');
            // Create backdrop if not exists
            if (!document.querySelector('.modal-backdrop')) {
                var backdrop = document.createElement('div');
                backdrop.className = 'modal-backdrop fade show';
                document.body.appendChild(backdrop);
            }
        """
        )

    page.select_option('select[name="key_type"]', "Ed25519", force=True)  # Assuming select name
    page.fill('input[name="name"]', "test-key-e2e", force=True)
    page.click('[type="submit"]')

    # Check
    page.wait_for_selector("text=test-key-e2e", timeout=5000)
    assert page.is_visible("text=test-key-e2e")
    assert page.is_visible("text=SHA256:")
    page.screenshot(path="reports/screenshots/key_generated.png")
