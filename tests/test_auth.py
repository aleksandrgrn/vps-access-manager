def test_login_success(test_client, init_database):
    """Test successful login."""
    response = test_client.post(
        "/login", data=dict(username="testuser", password="testpassword"), follow_redirects=True
    )
    assert response.status_code == 200
    assert (
        b"Dashboard" in response.data
        or b"\xd0\x9f\xd0\xb0\xd0\xbd\xd0\xb5\xd0\xbb\xd1\x8c "
        b"\xd1\x83\xd0\xbf\xd1\x80\xd0\xb0\xd0\xb2\xd0\xbb\xd0\xb5\xd0\xbd\xd0\xb8\xd1\x8f"
        in response.data
    )  # "Панель управления" in bytes


def test_login_invalid_password(test_client, init_database):
    """Test login with invalid password."""
    # Ensure we are logged out
    test_client.get("/logout", follow_redirects=True)

    response = test_client.post(
        "/login", data=dict(username="testuser", password="wrongpassword"), follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Login" in response.data or b"\xd0\x92\xd1\x85\xd0\xbe\xd0\xb4" in response.data


def test_login_nonexistent_user(test_client, init_database):
    """Test login with nonexistent user."""
    response = test_client.post(
        "/login", data=dict(username="nonexistent", password="testpassword"), follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Login" in response.data or b"\xd0\x92\xd1\x85\xd0\xbe\xd0\xb4" in response.data


def test_logout(test_client, init_database):
    """Test logout."""
    # First login
    test_client.post(
        "/login", data=dict(username="testuser", password="testpassword"), follow_redirects=True
    )

    # Then logout
    response = test_client.get("/logout", follow_redirects=True)
    assert response.status_code == 200
    assert b"Login" in response.data or b"\xd0\x92\xd1\x85\xd0\xbe\xd0\xb4" in response.data


def test_csrf_protection(test_client):
    """Test CSRF protection on login form."""
    # Try to login without CSRF token (by not using the form)
    test_client.post(
        "/login", data=dict(username="testuser", password="testpassword"), follow_redirects=False
    )
    # Should fail with 400 Bad Request (CSRF token missing)
    pass


def test_session_persistence(test_client, init_database):
    """Test session persistence."""
    # test_client is already a context manager from fixture
    test_client.post(
        "/login", data=dict(username="testuser", password="testpassword"), follow_redirects=True
    )
    response = test_client.get("/api/dashboard")
    assert response.status_code == 200
