"""
Tests for Category Routes
"""


def test_get_categories_empty(auth_client):
    """Test getting categories when list is empty."""
    response = auth_client.get("/api/categories")
    assert response.status_code == 200
    assert response.json == []


def test_create_category(auth_client):
    """Test creating a new category."""
    response = auth_client.post("/api/categories", json={"name": "Production", "color": "#ff0000"})
    assert response.status_code == 201
    assert response.json["success"] is True
    assert response.json["category"]["name"] == "Production"
    assert response.json["category"]["color"] == "#ff0000"


def test_create_category_duplicate(auth_client):
    """Test creating a duplicate category."""
    # Create first
    auth_client.post("/api/categories", json={"name": "Staging"})

    # Try duplicate
    response = auth_client.post("/api/categories", json={"name": "Staging"})
    assert response.status_code == 400
    assert response.json["success"] is False
    assert "уже существует" in response.json["message"]


def test_get_categories_with_data(auth_client):
    """Test getting categories list."""
    auth_client.post("/api/categories", json={"name": "Test1"})
    auth_client.post("/api/categories", json={"name": "Test2"})

    response = auth_client.get("/api/categories")
    assert response.status_code == 200
    assert len(response.json) >= 2

    names = [c["name"] for c in response.json]
    assert "Test1" in names
    assert "Test2" in names


def test_delete_category(auth_client):
    """Test deleting a category."""
    # Create
    resp = auth_client.post("/api/categories", json={"name": "To Delete"})
    cat_id = resp.json["category"]["id"]

    # Delete
    response = auth_client.delete(f"/api/categories/{cat_id}")
    assert response.status_code == 200
    assert response.json["success"] is True

    # Verify deleted
    response = auth_client.get("/api/categories")
    names = [c["name"] for c in response.json]
    assert "To Delete" not in names


def test_delete_nonexistent_category(auth_client):
    """Test deleting a non-existent category."""
    response = auth_client.delete("/api/categories/99999")
    assert response.status_code == 404
