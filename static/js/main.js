document.addEventListener('DOMContentLoaded', function () {
    const serverModal = document.getElementById('serverModal');
    const deleteConfirmModal = document.getElementById('deleteConfirmModal');
    const deleteKeyModal = document.getElementById('deleteKeyModal');
    const deployKeyModal = document.getElementById('deployKeyModal');

    // --- Логика для модального окна добавления/редактирования сервера ---
    if (serverModal) {
        serverModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const action = button.getAttribute('data-action');
            const form = document.getElementById('serverForm');
            const modalTitle = serverModal.querySelector('.modal-title');

            if (action === 'edit') {
                const serverId = button.getAttribute('data-id');
                const serverRow = document.getElementById(`server-${serverId}`);

                modalTitle.textContent = 'Редактировать сервер';
                form.action = `/servers/edit/${serverId}`;

                // Заполнение полей формы данными из таблицы
                document.getElementById('server-name').value = serverRow.querySelector('[data-field="name"]').textContent;
                document.getElementById('server-ip').value = serverRow.querySelector('[data-field="ip_address"]').textContent;
                document.getElementById('server-port').value = serverRow.querySelector('[data-field="ssh_port"]').textContent;
                document.getElementById('server-username').value = serverRow.querySelector('[data-field="username"]').textContent;
            } else {
                modalTitle.textContent = 'Добавить новый сервер';
                form.action = button.getAttribute('data-add-url');
                form.reset(); // Очистка формы для добавления
            }
        });
    }

    // --- Логика для модального окна подтверждения удаления ---
    if (deleteConfirmModal) {
        let serverIdToDelete = null;

        deleteConfirmModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            serverIdToDelete = button.getAttribute('data-id');
            const serverName = button.getAttribute('data-name');
            document.getElementById('serverNameToDelete').textContent = serverName;
        });

        document.getElementById('confirmDeleteBtn').addEventListener('click', function () {
            if (serverIdToDelete) {
                fetch(`/servers/delete/${serverIdToDelete}`, {
                    method: 'POST',
                    headers: {
                        // Flask-WTF ожидает CSRF токен
                        'X-CSRFToken': document.querySelector('input[name=csrf_token]').value
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Удаляем строку из таблицы
                        document.getElementById(`server-${serverIdToDelete}`).remove();
                        // Скрываем модальное окно
                        const modal = bootstrap.Modal.getInstance(deleteConfirmModal);
                        modal.hide();
                        // Можно добавить toast-уведомление
                    }
                })
                .catch(error => console.error('Ошибка:', error));
            }
        });
    }

    // --- Логика для модального окна подтверждения удаления ключа ---
    if (deleteKeyModal) {
        let keyIdToDelete = null;

        deleteKeyModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            keyIdToDelete = button.getAttribute('data-id');
            const keyName = button.getAttribute('data-name');
            document.getElementById('keyNameToDelete').textContent = keyName;
        });

        document.getElementById('confirmDeleteKeyBtn').addEventListener('click', function () {
            if (keyIdToDelete) {
                fetch(`/keys/delete/${keyIdToDelete}`, {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': document.querySelector('input[name=csrf_token]').value
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById(`key-${keyIdToDelete}`).remove();
                        const modal = bootstrap.Modal.getInstance(deleteKeyModal);
                        modal.hide();
                    }
                })
                .catch(error => console.error('Ошибка:', error));
            }
        });
    }

    // --- Логика для деплоя ключа ---
    if (deployKeyModal) {
        let keyIdToDeploy = null;

        deployKeyModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            keyIdToDeploy = button.getAttribute('data-id');
            const keyName = button.getAttribute('data-name');
            document.getElementById('keyNameToDeploy').textContent = keyName;
            document.getElementById('deployResult').innerHTML = ''; // Очистка результата
        });

        document.getElementById('confirmDeployKeyBtn').addEventListener('click', function () {
            const serverId = document.getElementById('serverSelect').value;
            const resultDiv = document.getElementById('deployResult');

            if (keyIdToDeploy && serverId) {
                resultDiv.innerHTML = '<div class="spinner-border spinner-border-sm" role="status"><span class="visually-hidden">Loading...</span></div>';

                fetch('/keys/deploy', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': document.querySelector('input[name=csrf_token]').value
                    },
                    body: JSON.stringify({ key_id: keyIdToDeploy, server_id: serverId })
                })
                .then(response => response.json())
                .then(data => {
                    const alertClass = data.success ? 'alert-success' : 'alert-danger';
                    resultDiv.innerHTML = `<div class="alert ${alertClass}">${data.message}</div>`;
                })
                .catch(error => {
                    resultDiv.innerHTML = `<div class="alert alert-danger">Ошибка сети: ${error}</div>`;
                });
            }
        });
    }

    // --- Логика для теста соединения ---
    document.querySelectorAll('.test-btn').forEach(button => {
        button.addEventListener('click', function () {
            const serverId = this.getAttribute('data-id');
            const statusCell = document.querySelector(`#server-${serverId} [data-field='status'] span`);
            const originalStatusText = statusCell.textContent;
            const originalStatusClass = statusCell.className;

            statusCell.innerHTML = '<div class="spinner-border spinner-border-sm" role="status"><span class="visually-hidden">...</span></div>';
            statusCell.className = 'badge';

            fetch(`/servers/test/${serverId}`, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': document.querySelector('input[name=csrf_token]').value
                }
            })
            .then(response => response.json())
            .then(data => {
                const statusClass = data.success ? 'bg-success' : 'bg-danger';
                statusCell.className = `badge ${statusClass}`;
                statusCell.textContent = data.status;
            })
            .catch(error => {
                statusCell.className = originalStatusClass;
                statusCell.textContent = originalStatusText;
                console.error('Ошибка:', error);
            });
        });
    });
});
