let currentUser = null;

document.addEventListener('DOMContentLoaded', function() {
    checkAuthStatus();
});

function checkAuthStatus() {
    const token = localStorage.getItem('token');
    if (token) {
        fetch('/api/auth/me', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error('Invalid token');
            }
        })
        .then(data => {
            currentUser = data.user;
            updateUI();
        })
        .catch(error => {
            console.error('Auth error:', error);
            localStorage.removeItem('token');
            updateUI();
        });
    } else {
        updateUI();
    }
}

function updateUI() {
    const userMenu = document.getElementById('user-menu');
    const username = document.getElementById('username');
    const welcomeContent = document.getElementById('welcome-content');
    const authenticatedContent = document.getElementById('authenticated-content');

    if (currentUser) {
        userMenu.style.display = 'flex';
        username.textContent = currentUser.username;
        welcomeContent.style.display = 'none';
        authenticatedContent.style.display = 'block';
        
        loadNotes();
    } else {
        userMenu.style.display = 'none';
        username.textContent = '';
        welcomeContent.style.display = 'block';
        authenticatedContent.style.display = 'none';
    }
}

function loadNotes() {
    const token = localStorage.getItem('token');
    
    if (!token) {
        console.log('No token found, skipping notes load');
        return;
    }

    const headers = {
        'Authorization': `Bearer ${token}`
    };

    fetch('/api/notes', { headers })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(notes => {
            displayNotes(notes);
        })
        .catch(error => {
            console.error('Error loading notes:', error);
            document.getElementById('gallery').innerHTML = '<p class="text-center text-danger">Error loading notes</p>';
        });
}

function displayNotes(notes) {
    const gallery = document.getElementById('gallery');
    
    if (notes.length === 0) {
        gallery.innerHTML = `
            <div class="col-12">
                <div class="empty-state">
                    <i class="bi bi-images"></i>
                    <h4>No notes yet</h4>
                    <p>Be the first to create a note!</p>
                </div>
            </div>
        `;
        return;
    }

    gallery.innerHTML = notes.map(note => `
        <div class="col-lg-4 col-md-6 col-sm-12">
            <div class="card h-100 shadow-sm">
                <img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAwIiBoZWlnaHQ9IjI1MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjZGRkIi8+PHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxNCIgZmlsbD0iIzk5OSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZHk9Ii4zZW0iPkxvYWRpbmcuLi48L3RleHQ+PC9zdmc+" alt="${note.title}" class="card-img-top" data-note-id="${note.id}">
                <div class="card-body d-flex flex-column">
                    <h5 class="card-title text-center mb-2">${note.title}</h5>
                    <p class="text-muted text-center mb-0">Автор: ${note.owner}</p>
                </div>
            </div>
        </div>
    `).join('');

    notes.forEach(note => {
        loadImageWithAuth(note.id, note.image_url);
    });
}

function loadImageWithAuth(noteId, imageUrl) {
    const token = localStorage.getItem('token');
    const headers = {};
    
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const apiImageUrl = `/api${imageUrl}`;

    fetch(apiImageUrl, { headers })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to load image');
            }
            return response.blob();
        })
        .then(blob => {
            const imageUrl = URL.createObjectURL(blob);
            const imgElement = document.querySelector(`img[data-note-id="${noteId}"]`);
            if (imgElement) {
                imgElement.src = imageUrl;
            }
        })
        .catch(error => {
            console.error('Error loading image:', error);
            const imgElement = document.querySelector(`img[data-note-id="${noteId}"]`);
            if (imgElement) {
                imgElement.src = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAwIiBoZWlnaHQ9IjI1MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjZGRkIi8+PHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxNCIgZmlsbD0iIzk5OSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZHk9Ii4zZW0iPkltYWdlIG5vdCBmb3VuZDwvdGV4dD48L3N2Zz4=';
            }
        });
}

function showLoginModal() {
    const modal = new bootstrap.Modal(document.getElementById('loginModal'));
    modal.show();
}

function closeLoginModal() {
    const modal = bootstrap.Modal.getInstance(document.getElementById('loginModal'));
    modal.hide();
    document.getElementById('loginForm').reset();
}

function showRegisterModal() {
    const modal = new bootstrap.Modal(document.getElementById('registerModal'));
    modal.show();
}

function closeRegisterModal() {
    const modal = bootstrap.Modal.getInstance(document.getElementById('registerModal'));
    modal.hide();
    document.getElementById('registerForm').reset();
}

document.getElementById('loginForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.token) {
            localStorage.setItem('token', data.token);
            currentUser = data.user;
            closeLoginModal();
            updateUI();
        } else {
            alert('Login error: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(error => {
        console.error('Login error:', error);
        alert('Login error. Check username and password');
    });
});

document.getElementById('registerForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;
    const passwordConfirm = document.getElementById('registerPasswordConfirm').value;

    if (password !== passwordConfirm) {
        alert('Passwords missmatch');
        return;
    }

    fetch('/api/auth/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            user: {
                username,
                password,
                password_confirmation: passwordConfirm
            }
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.token) {
            localStorage.setItem('token', data.token);
            currentUser = data.user;
            closeRegisterModal();
            updateUI();
        } else {
            alert('Register error: ' + (data.errors ? data.errors.join(', ') : 'Unknown error'));
        }
    })
    .catch(error => {
        console.error('Register error:', error);
        alert('Register error!');
    });
});

function logout() {
    localStorage.removeItem('token');
    currentUser = null;
    updateUI();
}

function goToAccount() {
    window.location.href = 'account.html';
}

window.onclick = function(event) {
    const loginModal = document.getElementById('loginModal');
    const registerModal = document.getElementById('registerModal');
    
    if (event.target === loginModal) {
        closeLoginModal();
    }
    if (event.target === registerModal) {
        closeRegisterModal();
    }
}
