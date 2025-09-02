document.addEventListener('DOMContentLoaded', function() {
    checkAuthStatus();
    loadUserNotes();
    
    setupInputValidation();
});

function setupInputValidation() {
    const titleInputs = ['noteTitle', 'editNoteTitle'];
    
    titleInputs.forEach(inputId => {
        const input = document.getElementById(inputId);
        if (input) {
            input.addEventListener('input', function(e) {
                const value = e.target.value;
                const isValid = /^[a-zA-Z0-9_]*$/.test(value);
                
                if (!isValid) {
                    e.target.value = value.replace(/[^a-zA-Z0-9_]/g, '');
                }
                
                if (value && !isValid) {
                    e.target.style.borderColor = '#dc3545';
                } else {
                    e.target.style.borderColor = '';
                }
            });
        }
    });
}

function checkAuthStatus() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'index.html';
        return;
    }

    fetch('/api/auth/me', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Invalid token');
        }
        return response.json();
    })
    .then(data => {
        document.getElementById('username').textContent = data.user.username;
    })
    .catch(error => {
        console.error('Auth error:', error);
        localStorage.removeItem('token');
        window.location.href = 'index.html';
    });
}

function loadUserNotes() {
    const token = localStorage.getItem('token');
    console.log('Loading user notes with token:', token ? 'present' : 'missing');
    
    fetch('/api/notes', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        console.log('Response status:', response.status);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(notes => {
        console.log('Received notes:', notes);
        displayUserNotes(notes);
    })
    .catch(error => {
        console.error('Error loading user notes:', error);
        document.getElementById('user-gallery').innerHTML = '<p>Error loading notes</p>';
    });
}

function displayUserNotes(notes) {
    const gallery = document.getElementById('user-gallery');
    
    const userNotes = notes.filter(note => note.is_owner === true);
    
    console.log('Total notes received:', notes.length);
    console.log('User notes (is_owner = true):', userNotes.length);
    
    if (userNotes.length === 0) {
        gallery.innerHTML = `
            <div class="col-12">
                <div class="empty-state">
                    <i class="bi bi-images"></i>
                    <h4>You don't have any notes yet</h4>
                    <p>Create your first note!</p>
                </div>
            </div>
        `;
        return;
    }

    gallery.innerHTML = userNotes.map(note => `
        <div class="col-lg-4 col-md-6 col-sm-12">
            <div class="card h-100 shadow-sm">
                <img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAwIiBoZWlnaHQ9IjI1MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjZGRkIi8+PHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxNCIgZmlsbD0iIzk5OSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZHk9Ii4zZW0iPkxvYWRpbmcuLi48L3RleHQ+PC9zdmc+" alt="${note.title}" class="card-img-top" data-note-id="${note.id}">
                <div class="card-body d-flex flex-column">
                    <h5 class="card-title text-center mb-2">${note.title}</h5>
                    <p class="text-muted text-center mb-0">Privacy: ${note.privacy === 'public' ? 'Public' : 'Private'}</p>
                    <div class="d-flex gap-2 mt-3 justify-content-center flex-wrap">
                        <button class="btn btn-outline-primary btn-sm" onclick="editNote('${note.id}', '${note.title}', '${note.privacy}')">
                            <i class="bi bi-pencil me-1"></i>Edit
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="deleteNote('${note.id}')">
                            <i class="bi bi-trash me-1"></i>Delete
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `).join('');

    userNotes.forEach(note => {
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

function showCreateNoteModal() {
    const modal = new bootstrap.Modal(document.getElementById('createNoteModal'));
    modal.show();
}

function closeCreateNoteModal() {
    const modal = bootstrap.Modal.getInstance(document.getElementById('createNoteModal'));
    modal.hide();
    document.getElementById('createNoteForm').reset();
}

function showEditNoteModal() {
    const modal = new bootstrap.Modal(document.getElementById('editNoteModal'));
    modal.show();
}

function closeEditNoteModal() {
    const modal = bootstrap.Modal.getInstance(document.getElementById('editNoteModal'));
    modal.hide();
    document.getElementById('editNoteForm').reset();
}

function showPrivacyModal() {
    const modal = new bootstrap.Modal(document.getElementById('privacyModal'));
    loadPrivacyNotesList();
    modal.show();
}

function closePrivacyModal() {
    const modal = bootstrap.Modal.getInstance(document.getElementById('privacyModal'));
    modal.hide();
}

function loadPrivacyNotesList() {
    const token = localStorage.getItem('token');
    const headers = {};
    
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    console.log('Loading privacy notes list with token:', token ? 'present' : 'missing');

    fetch('/api/notes', { headers })
        .then(response => {
            console.log('Privacy notes response status:', response.status);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(notes => {
            console.log('Received notes for privacy:', notes);
            const notesList = document.getElementById('privacy-notes-list');
            const userNotes = notes.filter(note => note.is_owner);
            console.log('User notes for privacy:', userNotes);
            
            if (userNotes.length === 0) {
                notesList.innerHTML = '<p class="text-muted">You don\'t have any notes yet</p>';
                return;
            }
            
            notesList.innerHTML = userNotes.map(note => `
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" value="${note.id}" id="note-${note.id}">
                    <label class="form-check-label" for="note-${note.id}">
                        ${note.title} (${note.privacy === 'public' ? 'Public' : 'Private'})
                    </label>
                </div>
            `).join('');
        })
        .catch(error => {
            console.error('Error loading notes for privacy:', error);
            document.getElementById('privacy-notes-list').innerHTML = '<p class="text-danger">Error loading notes</p>';
        });
}

function updatePrivacy() {
    const selectedNotes = Array.from(document.querySelectorAll('#privacy-notes-list input:checked'))
        .map(checkbox => checkbox.value);
    
    if (selectedNotes.length === 0) {
        alert('Please select at least one note');
        return;
    }
    
    const privacy = document.querySelector('input[name="privacy"]:checked').value;
    const token = localStorage.getItem('token');
    
    const payload = selectedNotes.length === 1 ? 
        { id: selectedNotes[0] } : 
        selectedNotes;
    
    fetch(`/api/notes/${privacy}`, {
        method: 'PATCH',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (response.ok) {
            closePrivacyModal();
            loadUserNotes();
            alert('Privacy updated successfully');
        } else {
            throw new Error('Failed to update privacy');
        }
    })
    .catch(error => {
        console.error('Error updating privacy:', error);
        alert('Error updating privacy');
    });
}

document.getElementById('createNoteForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const title = document.getElementById('noteTitle').value;
    const privacy = document.getElementById('notePrivacy').value;
    const imageFile = document.getElementById('noteImage').files[0];
    
    if (!/^[a-zA-Z0-9_]+$/.test(title)) {
        alert('Title can only contain letters, numbers, and underscores');
        return;
    }
    
    if (!imageFile) {
        alert('Please select an image');
        return;
    }

    const reader = new FileReader();
    reader.onload = function(event) {
        const imageData = event.target.result;
        const token = localStorage.getItem('token');

        fetch('/api/notes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                note: {
                    title,
                    privacy,
                    image_data: imageData
                }
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.id) {
                closeCreateNoteModal();
                loadUserNotes();
                alert('Note created successfully!');
            } else {
                alert('Error creating note: ' + (data.errors ? data.errors.join(', ') : 'Unknown error'));
            }
        })
        .catch(error => {
            console.error('Create note error:', error);
            alert('Error creating note');
        });
    };
    reader.readAsDataURL(imageFile);
});

function editNote(noteId, title, privacy) {
    document.getElementById('editNoteId').value = noteId;
    document.getElementById('editNoteTitle').value = title;
    document.getElementById('editNotePrivacy').value = privacy;
    showEditNoteModal();
}

document.getElementById('editNoteForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const noteId = document.getElementById('editNoteId').value;
    const title = document.getElementById('editNoteTitle').value;
    const privacy = document.getElementById('editNotePrivacy').value;
    const token = localStorage.getItem('token');
    
    if (!/^[a-zA-Z0-9_]+$/.test(title)) {
        alert('Title can only contain letters, numbers, and underscores');
        return;
    }

    fetch(`/api/notes/${noteId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            note: {
                title,
                privacy
            }
        })
    })
    .then(response => {
        if (response.ok) {
            closeEditNoteModal();
            loadUserNotes();
            alert('Note updated successfully!');
        } else {
            return response.json().then(data => {
                throw new Error(data.errors ? data.errors.join(', ') : 'Update error');
            });
        }
    })
    .catch(error => {
        console.error('Update note error:', error);
        alert('Error updating note: ' + error.message);
    });
});

function deleteNote(noteId) {
    if (!confirm('Are you sure you want to delete this note?')) {
        return;
    }

    const token = localStorage.getItem('token');

    fetch(`/api/notes/${noteId}`, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        if (response.ok) {
            loadUserNotes();
            alert('Note deleted successfully!');
        } else {
            throw new Error('Delete error');
        }
    })
    .catch(error => {
        console.error('Delete note error:', error);
        alert('Error deleting note');
    });
}

function logout() {
    localStorage.removeItem('token');
    window.location.href = 'index.html';
}

window.onclick = function(event) {
    const createModal = document.getElementById('createNoteModal');
    const editModal = document.getElementById('editNoteModal');
    
    if (event.target === createModal) {
        closeCreateNoteModal();
    }
    if (event.target === editModal) {
        closeEditNoteModal();
    }
}
