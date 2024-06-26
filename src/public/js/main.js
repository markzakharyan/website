// Logout function
function logout() {
  fetch('/logout', { method: 'POST' })
      .then(response => response.json())
      .then(data => {
          if (data.success) {
            window.location.href = '/';
          }
      })
      .catch(error => console.error('Error:', error));
}

// Function to show messages
function showMessage(message, type) {
  const messageElement = document.getElementById('message');
  if (messageElement) {
      messageElement.textContent = message;
      messageElement.className = `message ${type}`;
      messageElement.style.display = 'block';
      setTimeout(() => {
          messageElement.style.display = 'none';
      }, 5000);
  }
}

// Add event listeners when the DOM is loaded
document.addEventListener('DOMContentLoaded', (event) => {
  // Login form submission
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
      loginForm.addEventListener('submit', function(e) {
          e.preventDefault();
          const email = document.getElementById('email').value;
          const password = document.getElementById('password').value;
          
          fetch('/login', {
              method: 'POST',
              headers: {
                  'Content-Type': 'application/json',
              },
              body: JSON.stringify({ email, password }),
          })
          .then(response => response.json())
          .then(data => {
              if (data.success) {
                  window.location.reload();
              } else {
                  showMessage(data.error, 'error');
              }
          })
          .catch(error => {
              console.error('Error:', error);
              showMessage('An error occurred. Please try again.', 'error');
          });
      });
  }

  // Add more event listeners for other forms as needed
});