// Auto-dismiss flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const flashMessages = document.querySelectorAll('.p-4.mb-4');
    flashMessages.forEach(msg => {
        setTimeout(() => {
            msg.style.transition = 'opacity 0.5s';
            msg.style.opacity = '0';
            setTimeout(() => msg.remove(), 500);
        }, 5000);
    });

    // Handle OAuth hash fragment (access_token in URL)
    handleOAuthHash();
});

function handleOAuthHash() {
    const hash = window.location.hash;
    if (!hash || !hash.includes('access_token=')) {
        return;
    }

    // Parse the hash fragment
    const params = new URLSearchParams(hash.substring(1));
    const accessToken = params.get('access_token');

    if (accessToken) {
        console.log('Found access_token in URL hash, sending to backend...');
        
        // Send token to backend to set session
        fetch('/auth/set-session', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ access_token: accessToken })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Clear the hash from URL
                window.history.replaceState({}, document.title, window.location.pathname);
                // Redirect to dashboard
                window.location.href = data.redirect;
            } else {
                console.error('Failed to set session:', data.error);
            }
        })
        .catch(error => {
            console.error('Error setting session:', error);
        });
    }
}