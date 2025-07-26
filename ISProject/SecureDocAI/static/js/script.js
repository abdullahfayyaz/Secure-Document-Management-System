// Handle login form submission
async function handleLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    toggleLoader(true);

    try {
        // Here you would normally make an API call to your Django backend
        // For demonstration, we'll use a timeout to simulate an API call
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        // If login is successful, redirect to MFA page
        window.location.href = 'mfa.html';
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please try again.');
    } finally {
        toggleLoader(false);
    }
}

// Handle signup form submission
async function handleSignup(event) {
    event.preventDefault();

    const username = document.getElementById('newUsername').value;
    const email = document.getElementById('email').value;
    const role = document.getElementById('role').value;
    const password = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const errorElement = document.getElementById('passwordError');

    // Password validation
    if (password !== confirmPassword) {
        errorElement.textContent = 'Passwords do not match!';
        return;
    }

    if (password.length < 8) {
        errorElement.textContent = 'Password must be at least 8 characters long!';
        return;
    }

    if (!role) {
        errorElement.textContent = 'Please select a role!';
        return;
    }
    form.submit();
    
}

// Handle MFA form submission
async function handleMFA(event) {
    event.preventDefault();

    const otpCode = document.getElementById('otpCode').value;

    if (otpCode.length !== 6 || !/^\d+$/.test(otpCode)) {
        alert('Please enter a valid 6-digit code');
        return;
    }

    toggleLoader(true);

    try {
        // Here you would normally make an API call to your Django backend
        // For demonstration, we'll use a timeout to simulate an API call
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        // If MFA verification is successful, redirect to dashboard
        window.location.href = 'dashboard.html';
    } catch (error) {
        console.error('MFA verification error:', error);
        alert('MFA verification failed. Please try again.');
    } finally {
        toggleLoader(false);
    }
}

// Show/hide loader
function toggleLoader(show) {
    document.getElementById('loader').classList.toggle('hidden', !show);
}

// Add input validation for OTP input
if (document.getElementById('otpCode')) {
    document.getElementById('otpCode').addEventListener('input', function(e) {
        e.target.value = e.target.value.replace(/[^\d]/g, '').slice(0, 6);
    });
}