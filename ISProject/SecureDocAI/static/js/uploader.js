// Initialize Lucide icons
lucide.createIcons();


const uploadForm = document.getElementById('uploadForm');
const fileInput = document.getElementById('fileInput');

// File input change handler
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        fileName.textContent = e.target.files[0].name;
    }
});

// Form submit handler
uploadForm.addEventListener('submit', (e) => {

});
