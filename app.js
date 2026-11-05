document.addEventListener('DOMContentLoaded', () => {
    const codeInput = document.getElementById('codeInput');
    const fileInput = document.getElementById('fileInput');
    const fileName = document.getElementById('fileName');
    const deobfBtn = document.getElementById('deobfBtn');

    // Handle File Upload
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            fileName.textContent = file.name;
            const reader = new FileReader();
            reader.onload = (event) => {
                codeInput.value = event.target.result;
            };
            reader.readAsText(file);
        }
    });

    // Handle Deobfuscation Click
    deobfBtn.addEventListener('click', async () => {
        const code = codeInput.value.trim();
        if (!code) {
            alert('Payload kosong, Boss. Masukin kode dulu.');
            return;
        }

        deobfBtn.classList.add('loading');
        deobfBtn.disabled = true;

        try {
            // Kirim ke Worker API
            const response = await fetch('/api/deobfuscate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code }),
            });

            const data = await response.json();

            if (data.success) {
                // Trigger Download .txt
                const blob = new Blob([data.result], { type: 'text/plain' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'deobfuscated_output.txt';
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            } else {
                alert('Deobfuscation failed.');
            }
        } catch (error) {
            console.error(error);
            alert('Error connecting to KAIRO_ENGINE.');
        } finally {
            deobfBtn.classList.remove('loading');
            deobfBtn.disabled = false;
        }
    });
});
