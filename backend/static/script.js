// frontend/script.js
function registrarEmocao() {
    const emocao = document.getElementById('emocao').value;
    console.log('Emoção registrada:', emocao);
    // Aqui você fará uma chamada para o backend para salvar a emoção
}

function logout() {
    window.location.href = '/logout';
}

// Aqui você adicionará mais funcionalidades com JavaScript
// para interagir com o backend (e.g., carregar questionário,
// enviar respostas, exibir registros e gráficos).