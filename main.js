document.addEventListener('DOMContentLoaded', function () {
  // Sobreescribe el evento submit
  const form = document.getElementById('recepcionForm');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      const formData = new FormData(form);
      const data = {};
      formData.forEach((value, key) => data[key] = value);

      fetch('/api/recepcion', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      })
      .then(r => r.json())
      .then(resp => {
        if (resp.ok) {
          document.getElementById('alerta').textContent = "¡Recepción registrada exitosamente!";
          form.reset();
        } else {
          document.getElementById('alerta').textContent = "Error: " + (resp.error || "No se pudo registrar.");
        }
        setTimeout(() => { document.getElementById('alerta').textContent = ""; }, 4000);
      });
    });
  }
});