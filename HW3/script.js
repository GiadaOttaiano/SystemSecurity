function mostraCertificato() {
    // Percorso al file del certificato
    const certPath = 'certificates/localhost.crt';

    // Carica il file del certificato
    fetch(certPath)
        .then(response => {
            if (!response.ok) {
                throw new Error('Errore nel caricamento del certificato.');
            }
            return response.text();
        })
        .then(cert => {
            // Visualizza il contenuto grezzo del certificato
            document.getElementById('certInfo').textContent = cert;
        })
        .catch(error => {
            document.getElementById('certInfo').textContent = 
                'Errore nel caricamento: ' + error.message;
        });
}
