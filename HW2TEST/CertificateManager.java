package HW2TEST;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertificateManager {

    public static void main(String[] args) {
        try {
            // Percorso al keystore e password
            String keystorePath = "C:\\Users\\utente\\Desktop\\System Security\\HW\\keystore.jks";
            String keystorePassword = "123456"; 
            String alias = "mioCertificato"; // Alias del certificato nel keystore

            // 1. Carica il keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            FileInputStream keystoreStream = new FileInputStream(keystorePath);
            keystore.load(keystoreStream, keystorePassword.toCharArray());

            // Ottieni il certificato dal keystore usando l'alias
            Certificate cert = keystore.getCertificate(alias);

            // Verifica se è un certificato X.509
            if (cert instanceof X509Certificate) {
                X509Certificate x509Cert = (X509Certificate) cert;

                // 2. Estrazione delle informazioni dal certificato
                System.out.println("\nInformazioni del certificato:");
                System.out.println("Soggetto: " + x509Cert.getSubjectX500Principal());
                System.out.println("Emittente: " + x509Cert.getIssuerX500Principal());
                System.out.println("Valido da: " + x509Cert.getNotBefore());
                System.out.println("Valido fino a: " + x509Cert.getNotAfter());
                System.out.println("Numero di serie: " + x509Cert.getSerialNumber());
                System.out.println("Algoritmo di firma: " + x509Cert.getSigAlgName());

                // 3. Validazione del certificato
                System.out.println("\nValidazione del certificato:");
                
                // Validazione della data di validità
                try {
                    x509Cert.checkValidity();
                    System.out.println("Il certificato è valido nelle date di validità.");
                } catch (CertificateExpiredException e) {
                    System.out.println("Il certificato è scaduto: " + e.getMessage());
                } catch (CertificateNotYetValidException e) {
                    System.out.println("Il certificato non è ancora valido: " + e.getMessage());
                }

                // Verifica dell'algoritmo di firma
                String sigAlg = x509Cert.getSigAlgName();
                if (sigAlg.equalsIgnoreCase("SHA256withRSA") || sigAlg.equalsIgnoreCase("SHA512withRSA")) {
                    System.out.println("Algoritmo di firma sicuro: " + sigAlg);
                } else {
                    System.out.println("Algoritmo di firma non sicuro: " + sigAlg);
                }

                // 4. Mostra il certificato in formato Base64
                System.out.println("\nCertificato in formato Base64:");
                String base64Cert = Base64.getEncoder().encodeToString(x509Cert.getEncoded());
                System.out.println("-----BEGIN CERTIFICATE-----");
                System.out.println(base64Cert);
                System.out.println("-----END CERTIFICATE-----");

            } else {
                System.out.println("Certificato non di tipo X.509.");
            }

            keystoreStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
