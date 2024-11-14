package HW2TEST;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class CertificateValidation {
    public static void main(String[] args) {
        try {
            // Percorso del keystore e password
            String keystorePath = "C:\\Users\\utente\\Desktop\\System Security\\HW2\\keystore.jks";
            String keystorePassword = "123456";
            String alias = "mioCertificato";

            // Carica il keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            FileInputStream keystoreStream = new FileInputStream(keystorePath);
            keystore.load(keystoreStream, keystorePassword.toCharArray());

            // Ottieni il certificato
            Certificate cert = keystore.getCertificate(alias);

            if (cert instanceof X509Certificate) {
                X509Certificate x509Cert = (X509Certificate) cert;

                // Validazione della data di validità del certificato
                try {
                    x509Cert.checkValidity();
                    System.out.println("\nCertificato valido nelle date di validità.");
                } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                    System.out.println("Certificato non valido: " + e.getMessage());
                }

                // Controllo sull'algoritmo di firma
                String sigAlg = x509Cert.getSigAlgName();
                if (sigAlg.equalsIgnoreCase("SHA256withRSA") || sigAlg.equalsIgnoreCase("SHA512withRSA")) {
                    System.out.println("Algoritmo di firma sicuro: " + sigAlg);
                } else {
                    System.out.println("Algoritmo di firma non sicuro: " + sigAlg);
                }
            } else {
                System.out.println("Certificato non di tipo X.509.");
            }

            keystoreStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
