package HW2TEST;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class CertificateInfo {
    public static void main(String[] args) {
        try {
            // Percorso al keystore e password
            String keystorePath = "C:\\Users\\utente\\Desktop\\System Security\\HW2\\keystore.jks";
            String keystorePassword = "123456";
            String alias = "mioCertificato";

            // Carica il keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            FileInputStream keystoreStream = new FileInputStream(keystorePath);
            keystore.load(keystoreStream, keystorePassword.toCharArray());

            // Ottieni il certificato dal keystore
            Certificate cert = keystore.getCertificate(alias);

            // Verifica se è un certificato X509
            if (cert instanceof X509Certificate) {
                X509Certificate x509Cert = (X509Certificate) cert;

                // Estrai e mostra informazioni dal certificato
                System.out.println("\nSoggetto: " + x509Cert.getSubjectX500Principal());
                System.out.println("Emittente: " + x509Cert.getIssuerX500Principal());
                System.out.println("Valido da: " + x509Cert.getNotBefore());
                System.out.println("Valido fino a: " + x509Cert.getNotAfter());
                System.out.println("Numero di serie: " + x509Cert.getSerialNumber());
                System.out.println("Algoritmo di firma: " + x509Cert.getSigAlgName());
            } else {
                System.out.println("Certificato non di tipo X.509.");
            }

            keystoreStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
