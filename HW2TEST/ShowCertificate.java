package HW2TEST;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class ShowCertificate {
    public static void main(String[] args) {
        try {
            // Percorso al file .crt
            String certPath = "C:\\Users\\utente\\Desktop\\System Security\\HW1\\certificate.crt";

            // Crea un CertificateFactory per il tipo X.509
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            // Legge il file del certificato
            FileInputStream certInputStream = new FileInputStream(certPath);
            Certificate certificate = certFactory.generateCertificate(certInputStream);

            // Mostra le informazioni del certificato
            System.out.println("Certificato caricato con successo:");
            System.out.println(certificate.toString());

            certInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
