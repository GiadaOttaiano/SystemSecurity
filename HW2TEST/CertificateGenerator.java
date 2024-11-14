package HW2TEST;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.Security;

public class CertificateGenerator {

    public static void main(String[] args) {
        try {
            // Aggiungi il provider di BouncyCastle
            Security.addProvider(new BouncyCastleProvider());

            // 1. Genera una coppia di chiavi (privata e pubblica)
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // Usa una lunghezza di 2048 bit per la chiave
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // 2. Crea il certificato X.509 auto-firmato
            X500Name issuerName = new X500Name("CN=Test CA, O=Example Organization, C=US");
            X500Name subjectName = new X500Name("CN=Test User, O=Example Organization, C=US");

            // 2.1 Costruisci il certificato
            Date notBefore = new Date();
            Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L); // Certificato valido per 1 anno
            BigInteger serialNumber = new BigInteger(64, new java.security.SecureRandom()); // Numero di serie del certificato

            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                    issuerName,
                    serialNumber,
                    notBefore,
                    notAfter,
                    subjectName,
                    publicKey
            );

            // 2.2 Crea un ContentSigner (firma il certificato con la chiave privata)
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);

            // 2.3 Converti il certificato in un oggetto X509Certificate
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));

            // 3. Salva il certificato su un file (ad esempio in formato .crt)
            try (FileOutputStream fos = new FileOutputStream("generated_certificate.crt")) {
                fos.write(certificate.getEncoded());
                System.out.println("Certificato X.509 generato con successo e salvato come generated_certificate.crt");
            }

            // Mostra informazioni del certificato generato
            System.out.println("Certificato:");
            System.out.println(certificate.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
