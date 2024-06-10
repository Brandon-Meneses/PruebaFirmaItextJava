package org.example;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;

public class PDFSignerExample {
    // Usar rutas relativas desde el directorio del proyecto
    public static final String SRC = "src/main/resources/input.pdf";
    public static final String DEST = "src/main/resources/output_signed.pdf";
    public static final String KEYSTORE = "src/main/resources/C24030199740.pfx";
    public static final char[] PASSWORD = "988156699Ms".toCharArray();

    public static void main(String[] args) {
        // Registrar BouncyCastle como proveedor de seguridad
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Verificar existencia de archivos
        File inputFile = new File(SRC);
        File keystoreFile = new File(KEYSTORE);

        if (!inputFile.exists()) {
            System.err.println("El archivo de entrada no existe: " + inputFile.getAbsolutePath());
            return;
        }

        if (!keystoreFile.exists()) {
            System.err.println("El archivo de KeyStore no existe: " + keystoreFile.getAbsolutePath());
            return;
        }

        // Imprimir rutas para confirmar
        System.out.println("Ruta del archivo de entrada: " + inputFile.getAbsolutePath());
        System.out.println("Ruta del archivo de KeyStore: " + keystoreFile.getAbsolutePath());

        try {
            // Leer el archivo reparado y proceder a la firma
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(KEYSTORE), PASSWORD);
            String alias = ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
            Certificate[] chain = ks.getCertificateChain(alias);

            PdfReader reader;
            try {
                reader = new PdfReader(SRC);
            } catch (IOException e) {
                System.err.println("Error al leer el archivo PDF: " + e.getMessage());
                return;
            }

            PdfWriter writer = new PdfWriter(new FileOutputStream(DEST));
            PdfSigner signer = new PdfSigner(reader, writer, new StampingProperties());

            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance
                    .setReason("Digital Signature")
                    .setLocation("Location")
                    .setPageRect(new Rectangle(36, 648, 200, 100))
                    .setPageNumber(1);
            signer.setFieldName("sig");

            IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
            IExternalDigest digest = new BouncyCastleDigest();

            signer.signDetached(digest, pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
            System.out.println("Documento firmado exitosamente: " + DEST);
        } catch (GeneralSecurityException | IOException e) {
            System.err.println("Error al firmar el documento: " + e.getMessage());
            e.printStackTrace();
        }
    }
}