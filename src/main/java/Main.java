
import org.apache.commons.cli.*;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;
import com.google.gson.Gson;
import java.util.ArrayList;
import java.util.List;

class AliasSignature {
    String alias;
    String shaSignature;
    String creationDate;
    String certificate;

    public AliasSignature(String alias, String shaSignature, String certificate, String creationDate) {
        this.alias = alias;
        this.shaSignature = shaSignature;
        this.certificate = certificate;
        this.creationDate = creationDate;
    }

    @Override
    public String toString() {
        return "Alias: " + alias + ", SHA Signature: " + shaSignature + ", Date: "+creationDate;
    }
}

public class Main {
    public static void main(String[] args) {
        Options options = new Options();

        Option keystoreOpt = new Option("k", "keystore", true, "Keystore file path");
        options.addOption(keystoreOpt);

        Option passwordOpt = new Option("p", "storepass", true, "Keystore password");
        passwordOpt.setRequired(true);
        options.addOption(passwordOpt);

        Option jsonOpt = new Option("j", "json", false, "Output in JSON format");
        options.addOption(jsonOpt);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("jks-inspect", options);
            System.exit(1);
            return;
        }

        String keystorePath = cmd.getOptionValue("keystore");
        String keystorePassword = cmd.getOptionValue("storepass");
        boolean jsonOutput = cmd.hasOption("json");

        List<AliasSignature> aliasSignatures = new ArrayList<>();
        try {
            
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] password = keystorePassword.toCharArray();
            InputStream keystoreInputStream = null;

            if (keystorePath != null && !keystorePath.isEmpty()) {
                keystoreInputStream = new FileInputStream(keystorePath);
            } else {
                // Read Base64-encoded data from stdin
                Scanner scanner = new Scanner(System.in);
                StringBuilder base64KeystoreBuilder = new StringBuilder();
                while (scanner.hasNextLine()) {
                    base64KeystoreBuilder.append(scanner.nextLine());
                }
                scanner.close();

                if (base64KeystoreBuilder.length() == 0) {
                    System.err.println("Error: No keystore path provided and no data received from stdin.");
                    System.exit(1);
                }

                byte[] decodedKeystore = Base64.getDecoder().decode(base64KeystoreBuilder.toString());
                keystoreInputStream = new ByteArrayInputStream(decodedKeystore);
            }

            keystore.load(keystoreInputStream, password);
            keystoreInputStream.close();

            // Iterate through keystore entries
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = keystore.getCertificate(alias);

                if (cert != null) {
                    // Compute SHA-256 signature
                    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                    byte[] shaSignature = sha256.digest(cert.getEncoded());

                    // Convert to hexadecimal format
                    StringBuilder hexString = new StringBuilder();
                    for (int i = 0; i < shaSignature.length; i++) {
                        String hex = Integer.toHexString(0xff & shaSignature[i]);
                        if (hex.length() == 1) {
                            hexString.append('0');
                        }
                        hexString.append(hex);
                        if (i < shaSignature.length - 1) {
                            hexString.append(":");
                        }
                    }

                    // Format date
                    X509Certificate x509Cert = (X509Certificate) cert;

                    // Get the 'notBefore' date from the certificate
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
                    String creationDate = sdf.format(x509Cert.getNotBefore());

                    String pemCert = convertToPem(cert);

                    AliasSignature newEntry = new AliasSignature(alias, hexString.toString().toUpperCase(), pemCert, creationDate);
                    aliasSignatures.add(newEntry);

                }
            }
            // End JSON array

            if (jsonOutput) {
            // Convert and print in JSON format
                Gson gson = new Gson();
                String json = gson.toJson(aliasSignatures);
                System.out.println(json);
            } else {
                // Print in plain text
                for (AliasSignature as : aliasSignatures) {
                    System.out.println(as);
                }
        }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static String convertToPem(Certificate cert) throws Exception {
        Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes());
        byte[] derCert = cert.getEncoded();
        String pemCertPre = new String(encoder.encode(derCert));
        return "-----BEGIN CERTIFICATE-----\n" + pemCertPre + "\n-----END CERTIFICATE-----\n";
    }

}
