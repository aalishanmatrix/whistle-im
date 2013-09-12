/**
 * whistle.im Android cryptography library
 * Copyright (C) 2013 Daniel Wirtz - http://dcode.io
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package im.whistle.ca;

import android.util.Log;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

/**
 * PinningProvider for hostname verification, CA and certificate pinning.
 * @author Daniel Wirtz <dcode@dcode.io>
 */
public class PinningProvider {
    
    // Trusted CA chain (must match). Ensures that a proper check for possibly
    // revoked certificates is made.
    private static KeyStore caStore = null;
    // Pinned certificates (at least one must match). Ensures that a connection
    // uses a white-listed certificate.
    private static KeyStore certStore = null;
    
    /**
     * Reads PEM formatted data into a key store.
     * @param file File to read (may contain multiple entries)
     * @return KeyStore
     * @throws Exception 
     */
    private static KeyStore readPem(String file) throws Exception {
        Log.i("whistleCA", "Initializing key store: "+file.substring(0, file.length()-4).toUpperCase());
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream is = new BufferedInputStream(PinningProvider.class.getResourceAsStream(file));
        try {
            int i=0;
            while (is.available() > 0) {
                X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
                Log.i("whistleCA", "Adding certificate: "+cert.getSubjectDN()+" issued by "+cert.getIssuerDN());
                ks.setCertificateEntry(""+(i++), cert);
            }
        } catch (Exception ex) {
            throw(ex);
        } finally {
            is.close();
        }
        return ks;
    }
    
    /**
     * Initializes the provider.
     * @throws Exception 
     */
    public static void init() throws Exception {
        if (caStore == null) caStore = readPem("ca.pem");
        if (certStore == null) certStore = readPem("cert.pem");
    }
    
    /**
     * Gets a trusted SSLContext.
     * @return
     * @throws Exception
     */
    public static SSLContext getContext() throws Exception {
        if (caStore == null) init();

        // Create a TrustManager that trusts the CAs in our KeyStore
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init(caStore);

        // Create an SSLContext that uses our TrustManager
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        return context;
    }
    
    /**
     * Gets a verifier.
     * @param pattern Hostname pattern
     * @return Verifier
     */
    public static HostnameVerifier getVerifier(final Pattern pattern) {
        return new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                try {
                    if (certStore == null) init();
                    Matcher m = pattern.matcher(hostname);
                    boolean hostMatch = m.matches();
                    if (!hostMatch) {
                        Log.e("whistleCA", "Verification failed for host: "+hostname);
                        return false;
                    }
                    // Check for pinned certificate
                    X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];
                    Enumeration<String> aliases = certStore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        X509Certificate realCert = (X509Certificate) certStore.getCertificate(alias);
                        boolean certMatch = new Date().before(realCert.getNotAfter())
                                && new Date().after(realCert.getNotBefore())
                                && Arrays.equals(realCert.getEncoded(), cert.getEncoded());
                        if (certMatch) {
                            return true;
                        }
                    }
                    Log.e("whistleCA", "Verification failed for certificate: "+cert.getSubjectDN()+" issued by "+cert.getIssuerDN());
                    return false;
                } catch (Exception ex) {
                    Log.e("whistleCA", "Verification failed with exception: "+ex.getMessage(), ex);
                    return false;
                }
            }
        };
    }
}
