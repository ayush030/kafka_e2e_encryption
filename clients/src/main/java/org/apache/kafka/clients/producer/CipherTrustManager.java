package org.apache.kafka.clients.producer;

import javax.net.ssl.*;
import javax.security.cert.X509Certificate;
import java.io.*;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Base64;

import org.json.JSONObject;
public class CipherTrustManager {
    private String cipherTrustURL;
    private byte[] encryptedKey;
    private byte[] encryptedValue;
    public CipherTrustManager(String cipherTrust) {
        this.cipherTrustURL = "https://" + cipherTrust + "/api/v1/";
        this.encryptedKey = null;
        this.encryptedValue = null;
    }

    private String getJWT() throws NoSuchAlgorithmException, IOException, KeyManagementException {
        String apiEndPoint = "auth/tokens/";

        JSONObject requestPayload = new JSONObject();
        // key ID
        requestPayload.put("username", "username");
        requestPayload.put("password", "password");


        JSONObject response  = sendPostRequest(apiEndPoint, requestPayload, "");
        String jwt = (String) response.get("jwt");

        return jwt;
    }

    @SuppressWarnings("removal")
    private JSONObject sendPostRequest(String apiEndPoint, JSONObject requestJSONAuthBody, String accessToken) throws NoSuchAlgorithmException, KeyManagementException, IOException {
        TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        /*  Create all-trusting host name verifier
         HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        */
        HostnameVerifier allHostsValid = (hostname, session) -> true;

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        String requestURL = this.cipherTrustURL + apiEndPoint;
        URL url = new URL(requestURL);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setDoOutput(true);
        connection.setDoInput(true);

        if (accessToken.length() != 0) {
            connection.addRequestProperty("Authorization", "Bearer " + accessToken);
        }

//        System.out.println("Connecting to " + requestURL);
        connection.connect();
        //write request body with JSON

        OutputStreamWriter wr = new OutputStreamWriter(connection.getOutputStream());

        wr.write(requestJSONAuthBody.toString());
        wr.close();

        System.out.println("Connecting to " + requestURL + " | response: " + connection.getResponseCode());


        //read response body
        InputStream in = connection.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        StringBuilder response = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        connection.disconnect();

        JSONObject jsonResponse = new JSONObject(response.toString());
//        System.out.println("PostResponse: " + jsonResponse);

        /*
           JSONParser parser = new JSONParser();

            Object o = parser.parse(result.toString());
            JSONObject data = (JSONObject) o;
            System.out.println(data);
        */
        return jsonResponse;
    }

    public void encryptedKeyValuePair(String keyID, String initializationVector, byte[] serializedKey, byte[] serializedValue) throws NoSuchAlgorithmException, IOException, KeyManagementException {
        String jwt = getJWT();

        String apiEndPoint = "crypto/encrypt/";

        JSONObject requestPayload = new JSONObject();
        requestPayload.put("id", keyID);
        requestPayload.put("iv", initializationVector);
        requestPayload.put("mode", "CBC");

        /* Request JSON payload:
        * {
            "id": "testKey",
            "iv": "4cd9f569b7834b62",
            "plaintext": "toEncryptString",
            "tag_len": 4,
            "mode": "CBC"
          }
        */

        /* Response JSON payload:
        * {
            "ciphertext": "VY2D+Q9UyPRj2tIlHP/yVQ==",
            "tag": "ws/1krVDXQKA1JlThx6Ejg==",
            "id": "testKey",
            "version": 0,
            "mode": "cbc",
            "iv": "4cd9f569b7834b62",
            "aad": "YWJj"
        }
        */

        if (serializedKey != null) {
            String base64EncodedKeyBytes = Base64.getEncoder().encodeToString(serializedKey);
            requestPayload.put("plaintext", base64EncodedKeyBytes);

            System.out.println("Getting encrypted key " + requestPayload);
            JSONObject encryptedKeyResponse;
            try {
                encryptedKeyResponse = sendPostRequest(apiEndPoint, requestPayload, jwt);
                this.encryptedKey = ((String) encryptedKeyResponse.get("ciphertext")).getBytes();
                System.out.println("Encrypted key: " + encryptedKeyResponse.get("ciphertext"));
            }
            catch (Exception e) {
                System.out.println("Unable to get encrypted key. Exception: " + e);
                return;
            }
        }

        if (serializedValue != null) {
            String base64EncodedValueBytes = Base64.getEncoder().encodeToString(serializedValue);
            requestPayload.put("plaintext", base64EncodedValueBytes);

            System.out.println("Getting encrypted value " + requestPayload);
            JSONObject encryptedValueResponse;
            try {
                encryptedValueResponse = sendPostRequest(apiEndPoint, requestPayload, jwt);
                this.encryptedValue =  ((String) encryptedValueResponse.get("ciphertext")).getBytes();
                System.out.println("Encrypted value: " + encryptedValueResponse.get("ciphertext"));
            }
            catch (Exception e) {
                System.out.println("Unable to get encrypted value. Exception: " + e);
            }
        }
    }

    public  byte[] getEncryptedKey() {
        return this.encryptedKey;
    }

    public  byte[] getEncryptedValue() {
        return this.encryptedValue;
    }
}
