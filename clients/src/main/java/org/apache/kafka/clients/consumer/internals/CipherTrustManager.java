package org.apache.kafka.clients.consumer.internals;

import javax.net.ssl.*;
import javax.security.cert.X509Certificate;
import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Base64;


import org.json.JSONException;
import org.json.JSONObject;
public class CipherTrustManager {
    private String cipherTrustURL;
    public CipherTrustManager(String cipherTrust) {
        this.cipherTrustURL = "https://" + cipherTrust + "/api/v1/";
    }

    private String getJWT() throws NoSuchAlgorithmException, IOException, KeyManagementException {
        String apiEndPoint = "auth/tokens/";

        JSONObject requestPayload = new JSONObject();
        // key ID
        requestPayload.put("username", "username");
        requestPayload.put("password", "password");


        JSONObject response  = sendPostRequest(apiEndPoint, requestPayload, "");
        String jwt = (String) response.get("jwt");
//        System.out.println("JWT: "+ jwt);
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

        JSONObject jsonResponse;
        try {
            jsonResponse = new JSONObject(response.toString());
            return jsonResponse;
        }
        catch (JSONException e) {
            // this is a hack due to inconsistency in API.
//            System.out.println("response:" + response + " has exception: " +e);
            jsonResponse = new JSONObject();
            jsonResponse.put("plaintext", response.toString());
        }

        /*
           JSONParser parser = new JSONParser();

            Object o = parser.parse(result.toString());
            JSONObject data = (JSONObject) o;
            System.out.println(data);
        */

       return jsonResponse;
    }

    public ByteBuffer decrypteCipherText(String keyID, String initializationVector, ByteBuffer encryptedByteBuffer) throws NoSuchAlgorithmException, IOException, KeyManagementException {
        String jwt = getJWT();

        String apiEndPoint = "crypto/decrypt/";

        JSONObject requestPayload = new JSONObject();
        requestPayload.put("id", keyID);
        requestPayload.put("iv", initializationVector);
        requestPayload.put("mode", "CBC");

        /* Request JSON payload:
          {
            "id": "testKeyCBC",
            "iv": "GB1yLYeN5IljclAc38x6ow==",
            "ciphertext": "VY2D+Q9UyPRj2tIlHP/yVQ==",
            "mode": "CBC"
          }
        */

        /* Response JSON payload:
         {
            "plaintext": "decryptedString"
         }
        */

        ByteBuffer decryptedByteBuffer = null;
        if (encryptedByteBuffer != null) {
            requestPayload.put("ciphertext", StandardCharsets.UTF_8.decode(encryptedByteBuffer));

            System.out.println("Sending decrypt request  " + requestPayload);
            JSONObject encryptedResponse;

            try {
                encryptedResponse = sendPostRequest(apiEndPoint, requestPayload, jwt);
//                System.out.println("Received response: " + encryptedResponse);
//
//                System.out.println("Initial byte buffer: " + encryptedByteBuffer.array().toString());
//                System.out.println("get response" + encryptedResponse.get("plaintext"));
//                System.out.println("get response bytes" + ((String)encryptedResponse.get("plaintext")).getBytes());

                decryptedByteBuffer = ByteBuffer.wrap(((String)encryptedResponse.get("plaintext")).getBytes());
//                System.out.println("Final byte buffer: " + decryptedByteBuffer.array().toString());
            }
            catch (Exception e) {
                System.out.println("Unable to get decrypted byte buffer. Exception: " + e);
            }
        }
        return decryptedByteBuffer;
    }
}
