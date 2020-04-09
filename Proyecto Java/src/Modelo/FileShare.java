package Modelo;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Contiene toda la lógica en cuanto a las operaciones algoritmo RSA
 */
public class FileShare {

    /**
     *
     * @param path Directorio donde se crearán las llaves
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     */
    public void crearClaves(String path) throws NoSuchAlgorithmException, FileNotFoundException, IOException {

        PrivateKey privateKey;
        PublicKey publicKey;

        //Crear objeto para generar llaves
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);

        //Crear llaves
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        //Obtener llaves
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        //Guardar llaves como binario
        String publicKeyContent = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyContent = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        String publicKeyFormatted = "-----BEGIN PUBLIC KEY-----\n";
        String privateKeyFormatted = "-----BEGIN PRIVATE KEY-----\n";
        String[] publicKeyArray = publicKeyContent.split("");
        String[] privateKeyArray = privateKeyContent.split("");
        for (int i = 0; i < publicKeyArray.length; i++) {

            publicKeyFormatted += publicKeyArray[i];

            if (i != 0 && i % 64 == 0) {
                publicKeyFormatted += "\n";
            }

        }
        for (int i = 0; i < privateKeyArray.length; i++) {

            privateKeyFormatted += privateKeyArray[i];

            if (i != 0 && i % 64 == 0) {
                privateKeyFormatted += "\n";
            }

        }
        publicKeyFormatted += "\n-----END PUBLIC KEY-----";
        privateKeyFormatted += "\n-----END PRIVATE KEY-----";

        //Instanciando objeto para almacenar
        FileOutputStream savePublic = new FileOutputStream(path + "public_key.pem");
        FileOutputStream savePrivate = new FileOutputStream(path + "private_key.pem");

        //Guardar claves
        savePublic.write(publicKeyFormatted.getBytes());
        savePrivate.write(privateKeyFormatted.getBytes());

        //Cerrar File Output Stream
        savePublic.close();
        savePrivate.close();

    }

    /**
     *
     * @param fileToCipher Directorio de archivo a cifrar
     * @param publicKeyFile Directorio de llave pública para cifrar archivo
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void cifrarArchivo(String fileToCipher, String publicKeyFile) throws NoSuchAlgorithmException,
            FileNotFoundException, IOException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
            IllegalBlockSizeException, BadPaddingException {

        //Separar nombre para obtener nombre del archivo cifrado este sera:
        //'Nombre del Archivo Original'+'_Cifrado'
        String[] components = fileToCipher.split("\\.");

        //Crear objeto de cifrado indicando cifrado RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        //Leer archivo de la llave publica 
        FileInputStream inputStream = new FileInputStream(publicKeyFile);
        byte[] keyBytes = new byte[inputStream.available()];
        inputStream.read(keyBytes);

        String publicString = new String(keyBytes, "UTF-8");
        publicString = publicString.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicString = publicString.replace("\n-----END PUBLIC KEY-----", "");
        publicString = publicString.replace("\n", "");

        //Convertir datos a objeto PublicKey
        X509EncodedKeySpec ks = new X509EncodedKeySpec(Base64.getDecoder().decode(publicString));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(ks);

        //Inicializar cifrado e indicar archivo a cifrar
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        inputStream = new FileInputStream(fileToCipher);
        byte[] inputBytes = new byte[(int) fileToCipher.length()];
        inputStream.read(inputBytes);

        //Crear archivo, cifrarlo y guardarlo
        FileOutputStream outputStream = new FileOutputStream(components[0] + "_Cifrado." + components[1]);
        byte[] cipheredBytes = Base64.getEncoder().encode(cipher.doFinal(inputBytes));
        outputStream.write(cipheredBytes);

        //Cerrar File Streams
        inputStream.close();
        outputStream.close();

    }

    /**
     *
     * @param fileToDecrypt Directorio de archivo a decifrar
     * @param privateKeyFile Directorio de llave privada para descifrar archivo
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void descifrarArchivo(String fileToDecrypt, String privateKeyFile) throws NoSuchAlgorithmException,
            FileNotFoundException, IOException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
            IllegalBlockSizeException, BadPaddingException {

        //Crear objeto de cifrado indicando cifrado RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        //Separar nombre para obtener nombre del archivo cifrado este sera:
        //'Nombre del Archivo Original'+'_Cifrado'
        String[] components = fileToDecrypt.split("\\.");

        if (components[0].contains("_Cifrado")) {
            components[0] = components[0].replace("_Cifrado", "");
        }

        //Leer archivo de la llave privada 
        FileInputStream inputStream = new FileInputStream(privateKeyFile);
        byte[] keyBytes = new byte[inputStream.available()];
        inputStream.read(keyBytes);

        String privateString = new String(keyBytes, "UTF-8");
        privateString = privateString.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateString = privateString.replace("\n-----END PRIVATE KEY-----", "");
        privateString = privateString.replace("\n", "");

        //Convertir datos a objeto PrivateKey
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateString));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(ks);

        //Inicializar cifrado e indicar archivo a cifrar
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        inputStream = new FileInputStream(fileToDecrypt);
        byte[] inputBytes = new byte[inputStream.available()];
        inputStream.read(inputBytes);

        //Crear archivo, cifrarlo y guardarlo
        FileOutputStream outputStream = new FileOutputStream(components[0] + "_Descifrado." + components[1]);
        byte[] cipheredBytes = cipher.doFinal(Base64.getDecoder().decode(inputBytes));
        outputStream.write(cipheredBytes);

        //Cerrar File Streams
        inputStream.close();
        outputStream.close();

    }

}
