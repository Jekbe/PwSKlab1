import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class E_mail_emu {
    private final ServerSocket serverSocket;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final Scanner scanner;
    private Socket socket, sendSocket;
    private PublicKey sendPublicKey;

    public static void start(int port) throws IOException, NoSuchAlgorithmException {
        new E_mail_emu(port);
    }

    private E_mail_emu(int port) throws IOException, NoSuchAlgorithmException {
        serverSocket = new ServerSocket(port);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        scanner = new Scanner(System.in);

        Thread listener = new Thread(this::listener);
        listener.start();

        Thread cli = new Thread(this::cli);
        cli.start();
    }

    private void listener(){
        while (true){
            try {
                socket = serverSocket.accept();
                getPublicKey(socket);
                sendPublicKey(socket);
            } catch (IOException | ClassNotFoundException e){
                System.out.println("Błąd: " + e);
            }
        }
    }

    private void sendPublicKey(Socket socket) throws IOException {
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        objectOutputStream.writeObject(publicKey);
    }

    private void getPublicKey(Socket socket) throws IOException, ClassNotFoundException {
        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
        sendPublicKey = (PublicKey) objectInputStream.readObject();
    }

    private void cli(){
        boolean work = true;
        while (work){
            System.out.println("Podaj opcję:");
            switch (scanner.nextInt()){
                case 0 -> work = false;
                case 1 -> connect();
                case 2 -> {
                    try {
                        send();
                    } catch (Exception e) {
                        System.out.println("Błąd: " + e);
                    }
                }
                case 3 -> {
                    try {
                        read();
                    } catch (Exception e) {
                        System.out.println("Błąd: " + e);
                    }
                }
                default -> System.out.println("Nieznana opcja");
            }
        }
    }

    private void connect(){
        System.out.println("Podaj port do połączenia: ");
        try {
            sendSocket = new Socket("localhost", scanner.nextInt());
            sendPublicKey(sendSocket);
            getPublicKey(sendSocket);
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Błąd: " + e);
        }
    }

    private void send() throws Exception {
        if (sendSocket == null) throw new Exception("Brak połącznia");

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        System.out.println("Napisz wiadomość: ");
        scanner.nextLine();
        String text = scanner.nextLine();

        String signedText = sign(text);
        String encryptedMessage = encrypt(text, secretKey);
        String key = encryptKey(secretKey);
        Message message = new Message(signedText, encryptedMessage, key);

        ObjectOutputStream objectOutputStream = new ObjectOutputStream(sendSocket.getOutputStream());
        objectOutputStream.writeObject(message);
    }

    private String sign(String text) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(text.getBytes(StandardCharsets.UTF_8));

        byte[] bytes = signature.sign();

        return Base64.getEncoder().encodeToString(bytes);
    }

    private String encrypt(String text, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] bytes = cipher.doFinal(text.getBytes());

        return Base64.getEncoder().encodeToString(bytes);
    }

    private String encryptKey(SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, sendPublicKey);

        byte[] bytes = cipher.doFinal(secretKey.getEncoded());

        return Base64.getEncoder().encodeToString(bytes);
    }

    private void read() throws Exception {
        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
        Message message = (Message) objectInputStream.readObject();
        String encryptedText = message.text();
        String encryptedKey = message.key();

        SecretKey secretKey = decryptKey(encryptedKey);
        String text = decrypt(encryptedText, secretKey);
        String sign = message.sign();
        if (verify(sign, text)){
            System.out.println(text);
        } else System.out.println("Nie udało się zweryfikować nadawcy");
    }

    private SecretKey decryptKey(String encryptedKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));

        return new SecretKeySpec(bytes, 0, bytes.length, "AES");
    }

    private boolean verify(String sign, String text) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(sendPublicKey);
        signature.update(text.getBytes(StandardCharsets.UTF_8));

        byte[] bytes = Base64.getDecoder().decode(sign);

        return signature.verify(bytes);
    }

    private String decrypt(String encryptedText, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        return new String(bytes, StandardCharsets.UTF_8);
    }
}
