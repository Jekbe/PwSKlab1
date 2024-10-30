import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Podaj port");
        try {
            E_mail_emu.start(scanner.nextInt());
        } catch (IOException | NoSuchAlgorithmException e){
            System.out.println("Błąd: " + e);
        }
    }
}