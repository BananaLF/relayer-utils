import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;

class ZKEmail {
    private static native String generateEmailInput(String email,String account_code);

    static {
        System.loadLibrary("relayer_utils");
    }

    public static void main(String[] args) {
        
        try {
        String rawEmail = new String(Files.readAllBytes(Paths.get("./okx_pay_test0.eml")));
        String output = ZKEmail.generateEmailInput(rawEmail,"0x01eb9b204cc24c3baee11accc37d253a9c53e92b1a2cc07763475c135d575b76");
        System.out.println(output);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}