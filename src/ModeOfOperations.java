import java.math.BigInteger;


public class ModeOfOperations extends DES {
    public static String encryptCBC(String plaintext, BigInteger master, String init_val) { //input is binary, multiple of 64
        String padded = padBlocks(plaintext);
        StringBuilder str = new StringBuilder();
         // pads to multiple of 64, for DES.
        // y_0= e(IV xor x_0)
        String temp = xor(init_val, padded.substring(0,64),64);
        String previous = encryptDES(master,temp);
        str.append(previous);
        for (int i = 64; i < padded.length(); i += 64) { //y_i = e(x_i xor y_{i-1})
            temp = xor(padded.substring(i,i+64),previous,64);
            previous = encryptDES(master, temp);
            str.append(previous);
        }
        return str.toString();
    }


    public static String decryptCBC(String cipher, BigInteger master, String init_val) {
        StringBuilder str = new StringBuilder();
        // x_0 = e^-1(y_0) xor IV
        String decryptCurrent = decryptDES(master, cipher.substring(0,64));
        String previous = xor(decryptCurrent, init_val, 64);
        str.append(previous);

        // x_i = e^-1(y_i) xor y_{i-1}
        for (int i = 64; i < cipher.length(); i += 64) {
            decryptCurrent = decryptDES(master, cipher.substring(i,i+64));
            previous = xor(decryptCurrent, cipher.substring(i-64,i), 64);
            str.append(previous);
        }
        return str.toString();
    }

    public static String encryptOFB(String plaintext, BigInteger master, String init_val){
        StringBuilder str = new StringBuilder();
        String padded = padBlocks(plaintext);
        String currentKey = encryptDES(master,init_val);
        String current;

        for(int i = 0; i < padded.length(); i+=64){
            current = xor(padded.substring(i,i+64), currentKey, 64);
            currentKey = encryptDES(master, currentKey);
            str.append(current);
        }
        return str.toString();
    }

    public static String decryptOFB(String plaintext, BigInteger master, String init_val){
        StringBuilder str = new StringBuilder();
        String currentKey = encryptDES(master,init_val);
        String current;
        for(int i = 0; i < plaintext.length(); i+=64){
            current = xor(plaintext.substring(i,i+64), currentKey, 64);
            currentKey = encryptDES(master, currentKey);
            str.append(current);
        }
        return str.toString();
    }


    public static String encryptCFB(String plaintext, BigInteger master, String init_val){
        StringBuilder str = new StringBuilder();
        String padded = padBlocks(plaintext);
        String currentKey = encryptDES(master,init_val);
        String current;

        for(int i = 0; i < padded.length(); i+=64){
            current = xor(padded.substring(i,i+64), currentKey, 64);
            currentKey = encryptDES(master, current);
            str.append(current);
        }
        return str.toString();
    }

    public static String decryptCFB(String cipher, BigInteger master, String init_val){
        StringBuilder str = new StringBuilder();
        String currentKey = encryptDES(master,init_val);
        String current = xor(cipher.substring(0, 64),currentKey, 64);
        str.append(current);
        for(int i = 64; i < cipher.length(); i+=64){
            currentKey = encryptDES(master, cipher.substring(i-64,i));
            current = xor(cipher.substring(i,i+64), currentKey, 64);

            str.append(current);
        }
        return str.toString();
    }

    public static String encryptCTR(String plaintext, BigInteger master, String init_val){ //counter 32 bit
        String counter = "00000000000000000000000000000001";
        StringBuilder str = new StringBuilder();
        String padded = padBlocks(plaintext);
        String concatenated = init_val.concat(counter);
        BigInteger c = new BigInteger(counter,2);
        String current;
        for(int i = 0; i < padded.length(); i+=64){
            current = xor(padded.substring(i,i+64), encryptDES(master,concatenated),64);
            c = c.add(BigInteger.ONE);
            concatenated = init_val.concat(c.toString(2));
            concatenated = padBinary(concatenated,32);
            str.append(current);
        }
        return str.toString();
    }


    public static String decryptCTR(String cipher, BigInteger master, String init_val){ //counter 32 bit
        String counter = "00000000000000000000000000000001";
        StringBuilder str = new StringBuilder();
        String concatenated = init_val.concat(counter);
        BigInteger c = new BigInteger(counter,2);
        String current;
        for(int i = 0; i < cipher.length(); i+=64){
            current = xor(cipher.substring(i,i+64), encryptDES(master,concatenated),64);
            c = c.add(BigInteger.ONE);
            concatenated = init_val.concat(c.toString(2));
            concatenated = padBinary(concatenated,32);
            str.append(current);
        }
        return str.toString();
    }

}