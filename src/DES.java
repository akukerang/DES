import java.math.BigInteger;
import java.util.Arrays;

public class DES extends DES_Tables {

    public static String xor(String a, String b, int size) {
        StringBuilder str = new StringBuilder();
        char[] a_chars = padBinary(a, size).toCharArray();
        char[] b_chars = padBinary(b, size).toCharArray();

        for (int i = 0; i < size; i++) {
            if (a_chars[i] == b_chars[i]) {
                str.append('0');
            } else {
                str.append('1');
            }
        }
        return str.toString();
    }

    public static char[] generateTemplate(int size) { //for generating a char[] of zeroes, for permutation purposes
        char[] c = new char[size];
        Arrays.fill(c, '0');
        return c;
    }

    public static String generateTemplateStr(int size) { //for generating a string of zeroes, for padding.
        char[] c = new char[size];
        Arrays.fill(c, '0');
        return new String(c);
    }

    public static String padBinary(String input, int size) { //padding to size
        String output = input;
        String temp;
        if (input.length() < size) { //padding to size
            temp = generateTemplateStr(size - input.length());
            output = temp.concat(output);
        }
        return output;
    }

    public static String padBlocks(String input){
        String padded = input;
        String temp;
        if (padded.length() % 64 != 0) {
            temp = generateTemplateStr(64 - (input.length() % 64));
            padded = temp.concat(input);
        }
        return padded;
    }

    public static String textToBinary(String input) {
        StringBuilder str = new StringBuilder();
        char[] inputChar = input.toCharArray();
        for (char c : inputChar) {
            str.append(String.format("%8s", Integer.toBinaryString(c)).replaceAll(" ", "0"));
        }

        return str.toString();
    }

    public static String binaryToText(String binary) {
        StringBuilder str = new StringBuilder();
        int decimal;
        for (int i = 0; i < binary.length(); i += 8) {
            decimal = Integer.parseInt(binary.substring(i, i + 8), 2);
            str.append((char) (decimal));
        }
        return str.toString();
    }


    static String rotateLeft(BigInteger num, int toRotate, int size) {
        BigInteger mask = BigInteger.ONE.shiftLeft(size).subtract(BigInteger.ONE);
        BigInteger p_1 = num.shiftLeft(toRotate);
        BigInteger p_2 = num.shiftRight(size - toRotate);
        String rotated = p_1.or(p_2).and(mask).toString(2);
        rotated = padBinary(rotated, size);
        return rotated;
    }

    public static String rotateRight(BigInteger num, int toRotate, int size) {
        BigInteger mask = BigInteger.ONE.shiftLeft(size).subtract(BigInteger.ONE);
        BigInteger p_1 = num.shiftRight(toRotate);
        BigInteger p_2 = num.shiftLeft(size - toRotate);
        String rotated = p_1.or(p_2).and(mask).toString(2);
        rotated = padBinary(rotated, size);
        return rotated;
    }


    public static String PC1(BigInteger MasterKey) { //INPUT 64-BIT MASTER KEY
        char[] PC1_Key = new char[56];
        String binary = padBinary(MasterKey.toString(2),64);



        //PC1 Permutation Here
        for (int j : PC1_Table.keySet()) {
            PC1_Key[j] = binary.toCharArray()[(PC1_Table.get(j) - 1)];
        }
        return new String(PC1_Key); //outputs 56 bit string
    }

    public static String[] generateSubKeys(BigInteger MasterKey) {
        String[] subKeys = new String[16];
        String bit56 = PC1(MasterKey); //PC1
        char[] currKey = generateTemplate(48);
        //Split into Left and Right
        String left56 = bit56.substring(0, 28);
        String right56 = bit56.substring(28);
        //PC-2 -> Key 1
        for (int i = 0; i < 16; i++) {
            //Rotate, and set new bit 56, left, right.
            left56 = rotateLeft(new BigInteger(left56, 2), rotateTable[i], 28);
            right56 = rotateLeft(new BigInteger(right56, 2), rotateTable[i], 28);
            bit56 = left56 + right56;

            for (int j : PC2_Table.keySet()) { //PC-2
                currKey[j] = bit56.toCharArray()[PC2_Table.get(j) - 1];
            }
            subKeys[i] = new String(currKey);
        }
        return subKeys;
    }

    public static String[] generateDecryptKeys(BigInteger MasterKey) {
        String[] subKeys = new String[16];
        String bit56 = PC1(MasterKey); //PC1
        char[] currKey = generateTemplate(48);
        //Split into Left and Right
        String left56 = bit56.substring(0, 28);
        String right56 = bit56.substring(28);

        //FIRST KEY NO ROTATION
        for (int j : PC2_Table.keySet()) { //PC-2
            currKey[j] = bit56.toCharArray()[PC2_Table.get(j) - 1];
        }
        subKeys[0] = new String(currKey);

        //PC-2 -> Key 1
        for (int i = 1; i < 16; i++) {
            left56 = rotateRight(new BigInteger(left56, 2), rotateTable[i], 28);
            right56 = rotateRight(new BigInteger(right56, 2), rotateTable[i], 28);
            bit56 = left56 + right56;
            for (int j : PC2_Table.keySet()) { //PC-2
                currKey[j] = bit56.toCharArray()[PC2_Table.get(j) - 1];
            }
            subKeys[i] = new String(currKey);
        }
        return subKeys;
    }

    public static String initialPerm(String plaintext) { //64-bit input and output. Plaintext in binary.
        plaintext = padBinary(plaintext, 64);
        char[] output = generateTemplate(64); // 64-bit 0.
        for (int j : init_Table.keySet()) { //PC-2
            output[j] = plaintext.toCharArray()[init_Table.get(j) - 1];
        }
        return new String(output);
    }

    public static String expansion(String bit32) { //32-bit input, 48-bit output
        char[] output = generateTemplate(48); //48-bit 0.
        for (int j : expansion_table.keySet()) { //PC-2
            output[j] = bit32.toCharArray()[expansion_table.get(j) - 1];
        }
        return new String(output);
    }

    public static String F_Function(String expanded, String subkey) {
        char[] output = generateTemplate(32); //32-bit 0.
        String temp;
        String s_output = "";
        int p1, p2;
        String XOR_Output = xor(expanded, subkey, 48);

        //divide output into 8 blocks of 6. s-box sub.
        for (int i = 0; i < 48; i += 6) {
            temp = XOR_Output.substring(i, i + 6);
            p1 = Integer.parseInt(temp.charAt(0) + "" + temp.charAt(5), 2); //outside, convert into decimal.
            p2 = Integer.parseInt(temp.substring(1, 5), 2); //inside values ,convert into decimal
            temp = Integer.toBinaryString(s_tables[i / 6][p1][p2]);
            temp = padBinary(temp, 4);
            s_output += temp;
        }

        //permutation
        for (int i : p_table.keySet()) {
            output[i] = s_output.toCharArray()[(p_table.get(i) - 1)];
        }
        //  32 bit output
        return new String(output);
    }

    public static String encryptDES(BigInteger master, String plainText) {
        String[] subkeys = generateSubKeys(master);
        //initial Perm
        //split into left and right
        String init = initialPerm(plainText);
        String left = init.substring(0, 32);
        String right = init.substring(32);
        String f_func, expand, temp, rounds_output;
        char[] output = generateTemplate(64); // 64-bit 0.
        //16 rounds
        for (int i = 0; i < 16; i++) {
            //expand right
            expand = expansion(right);
            //F function right
            f_func = F_Function(expand, subkeys[i]);
            //Next Right = F-output XOR Left
            temp = right;
            right = new BigInteger(f_func, 2).xor(new BigInteger(left, 2)).toString(2);
            right = padBinary(right, 32);
            //Next Left = Right
            left = temp;
        }
        //Final Perm
        rounds_output = right + left;
        for (int i : inverse_table.keySet()) {
            output[i] = rounds_output.toCharArray()[(inverse_table.get(i) - 1)];
        }
        return new String(output);
    }

    public static String decryptDES(BigInteger master, String cipherText) {
        String[] subkeys = generateDecryptKeys(master);
        //initial Perm
        //split into left and right
        String init = initialPerm(cipherText);
        String left = init.substring(0, 32);
        String right = init.substring(32);
        String f_func, expand, temp;
        char[] output = generateTemplate(64);// 64-bit 0.
        //16 rounds
        for (int i = 0; i < 16; i++) {
            //expand right
            expand = expansion(right);
            //F function right
            f_func = F_Function(expand, subkeys[i]);
            //Next Right = F-output XOR Left
            temp = right;
            right = new BigInteger(f_func, 2).xor(new BigInteger(left, 2)).toString(2);
            right = padBinary(right, 32);
            //Next Left = Right
            left = temp;
        }
        //Final Perm
        for (int i : inverse_table.keySet()) {
            output[i] = (right + left).toCharArray()[(inverse_table.get(i) - 1)];
        }
        return new String(output);
    }

    public static String encrypt(String input, BigInteger master) { //input is binary, multiple of 64
        String padded = padBlocks(input);
        // pads to multiple of 64, for DES.
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < padded.length(); i += 64) {
            str.append(encryptDES(master, padded.substring(i, i + 64)));
        }
        return str.toString();
    }

    public static String decrypt(String cipher, BigInteger master) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < cipher.length(); i += 64) {
            str.append(decryptDES(master, cipher.substring(i, i + 64)));
        }
        return str.toString();
    }

    public static String removePadding(String padded) {
        // remove padding of 8-bit 0.
        while (padded.startsWith("00000000")) {
            padded = padded.substring(8);
        }
        return padded;
    }

}