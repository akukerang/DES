import javax.swing.*;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.text.DecimalFormat;

public class Main extends ModeOfOperations {
    public static String encrypted;
    public static String decrypted;
    public static String decryptedText;

    public static void generateResults(String selectedMode){
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.insets = new Insets(10, 10, 10, 10);

        JTextArea encr_results = new JTextArea(encrypted);
        encr_results.setLineWrap(true);
        encr_results.setEditable(false);
        JScrollPane encr_pane = new JScrollPane(encr_results);
        encr_pane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        encr_pane.setPreferredSize(new Dimension(300, 100));

        JTextArea decr_results = new JTextArea(decrypted);
        decr_results.setLineWrap(true);
        decr_results.setEditable(false);
        JScrollPane decr_pane = new JScrollPane(decr_results);
        decr_pane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        decr_pane.setPreferredSize(new Dimension(300, 100));

        JTextArea decr_text = new JTextArea(decryptedText);
        decr_text.setLineWrap(true);
        decr_text.setEditable(false);
        JScrollPane text_pane = new JScrollPane(decr_text);
        text_pane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        text_pane.setPreferredSize(new Dimension(300, 100));



        JFrame results = new JFrame("Results of "+selectedMode);
        results.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        JPanel resultPanel = new JPanel(new GridBagLayout());
        constraints.gridx = 0;
        constraints.gridy = 1;
        resultPanel.add(new JLabel("Encrypted Binary:"), constraints);
        constraints.gridx = 0;
        constraints.gridy = 2;
        resultPanel.add(new JLabel("Decrypted Binary:"), constraints);
        constraints.gridx = 0;
        constraints.gridy = 3;
        resultPanel.add(new JLabel("Decrypted Text:"), constraints);

        constraints.gridx = 1;
        constraints.gridy = 1;
        resultPanel.add(encr_pane,constraints);
        constraints.gridx = 1;
        constraints.gridy = 2;
        resultPanel.add(decr_pane,constraints);
        constraints.gridx = 1;
        constraints.gridy = 3;
        resultPanel.add(text_pane, constraints);
        results.setContentPane(resultPanel);
        results.pack();
        results.setVisible(true);

    }


    public static void main(String[] args) {
        fillMaps();
        JFrame f = new JFrame();
        f.setTitle("DES Encryption Tool");
        f.setResizable(false);
        NumberFormatter intFormat = new NumberFormatter(new DecimalFormat("#"));



        JTextArea plaintextArea = new JTextArea();
        plaintextArea.setLineWrap(true);
        JScrollPane plaintextScrollPane = new JScrollPane(plaintextArea);
        plaintextScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        plaintextScrollPane.setPreferredSize(new Dimension(300, 100));
        JFormattedTextField masterKeyField = new JFormattedTextField(intFormat);

        masterKeyField.setPreferredSize(new Dimension(200, 30));

        JFormattedTextField initialValueField = new JFormattedTextField(intFormat);
        initialValueField.setPreferredSize(new Dimension(200, 30));

        String[] modes = {"ECB", "CBC", "OFB", "CFB", "CTR"};
        JComboBox<String> modeCombo = new JComboBox<String>(modes);
        modeCombo.setPreferredSize(new Dimension(150, 30));

        JButton submitButton = new JButton("Encrypt");



        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();

        JLabel plaintextLabel = new JLabel("Plaintext: ");
        JLabel masterkeyLabel = new JLabel("Master Key (64-bit): ");
        JLabel initialLabel = new JLabel("Initial Value (64-bit): ");

        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.insets = new Insets(10, 10, 10, 10);
        panel.add(plaintextLabel, constraints);

        constraints.gridx = 1;
        constraints.gridy = 0;
        panel.add(plaintextScrollPane, constraints);

        constraints.gridx = 0;
        constraints.gridy = 1;
        panel.add(masterkeyLabel, constraints);

        constraints.gridx = 1;
        constraints.gridy = 1;
        panel.add(masterKeyField, constraints);

        constraints.gridx = 0;
        constraints.gridy = 2;
        panel.add(initialLabel, constraints);

        constraints.gridx = 1;
        constraints.gridy = 2;
        panel.add(initialValueField, constraints);

        constraints.gridx = 0;
        constraints.gridy = 3;
        panel.add(new JLabel("Mode of Operation:"), constraints);

        constraints.gridx = 1;
        constraints.gridy = 3;
        panel.add(modeCombo, constraints);

        constraints.gridx = 1;
        constraints.gridy = 4;
        panel.add(submitButton, constraints);



        f.setContentPane(panel);
        f.pack();
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        f.setVisible(true);

        initialLabel.setVisible(false);
        initialValueField.setVisible(false);
        submitButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String initialValue = "";
                String selectedMode = (String) modeCombo.getSelectedItem();
                String plaintext = textToBinary(plaintextArea.getText());
                BigInteger masterKey = new BigInteger(masterKeyField.getText());
                switch(selectedMode) {
                    case "ECB":
                        encrypted = encrypt(plaintext, masterKey);
                        decrypted = decrypt(encrypted, masterKey);
                        decryptedText = binaryToText(removePadding(decrypted));
                        break;
                    case "CBC":
                        initialValue = padBinary(initialValue, 64);
                        encrypted = encryptCBC(plaintext, masterKey, initialValue);
                        decrypted = decryptCBC(encrypted, masterKey, initialValue);
                        decryptedText = binaryToText(removePadding(decrypted));
                        break;
                    case "OFB":
                        initialValue = padBinary(initialValue, 64);
                        encrypted = encryptOFB(plaintext, masterKey, initialValue);
                        decrypted = decryptOFB(encrypted, masterKey, initialValue);
                        decryptedText = binaryToText(removePadding(decrypted));
                        break;
                    case "CFB":
                        initialValue = padBinary(initialValue, 64);
                        encrypted = encryptCFB(plaintext, masterKey, initialValue);
                        decrypted = decryptCFB(encrypted, masterKey, initialValue);
                        decryptedText = binaryToText(removePadding(decrypted));
                        break;
                    default:
                        initialValue = padBinary(initialValue, 32);
                        encrypted = encryptCTR(plaintext, masterKey, initialValue);
                        decrypted = decryptCTR(encrypted, masterKey, initialValue);
                        decryptedText = binaryToText(removePadding(decrypted));

                }

                // Result Frame
               generateResults(selectedMode);




            }
        });

        modeCombo.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String mode = (String) modeCombo.getSelectedItem();

                        switch(mode) {
                            case "ECB":
                                initialLabel.setVisible(false);
                                initialValueField.setVisible(false);
                                break;
                            case "CTR":
                                initialLabel.setText("Initial Value (32-bit): ");
                                initialLabel.setVisible(true);
                                initialValueField.setVisible(true);
                                break;
                            default:
                                initialLabel.setText("Initial Value (64-bit): ");
                                initialLabel.setVisible(true);
                                initialValueField.setVisible(true);

                        }
                    }
                }

        );



    }

}
