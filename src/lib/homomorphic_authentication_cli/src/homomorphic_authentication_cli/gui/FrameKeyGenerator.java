package homomorphic_authentication_cli.gui;

import homomorphic_authentication_cli.services.KeyGenerator;

import java.awt.Component;
import java.awt.EventQueue;
import java.awt.TextArea;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JTextPane;

public class FrameKeyGenerator {

    private JFrame frame;
    private JTextField pairingTextBox;
    private JTextField gTextBox;
    private JTextField wTextBox;
    private JTextField privateKeyTextBox;
    private JTextField publicKeyTextBox;
    TextArea textPane;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    FrameKeyGenerator window = new FrameKeyGenerator();
                    window.frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * Create the application.
     */
    public FrameKeyGenerator() {
        initialize();
    }

    /**
     * Initialize the contents of the frame.
     */
    private void initialize() {
        frame = new JFrame();
        frame.setBounds(100, 100, 450, 300);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(null);

        JLabel lblKeygeneration = new JLabel("KeyGeneration");
        lblKeygeneration.setBounds(0, 0, 434, 30);
        frame.getContentPane().add(lblKeygeneration);

        Box verticalBox = Box.createVerticalBox();
        verticalBox.setBounds(0, 26, 434, 155);
        frame.getContentPane().add(verticalBox);

        Box verticalBox_1 = Box.createVerticalBox();
        verticalBox.add(verticalBox_1);

        Box horizontalBox = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox);

        JLabel label = new JLabel("Pairing Path");
        horizontalBox.add(label);

        pairingTextBox = new JTextField();
        //pairingTextBox.setText("path to pairing");
        pairingTextBox.setColumns(10);
        horizontalBox.add(pairingTextBox);

        JButton btnSearch = new JButton("Search...");
        horizontalBox.add(btnSearch);
        btnSearch.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                //Create a file chooser
                final JFileChooser fc = new JFileChooser();
                int returnVal = fc.showOpenDialog(frame);

                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    //This is where a real application would open the file.
                    try {
                        pairingTextBox.setText(file.getCanonicalPath());
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            }
        });

        Box horizontalBox_1 = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox_1);

        JLabel label_1 = new JLabel("G Path");
        horizontalBox_1.add(label_1);

        gTextBox = new JTextField();
        //gTextBox.setText("path to g");
        gTextBox.setColumns(10);
        horizontalBox_1.add(gTextBox);


        JButton button = new JButton("Search...");
        horizontalBox_1.add(button);
        button.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                //Create a file chooser
                final JFileChooser fc = new JFileChooser();
                int returnVal = fc.showOpenDialog(frame);

                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    //This is where a real application would open the file.
                    try {
                        gTextBox.setText(file.getCanonicalPath());
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            }
        });

        Box horizontalBox_2 = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox_2);

        JLabel label_2 = new JLabel("W Path");
        horizontalBox_2.add(label_2);

        wTextBox = new JTextField();
        //wTextBox.setText("path to w");
        wTextBox.setColumns(10);
        horizontalBox_2.add(wTextBox);

        JButton button_1 = new JButton("Search...");
        horizontalBox_2.add(button_1);

        button_1.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                //Create a file chooser
                final JFileChooser fc = new JFileChooser();
                int returnVal = fc.showSaveDialog(frame);

                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    //This is where a real application would open the file.
                    try {
                        wTextBox.setText(file.getCanonicalPath());
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            }
        });

        Box horizontalBox_3 = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox_3);

        JLabel label_3 = new JLabel("Private Key Output Path");
        horizontalBox_3.add(label_3);

        privateKeyTextBox = new JTextField();
        //privateKeyTextBox.setText("path to pairing");
        privateKeyTextBox.setColumns(10);
        horizontalBox_3.add(privateKeyTextBox);

        JButton button_2 = new JButton("Search...");
        horizontalBox_3.add(button_2);
        button_2.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                //Create a file chooser
                final JFileChooser fc = new JFileChooser();
                int returnVal = fc.showSaveDialog(frame);

                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    //This is where a real application would open the file.
                    try {
                        privateKeyTextBox.setText(file.getCanonicalPath());
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            }
        });
        Box horizontalBox_4 = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox_4);

        JLabel label_4 = new JLabel("Public Key Output Path");
        horizontalBox_4.add(label_4);

        publicKeyTextBox = new JTextField();
        //publicKeyTextBox.setText("path to pairing");
        publicKeyTextBox.setColumns(10);
        horizontalBox_4.add(publicKeyTextBox);

        JButton button_3 = new JButton("Search...");
        button_3.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                //Create a file chooser
                final JFileChooser fc = new JFileChooser();
                int returnVal = fc.showSaveDialog(frame);

                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    //This is where a real application would open the file.
                    try {
                        publicKeyTextBox.setText(file.getCanonicalPath());
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            }
        });
        horizontalBox_4.add(button_3);

        JButton btnSubmit = new JButton("Submit");
        verticalBox_1.add(btnSubmit);
        btnSubmit.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                // TODO Auto-generated method stub
                buttonSubmit();
            }
        });
        textPane = new TextArea();
        textPane.setBounds(0, 182, 434, 79);

        frame.getContentPane().add(textPane);
    }

    public void buttonSubmit() {
        String pairingPath = pairingTextBox.getText();
        String gPath = gTextBox.getText();
        String wPath = wTextBox.getText();
        String privateKeyPath = privateKeyTextBox.getText();
        String publicKeyPath = publicKeyTextBox.getText();

        KeyGenerator s =
            new KeyGenerator(pairingPath, gPath, wPath, privateKeyPath, publicKeyPath, false);
        textPane.setText(s.run());
    }
}
