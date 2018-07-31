package homomorphic_authentication_cli.gui;

import homomorphic_authentication_cli.services.TagVerifier;

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

public class FrameVerify {
    private JFrame frame;
    private JTextField pairingTextBox;
    private JTextField gTextBox;
    private JTextField wTextBox;
    private JTextField publicKeyTextBox;
    private JTextField fileIDTextBox;
    //JTextPane textPane;
    private JTextField filePathTextBox;
    private JTextField sigOutPathTextBox;
    private TextArea textArea;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    FrameVerify window = new FrameVerify();
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
    public FrameVerify() {
        initialize();
    }

    /**
     * Initialize the contents of the frame.
     */
    private void initialize() {
        frame = new JFrame();
        frame.setBounds(100, 100, 450, 436);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(null);

        JLabel lblKeygeneration = new JLabel("Storage Verifier");
        lblKeygeneration.setBounds(0, 0, 434, 30);
        frame.getContentPane().add(lblKeygeneration);

        Box verticalBox = Box.createVerticalBox();
        verticalBox.setBounds(0, 26, 432, 196);
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
                int returnVal = fc.showOpenDialog(frame);

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

        JLabel label_3 = new JLabel("Public Key Output Path");
        horizontalBox_3.add(label_3);

        publicKeyTextBox = new JTextField();
        //privateKeyTextBox.setText("path to pairing");
        publicKeyTextBox.setColumns(10);
        horizontalBox_3.add(publicKeyTextBox);

        JButton button_2 = new JButton("Search...");
        horizontalBox_3.add(button_2);
        button_2.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                //Create a file chooser
                final JFileChooser fc = new JFileChooser();
                int returnVal = fc.showOpenDialog(frame);

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
        Box horizontalBox_4 = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox_4);

        JLabel label_4 = new JLabel("File id:");
        horizontalBox_4.add(label_4);

        fileIDTextBox = new JTextField();
        //publicKeyTextBox.setText("path to pairing");
        fileIDTextBox.setColumns(10);
        horizontalBox_4.add(fileIDTextBox);
        /*
                JButton button_3 = new JButton("Search...");
                button_3.addActionListener(new ActionListener() {
        
                    @Override
                    public void actionPerformed(ActionEvent arg0) {
                        //Create a file chooser
                        final JFileChooser fc = new JFileChooser();
                        int returnVal = fc.showOpenDialog(frame);
        
                        if (returnVal == JFileChooser.APPROVE_OPTION) {
                            File file = fc.getSelectedFile();
                            //This is where a real application would open the file.
                            try {
                                fileIDTextBox.setText(file.getCanonicalPath());
                            } catch (IOException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            }
                        }
        
                    }
                });
                horizontalBox_4.add(button_3);*/

        Box horizontalBox_5 = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox_5);

        JLabel label_5 = new JLabel("File Path:");
        horizontalBox_5.add(label_5);

        filePathTextBox = new JTextField();
        //publicKeyTextBox.setText("path to pairing");
        filePathTextBox.setColumns(10);
        horizontalBox_5.add(filePathTextBox);

        JButton button_5 = new JButton("Search...");
        button_5.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                //Create a file chooser
                final JFileChooser fc = new JFileChooser();
                int returnVal = fc.showOpenDialog(frame);

                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    //This is where a real application would open the file.
                    try {
                        filePathTextBox.setText(file.getCanonicalPath());
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            }
        });
        horizontalBox_5.add(button_5);


        Box horizontalBox_6 = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox_6);

        JLabel label_6 = new JLabel("Sig Output Path:");
        horizontalBox_6.add(label_6);

        sigOutPathTextBox = new JTextField();
        //publicKeyTextBox.setText("path to pairing");
        sigOutPathTextBox.setColumns(10);
        horizontalBox_6.add(sigOutPathTextBox);

        JButton button_6 = new JButton("Search...");
        button_6.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                //Create a file chooser
                final JFileChooser fc = new JFileChooser();
                int returnVal = fc.showSaveDialog(frame);

                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    //This is where a real application would open the file.
                    try {
                        sigOutPathTextBox.setText(file.getCanonicalPath());
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            }
        });
        horizontalBox_6.add(button_6);
        JButton btnSubmit = new JButton("Submit");
        verticalBox_1.add(btnSubmit);

        textArea = new TextArea();
        textArea.setBounds(0, 228, 434, 160);
        frame.getContentPane().add(textArea);
        btnSubmit.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                // TODO Auto-generated method stub
                buttonSubmit();
            }
        });/*
           textPane = new JTextPane();
           textPane.setBounds(0, 200, 434, 60);
           
           frame.getContentPane().add(textPane);*/
    }

    public void buttonSubmit() {
        String pairingPath = pairingTextBox.getText();
        String gPath = gTextBox.getText();
        String wPath = wTextBox.getText();
        String publicKeyPath = publicKeyTextBox.getText();
        String fILE_ID = fileIDTextBox.getText();
        String fILE_PATH = filePathTextBox.getText();
        String sIGNATURE_OUT_FILE_PATH = sigOutPathTextBox.getText();
        TagVerifier s = new TagVerifier(pairingPath, gPath, wPath, publicKeyPath, fILE_ID,
                fILE_PATH, sIGNATURE_OUT_FILE_PATH, false);
        textArea.setText(s.run());
    }
}
