package homomorphic_authentication_cli.gui;

import homomorphic_authentication_cli.services.SetupA;
import homomorphic_authentication_library_Java.io.FileSystemHandler;

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

public class FrameSetup {

    private JFrame frame;
    private JTextField pairingTextBox;
    private JTextField gTextBox;
    TextArea textPane;
    private JTextField txtQ;
    private JTextField txtR;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    FrameSetup window = new FrameSetup();
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
    public FrameSetup() {
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

        JLabel lblSetup = new JLabel("Setup");
        lblSetup.setBounds(0, 0, 434, 30);
        frame.getContentPane().add(lblSetup);

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
                int returnVal = fc.showSaveDialog(frame);

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
                int returnVal = fc.showSaveDialog(frame);

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

        JLabel lblQ = new JLabel("q");
        horizontalBox_2.add(lblQ);

        txtQ = new JTextField();

        horizontalBox_2.add(txtQ);
        txtQ.setColumns(10);

        JLabel lblR = new JLabel("r");
        horizontalBox_2.add(lblR);

        txtR = new JTextField();

        horizontalBox_2.add(txtR);
        txtR.setColumns(10);
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
        int q = Integer.parseInt(txtQ.getText());
        int r = Integer.parseInt(txtR.getText());

        SetupA s = new SetupA(q, r);
        System.out.println(s.run());

        FileSystemHandler.writeFile(pairingPath, s.getPairingParameters());

        try {
            FileSystemHandler.writeFile(gPath, s.getG().toBytes());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }
}
