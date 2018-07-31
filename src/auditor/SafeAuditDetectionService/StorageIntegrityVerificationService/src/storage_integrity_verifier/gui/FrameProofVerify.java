package storage_integrity_verifier.gui;




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

import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

import communication.AwsAPICommunicationHandler;
import storage_integrity_verifier.json.RequestParser;
import storage_integrity_verifier.service.StorageIntegrityVerificationService;

public class FrameProofVerify {
    private JFrame frame;
    private JTextField pairingTextBox;
    private JTextField gTextBox;
    private JTextField wTextBox;
    private JTextField publicKeyTextBox;
    JTextPane textPane;
    private TextArea textArea;
    private TextArea chalArea;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    FrameProofVerify window = new FrameProofVerify();
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
    public FrameProofVerify() {
        initialize();
    }

    /**
     * Initialize the contents of the frame.
     */
    private void initialize() {
        frame = new JFrame();
        frame.setBounds(100, 100, 760, 565);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(null);

        JLabel lblKeygeneration = new JLabel("Storage Verifier");
        lblKeygeneration.setBounds(0, 0, 434, 30);
        frame.getContentPane().add(lblKeygeneration);

        Box verticalBox = Box.createVerticalBox();
        verticalBox.setBounds(0, 26, 741, 84);
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

        Box horizontalBox_5 = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox_5);


        Box horizontalBox_6 = Box.createHorizontalBox();
        verticalBox_1.add(horizontalBox_6);

        JButton btnSubmit = new JButton("Submit");
        btnSubmit.setBounds(338, 316, 65, 23);
        frame.getContentPane().add(btnSubmit);
        btnSubmit.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                // TODO Auto-generated method stub
                buttonSubmit();
            }
        });

        textArea = new TextArea();
        textArea.setBounds(0, 345, 741, 181);
        frame.getContentPane().add(textArea);

        chalArea = new TextArea();
        chalArea.setBounds(0, 141, 741, 160);
        frame.getContentPane().add(chalArea);

        JLabel lblChal = new JLabel("Chal:");
        lblChal.setBounds(0, 121, 46, 14);
        frame.getContentPane().add(lblChal);
    }

    public void buttonSubmit() {
        String pairingPath = pairingTextBox.getText();
        String gPath = gTextBox.getText();
        String wPath = wTextBox.getText();
        String publicKeyPath = publicKeyTextBox.getText();
        String json = chalArea.getText();

        /*String proof_path = proofArea.getText();
        if (proof_path.isEmpty()) {
            proof_path = proofTextBox.getText();
        }*/
        JSONObject j_o;
        String chal_json = "";
        String meta_json = "";
        try {
            j_o = new JSONObject(json);
            meta_json = j_o.getJSONObject("meta").toString();

            chal_json = j_o.getJSONObject("chal").toString();
            RequestParser p = new RequestParser();
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        AwsAPICommunicationHandler h = new AwsAPICommunicationHandler(
                "https://cb5fguhx0m.execute-api.eu-west-1.amazonaws.com/test/S3CloudProverIR",
                chal_json);
        String proof_path = h.post();

        if (proof_path == null) {
            return;
        }
        StorageIntegrityVerificationService s = new StorageIntegrityVerificationService(pairingPath,
                gPath, wPath, meta_json, chal_json, proof_path);
        textArea.setText(s.run());
    }
}
