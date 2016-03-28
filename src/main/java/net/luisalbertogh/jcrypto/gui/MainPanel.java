/**
 * © 2009-2012 Tex Toll Services, LLC
 */
package net.luisalbertogh.jcrypto.gui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.imageio.ImageIO;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.border.TitledBorder;

import net.luisalbertogh.jcrypto.Jcrypto;
import net.luisalbertogh.jcrypto.utils.CryptoUtils;

/**
 * Main panel.
 * 
 * @author lagarcia
 */
public class MainPanel extends JTabbedPane {

    /** The main frame. */
    private JFrame mainFrame;

    /** Message digest and encryption algorithms. */
    private JComboBox providers, mdProviders, mdAlgorithms, encAlgorithms;

    /** Text to digest. */
    private JTextArea textDigest, mdResult;

    /** Submit & reset buttons. */
    private JButton mdSubmit, mdReset, encBut, decBut, encReset, fileBut, fileSave, ksOpenBt;

    /** Encryption/decryption text. */
    private JTextArea textEnc, textDec;

    /** Password. */
    private JPasswordField password, ksPasswd;

    /** File path to encrypt/decrypt. */
    private JTextField filePath, fileDest, keystoreFile;

    /** File chooser. */
    private JFileChooser fileChooser;

    /** Wait panel. */
    private WaitPanel waitPanel;

    /** Button name. */
    private String name;

    /** Button listener. */
    private ButtonListener btListener;

    /** ComboBox listener. */
    private ComboListener comboListener;

    /**
     * Default constructor.
     * 
     * @param mainFrame - The main frame reference
     */
    public MainPanel(JFrame mainFrame) {
        this.mainFrame = mainFrame;
        this.fileChooser = new JFileChooser(new File(System.getProperty("user.dir")));
        this.waitPanel = new WaitPanel();

        /* Button listener */
        btListener = new ButtonListener(this);

        /* Combo listener */
        comboListener = new ComboListener();

        /* JCA providers */
        List<String> provList = CryptoUtils.findProviders();
        providers = new JComboBox(provList.toArray());
        providers.setName("algProviders");
        providers.setSelectedItem("SunJCE"); // Default provider
        providers.addActionListener(comboListener);
        mdProviders = new JComboBox(provList.toArray());
        mdProviders.setName("mdProviders");
        mdProviders.setSelectedItem("SUN"); // Default provider
        mdProviders.addActionListener(comboListener);

        /* Add encryption/decryption form */
        addTab(TextMessages.CRYPT_FORM_TITLE.getMsg(), getCryptForm());

        /* Add message digest form */
        addTab(TextMessages.MD_FORM_TITLE.getMsg(), getMDForm());

        /* Add about panel */
        addTab(TextMessages.ABOUT.getMsg(), getAboutPanel());

        /* Set glass panel */
        this.mainFrame.setGlassPane(this.waitPanel);
    }

    /**
     * Create an "About..." panel.
     * 
     * @return The "About..." panel
     */
    private JPanel getAboutPanel() {
        JPanel aboutPane = new JPanel();
        aboutPane.setLayout(new BorderLayout());
        aboutPane.add(Box.createVerticalStrut(Jcrypto.HEIGHT / 4), BorderLayout.NORTH);
        aboutPane.add(Box.createHorizontalStrut(Jcrypto.WIDTH / 6), BorderLayout.WEST);

        Font f = new Font("Arial", Font.PLAIN, 18);
        JPanel labelPane = new JPanel();
        labelPane.setLayout(new GridLayout(0, 1));

        BufferedImage bi = null;
        try {
            bi = ImageIO.read(new File("./pics/PadLock-icon-48.png"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        JLabel icon = new JLabel(new ImageIcon(bi));

        JLabel label = new JLabel("JCrypto - Encrypt and decrypt using Java");
        label.setFont(f);
        label.setHorizontalAlignment(SwingConstants.CENTER);

        JLabel label2 = new JLabel(
                "<html>All rights reserved - Created by <a href='http://it.luisalbertogh.net'>luisalbertogh.net</a></html>");
        label2.setHorizontalAlignment(SwingConstants.CENTER);

        labelPane.add(icon);
        labelPane.add(label);
        labelPane.add(label2);

        aboutPane.add(labelPane, BorderLayout.CENTER);
        aboutPane.add(Box.createHorizontalStrut(Jcrypto.WIDTH / 6), BorderLayout.EAST);
        aboutPane.add(Box.createVerticalStrut(Jcrypto.HEIGHT / 3), BorderLayout.SOUTH);
        return aboutPane;
    }

    /**
     * Create encryption/decryption form.
     * 
     * @return The crypto panel
     */
    private JPanel getCryptForm() {
        JPanel criptoForm = new JPanel();

        /* Set layout */
        criptoForm.setLayout(new BorderLayout());

        /* Inputs */
        JPanel fields = new JPanel();
        fields.setLayout(new BoxLayout(fields, BoxLayout.Y_AXIS));

        /* Providers & Encryption algorithms */
        JPanel algPanel = new JPanel();
        algPanel.setLayout(new GridLayout(1, 2));

        JPanel provPanel = new JPanel();
        provPanel.setBorder(new TitledBorder(TextMessages.PROVIDERS.getMsg()));
        provPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        provPanel.add(providers);
        algPanel.add(provPanel);

        List<String> algs = CryptoUtils.findAlgorithms((String) providers.getSelectedItem());
        encAlgorithms = new JComboBox(algs.toArray());
        JPanel comboPanel = new JPanel();
        comboPanel.setBorder(new TitledBorder(TextMessages.SEL_ALGORITHM.getMsg()));
        comboPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        comboPanel.add(encAlgorithms);
        algPanel.add(comboPanel);

        fields.add(algPanel);

        /* Password panel and/or keystore file */
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBorder(new TitledBorder(TextMessages.PASS_KEYSTORE.getMsg()));
        JPanel passPanel = new JPanel();
        passPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        password = new JPasswordField(20);
        passPanel.add(password);
        tabbedPane.addTab(TextMessages.PASSWORD.getMsg(), passPanel);
        /* Keystore panel */
        JPanel ksPanel = new JPanel();
        ksPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        keystoreFile = new JTextField(20);
        ksPanel.add(keystoreFile);
        ksOpenBt = new JButton(TextMessages.SELECT.getMsg());
        ksOpenBt.setName("ks open");
        ksOpenBt.addActionListener(btListener);
        ksPanel.add(ksOpenBt);
        ksPanel.add(new JLabel(TextMessages.PASSWORD.getMsg()));
        ksPasswd = new JPasswordField(20);
        ksPanel.add(ksPasswd);
        tabbedPane.addTab(TextMessages.KEYSTORE.getMsg(), ksPanel);
        fields.add(tabbedPane);

        /* Encrypt/decrypt */
        JTabbedPane encryptPane = new JTabbedPane();
        encryptPane.setBorder(new TitledBorder(TextMessages.ENC_DEC.getMsg()));

        /* File path to encrypt/decrypt */
        JPanel filePanel = new JPanel();
        filePanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        filePath = new JTextField(20);
        fileBut = new JButton(TextMessages.SELECT.getMsg());
        fileBut.setName("fileBut");
        fileBut.addActionListener(btListener);
        fileDest = new JTextField(20);
        fileSave = new JButton(TextMessages.SAVE.getMsg());
        fileSave.setName("fileSave");
        fileSave.addActionListener(btListener);
        filePanel.add(new JLabel(TextMessages.SELECT.getMsg()));
        filePanel.add(filePath);
        filePanel.add(fileBut);
        filePanel.add(new JLabel(TextMessages.SAVE.getMsg()));
        filePanel.add(fileDest);
        filePanel.add(fileSave);
        encryptPane.addTab(TextMessages.FILE.getMsg(), filePanel);

        /* text */
        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.PAGE_AXIS));
        textEnc = new JTextArea();
        JScrollPane scrollPane1 = new JScrollPane(textEnc);
        scrollPane1.setBorder(new TitledBorder(TextMessages.ENC.getMsg()));
        textPanel.add(scrollPane1);
        textDec = new JTextArea();
        JScrollPane scrollPane2 = new JScrollPane(textDec);
        scrollPane2.setBorder(new TitledBorder(TextMessages.DEC.getMsg()));
        textPanel.add(scrollPane2);
        encryptPane.addTab(TextMessages.TEXT.getMsg(), textPanel);

        fields.add(encryptPane);

        /* Buttons panel */
        JPanel butPanel = new JPanel();
        butPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        encBut = new JButton(TextMessages.ENC.getMsg());
        encBut.setName("Enc button");
        encBut.addActionListener(btListener);
        butPanel.add(encBut);
        decBut = new JButton(TextMessages.DEC.getMsg());
        decBut.setName("Dec button");
        decBut.addActionListener(btListener);
        butPanel.add(decBut);
        encReset = new JButton(TextMessages.RESET.getMsg());
        encReset.setName("Enc reset button");
        encReset.addActionListener(btListener);
        butPanel.add(encReset);

        criptoForm.add(fields, BorderLayout.CENTER);
        criptoForm.add(butPanel, BorderLayout.SOUTH);

        return criptoForm;
    }

    /**
     * Create message digest form.
     * 
     * @return The message digest form
     */
    private JPanel getMDForm() {
        JPanel mdForm = new JPanel();

        /* Set layout */
        mdForm.setLayout(new BorderLayout());

        /* labels */
        JPanel labels = new JPanel();
        labels.setLayout(new BoxLayout(labels, BoxLayout.Y_AXIS));
        labels.add(new JLabel(TextMessages.SEL_ALGORITHM.getMsg()));
        labels.add(Box.createVerticalStrut(20));
        labels.add(new JLabel(TextMessages.ENTER_TEXT.getMsg()));
        labels.add(Box.createVerticalStrut(30));
        labels.add(new JLabel(TextMessages.DIGESTED.getMsg()));
        labels.add(Box.createVerticalStrut(60));
        mdForm.add(labels);

        /* Inputs */
        JPanel fields = new JPanel();
        fields.setLayout(new BoxLayout(fields, BoxLayout.Y_AXIS));

        /* MD algorithms & providers */
        JPanel algPanel = new JPanel();
        algPanel.setLayout(new GridLayout(1, 2));

        JPanel provPanel = new JPanel();
        provPanel.setBorder(new TitledBorder(TextMessages.PROVIDERS.getMsg()));
        provPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        provPanel.add(mdProviders);
        algPanel.add(provPanel);

        List<String> mdAlgs = CryptoUtils.findMessageDigesters((String) mdProviders.getSelectedItem());
        mdAlgorithms = new JComboBox(mdAlgs.toArray());
        JPanel mdPanel = new JPanel();
        mdPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        mdPanel.setBorder(new TitledBorder(TextMessages.SEL_ALGORITHM.getMsg()));
        mdPanel.add(mdAlgorithms);
        algPanel.add(mdPanel);

        fields.add(algPanel);

        /* Text */
        textDigest = new JTextArea();
        JScrollPane scrollPane1 = new JScrollPane(textDigest);
        scrollPane1.setBorder(new TitledBorder(TextMessages.ENTER_TEXT.getMsg()));
        fields.add(scrollPane1);

        mdResult = new JTextArea();
        JScrollPane scrollPane2 = new JScrollPane(mdResult);
        scrollPane2.setBorder(new TitledBorder(TextMessages.DIGESTED.getMsg()));
        mdResult.setLineWrap(true);
        mdResult.setEditable(false);
        fields.add(scrollPane2);

        /* Buttons panel */
        JPanel butPanel = new JPanel();
        butPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        mdSubmit = new JButton(TextMessages.SUBMIT.getMsg());
        mdSubmit.setName("Submit MD");
        mdSubmit.addActionListener(btListener);
        butPanel.add(mdSubmit);
        mdReset = new JButton(TextMessages.RESET.getMsg());
        mdReset.setName("Reset MD");
        mdReset.addActionListener(btListener);
        butPanel.add(mdReset);

        mdForm.add(fields, BorderLayout.CENTER);
        mdForm.add(butPanel, BorderLayout.SOUTH);

        return mdForm;
    }

    /**
     * Combo listener class.
     * 
     * @author lagarcia
     */
    class ComboListener implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent eArg) {
            /* Action source */
            JComboBox combo = (JComboBox) eArg.getSource();
            String name = combo.getName();
            String selectedItem = null;

            /* Algorithm providers */
            if ("algProviders".equals(name)) {
                selectedItem = (String) combo.getSelectedItem();
                List<String> algorithms = CryptoUtils.findAlgorithms(selectedItem);
                ComboBoxModel cbm = new DefaultComboBoxModel(algorithms.toArray());
                encAlgorithms.setModel(cbm);
            }
            /* MD providers */
            else if ("mdProviders".equals(name)) {
                selectedItem = (String) combo.getSelectedItem();
                List<String> algorithms = CryptoUtils.findMessageDigesters(selectedItem);
                ComboBoxModel cbm = new DefaultComboBoxModel(algorithms.toArray());
                mdAlgorithms.setModel(cbm);
            }
        }
    }

    /**
     * Button listener class.
     * 
     * @author lagarcia
     */
    class ButtonListener implements ActionListener {

        /** Main panel reference. */
        MainPanel mainPanel;

        /**
         * Constructor.
         * 
         * @param mainPanel
         */
        public ButtonListener(MainPanel mainPanel) {
            this.mainPanel = mainPanel;
        }

        @Override
        public void actionPerformed(ActionEvent eArg) {
            try {
                /* Button source */
                Object source = eArg.getSource();
                name = ((JButton) source).getName();

                /* Submit message digest */
                if ("Submit MD".equals(name)) {
                    String algorithm = (String) mdAlgorithms.getSelectedItem();
                    String text = textDigest.getText();
                    String digested = CryptoUtils.digestPassword(text, algorithm);
                    mdResult.setText(digested);
                }
                /* Reset message digest */
                else if ("Reset MD".equals(name)) {
                    textDigest.setText("");
                    mdResult.setText("");
                }
                /* Reset enc/dec form */
                else if ("Enc reset button".equals(name)) {
                    password.setText("");
                    textEnc.setText("");
                    textDec.setText("");
                    fileDest.setText("");
                    filePath.setText("");
                    keystoreFile.setText("");
                    ksPasswd.setText("");
                }
                /* Encryption / Decryption */
                else if ("Enc button".equals(name) || "Dec button".equals(name)) {
                    /* Show progress */
                    waitPanel.setVisible(true);

                    /* Disable buttons */
                    encBut.setEnabled(false);
                    decBut.setEnabled(false);
                    encReset.setEnabled(false);

                    /* Execute encryption/decryption in background */
                    SwingWorker sw = new SwingWorker() {
                        @Override
                        protected Object doInBackground() {
                        	try{
	                            /* Selected algorithm */
	                            String algorithm = (String) encAlgorithms.getSelectedItem();
	
	                            /* Plain Password */
	                            char[] pwd = password.getPassword();
	
	                            /* Default cipher type */
	                            int cipherType = CryptoUtils.CipherType.SYMMETRIC.value;
	
	                            /* Asymmetric cipher type */
	                            if (algorithm.indexOf("RSA") != -1) {
	                                cipherType = CryptoUtils.CipherType.ASYMMETRIC.value;
	                            }
	
	                            /* Load keystore passwords */
	                            String ksFile = keystoreFile.getText();
	                            if (ksFile != null && !"".equals(ksFile)) {
	                                CryptoUtils.loadKeysFromKeyStore(new File(ksFile), ksPasswd.getPassword());
	                            }
	
	                            /* Encryption button */
	                            if ("Enc button".equals(name)) {
	                                /* Attempt to encrypt file */
	                                String file = filePath.getText();
	                                String dest = fileDest.getText();
	                                if (file != null && !"".equals(file) && dest != null && !"".equals(dest)) {
	                                    CryptoUtils.encryptFile(file, dest, algorithm, pwd, cipherType);
	                                }
	                                /* Encrypt text */
	                                else {
	                                    String text = textEnc.getText();
	                                    String encryptedText = "";
	                                    if (algorithm.indexOf("RSA") != -1) {
	                                        encryptedText = CryptoUtils.encrypt(text, algorithm);
	                                    } else {
	                                        encryptedText = CryptoUtils.encrypt(text, algorithm, pwd);
	                                    }
	                                    textDec.setText(encryptedText);
	                                }
	                            }
	                            /* Decryption button */
	                            else if ("Dec button".equals(name)) {
	                                /* Attempt to decrypt file */
	                                String file = filePath.getText();
	                                String dest = fileDest.getText();
	                                if (file != null && !"".equals(file) && dest != null && !"".equals(dest)) {
	                                    CryptoUtils.decryptFile(file, dest, algorithm, pwd, cipherType);
	                                }
	                                /* Decrypt text */
	                                else {
	                                    String text = textDec.getText();
	                                    String decryptedText = "";
	                                    if (algorithm.indexOf("RSA") != -1) {
	                                        decryptedText = CryptoUtils.decrypt(text, algorithm);
	                                    } else {
	                                        decryptedText = CryptoUtils.decrypt(text, algorithm, pwd);
	                                    }
	                                    textEnc.setText(decryptedText);
	                                }
	                            }
                        	}catch(Exception ex){
                        		ex.printStackTrace();
                        	}
                            
                            /* Hide progress */
                            waitPanel.setVisible(false);

                            /* Enable buttons */
                            encBut.setEnabled(true);
                            decBut.setEnabled(true);
                            encReset.setEnabled(true);

                            return null;
                        }
                    };

                    /* Execute SW */
                    sw.execute();
                }
                /* File button */
                else if ("fileBut".equals(name)) {
                    int returnVal = fileChooser.showOpenDialog(mainPanel);
                    if (returnVal == JFileChooser.APPROVE_OPTION) {
                        File file = fileChooser.getSelectedFile();
                        filePath.setText(file.getAbsolutePath());
                    }
                }
                /* Save button */
                else if ("fileSave".equals(name)) {
                    int returnVal = fileChooser.showSaveDialog(mainPanel);
                    if (returnVal == JFileChooser.APPROVE_OPTION) {
                        File file = fileChooser.getSelectedFile();
                        fileDest.setText(file.getAbsolutePath());
                    }
                }
                /* Open keystore file */
                else if ("ks open".equals(name)) {
                    int returnVal = fileChooser.showOpenDialog(mainPanel);
                    if (returnVal == JFileChooser.APPROVE_OPTION) {
                        File file = fileChooser.getSelectedFile();
                        keystoreFile.setText(file.getAbsolutePath());
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace();
                /* Hide progress */
                waitPanel.setVisible(false);

                /* Enable buttons */
                encBut.setEnabled(true);
                decBut.setEnabled(true);
                encReset.setEnabled(true);

                /* Show pop-up */
                JOptionPane.showMessageDialog(mainFrame, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
