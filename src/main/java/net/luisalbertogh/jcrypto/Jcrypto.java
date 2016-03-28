/**
 * © 2009-2012 Tex Toll Services, LLC
 */
package net.luisalbertogh.jcrypto;

import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Properties;

import javax.imageio.ImageIO;
import javax.swing.JFrame;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

import net.luisalbertogh.jcrypto.gui.MainPanel;

/**
 * Main class.
 * 
 * @author lagarcia
 */
public class Jcrypto {

    /** Frame width */
    public static final int WIDTH = 800;

    /** Frame height */
    public static final int HEIGHT = 600;

    /**
     * Main method.
     * 
     * @param args
     */
    public static void main(String[] args) {
        /* Init Jcrypto */
        Jcrypto jcrypto = new Jcrypto();
        jcrypto.init();
    }

    /**
     * Init GUI.
     */
    private void init() {
        try {
            /* Set Nimbus L&F */
            for (LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }

            /* Load external providers */
            loadProviders();

            /* Main frame */
            JFrame frame = new JFrame();
            frame.setPreferredSize(new Dimension(WIDTH, HEIGHT));
            frame.setTitle("JCrypto");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setResizable(false);

            /* Main panel */
            MainPanel mp = new MainPanel(frame);
            frame.add(mp);

            /* Set icon */
            BufferedImage bi = null;
            try {
                bi = ImageIO.read(new File("./pics/PadLock-icon.png"));
            } catch (IOException e) {
                e.printStackTrace();
            }
            frame.setIconImage(bi);

            /* Show frame */
            frame.pack();
            frame.setVisible(true);
            frame.setLocationRelativeTo(null);
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    /**
     * Load external JCE providers.
     */
    private void loadProviders() throws Exception {
        Properties providers = new Properties();
        providers.load(new FileReader("config/providers.properties"));
        String name = "provider";
        int cont = 1;
        while (true) {
            String provClass = providers.getProperty(name + cont);
            if (provClass != null) {
                Security.addProvider((Provider) Class.forName(provClass).newInstance());
                cont++;
            } else {
                break; // Out of the loop
            }
        }
    }
}
