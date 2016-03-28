/**
 * © 2009-2012 Tex Toll Services, LLC
 */
package net.luisalbertogh.jcrypto.gui;

import javax.swing.JPanel;
import javax.swing.JProgressBar;

import net.luisalbertogh.jcrypto.Jcrypto;

/**
 * This class implements a "wait" panel as a glass panel.
 * 
 * @author lagarcia
 */
public class WaitPanel extends JPanel {

    /** Progress bar. */
    private JProgressBar progressBar;

    /** Progress width. */
    private final int width = 300;

    /** Progress height. */
    private final int height = 50;

    /**
     * Default constructor.
     */
    public WaitPanel() {
        /* Set layout */
        setLayout(null);

        /* Transparent background */
        setOpaque(false);

        /* Progress bar */
        progressBar = new JProgressBar();
        progressBar.setIndeterminate(true); // Continues movement
        progressBar.setBounds((Jcrypto.WIDTH / 2) - (width / 2), (Jcrypto.HEIGHT / 2) - (height / 2), width, height);
        add(progressBar);
    }
}
