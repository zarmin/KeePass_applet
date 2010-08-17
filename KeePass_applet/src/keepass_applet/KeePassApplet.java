/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package keepass_applet;

import java.applet.Applet;
import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.GridLayout;
import java.awt.Panel;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.net.URLConnection;

/**
 *
 * @author mrz
 */
public class KeePassApplet implements ActionListener {

    /**
     * Initialization method that will be called after the applet is loaded
     * into the browser.
     */
    private TextField URL;
    private TextField PWD;
    private Button BTN;
    private java.awt.List LOG;

    public void init() {
        // TODO start asynchronous download of heavy resources
        PWD = new TextField( 8 );
        PWD.setEchoChar( (char)8226 );
        Panel p = new Panel();
        p.setLayout(new GridLayout(4,1));
  
        URL = new TextField( 16 );
        BTN = new Button( "Access" );
        BTN.addActionListener( this );
        LOG = new java.awt.List( 6 );
        p.add( URL );
        p.add( PWD );
        p.add( BTN );
        p.add( LOG );
   
    }

    public void actionPerformed( ActionEvent e ) {
        if( e.getSource() == BTN ) {
            String pass = PWD.getText();
            String url = URL.getText();
            LOG.add( "Trying to connect to: "+url );
            try {
                URL u = new URL( url );
                URLConnection uc = u.openConnection();
                uc.connect();
                BufferedInputStream in = new BufferedInputStream( u.openStream() );
                byte buffer[] = new byte[1024];
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                int count;
                while( ( count = in.read( buffer, 0, 1024 )) != -1 ) {
                    os.write( buffer, 0, count );
                }
                byte data[] = new byte[os.size()];
                data = os.toByteArray();
                LOG.add( "File got!" );
            } catch ( Exception ex ) {
                LOG.add( "Download error" );
            }
        }
       // this.repaint();
    }

    // TODO overwrite start(), stop() and destroy() methods
}
