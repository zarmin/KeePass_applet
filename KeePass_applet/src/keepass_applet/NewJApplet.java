/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * NewJApplet.java
 *
 * Created on Jan 7, 2010, 12:53:44 PM
 */

package keepass_applet;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.net.URLConnection;
import javax.swing.JOptionPane;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import net.sourceforge.keepassj2me.keydb.IKeydbGroupContentRecever;
import net.sourceforge.keepassj2me.keydb.KeydbDatabase;
import net.sourceforge.keepassj2me.keydb.KeydbEntry;
import net.sourceforge.keepassj2me.keydb.KeydbGroup;

/**
 *
 * @author mrz
 */
public class NewJApplet extends javax.swing.JApplet {

    public static final int APPLICATION_WIDTH = 500;
    public static final int APPLICATION_HEIGHT = 500;

    /** Initializes the applet NewJApplet */
    public void init() {
        try {
            java.awt.EventQueue.invokeAndWait(new Runnable() {
                public void run() {
                    initComponents();
                    PanelShow.setVisible(false);
                }
            });
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void destroy() {
        db.close();
        System.gc();
    }

    /** This method is called from within the init() method to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */

    private void ShowDialogBox( String title, String content ) {
        JOptionPane.showMessageDialog( this, content, title, JOptionPane.INFORMATION_MESSAGE );

    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        PanelInput = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        EditURL = new javax.swing.JTextField();
        EditPassword = new javax.swing.JPasswordField();
        ButtonGO = new javax.swing.JButton();
        PanelShow = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        EditShowName = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        EditShowUsername = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        EditShowURL = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        TreeShowDB = new javax.swing.JTree();
        EditShowPassword = new javax.swing.JPasswordField();
        ButtonPasswordCopy = new javax.swing.JButton();
        label1 = new java.awt.Label();

        PanelInput.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 0, 0)));

        jLabel1.setText("KeePass File URL");

        jLabel2.setText("Password");

        ButtonGO.setText("GO");
        ButtonGO.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                ButtonGOMouseClicked(evt);
            }
        });

        javax.swing.GroupLayout PanelInputLayout = new javax.swing.GroupLayout(PanelInput);
        PanelInput.setLayout(PanelInputLayout);
        PanelInputLayout.setHorizontalGroup(
            PanelInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(PanelInputLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(PanelInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(PanelInputLayout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(EditURL, javax.swing.GroupLayout.PREFERRED_SIZE, 148, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(PanelInputLayout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(EditPassword)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(ButtonGO, javax.swing.GroupLayout.DEFAULT_SIZE, 92, Short.MAX_VALUE)
                .addContainerGap())
        );
        PanelInputLayout.setVerticalGroup(
            PanelInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(PanelInputLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(PanelInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(ButtonGO, javax.swing.GroupLayout.PREFERRED_SIZE, 53, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(PanelInputLayout.createSequentialGroup()
                        .addGroup(PanelInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel1)
                            .addComponent(EditURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(PanelInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel2)
                            .addComponent(EditPassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        PanelShow.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 0, 0)));

        jLabel3.setText("Name");

        jLabel4.setText("Username");

        jLabel5.setText("URL");

        jLabel6.setText("Password");

        javax.swing.tree.DefaultMutableTreeNode treeNode1 = new javax.swing.tree.DefaultMutableTreeNode("KeePass Password Database");
        TreeShowDB.setModel(new javax.swing.tree.DefaultTreeModel(treeNode1));
        TreeShowDB.addTreeSelectionListener(new javax.swing.event.TreeSelectionListener() {
            public void valueChanged(javax.swing.event.TreeSelectionEvent evt) {
                TreeShowDBValueChanged(evt);
            }
        });
        jScrollPane1.setViewportView(TreeShowDB);

        ButtonPasswordCopy.setText("Copy Password");
        ButtonPasswordCopy.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                ButtonPasswordCopyMouseClicked(evt);
            }
        });

        label1.setText("0.1a");

        javax.swing.GroupLayout PanelShowLayout = new javax.swing.GroupLayout(PanelShow);
        PanelShow.setLayout(PanelShowLayout);
        PanelShowLayout.setHorizontalGroup(
            PanelShowLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(PanelShowLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(PanelShowLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, PanelShowLayout.createSequentialGroup()
                        .addGroup(PanelShowLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel3)
                            .addComponent(EditShowName, javax.swing.GroupLayout.DEFAULT_SIZE, 143, Short.MAX_VALUE)
                            .addComponent(jLabel4)
                            .addComponent(EditShowUsername, javax.swing.GroupLayout.DEFAULT_SIZE, 143, Short.MAX_VALUE)
                            .addComponent(jLabel5)
                            .addComponent(EditShowURL, javax.swing.GroupLayout.DEFAULT_SIZE, 143, Short.MAX_VALUE)
                            .addComponent(jLabel6)
                            .addComponent(EditShowPassword, javax.swing.GroupLayout.DEFAULT_SIZE, 143, Short.MAX_VALUE))
                        .addContainerGap())
                    .addGroup(PanelShowLayout.createSequentialGroup()
                        .addComponent(ButtonPasswordCopy)
                        .addGap(32, 32, 32))
                    .addGroup(PanelShowLayout.createSequentialGroup()
                        .addComponent(label1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap())))
        );
        PanelShowLayout.setVerticalGroup(
            PanelShowLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, PanelShowLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(PanelShowLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, PanelShowLayout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(EditShowName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(EditShowUsername, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(EditShowURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel6)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(EditShowPassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(ButtonPasswordCopy)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(label1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(PanelInput, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(PanelShow, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(PanelInput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(PanelShow, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void ButtonGOMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ButtonGOMouseClicked
        // TODO add your handling code here:
        String url = EditURL.getText();
        String pass = new String( EditPassword.getPassword() );
        EditPassword.setText( "" );
        
        if( url.length() == 0 || pass.length() == 0 ) {
            ShowDialogBox( "Error", "Please give us an URL and a password!" );
            return;
        }

        byte data[];
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
            data = new byte[os.size()];
            data = os.toByteArray();
        } catch( Exception e ) {
            ShowDialogBox( "Error", "Download error!"+"\n"+e.toString() );
            return;
        }

        db = new KeydbDatabase();
        try {
            db.open( data, pass, null );
        } catch( Exception e ) {
            ShowDialogBox( "Error", "Bad password or invalid file format!" );
            return;
        }

        PanelInput.setVisible( false );
        PanelShow.setVisible( true );

        KeePassTreeNode dmRoot = new KeePassTreeNode( "KeePass Database" );
        enumGroup( db, 0, dmRoot );
        DefaultTreeModel dmModel = new DefaultTreeModel( dmRoot );
        TreeShowDB.setModel( dmModel );
    }//GEN-LAST:event_ButtonGOMouseClicked

    private void TreeShowDBValueChanged(javax.swing.event.TreeSelectionEvent evt) {//GEN-FIRST:event_TreeShowDBValueChanged
        // TODO add your handling code here:
        if( db == null )
            return;
        EditShowName.setText( evt.getNewLeadSelectionPath().toString() );
        try {
            Object a = evt.getNewLeadSelectionPath().getLastPathComponent();
            KeydbEntry e = ((KeePassTreeNode)a).getKeydbEntry();
            EditShowURL.setText( e.getUrl( this.db ) );
            EditShowUsername.setText( e.getUsername( this.db ) );
            EditShowPassword.setText( e.getPassword( this.db ) );
        } catch( Exception e ) {
            EditShowURL.setText( "" );
            EditShowUsername.setText( "" );
            EditShowPassword.setText( "" );
        }
    }//GEN-LAST:event_TreeShowDBValueChanged

    private void ButtonPasswordCopyMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ButtonPasswordCopyMouseClicked
        // TODO add your handling code here:
        String pass = new String( EditShowPassword.getPassword() );
        StringSelection ss = new StringSelection( pass );
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents( ss, null );
    }//GEN-LAST:event_ButtonPasswordCopyMouseClicked

    private void enumGroup( final KeydbDatabase db, int gid, final DefaultMutableTreeNode root ) {
        db.enumGroupContent(gid, new IKeydbGroupContentRecever() {

            public void addKeydbGroup(KeydbGroup group) {
                KeePassTreeNode n = new KeePassTreeNode( group.name );
                enumGroup( db, group.id, n );
                root.add( n );
            }

            public void addKeydbEntry(KeydbEntry entry) {
                KeePassTreeNode n = new KeePassTreeNode( entry.title, entry );
                
                root.add( n );
            }

        }, 0 , 1000 );
    }

    private KeydbDatabase db = null;
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton ButtonGO;
    private javax.swing.JButton ButtonPasswordCopy;
    private javax.swing.JPasswordField EditPassword;
    private javax.swing.JTextField EditShowName;
    private javax.swing.JPasswordField EditShowPassword;
    private javax.swing.JTextField EditShowURL;
    private javax.swing.JTextField EditShowUsername;
    private javax.swing.JTextField EditURL;
    private javax.swing.JPanel PanelInput;
    private javax.swing.JPanel PanelShow;
    private javax.swing.JTree TreeShowDB;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JScrollPane jScrollPane1;
    private java.awt.Label label1;
    // End of variables declaration//GEN-END:variables

}
