/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package keepass_applet;

import javax.swing.tree.DefaultMutableTreeNode;
import net.sourceforge.keepassj2me.keydb.KeydbEntry;

/**
 *
 * @author mrz
 */
public class KeePassTreeNode extends DefaultMutableTreeNode {
    private KeydbEntry entry;

    KeePassTreeNode( Object std ) {
        super( std );
        entry = null;
    }

    KeePassTreeNode( Object std, KeydbEntry e ) {
        super( std );
        entry = e;
    }

    public KeydbEntry getKeydbEntry() {
        return( entry );
    }
}
