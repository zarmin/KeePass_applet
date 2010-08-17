/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package keepass_applet;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import net.sourceforge.keepassj2me.keydb.IKeydbGroupContentRecever;
import net.sourceforge.keepassj2me.keydb.KeydbDatabase;
import net.sourceforge.keepassj2me.keydb.KeydbEntry;
import net.sourceforge.keepassj2me.keydb.KeydbGroup;

/**
 *
 * @author mrz
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {
        // TODO code application logic here
        KeydbDatabase db = new KeydbDatabase();
        System.out.println("Password:");
        BufferedReader kb = new BufferedReader(new java.io.InputStreamReader(System.in));
        String code = kb.readLine();
       
        File f = new File("/home/mrz/passwords.kdb");
        InputStream in = new FileInputStream(f);
        long lgn = f.length();
        byte[] bytecode = new byte[(int)lgn];
        in.read(bytecode);
        in.close();
        try {
            db.open(bytecode, code, null);
        } catch( Exception e ) {
            System.out.println("BADC0DE");
            System.exit(0);
        }

        System.out.println("PASSWORD OK");
        
        enumGroup( db, 0, 0 );
    }

    public static void enumGroup( final KeydbDatabase db, int gid, final int level ) {
        StringBuilder b = new StringBuilder();
        for( int i=0; i<level; ++i ) {
            b.append("    ");
        }
        final String prefix = b.toString();
        int num = db.enumGroupContent(gid, new IKeydbGroupContentRecever() {
            public void addKeydbEntry( KeydbEntry en ) {
                System.out.println(prefix+en.title);
            }
            public void addKeydbGroup( KeydbGroup gr ) {
                System.out.println(prefix+" + "+gr.name);
                enumGroup( db, gr.id, level+1 );
            }            
        }, 0, 1000 );
    }

}