/*
KeePass for J2ME

Copyright 2007 Naomaru Itoi <nao@phoneid.org>

This file was derived from 

Java clone of KeePass - A KeePass file viewer for Java
Copyright 2006 Bill Zwicky <billzwicky@users.sourceforge.net>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

package net.sourceforge.keepassj2me.importerv3;

// Java
import java.io.InputStream;
import java.io.IOException;
import java.lang.RuntimeException;
import java.io.UnsupportedEncodingException;

// Bouncy Castle

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.paddings.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.engines.*;


/**
 * Load a v3 database file.
 *
 * @author Naomaru Itoi <nao@phoneid.org>
 * @author Bill Zwicky <wrzwicky@pobox.com>
 * @author Stepan Strelets
 */
public class ImporterV3 {
    // Platform platform = new JavaPlatform();
  
    public ImporterV3() {
    	super();
    }

    /**
     * Constructor which takes form for debugging
     */

    private void setProgress(int procent, String message) {

    }


  /**
   * Load a v3 database file, return contents in a new PwManager.
   * 
   * @param infile  Existing file to load.
   * @param password Pass phrase for infile.
   * @param pRepair (unused)
   * @return new PwManager container.
   * 
   * @throws IOException on any file error.
   * @throws InvalidKeyException on a decryption error, or possible internal bug.
   * @throws IllegalBlockSizeException on a decryption error, or possible internal bug.
   * @throws BadPaddingException on a decryption error, or possible internal bug.
   * @throws NoSuchAlgorithmException on a decryption error, or possible internal bug.
   * @throws NoSuchPaddingException on a decryption error, or possible internal bug.
   * @throws InvalidAlgorithmParameterException if error decrypting main file body. 
   * @throws ShortBufferException if error decrypting main file body.
   */
    public PwManager openDatabase( InputStream inStream, String password )
      		throws IOException, InvalidCipherTextException, Exception {
    	PwManager        newManager;
    	SHA256Digest    md;
    	/** Master key encrypted several times */
    	byte[]           transformedMasterKey;
    	byte[]           finalKey;

    	setProgress(5, "Open database");
		// #ifdef DEBUG
			System.out.println ("Open database");
		// #endif

    	// Load entire file, most of it's encrypted.
    	// InputStream in = new FileInputStream( infile );
    	byte[] filebuf = new byte[(int)inStream.available()];
    	inStream.read( filebuf, 0, (int)inStream.available());
    	inStream.close();

    	// Parse header (unencrypted)
    	if( filebuf.length < PwDbHeader.BUF_SIZE )
    		throw new IOException( "File too short for header" );
    	PwDbHeader hdr = new PwDbHeader( filebuf, 0 );

    	if( (hdr.signature1 != PwManager.PWM_DBSIG_1) || (hdr.signature2 != PwManager.PWM_DBSIG_2) ) {
    		// #ifdef DEBUG
    			System.out.println ( "Bad database file signature" );
    		// #endif
    		throw new IOException( "Bad database file signature" );
    	}

    	if( hdr.version != PwManager.PWM_DBVER_DW ) {
    		// #ifdef DEBUG
    			System.out.println ( "Bad database file version");
    		// #endif
    		throw new IOException( "Bad database file version" );
    	}

    	newManager = new PwManager();
    	newManager.setMasterKey( password );
    
    	// Select algorithm
    	if( (hdr.flags & PwManager.PWM_FLAG_RIJNDAEL) != 0 ) {
    		// #ifdef DEBUG
    			System.out.println ( "Algorithm AES");
    		// #endif
    		newManager.algorithm = PwManager.ALGO_AES;
    	} else if( (hdr.flags & PwManager.PWM_FLAG_TWOFISH) != 0 ) {
    		// #ifdef DEBUG
    			System.out.println ( "Algorithm TWOFISH");
    		// #endif
    		newManager.algorithm = PwManager.ALGO_TWOFISH;
    	} else {
    		throw new IOException( "Unknown algorithm." );
    	}

    	if( newManager.algorithm == PwManager.ALGO_TWOFISH )
    		throw new IOException( "TwoFish algorithm is not supported" );

    
    	newManager.numKeyEncRounds = hdr.numKeyEncRounds;
		// #ifdef DEBUG
			System.out.println ("rounds = " + newManager.numKeyEncRounds);
		// #endif
    
    	// testRijndael_JCE();

    	newManager.name = "KeePass Password Manager";

    	// Generate transformedMasterKey from masterKey
    	//KeePassMIDlet.logS ("masterSeed2: " + new String(Hex.encode(hdr.masterSeed2)));
    
    	setProgress(10, "Decrypt key");
    	transformedMasterKey = transformMasterKey( hdr.masterSeed2,
                                               newManager.masterKey,
                                               newManager.numKeyEncRounds );
    	// Hash the master password with the salt in the file
    	md = new SHA256Digest();
    	md.update( hdr.masterSeed, 0, hdr.masterSeed.length );
    	md.update( transformedMasterKey, 0, transformedMasterKey.length );
    	finalKey = new byte[md.getDigestSize()];
    	md.doFinal ( finalKey, 0);

    	setProgress(90, "Decrypt database");
    	
    	// NI
    	//KeePassMIDlet.logS ("finalKey: " + new String(Hex.encode(finalKey)));
    
    	// Initialize Rijndael algorithm

    	// Cipher cipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
    	//PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
    	BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
    
    	//cipher.init( Cipher.DECRYPT_MODE, new SecretKeySpec( finalKey, "AES" ), new IvParameterSpec( hdr.encryptionIV ) );

    	cipher.init(false, new ParametersWithIV(new KeyParameter(finalKey), hdr.encryptionIV));
    	// Decrypt! The first bytes aren't encrypted (that's the header)
    	//int encryptedPartSize = cipher.doFinal( filebuf, PwDbHeader.BUF_SIZE, filebuf.length - PwDbHeader.BUF_SIZE, filebuf, PwDbHeader.BUF_SIZE );
    	//int encryptedPartSize
    	int paddedEncryptedPartSize = cipher.processBytes(filebuf, PwDbHeader.BUF_SIZE, filebuf.length - PwDbHeader.BUF_SIZE, filebuf, PwDbHeader.BUF_SIZE );

    	int encryptedPartSize = 0;
    	//try {
    	PKCS7Padding padding = new PKCS7Padding();
    	encryptedPartSize = paddedEncryptedPartSize - padding.padCount(filebuf);
    	//} catch (Exception e) {
    	//}
    	// NI
    	byte[] plainContent = new byte[encryptedPartSize];
    	System.arraycopy(filebuf, PwDbHeader.BUF_SIZE, plainContent, 0, encryptedPartSize);
		// #ifdef DEBUG
			System.out.println ("filebuf length: " + filebuf.length);
		// #endif
    	//System.out.println ("file length: " + filebuf.length);
    	//System.out.println ("plaintext contents length: " + encryptedPartSize);
    	//System.out.println ("plaintext contents:\n" + new String(Hex.encode(plainContent)));
    
    	//if( pRepair == null ) {
    	//md = MessageDigest.getInstance( "SHA-256" );
    	md = new SHA256Digest();
    	md.update( filebuf, PwDbHeader.BUF_SIZE, encryptedPartSize );
    	//      md.update( makePad(filebuf) );
    	md.doFinal (finalKey, 0);
    
    	if( Util.compare( finalKey, hdr.contentsHash ) == false) {
    		//KeePassMIDlet.logS ( "Database file did not decrypt correctly. (checksum code is broken)" );
    		// #ifdef DEBUG
    			System.out.println ("Database file did not decrypt correctly. (checksum code is broken)");
    		// #endif
    		throw new Exception("Wrong Password, or Database File Corrupted (database file did not decrypt correctly)");
    	}
    	// }
    
    	setProgress(95, "Import groups");
    	// Import all groups
		// #ifdef DEBUG
			System.out.println ("Import all groups");
		// #endif
    
    	int pos = PwDbHeader.BUF_SIZE;
    	PwGroup newGrp = new PwGroup();
    	for( int i = 0; i < hdr.numGroups; ) {
    		int fieldType = Types.readShort( filebuf, pos );
    		pos += 2;
    		int fieldSize = Types.readInt( filebuf, pos );
    		pos += 4;

    		if( fieldType == 0xFFFF ) {
    			// #ifdef DEBUG
    				System.out.println ( newGrp.level + " " + newGrp.name );
    			// #endif

    			// End-Group record.  Save group and count it.
    			//newManager.groups.add( newGrp );
    			newManager.addGroup( newGrp );
    			newGrp = new PwGroup();
    			i++;
    		} else {
    			readGroupField( newGrp, fieldType, filebuf, pos );
    		}
    		pos += fieldSize;
    	}

    	//    fixGroups( groups );

    	setProgress(97, "Import entries");
    	// Import all entries
		// #ifdef DEBUG
			System.out.println ("Import all entries");
		// #endif
    	
    	PwEntry newEnt = new PwEntry();
    	for( int i = 0; i < hdr.numEntries; ) {
    		int fieldType = Types.readShort( filebuf, pos );
    		int fieldSize = Types.readInt( filebuf, pos + 2 );

    		if( fieldType == 0xFFFF ) {
    			// End-Group record.  Save group and count it.
    			newManager.addEntry( newEnt );
    			// #ifdef DEBUG
    				System.out.println( newEnt.title );
    			// #endif
    			newEnt = new PwEntry();
    			i++;
    		} else {
    			readEntryField( newEnt, filebuf, pos );
    		}
    		pos += 2 + 4 + fieldSize;
    	}

    	// Keep the Meta-Info entry separate
		// #ifdef DEBUG
			System.out.println ("Keep the Meta-Info entry separate");
		// #endif
    	
    	for( int i=0; i<newManager.entries.size(); i++) {
    		PwEntry ent = (PwEntry)newManager.entries.elementAt(i);
    		if( ent.title.equals( "Meta-Info" )
    				&& ent.url.equals( "$" )
    				&& ent.username.equals( "SYSTEM" ) ) {
    			newManager.metaInfo = ent;
    			newManager.entries.removeElementAt(i);
    		}
    	}

    	setProgress(100, "Done");
		// #ifdef DEBUG
			System.out.println ("Return newManager: " + newManager);
		// #endif
    
    	return newManager;
    }


  /**
   * KeePass's custom pad style.
   * 
   * @param data buffer to pad.
   * @return addtional bytes to append to data[] to make
   *    a properly padded array.
   */
  public static byte[] makePad( byte[] data ) {
    //custom pad method
    //TODO //WRZ doesn't work (yet)

    // append 0x80 plus zeros to a multiple of 4 bytes
    int thisblk = 32 - data.length % 32;  // bytes needed to finish blk
    int nextblk = 0;                      // 32 if we need another block
    // need 9 bytes; add new block if no room
    if( thisblk < 9 ) {
      nextblk = 32;
    }
    
    // all bytes are zeroed for free
    byte[] pad = new byte[ thisblk + nextblk ];
    pad[0] = (byte)0x80;

    // write length*8 to end of final block
    int ix = thisblk + nextblk - 8;
    Types.writeInt( data.length>>29, pad, ix );
    bsw32( pad, ix );
    ix += 4;
    Types.writeInt( data.length<<3, pad, ix );
    bsw32( pad, ix );
    
    return pad;
  }

  public static void bsw32( byte[] ary, int offset ) {
    byte t = ary[offset];
    ary[offset] = ary[offset+3];
    ary[offset+3] = t;
    t = ary[offset+1];
    ary[offset+1] = ary[offset+2];
    ary[offset+2] = t;
  }
  

  /**
   * Encrypt the master key a few times to make brute-force key-search harder
   * @throws NoSuchPaddingException 
   * @throws NoSuchAlgorithmException 
   * @throws ShortBufferException
   */

  	private byte[] transformMasterKey( byte[] pKeySeed, byte[] pKey, int rounds )
      /*throws InvalidKeyException,
	     IllegalBlockSizeException,
	     BadPaddingException,
	     NoSuchAlgorithmException,
	     NoSuchPaddingException, ShortBufferException*/ {
  		// #ifdef DEBUG
  			System.out.println("transformMasterKey, rounds=" + rounds);
  			System.out.println("transformMasterKey, pkey=" + new String(Hex.encode(pKey)));
  		// #endif
	  
  		byte[] newKey = new byte[pKey.length];
  		int i;
      
  		BufferedBlockCipher cipher = new BufferedBlockCipher(new AESEngine());
  		cipher.init(true, new KeyParameter(pKeySeed));

  		int procent = 10; //10% - progress start
  		int step = 5;//% step
  		int roundsByStep = rounds * step / ((90 - procent)); //90% - progress end
  		int count = 0;
  		
  		newKey = pKey;
  		for (i = 0; i < rounds; i++) {
  			cipher.processBytes (newKey, 0, newKey.length, newKey, 0);
  			
  			if (++count == roundsByStep) {
  				count = 0;
  				setProgress(procent += step, null);
  			}
  		}
  		// Hash once with SHA-256
  		SHA256Digest md = new SHA256Digest();
  		md.update(newKey, 0, newKey.length );
  		//newKey = md.digest( newKey );
  		md.doFinal(newKey, 0);

  		return newKey;
  	}




  /**
   * Parse and save one record from binary file.
   * @param buf
   * @param offset
   * @return If >0, 
   */
  void readGroupField( PwGroup grp, int fieldType, byte[] buf, int offset ) throws UnsupportedEncodingException {
    switch( fieldType ) {
      case 0x0000 :
        // Ignore field
        break;
      case 0x0001 :
        grp.groupId = Types.readInt( buf, offset );
        break;
      case 0x0002 :
        grp.name = new String( buf, offset, Types.strlen( buf, offset ), "UTF-8" );
        break;
      case 0x0003 :
        grp.tCreation = Types.readTime( buf, offset );
        break;
      case 0x0004 :
        grp.tLastMod = Types.readTime( buf, offset );
        break;
      case 0x0005 :
        grp.tLastAccess = Types.readTime( buf, offset );
        break;
      case 0x0006 :
        grp.tExpire = Types.readTime( buf, offset );
        break;
      case 0x0007 :
        grp.imageId = Types.readInt( buf, offset );
        break;
      case 0x0008 :
        grp.level = Types.readShort( buf, offset );
        break;
      case 0x0009 :
        grp.flags = Types.readInt( buf, offset );
        break;
    }
  }



  void readEntryField( PwEntry ent, byte[] buf, int offset )
      throws UnsupportedEncodingException
    {
    int fieldType = Types.readShort( buf, offset );
    offset += 2;
    int fieldSize = Types.readInt( buf, offset );
    offset += 4;

    switch( fieldType ) {
      case 0x0000 :
        // Ignore field
        break;
      case 0x0001 :
        System.arraycopy( buf, offset, ent.uuid, 0, 16 );
        break;
      case 0x0002 :
        ent.groupId = Types.readInt( buf, offset );
        break;
      case 0x0003 :
        ent.imageId = Types.readInt( buf, offset );
        break;
      case 0x0004 :
        ent.title = new String( buf, offset, Types.strlen( buf, offset ), "UTF-8" );
        break;
      case 0x0005 :
        ent.url = new String( buf, offset, Types.strlen( buf, offset ), "UTF-8" );
        break;
      case 0x0006 :
        ent.username = new String( buf, offset, Types.strlen( buf, offset ), "UTF-8" );
        break;
      case 0x0007 :
        ent.setPassword( buf, offset, Types.strlen( buf, offset ) );
        break;
      case 0x0008 :
        ent.additional = new String( buf, offset, Types.strlen( buf, offset ), "UTF-8" );
        break;
      case 0x0009 :
        ent.tCreation = Types.readTime( buf, offset );
        break;
      case 0x000A :
        ent.tLastMod = Types.readTime( buf, offset );
        break;
      case 0x000B :
        ent.tLastAccess = Types.readTime( buf, offset );
        break;
      case 0x000C :
        ent.tExpire = Types.readTime( buf, offset );
        break;
      case 0x000D :
        ent.binaryDesc = new String( buf, offset, Types.strlen( buf, offset ), "UTF-8" );
        break;
      case 0x000E :
        ent.setBinaryData( buf, offset, fieldSize );
        break;
    }
  }
  
  
  
  /**
   * Attach groups to parent groups.
   * 
   * @param groups
   * @return root group.
   *//*
  private PwGroup fixGroups( List groups ) {
    int   curLevel = -1;
    Stack parents = new Stack();
    PwGroup root;
    
    root = new PwGroup();
    root.level = curLevel;
    parents.push( root );

    for( Iterator iter = groups.iterator(); iter.hasNext(); ) {
      PwGroup group = (PwGroup)iter.next();

      while( group.level <= curLevel ){
        parents.pop();
        curLevel = ((PwGroup)parents.peek()).level;
      }

      if( group.level >= curLevel ) {
        if( !parents.isEmpty() )
          ((PwGroup)parents.peek()).children.add( group );
        parents.push( group );
        curLevel = group.level;
      }
    }

    return root;
  }*/



  /**
   * Test the BouncyCastle lib.
   */
  /* -- we're not using BouncyCastle
  static void testRijndael_Bouncy() {
    byte[] aKey = new byte[32];
    byte[] aTest = new byte[16];
    byte[] aRef = new byte[16];
    // The Rijndael class will be tested, that's the expected ciphertext
    int[] aRef_int = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
    };
    int i;

    // Do a quick test if the Rijndael class worked correctly
    for( i = 0; i < 32; i++ ) {
      aKey[i] = (byte)i;
    }
    for( i = 0; i < 16; i++ ) {
      aTest[i] = (byte)((i << 4) | i);
      aRef[i] = (byte)aRef_int[i];
    }

    RijndaelEngine rijndael = new RijndaelEngine( 128 );
    rijndael.init( true, new KeyParameter( aKey ) );
    rijndael.processBlock( aTest, 0, aTest, 0 );

    if( !Arrays.equals( aTest, aRef ) )
      throw new RuntimeException( "RijndaelEngine failed test" );
  }
*/


  /**
   * Test Sun's JCE.
   * Note you need the "unlimited security" policy files from Sun.
   * They're where you download the JDK, i.e.
   * <a href="http://java.sun.com/j2se/1.5.0/download.jsp"
   * >http://java.sun.com/j2se/1.5.0/download.jsp</a>
   * @throws NoSuchPaddingException 
   * @throws NoSuchAlgorithmException 
   */
  static void testRijndael_JCE() {
    byte[] aKey = new byte[32];
    byte[] aTest = new byte[16];
    byte[] aRef = new byte[16];
    // The Rijndael class will be tested, that's the expected ciphertext
    int[] aRef_int = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
    };
    int i;

    // Do a quick test if the Rijndael class worked correctly
    for( i = 0; i < 32; i++ ) {
      aKey[i] = (byte)i;
    }
    for( i = 0; i < 16; i++ ) {
      aTest[i] = (byte)((i << 4) | i);
      aRef[i] = (byte)aRef_int[i];
    }

    try {
	// Cipher cipher = Cipher.getInstance( "AES/ECB/NoPadding" );
	BufferedBlockCipher cipher = new BufferedBlockCipher(new AESEngine());
	//cipher.init( Cipher.ENCRYPT_MODE, new SecretKeySpec( aKey, "AES" ) );
	cipher.init(true, new KeyParameter(aKey));
	//aTest = cipher.doFinal( aTest );
	cipher.processBytes(aTest, 0, aTest.length, aTest, 0);
    }
    catch (Exception ex) {
	ex.printStackTrace();
	throw new RuntimeException( "JCE failed test" );
    }

    if( Util.compare (aTest, aRef) == false)
	throw new RuntimeException( "JCE failed test" );
  }
}
    


/*
NIST.gov states the following:

Suppose that the length of the message, M, is l bits. Append the bit 1 to the end of the
message, followed by k zero bits, where k is the smallest, non-negative solution to the equation
l +1+ k º 448mod 512 . Then append the 64-bit block that is equal to the number l expressed
using a binary representation. For example, the (8-bit ASCII) message abc has length
8´3 = 24, so the message is padded with a one bit, then 448 - (24 +1) = 423 zero bits, and then
the message length, to become the 512-bit padded message

                              423     64
01100001 01100010 01100011 1 0000 00011000
  a      b      c               l = 24

The length of the padded message should now be a multiple of 512 bits.
*/
