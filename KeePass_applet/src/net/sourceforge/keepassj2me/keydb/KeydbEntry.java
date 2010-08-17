package net.sourceforge.keepassj2me.keydb;

import java.util.Date;

import net.sourceforge.keepassj2me.importerv3.Types;

/**
 * KDB Entry
 * @author Stepan Strelets
 */
public class KeydbEntry {
	public final static short FIELD_IGNORE 		= 0x0000; //Invalid or comment block, block is ignored
	public final static short FIELD_UUID 		= 0x0001; //UUID, uniquely identifying an entry, FIELDSIZE must be 16
	public final static short FIELD_GID 		= 0x0002; //Group ID, identifying the group of the entry, FIELDSIZE = 4
														  //It can be any 32-bit value except 0 and 0xFFFFFFFF
	public final static short FIELD_IMAGE 		= 0x0003; //Image ID, identifying the image/icon of the entry, FIELDSIZE = 4
	public final static short FIELD_TITLE 		= 0x0004; //Title of the entry, FIELDDATA is an UTF-8 encoded string
	public final static short FIELD_URL 		= 0x0005; //URL string, FIELDDATA is an UTF-8 encoded string
	public final static short FIELD_USER 		= 0x0006; //UserName string, FIELDDATA is an UTF-8 encoded string
	public final static short FIELD_PASSWORD 	= 0x0007; //Password string, FIELDDATA is an UTF-8 encoded string
	public final static short FIELD_NOTE 		= 0x0008; //Notes string, FIELDDATA is an UTF-8 encoded string
	public final static short FIELD_CTIME 		= 0x0009; //Creation time, FIELDSIZE = 5, FIELDDATA = packed date/time
	public final static short FIELD_MTIME 		= 0x000A; //Last modification time, FIELDSIZE = 5, FIELDDATA = packed date/time
	public final static short FIELD_ATIME 		= 0x000B; //Last access time, FIELDSIZE = 5, FIELDDATA = packed date/time
	public final static short FIELD_EXPIRE 		= 0x000C; //Expiration time, FIELDSIZE = 5, FIELDDATA = packed date/time
	public final static short FIELD_BINDESC 	= 0x000D; //Binary description UTF-8 encoded string
	public final static short FIELD_BINDATA 	= 0x000E; //Binary data
	public final static short FIELD_TERMINATOR	= (short)0xFFFF; //Entry terminator, FIELDSIZE must be 0

	public int offset;
	
	public int uuidOffset;
	public int groupId;
	public int imageIndex;
	public String title;
	public int urlOffset;
	public int usernameOffset;
	public int passwordOffset;
	public int noteOffset;
	public int ctimeOffset;
	public int mtimeOffset;
	public int atimeOffset;
	public int expireOffset;
	public int binaryDescOffset;
	public int binaryDataOffset;
	public int binaryDataLength;
	
	public KeydbEntry() {
		clean();
	}
	
	/**
	 * Reset all fields
	 */
	public void clean() {
		offset = -1;
		uuidOffset = -1;
		groupId = 0;
		imageIndex = 0;
		title = null;
		urlOffset = -1;
		usernameOffset = -1;
		passwordOffset = -1;
		noteOffset = -1;
		ctimeOffset = -1;
		mtimeOffset = -1;
		atimeOffset = -1;
		expireOffset = -1;
		binaryDescOffset = -1;
		binaryDataOffset = -1;
		binaryDataLength = 0;
	}
	
	/**
	 * Read entry data from buffer
	 * @param buf
	 * @param offset
	 * @return bytes readed
	 */
	protected int read(byte[] buf, int offset) {
		this.offset = offset;
		short fieldType;
		int fieldSize;
		while(true) {
			fieldType = (short)Types.readShort(buf, offset);
			offset += 2;
			fieldSize = Types.readInt(buf, offset);
			offset += 4;

			switch (fieldType) {
			case FIELD_IGNORE:
				// Ignore field
				break;
			case FIELD_UUID:
				uuidOffset = offset;
				break;
			case FIELD_GID:
				groupId = Types.readInt(buf, offset);
				break;
			case FIELD_IMAGE:
				imageIndex = Types.readInt(buf, offset);
				break;
			case FIELD_TITLE:
				title = KeydbUtil.getString(buf, offset);
				break;
			case FIELD_URL:
				urlOffset = offset;
				break;
			case FIELD_USER:
				usernameOffset = offset;
				break;
			case FIELD_PASSWORD:
				passwordOffset = offset;
				break;
			case FIELD_NOTE:
				noteOffset = offset;
				break;
			case FIELD_CTIME:
				ctimeOffset = offset;
				break;
			case FIELD_MTIME:
				mtimeOffset = offset;
				break;
			case FIELD_ATIME:
				atimeOffset = offset;
				break;
			case FIELD_EXPIRE:
				expireOffset = offset;
				break;
			case FIELD_BINDESC:
				binaryDescOffset = offset;
				break;
			case FIELD_BINDATA:
				binaryDataOffset = offset;
				binaryDataLength = fieldSize;
				break;
			case FIELD_TERMINATOR:
				return offset - this.offset;
			}
			offset += fieldSize;
		}
	}
	
	public byte[] getUUID(byte[] buf) {
		byte uuid[] = new byte[16];
		System.arraycopy(buf, uuidOffset, uuid, 0, 16);
		return uuid;
	}
	public String getUrl(KeydbDatabase db) {
		return KeydbUtil.getString(db.plainContent, urlOffset);
	}
	public String getUsername(KeydbDatabase db) {
		return KeydbUtil.getString(db.plainContent, usernameOffset);
	}
	public String getNote(KeydbDatabase db) {
		return KeydbUtil.getString(db.plainContent, noteOffset);
	}
	public Date getCTime(KeydbDatabase db) {
		return KeydbUtil.getDate(db.plainContent, ctimeOffset);
	}
	public Date getMTime(KeydbDatabase db) {
		return KeydbUtil.getDate(db.plainContent, mtimeOffset);
	}
	public Date getATime(KeydbDatabase db) {
		return KeydbUtil.getDate(db.plainContent, atimeOffset);
	}
	public Date getExpire(KeydbDatabase db) {
		return KeydbUtil.getDate(db.plainContent, expireOffset);
	}
	public String getBinaryDesc(KeydbDatabase db) {
		return KeydbUtil.getString(db.plainContent, binaryDescOffset);
	}
	public byte[] getBinaryData(KeydbDatabase db) {
		return KeydbUtil.getBinary(db.plainContent, binaryDataOffset, binaryDataLength);
	}
	public byte[] getPasswordBin(KeydbDatabase db) {
		return KeydbUtil.getBinary(db.plainContent, passwordOffset, Types.strlen(db.plainContent, passwordOffset));
	}
	public String getPassword(KeydbDatabase db) {
		return KeydbUtil.getString(db.plainContent, passwordOffset);
	}
}
