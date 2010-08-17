package net.sourceforge.keepassj2me.keydb;

import java.util.Date;

import net.sourceforge.keepassj2me.importerv3.Types;

/**
 * KDB Group
 * @author Stepan Strelets
 */
public class KeydbGroup {
	public final static short FIELD_IGNORE		= 0x0000; //Invalid or comment block, block is ignored
	public final static short FIELD_ID			= 0x0001; //Group ID, FIELDSIZE must be 4 bytes
														  //It can be any 32-bit value except 0 and 0xFFFFFFFF
	public final static short FIELD_NAME		= 0x0002; //Group name, FIELDDATA is an UTF-8 encoded string
	public final static short FIELD_CTIME		= 0x0003; //Creation time, FIELDSIZE = 5, FIELDDATA = packed date/time
	public final static short FIELD_MTIME		= 0x0004; //Last modification time, FIELDSIZE = 5, FIELDDATA = packed date/time
	public final static short FIELD_ATIME		= 0x0005; //Last access time, FIELDSIZE = 5, FIELDDATA = packed date/time
	public final static short FIELD_EXPIRE		= 0x0006; //Expiration time, FIELDSIZE = 5, FIELDDATA = packed date/time
	public final static short FIELD_IMAGE		= 0x0007; //Image ID, FIELDSIZE must be 4 bytes
	public final static short FIELD_LEVEL		= 0x0008; //Level, FIELDSIZE = 2
	public final static short FIELD_FLAGS		= 0x0009; //Flags, 32-bit value, FIELDSIZE = 4
	public final static short FIELD_TERMINATOR	= (short)0xFFFF; //Group entry terminator, FIELDSIZE must be 0

	public int offset;
	
	public int id;
	public int imageIndex;
	public String name;
	public int ctimeOffset;
	public int mtimeOffset;
	public int atimeOffset;
	public int expireOffset;
	public int level;       //short
	/** Used by KeePass internally, don't use */
	public int flags;

	public KeydbGroup() {
		clean();
	}
	
	public void clean() {
		offset = 0;
		id = 0;
		imageIndex = 0;
		name = null;
		ctimeOffset = -1;
		mtimeOffset = -1;
		atimeOffset = -1;
		expireOffset = -1;
		level = 0;
		flags = 0;
	}
	
	/**
	 * Read group data from buffer
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
			case FIELD_ID:
				id = Types.readInt(buf, offset);
				break;
			case FIELD_NAME:
				name = KeydbUtil.getString(buf, offset);
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
			case FIELD_IMAGE:
				imageIndex = Types.readInt(buf, offset);
				break;
			case FIELD_LEVEL:
				level = Types.readShort(buf, offset);
				break;
			case FIELD_FLAGS:
				flags = Types.readInt(buf, offset);
				break;
			case FIELD_TERMINATOR:
				return offset - this.offset;
			}
			offset += fieldSize;
		}
	}
	
	public Date getCTime(byte[] buf) {
		return KeydbUtil.getDate(buf, ctimeOffset);
	}
	public Date getMTime(byte[] buf) {
		return KeydbUtil.getDate(buf, mtimeOffset);
	}
	public Date getATime(byte[] buf) {
		return KeydbUtil.getDate(buf, atimeOffset);
	}
	public Date getExpire(byte[] buf) {
		return KeydbUtil.getDate(buf, expireOffset);
	}
}
