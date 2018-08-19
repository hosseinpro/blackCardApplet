package blackCardApplet;

import javacard.framework.*;

public class TX2 {

	public static final byte BYTE_SIZE = 1;
	public static final byte INT32_SIZE = 4;
	public static final byte HASH_SIZE = 32;
	public static final byte SCRIPT_SIZE = 26;
	public static final byte INT64_SIZE = 8;

	public short version;
	public byte inputCount;
	public short[] inputPreTxHash;
	public short[] inputUTXOindex;
	public short[] inputScript;
	public short[] inputSequence;
	public short outputCount;
	public short spendValue;
	public short spendScript;
	public short changeValue;
	public short changeScript;
	public short lockTime;
	public short unknown;

	public TX2() {
	}

	public void decode(byte[] buf, short bufOffset) {
		short offset = bufOffset;
		version = offset;
		offset += INT32_SIZE;
		inputCount = buf[offset];
		offset += BYTE_SIZE;

		inputPreTxHash = JCSystem.makeTransientShortArray((short) inputCount, JCSystem.CLEAR_ON_DESELECT);
		inputUTXOindex = JCSystem.makeTransientShortArray((short) inputCount, JCSystem.CLEAR_ON_DESELECT);
		inputScript = JCSystem.makeTransientShortArray((short) inputCount, JCSystem.CLEAR_ON_DESELECT);
		inputSequence = JCSystem.makeTransientShortArray((short) inputCount, JCSystem.CLEAR_ON_DESELECT);

		for (short i = 0; i < inputCount; i++) {
			inputPreTxHash[i] = offset;
			offset += HASH_SIZE;
			inputUTXOindex[i] = offset;
			offset += INT32_SIZE;
			inputScript[i] = offset;
			offset += SCRIPT_SIZE;
			inputSequence[i] = offset;
			offset += INT32_SIZE;
		}

		outputCount = offset;
		offset += BYTE_SIZE;
		spendValue = offset;
		offset += INT64_SIZE;
		spendScript = offset;
		offset += SCRIPT_SIZE;
		changeValue = offset;
		offset += INT64_SIZE;
		changeScript = offset;
		offset += SCRIPT_SIZE;
		lockTime = offset;
		offset += INT32_SIZE;
		unknown = offset;
		offset += INT32_SIZE;
	}
}
