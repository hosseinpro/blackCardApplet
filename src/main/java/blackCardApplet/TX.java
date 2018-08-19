package blackCardApplet;

// import javacard.framework.*;

public class TX {

	/*
	 * private static byte[] version;// = new byte[]{(byte)0x01, (byte)0x00,
	 * (byte)0x00, (byte)0x00}; private static byte[] inputCount;
	 * 
	 * private static byte[] input1preTxHash; private static byte[] input1UTXOindex;
	 * private static byte[] input1Script; private static byte[] input1Sequence;
	 * 
	 * private static byte[] input2preTxHash; private static byte[] input2UTXOindex;
	 * private static byte[] input2Script; private static byte[] input2Sequence;
	 * 
	 * private static byte[] input3preTxHash; private static byte[] input3UTXOindex;
	 * private static byte[] input3Script; private static byte[] input3Sequence;
	 * 
	 * private static byte[] input4preTxHash; private static byte[] input4UTXOindex;
	 * private static byte[] input4Script; private static byte[] input4Sequence;
	 * 
	 * private static byte[] input5preTxHash; private static byte[] input5UTXOindex;
	 * private static byte[] input5Script; private static byte[] input5Sequence;
	 * 
	 * //private static byte[] inputSequence = new byte[]{(byte)0xFF, (byte)0xFF,
	 * (byte)0xFF, (byte)0xFF};
	 * 
	 * private static byte[] outputCount;// = new byte[]{(byte)0x02}; private static
	 * byte[] spendValue; private static byte[] spendScript; private static byte[]
	 * changeValue; private static byte[] changeScript;
	 * 
	 * private static byte[] lockTime;// = new byte[]{(byte)0x00, (byte)0x00,
	 * (byte)0x00, (byte)0x00}; private static byte[] unknown;// = new
	 * byte[]{(byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00};
	 * 
	 * public TX() {
	 * 
	 * version = JCSystem.makeTransientByteArray((short)4,
	 * JCSystem.CLEAR_ON_RESET);//new byte[4]; inputCount =
	 * JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET);//new
	 * byte[1];
	 * 
	 * input1preTxHash = JCSystem.makeTransientByteArray((short)32,
	 * JCSystem.CLEAR_ON_RESET);//new byte[32]; input1UTXOindex =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4]; input1Script = JCSystem.makeTransientByteArray((short)26,
	 * JCSystem.CLEAR_ON_RESET);//new byte[26];//1976a914
	 * xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 88ac input1Sequence =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4];
	 * 
	 * input2preTxHash = JCSystem.makeTransientByteArray((short)32,
	 * JCSystem.CLEAR_ON_RESET);//new byte[32]; input2UTXOindex =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4]; input2Script = JCSystem.makeTransientByteArray((short)26,
	 * JCSystem.CLEAR_ON_RESET);//new byte[26]; input2Sequence =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4];
	 * 
	 * input3preTxHash = JCSystem.makeTransientByteArray((short)32,
	 * JCSystem.CLEAR_ON_RESET);//new byte[32]; input3UTXOindex =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4]; input3Script = JCSystem.makeTransientByteArray((short)26,
	 * JCSystem.CLEAR_ON_RESET);//new byte[26]; input3Sequence =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4];
	 * 
	 * input4preTxHash = JCSystem.makeTransientByteArray((short)32,
	 * JCSystem.CLEAR_ON_RESET);//new byte[32]; input4UTXOindex =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4]; input4Script = JCSystem.makeTransientByteArray((short)26,
	 * JCSystem.CLEAR_ON_RESET);//new byte[26]; input4Sequence =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4];
	 * 
	 * input5preTxHash = JCSystem.makeTransientByteArray((short)32,
	 * JCSystem.CLEAR_ON_RESET);//new byte[32]; input5UTXOindex =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4]; input5Script = JCSystem.makeTransientByteArray((short)26,
	 * JCSystem.CLEAR_ON_RESET);//new byte[26]; input5Sequence =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4];
	 * 
	 * outputCount = JCSystem.makeTransientByteArray((short)1,
	 * JCSystem.CLEAR_ON_RESET);//new byte[1]; spendValue =
	 * JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);//new
	 * byte[8]; spendScript = JCSystem.makeTransientByteArray((short)26,
	 * JCSystem.CLEAR_ON_RESET);//new byte[26]; changeValue =
	 * JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);//new
	 * byte[8]; changeScript = JCSystem.makeTransientByteArray((short)26,
	 * JCSystem.CLEAR_ON_RESET);//new byte[26];
	 * 
	 * lockTime = JCSystem.makeTransientByteArray((short)4,
	 * JCSystem.CLEAR_ON_RESET);//new byte[4]; unknown =
	 * JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);//new
	 * byte[4];
	 * 
	 * }
	 * 
	 * public static boolean decode(byte[] buf, short bufOffset) {
	 * Util.arrayCopyNonAtomic(buf, bufOffset, version, (short)0, (short)4);
	 * bufOffset += 4; Util.arrayCopyNonAtomic(buf, bufOffset, inputCount, (short)0,
	 * (short)1); bufOffset += 1; short sInputCount = inputCount[0]; if(sInputCount
	 * > 5){ return false;} if(sInputCount >=1){ Util.arrayCopyNonAtomic(buf,
	 * bufOffset, input1preTxHash, (short)0, (short)32); bufOffset += 32;
	 * Util.arrayCopyNonAtomic(buf, bufOffset, input1UTXOindex, (short)0, (short)4);
	 * bufOffset += 4; Util.arrayCopyNonAtomic(buf, bufOffset, input1Script,
	 * (short)0, (short)26); bufOffset += 26; Util.arrayCopyNonAtomic(buf,
	 * bufOffset, input1Sequence, (short)0, (short)4); bufOffset += 4; }
	 * if(sInputCount >=2){ Util.arrayCopyNonAtomic(buf, bufOffset, input2preTxHash,
	 * (short)0, (short)32); bufOffset += 32; Util.arrayCopyNonAtomic(buf,
	 * bufOffset, input2UTXOindex, (short)0, (short)4); bufOffset += 4;
	 * Util.arrayCopyNonAtomic(buf, bufOffset, input2Script, (short)0, (short)26);
	 * bufOffset += 26; Util.arrayCopyNonAtomic(buf, bufOffset, input2Sequence,
	 * (short)0, (short)4); bufOffset += 4; } if(sInputCount >=3){
	 * Util.arrayCopyNonAtomic(buf, bufOffset, input3preTxHash, (short)0,
	 * (short)32); bufOffset += 32; Util.arrayCopyNonAtomic(buf, bufOffset,
	 * input3UTXOindex, (short)0, (short)4); bufOffset += 4;
	 * Util.arrayCopyNonAtomic(buf, bufOffset, input3Script, (short)0, (short)26);
	 * bufOffset += 26; Util.arrayCopyNonAtomic(buf, bufOffset, input3Sequence,
	 * (short)0, (short)4); bufOffset += 4; } if(sInputCount >=4){
	 * Util.arrayCopyNonAtomic(buf, bufOffset, input4preTxHash, (short)0,
	 * (short)32); bufOffset += 32; Util.arrayCopyNonAtomic(buf, bufOffset,
	 * input4UTXOindex, (short)0, (short)4); bufOffset += 4;
	 * Util.arrayCopyNonAtomic(buf, bufOffset, input4Script, (short)0, (short)26);
	 * bufOffset += 26; Util.arrayCopyNonAtomic(buf, bufOffset, input4Sequence,
	 * (short)0, (short)4); bufOffset += 4; } if(sInputCount >=5){
	 * Util.arrayCopyNonAtomic(buf, bufOffset, input5preTxHash, (short)0,
	 * (short)32); bufOffset += 32; Util.arrayCopyNonAtomic(buf, bufOffset,
	 * input5UTXOindex, (short)0, (short)4); bufOffset += 4;
	 * Util.arrayCopyNonAtomic(buf, bufOffset, input5Script, (short)0, (short)26);
	 * bufOffset += 26; Util.arrayCopyNonAtomic(buf, bufOffset, input5Sequence,
	 * (short)0, (short)4); bufOffset += 4; } Util.arrayCopyNonAtomic(buf,
	 * bufOffset, outputCount, (short)0, (short)1); bufOffset += 1;
	 * Util.arrayCopyNonAtomic(buf, bufOffset, spendValue, (short)0, (short)8);
	 * bufOffset += 8; Util.arrayCopyNonAtomic(buf, bufOffset, spendScript,
	 * (short)0, (short)26); bufOffset += 26; Util.arrayCopyNonAtomic(buf,
	 * bufOffset, changeValue, (short)0, (short)8); bufOffset += 8;
	 * Util.arrayCopyNonAtomic(buf, bufOffset, changeScript, (short)0, (short)26);
	 * bufOffset += 26; Util.arrayCopyNonAtomic(buf, bufOffset, lockTime, (short)0,
	 * (short)4); bufOffset += 4; Util.arrayCopyNonAtomic(buf, bufOffset, unknown,
	 * (short)0, (short)4); bufOffset += 4; return true; }
	 */

}
