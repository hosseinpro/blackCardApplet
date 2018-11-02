package blackCardApplet;

class MathMod256 {

    /**
     * c = a+b mod n
     *
     * a,b,n 256 unsigned bits value precondition: 0 <= a < n 0 <= b < n n > 0 c
     * shall either NOT partially overlap a or b, or shall be a or b
     *
     */
    public static void addm(byte[] c, short c_off, byte[] a, short a_off, byte[] b, short b_off, byte[] n,
            short n_off) {
        if ((add(c, c_off, a, a_off, b, b_off) != 0) || (ucmp(c, c_off, n, n_off) > 0)) {
            sub(c, c_off, c, c_off, n, n_off);
        }
    }

    /**
     * unsigned compare a and b return 0 if a == b return < 0 if a < b return > 0 if
     * a > b
     */
    public static short ucmp(byte[] a, short a_off, byte[] b, short b_off) {
        short ai, bi;
        for (short i = 0; i < 32; i++) {
            ai = (short) (a[(short) (a_off + i)] & 0x00ff);
            bi = (short) (b[(short) (b_off + i)] & 0x00ff);
            if (ai != bi) {
                return (short) (ai - bi);
            }
        }
        return 0;
    }

    protected static short add(byte[] c, short c_off, byte[] a, short a_off, byte[] b, short b_off) {

        short ci = 0;
        for (short i = 31; i >= 0; i--) {
            ci = (short) ((short) (a[(short) (a_off + i)] & 0x00FF) + (short) (b[(short) (b_off + i)] & 0xFF) + ci);
            c[(short) (c_off + i)] = (byte) ci;
            ci = (short) (ci >> 8);
        }
        return ci;
    }

    protected static short sub(byte[] c, short c_off, byte[] a, short a_off, byte[] b, short b_off) {
        short ci = 0;
        for (short i = 31; i >= 0; i--) {
            ci = (short) ((short) (a[(short) (a_off + i)] & 0xFF) - (short) (b[(short) (b_off + i)] & 0xFF) - ci);
            c[(short) (c_off + i)] = (byte) ci;
            ci = (short) (((ci >> 8) != 0) ? 1 : 0);
        }
        return ci;
    }

    protected static short sub(byte[] c, short c_off, byte[] a, short a_off, byte[] b, short b_off, short length) {
        short ci = 0;
        for (short i = (short) (length - 1); i >= 0; i--) {
            ci = (short) ((short) (a[(short) (a_off + i)] & 0xFF) - (short) (b[(short) (b_off + i)] & 0xFF) - ci);
            c[(short) (c_off + i)] = (byte) ci;
            ci = (short) (((ci >> 8) != 0) ? 1 : 0);
        }
        return ci;
    }

}