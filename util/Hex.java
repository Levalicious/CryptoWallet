package util;

public class Hex {
    private static final char[] DIGITS = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    public static String getHex(byte[] data) {
        final int l = data.length;
        final char[] outData = new char[l << 1];
        for(int i = 0, j=0; i < l; i++) {
            outData[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
            outData[j++] = DIGITS[(0x0F & data[i])];
        }

        return new String(outData);
    }

    public static byte[] fromHex(String s) {
        if(s.substring(0,2).equals("0x")) {
            s = s.substring(2,s.length());
        }
        if(s.length() % 2 != 0) {
            s = "0" + s;
        }

        return org.bouncycastle.util.encoders.Hex.decode(s);
    }

    public static String getReverseHex(byte[] data) {
        return getHex(reverse(data));
    }

    private static byte[] reverse(byte[] data) {
        int i = 0;
        int j = data.length - 1;
        byte tmp;

        while(j > i) {
            tmp = data[j];
            data[j] = data[i];
            data[i] = tmp;
            j--;
            i++;
        }

        return data;
    }
}