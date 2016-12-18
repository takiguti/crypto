/*
** Test AES
*/

import	javax.crypto.*;
import	javax.crypto.spec.*;
import	javax.crypto.interfaces.*;

public class AES {
    byte[] keyBytes;
    byte[] ivBytes;

    public static void main( String[] args ) {
        String KEY = "1234567890123456";
        String IV = "abcdefghijklmnop";

        try {
            AES aes = new AES( KEY.getBytes("UTF-8"), IV.getBytes("UTF-8") );

            byte[] ecnryptedBytes = aes.encrypt(args[0].getBytes());

            System.out.println(toHexString(ecnryptedBytes));

            byte[] plainBytes = aes.decrypt(ecnryptedBytes);
            System.out.println(toHexString(plainBytes));
        }
        catch( Exception e) {
			e.printStackTrace();
        }
    }

    AES(byte[] key, byte[] iv) {
        keyBytes = key;
        ivBytes = iv;
    }

    byte[] encrypt( byte[] plainTextBytes ) throws Exception {

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        int plainTextBytesLen = plainTextBytes.length;

        byte[] w = new byte[16];
        System.arraycopy( plainTextBytes, 0, w, 0, plainTextBytesLen);


        byte[] resultBytes = cipher.doFinal(w);

        // パディングを無視して、元データサイズにカットする
        byte[] b = new byte[plainTextBytesLen];
        System.arraycopy(resultBytes, 0, b, 0, plainTextBytesLen);

        return( b );
    }


    byte[] decrypt( byte[] cipherTextBytes )  throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] b = new byte[16];
        int cipherTextBytesLen = cipherTextBytes.length;
        System.arraycopy(cipherTextBytes, 0, b, 0, cipherTextBytesLen);

        byte[] resultBytes = cipher.doFinal(b);

        return( resultBytes );
    }

	/**
	 * バイナリデータを16進表記の文字列に変換する。
	 */
	static String toHexString( byte[] d ) {
		String str = "";

		for( int i = 0 ; i < d.length ; i++ ) {

			int r = (d[i] >= 0 ? d[i] : 256 + d[i] );
			if( r < 0x10 ) {
				str += "0";
			}
			str += Integer.toHexString(r).toUpperCase();

			if( i != 0 && ( i + 1 ) % 16 == 0 ) {
				str += "\n";
			}
			else {
				str += " ";
			}
		}

		return( str );
	}
}
