
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class Crypto {

	public static final String CIPHER_NAME = "AES";
	public static final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";
	public static final String RNG = "SHA1PRNG";
	public static final String MD = "SHA-1";
	public static final String MAC = "HmacSHA1";

	public static final String HEX_CHARS = "0123456789abcdef";
	public static final char[] HEX_BYTES = HEX_CHARS.toCharArray();
	public static final String MODHEX_CHARS = "cbdefghijklnrtuv";
	public static final char[] MODHEX_BYTES = MODHEX_CHARS.toCharArray();

	public boolean compare(byte[] first, byte[] second) {
		return java.util.Arrays.equals(first, second);
	}
		
	public byte[] concat(byte[] first, byte[] second) {
		byte[] result = java.util.Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}

	public byte[] dec(byte[] data, byte[] keyData, byte[] ivData) throws NoSuchAlgorithmException, NoSuchPaddingException {
		try {
			Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
			final IvParameterSpec iv = new IvParameterSpec(ivData);
			SecretKey key = new SecretKeySpec(keyData, CIPHER_NAME);
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] dehex(String data) {
		byte[] res = new byte[data.length() / 2];
		for (int i = 0; i < res.length; i++) {
			res[i] = (byte) Integer.parseInt(data.substring(2*i, 2*i+2), 16);
		}
		return res;
	}

	public byte[] derive(byte[] input, byte[] salt, Integer count, Integer iterations) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(MD);
			byte[] keyMaterial = new byte[md.getDigestLength() * iterations];
			
			byte[] data00 = concat(input, salt); 

			byte[] result = null;
			byte[] hashtarget = new byte[md.getDigestLength() + data00.length];
			
			for (int j = 0; j < iterations; j++) {
				if (j == 0) {
					result = data00;
				} else {
					hashtarget = concat(result, data00);
					result = hashtarget;
				}
				for(int i = 0; i < count; i++)
					result = md.digest(result);
				System.arraycopy(result, 0, keyMaterial, j * md.getDigestLength(), result.length);
			}
			return keyMaterial;
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public byte[] enc(byte[] data, byte[]keyData, byte[] ivData) throws NoSuchAlgorithmException, NoSuchPaddingException {
		try {
			Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
			final IvParameterSpec iv = new IvParameterSpec(ivData);
			SecretKey key = new SecretKeySpec(keyData, CIPHER_NAME);
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public String hex(byte data[]) {
		char[] res = new char[2 * data.length];
		for (int i = 0; i < data.length; ++i)
		{
			res[2 * i] = HEX_BYTES[(data[i] & 0xF0) >>> 4];
			res[2 * i + 1] = HEX_BYTES[data[i] & 0x0F];
		}
		return new String(res).toUpperCase();
	}

	public void inc(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            ++counter[i];
            if (counter[i] != 0) break; //Check whether we need to loop again to carry the one.
        }
    }
	
	public byte[] mac(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance(MAC);
		mac.init(new SecretKeySpec(key, "RAW"));
		return mac.doFinal(data);
	}
		
	public byte[] md(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(MD);
		return md.digest(data);
	}

	public byte[] modehex(String data) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int len = data.length();

		boolean toggle = false;
		int keep = 0;

		for (int i = 0; i < len; i++) {
			char ch = data.charAt(i);
			int n = MODHEX_CHARS.indexOf(Character.toLowerCase(ch));
			if (n == -1) {
				throw new 
				IllegalArgumentException(data + " is not properly encoded");
			}

			toggle = !toggle;

			if (toggle) {
				keep = n;
			} else {
				baos.write((keep << 4) | n);
			}
		}
		return baos.toByteArray();
}

	public String modhex(byte[] data) {
		StringBuffer result = new StringBuffer();

		for (int i = 0; i < data.length; i++) {
			result.append(MODHEX_BYTES[(data[i] >> 4) & 0xf]);
			result.append(MODHEX_BYTES[data[i] & 0xf]);
		}

		return result.toString();
	}

	public void rng(byte[] bytes) throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance(RNG);
		sr.nextBytes(bytes);
	}
		
}
