
public class Bob extends Crypto {

	byte[] counter = new byte[16]; // 128-bit counter.

	byte[] randomC = new byte[20];
	byte[] randomD = new byte[20];
	byte[] randomY = new byte[20];

	byte[] key = new byte[20]; // Encrypted Master Key
	byte[] salt = new byte[20];
	byte[] sequence = new byte[20]; // Sequence Key
	byte[] token;
	
	// TEMPORARY
	String password;
	byte[] otp = new byte[20];
	byte[] master = new byte[20];
	byte[] hmac;
	byte[] dkey;
	byte[] K = new byte[16];
	byte[] iv = new byte[16];
	byte[] alice = new byte[20];
	byte[] T;

	public Bob() {
		this("");
	}
	public Bob(String data) {
		super();
		fromString(data);
	}

	public void clear() {
		password = null;
		counter = new byte[16];
		randomC = null;
		randomD = null;
		randomY = null;
		otp = null;
		master = null;
		hmac = null;
		dkey = null;
		K = new byte[16];
		iv = new byte[16];
		alice = null;
		T = null;
	}

	public void fromString(String data) {
		String[] parts = data.split("\\|");
		if (parts.length == 5) {
			counter = dehex(parts[0]);
			key = dehex(parts[1]);
			salt = dehex(parts[2]);
			sequence = dehex(parts[3]);
			token = dehex(parts[4]);
			
			randomC = null;
			randomD = null;
			randomY = null;
			password = null;
			otp = new byte[20];
			master = new byte[20];
			hmac = null;
			dkey = null;
			K = new byte[16];
			iv = new byte[16];
			alice = new byte[20];
			T = null;
		}
	}
	
	@Override
	public String toString() {
		return hex(counter) + "|" + hex(key) + "|" + hex(salt) + "|" + hex(sequence) + "|" + hex(token);
	}
	
	
}
