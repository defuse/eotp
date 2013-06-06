package nl.coolview.java.app;

public class Alice extends Crypto {

	String password;

	byte[] counter = new byte[16]; // 128-bit counter.
	
	byte[] randomA = new byte[20];
	byte[] randomB = new byte[20];
	byte[] randomX = new byte[20];
	
	byte[] key = new byte[20]; // Static Key
	byte[] salt = new byte[20];
	byte[] sequence = new byte[20];
	
	//TEMPORARY
	byte[] otp = new byte[20];
	
	public Alice() {
		this("");
	}
	public Alice(String data) {
		super();
		fromString(data);
	}
	
	public void clear() {
		counter = new byte[16];
		randomA = null;
		randomB = null;
		randomX = null;
		otp = null;
	}

	public void fromString(String data) {
		String[] parts = data.split("\\|");
		if (parts.length == 5) {
			counter = dehex(parts[0]);
			key = dehex(parts[1]);
			salt = dehex(parts[2]);
			sequence = dehex(parts[3]);
			password = parts[4];
			randomA = null;
			randomB = null;
			randomX = null;
			otp = new byte[20];
		}
	}

	@Override
	public String toString() {
		return hex(counter) + "|" + hex(key) + "|" + hex(salt) + "|" + hex(sequence) + "|" + password;
	}
	
}