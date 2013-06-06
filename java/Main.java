package nl.coolview.java.app;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

public class Main {

	//------------------------------------------------------------------------------------------------------------------------

	/**
	 * The communication routine for E-OTP between Alice and Bob.<br />
	 * This routine assumes an insecure communication layer between parties.<br />
	 * <ol>
	 * <li>Alice identifies herself to Bob</li>
	 * <li>Bob responds with the current counter value for her record</li>
	 * <li>Alice repeatedly computes sequence = HMAC(sequence, counter || salt), until her counter matches Bob's</li>
	 * <li>Alice computes otp = sequence XOR her key and sends her password and otp to Bob</li>
	 * <li>Bob obtains Alice's key = otp XOR sequence</li>
	 * <li>Bob computes auth = HMAC(Alice's key || salt, <Alice's Password> || salt)</li>
	 * <li>Bob verifies if auth matches token, and stops if it doesn't</li>
	 * <li>Bob obtains his key by decrypting Cb with key = HMAC(Alice's Key, Alice's password)</li>
	 * <li>Bob computes sequence  = HMAC(sequence, counter || salt) and increments his counter</li>
	 * <li>Bob saves the counter and sequence, and destroys Alice's key and previous sequence</li>
	 * <li>Bob can now use his key and decrypt Alice's data, destroying the key when done</li>
	 * </ol>
	 * @param Alice
	 * @param Bob
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static void communicateAliceBob(Alice alice, Bob bob) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		//Alice identifies herself to Bob.
		//Bob responds with the current value of his 128-bit counter.
		
		//Alice repeatedly computes Ks = HMAC(Ks, Ia || S) and increments Ia until Ia == Ib.
		while (!alice.compare(alice.counter, bob.counter)) {
			alice.sequence = alice.mac(alice.sequence, alice.concat(alice.counter, alice.salt));
			alice.inc(alice.counter);
		}
		
		//Alice computes OTP = Ks XOR Kt and sends her password and OTP to Bob.
		//Alice could possibly encrypt her Kt using Ks as key together with S
		alice.otp = new byte[20];
		for (int i = 0; i < alice.otp.length; i++)
			alice.otp[i] = (byte)((alice.sequence[i] ^ alice.key[i]) & 0x000000ff);

		// EXCHANGE!!!!!
		bob.password = alice.password;
		bob.otp = new byte[20];
		System.arraycopy(alice.otp, 0, bob.otp, 0, bob.otp.length);
		
		//Bob obtains Kt = OTP XOR Ks.
		bob.alice = new byte[20];
		for (int i = 0; i < bob.alice.length; i++)
			bob.alice[i] = (byte)((bob.otp[i] ^ bob.sequence[i]) & 0x000000ff);

		//Bob computes T' = HMAC(Kt || S, <Alice's Password> || S).
		bob.T = bob.mac(bob.concat(bob.alice, bob.salt), bob.concat(bob.password.getBytes(), bob.salt));
		
		Boolean authenticated = bob.compare(bob.T, bob.token);
		System.out.println("Athentication: " + authenticated);
		
		//Bob compares T' and T. If they are identical, Alice is authenticated, if not, Bob stops here.
		
		if (authenticated) {
			//Bob computes Km by decrypting Cm with key HMAC(Kt, <Alice's Password>).

			bob.hmac = bob.mac(bob.alice, bob.password.getBytes());
			bob.dkey = bob.derive(bob.hmac, new byte[0], 1, 3);
			System.arraycopy(bob.dkey, 0, bob.K, 0, bob.K.length);
			System.arraycopy(bob.dkey, bob.K.length, bob.iv, 0, bob.iv.length);
			bob.master = bob.dec(bob.key, bob.K, bob.iv);

			// Bob computes Ks = HMAC(Ks, Ib || S) and increments Ib.
			bob.sequence = bob.mac(bob.sequence, bob.concat(bob.counter, bob.salt));
			bob.inc(bob.counter);

			// Alice does the same
			alice.sequence = alice.mac(alice.sequence, alice.concat(alice.counter, alice.salt));
			alice.inc(alice.counter);

			//Bob destroys of Kt and the previous Ks.
			//Bob uses Km to encrypt and decrypt Alice's data and destroys it when finished.
			System.out.println("Bobs password: " + new String(bob.master));

			// Both Alice and Bob now save their new values of the counter and sequence
		}
	}

	/**
	 * The initialization routine for E-OTP between Alice and Bob<br />
	 * This routine assumes a secure communication layer between parties.<br />
	 * <ol>
	 * <li>Alice sends her ID/password to Bob</li>
	 * <li>Alice generates three random numbers A, B and X</li>
	 * <li>Bob generates three random numbers C, D and Y</li>
	 * <li>Both compute sequence = H(A || C)</li>
	 * <li>Both compute Alice's key Ka = H(B || D)</li>
	 * <li>Both compute salt = H(X || Y)</li>
	 * <li>Bob generates random key Kb</li>
	 * <li>Bob encodes Kb into Cb using E( HMAC(Ka, <Alice's Password>), Kb) then destroys Kb</li>
	 * <li>Bob saves token = HMAC(Ka || salt, <Alice's Password> || salt) and destroys Ka</li>
	 * <li>Bob destroys all information related to Alice's password other than token</li>
	 * <li>Both initialize 128-bit counters to zero, and save current state</li> 
	 * </ol>
	 * <ul>
	 * <li>Alice and Bob now share the secret sequence and salt</li>
	 * <li>Alice has her static key</li>
	 * <li>Bob has Cb which is Bob's key encrypted with Alice's key which he doesn't have</li>
	 * <li>Bob also has the token, the HMAC of Alice's password and key</li>
	 * </ul>
	 * @param Alice
	 * @param Bob
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static void initializeAliceBob(Alice alice, Bob bob) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		
		//Alice authenticates herself to Bob using the existing password-based authentication.
		alice.password = "password";
		bob.password = alice.password;
		
		//Alice uses a RNG to generate three random numbers Ra, Rb, Rx and sends them to Bob.
		alice.rng(alice.randomA);
		alice.rng(alice.randomB);
		alice.rng(alice.randomX);
		
		//Bob uses a RNG to generate three random numbers Rc, Rd, Ry and sends them to Alice.
		bob.rng(bob.randomC);
		bob.rng(bob.randomD);
		bob.rng(bob.randomY);
		
		//Alice and Bob both compute (and save) sequence key Ks = H(Ra || Rc).
		alice.sequence = alice.md(alice.concat(alice.randomA, bob.randomC));
		bob.sequence = bob.md(bob.concat(alice.randomA, bob.randomC));
		//assert Arrays.CompareByteArray(alice.sequence, bob.sequence);

		//Bob and Alice both compute static key Kt = H(Rb || Rd).
		alice.key = alice.md(alice.concat(alice.randomB, bob.randomD));
		bob.alice = bob.md(bob.concat(alice.randomB, bob.randomD));
		//assert Arrays.CompareByteArray(alice.key, bob.alice);
		
		//Bob and Alice both compute (and save) salt S = H(Rx || Ry).
		alice.salt = alice.md(alice.concat(alice.randomX, bob.randomY));
		bob.salt = bob.md(bob.concat(alice.randomX, bob.randomY));
		//assert Arrays.CompareByteArray(alice.salt, bob.salt);
		
		//Bob uses a RNG to generate a master key Km.
		bob.rng(bob.master);
		bob.master = "master".getBytes(); // Temporary override!!!
		
		//Bob computes Cm = E( HMAC(Kt, <Alice's Password>), Km) then destroys Km
		bob.hmac = bob.mac(bob.alice, bob.password.getBytes());
		bob.dkey = bob.derive(bob.hmac, new byte[0], 1, 3);
		System.arraycopy(bob.dkey, 0, bob.K, 0, bob.K.length);
		System.arraycopy(bob.dkey, bob.K.length, bob.iv, 0, bob.iv.length);
		bob.key = bob.enc(bob.master, bob.K, bob.iv);
		
		//Bob saves token T = HMAC(Kt || S, <Alice's Password> || S) and destroys Kt.
		bob.token = bob.mac(bob.concat(bob.alice, bob.salt), bob.concat(bob.password.getBytes(), bob.salt));
		
		//Bob destroys all information related to Alice's password other than T.
		//Bob and Alice save 128-bit counters initialized to 0. Let Ia and Ib denote Alice's and Bob's counter respectively.
		alice.clear();
		bob.clear();
		
		//At this point, Bob and Alice share a secret "sequence" key Ks and salt S. They both have 128-bit counters set to 0.
		//Alice has the "static" key Kt.
		//Bob has Cm which is the "master" key Km encrypted with Kt, but does not have Kt.
		//Bob also has T, the HMAC of Alice's password and Kt.

		//Alice's random numbers Ra, Rb, and Rx may be omitted if she is unable to generate random numbers (e.g. if she is a website user).

		System.out.println(alice);
		System.out.println(bob);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
		Alice alice = new Alice();
		Bob bob = new Bob();
		initializeAliceBob(alice, bob);
		
		alice = new Alice(alice.toString());
		bob = new Bob(bob.toString());
		communicateAliceBob(alice, bob); // Round #1

		alice = new Alice(alice.toString());
		bob = new Bob(bob.toString());
		communicateAliceBob(alice, bob); // Round #2

		alice = new Alice(alice.toString());
		bob = new Bob(bob.toString());
		communicateAliceBob(alice, bob); // Round #3
		
		System.out.println(alice);
		System.out.println(bob);

	}

}
