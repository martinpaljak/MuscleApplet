//  MUSCLE SmartCard Development
//      Authors:          Tommaso Cucinotta <cucinotta@sssup.it>
//                        David Corcoran    <corcoran@linuxnet.com>
//                        Ludovic Rousseau  <ludovic.rousseau@free.fr>
//      Package:          CardEdgeApplet
//      Description:      CardEdge implementation with JavaCard
//      Protocol Authors: Tommaso Cucinotta <cucinotta@sssup.it>
//                        David Corcoran <corcoran@linuxnet.com>
//      Modified:
//                        Eirik Herskedal <ehersked@cs.purdue.edu>
//      License:          See LICENSE file
//
//      $Id$

package com.musclecard.CardEdge;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

// Referenced classes of package com.musclecard.CardEdge:
//			MemoryManager, ObjectManager

/**
 * Implements MUSCLE's Card Edge Specification.
 *
 * <p>TODO:
 *
 * <ul>
 *  <li>Allows maximum number of keys and PINs and total mem to be
 *  specified at the instantiation moment.</li>
 *
 *  <li>How do transactions fit in the methods?</li>
 *  <li>Where should we issue begin/end transaction?</li>
 *  <li>Should we ever abort transaction? Where?</li>
 *  <li>Everytime there is an <tt>"if (avail &lt; )"</tt> check, call
 *  <tt>ThrowDeleteObjects()</tt>.</li>
 * </ul>
 * </p>
 *
 * <p>NOTES:
 *
 * <ul>
 *  <li>C preprocessor flags:
 *   <ul>
 *    <li>Encryption algorithms: WITH_RSA, WITH_DSA, WITH_DES, WITH_3DES</li>
 *    <li>ComputeCrypt directions: WITH_ENCRYPT, WITH_DECRYPT, WITH_SIGN</li>
 *    <li>Enable/Disable External Authenticate: WITH_EXT_AUTH</li>
 *    <li>Enable/Disable PIN Policy enforcement: WITH_PIN_POLICY</li>
 *   </ul>
 *  </li>
 *  <li>C preprocessor defines:
 *   <ul>
 *    <li>JAVA_PACKAGE: The name of Java package for this Applet</li>
 *    <li>CardEdge: The name of Java class for the Applet</li>
 *   </ul>
 *  </li>
 * </ul>
 * </p>
 *
 * @author Tommaso Cucinotta
 * @author David Corcoran
 * @author Ludovic Rousseau
 * @version 0.9.11
 */
public class CardEdge extends Applet
{
	private static final byte MAX_NUM_KEYS = 8;
	private static final byte MAX_NUM_PINS = 8;
	private static final byte MAX_NUM_AUTH_KEYS = 6;

	private static final byte VERSION_PROTOCOL_MAJOR = 0;
	private static final byte VERSION_PROTOCOL_MINOR = 1;
	private static final byte VERSION_APPLET_MAJOR = 0;
	private static final byte VERSION_APPLET_MINOR = 6;

	/**
	 * Enable pin size check
	 */
	private static final byte PIN_POLICY_SIZE = 1;

	/**
	 * Enable pin charset check
	 */
	private static final byte PIN_POLICY_CHARSET = 2;

	/**
	 * Enable charset mixing check
	 */
	private static final byte PIN_POLICY_MIXED = 4;

	/**
	 * Numbers are allowed
	 */
	private static final byte PIN_CHARSET_NUMBERS = 1;

	/**
	 * Upper case letters
	 */
	private static final byte PIN_CHARSET_UC_LETTERS = 2;

	/**
	 * Lower case letters
	 */
	private static final byte PIN_CHARSET_LC_LETTERS = 4;

	/**
	 * Punctuation symbols: , .
	 */
	private static final byte PIN_CHARSET_PUNCT = 8;

	/**
	 * Other binary codes (NUMBERS | OTHERS excludes LETTERS and PUNCT)
	 */
	private static final byte PIN_CHARSET_OTHERS = (byte)0x80;

	/**
	 * PIN must contain chars from at least 2 different char sets
	 */
	private static final byte PIN_MIXED_TWO = 1;

	/**
	 * PIN must at least contain chars from both upper and lower case
	 */
	private static final byte PIN_MIXED_CASE = 2;

	/**
	 * PIN must at least contain 1 char from each char set
	 */
	private static final byte PIN_MIXED_ALL = 4;

	private static final byte pinPolicies = 7;
	private static final byte pinMinSize = 4;
	private static final byte pinMaxSize = 16;

	private static final byte MAX_KEY_TRIES = 5;
	private static byte PIN_INIT_VALUE[];
	private static final short IN_OBJECT_CLA = -1;
	private static final short IN_OBJECT_ID = -2;
	private static final short OUT_OBJECT_CLA = -1;
	private static final short OUT_OBJECT_ID = -1;
	private static final byte KEY_ACL_SIZE = 6;
	private static byte STD_PUBLIC_ACL[];
	private static byte acl[];

	private static final byte CardEdge_CLA = (byte)0xB0;
	private static final byte INS_SETUP = (byte)0x2A;
	/**
	 * Instruction codes
	 */
	private static final byte INS_GEN_KEYPAIR = (byte)0x30;
	private static final byte INS_IMPORT_KEY = (byte)0x32;
	private static final byte INS_EXPORT_KEY = (byte)0x34;
	private static final byte INS_COMPUTE_CRYPT = (byte)0x36;
	private static final byte INS_CREATE_PIN = (byte)0x40;
	private static final byte INS_VERIFY_PIN = (byte)0x42;
	private static final byte INS_CHANGE_PIN = (byte)0x44;
	private static final byte INS_UNBLOCK_PIN = (byte)0x46;
	private static final byte INS_LOGOUT_ALL = (byte)0x70;
	private static final byte INS_GET_CHALLENGE = (byte)0x72;
	private static final byte INS_EXT_AUTH = (byte)0x38;
	private static final byte INS_CREATE_OBJ = (byte)0x5A;
	private static final byte INS_DELETE_OBJ = (byte)0x52;
	private static final byte INS_READ_OBJ = (byte)0x56;
	private static final byte INS_WRITE_OBJ = (byte)0x54;
	private static final byte INS_LIST_OBJECTS = (byte)0x58;
	private static final byte INS_LIST_PINS = (byte)0x48;
	private static final byte INS_LIST_KEYS = (byte)0x3A;
	private static final byte INS_GET_STATUS = (byte)0x3C;

	/**
	 * There have been memory problems on the card
	 */
	private static final short SW_NO_MEMORY_LEFT = (short)0x9C01;

	/**
	 * Entered PIN is not correct
	 */
	private static final short SW_AUTH_FAILED = (short)0x9C02;

	/**
	 * Required operation is not allowed in actual circumstances
	 */
	private static final short SW_OPERATION_NOT_ALLOWED = (short)0x9C03;

	/**
	 * Required feature is not (yet) supported
	 */
	private static final short SW_UNSUPPORTED_FEATURE = (short)0x9C05;

	/**
	 * Required operation was not authorized because of a lack of privileges
	 *
	 */
	private static final short SW_UNAUTHORIZED = (short)0x9C06;

	/**
	 * Required object is missing
	 */
	private static final short SW_OBJECT_NOT_FOUND = (short)0x9C07;

	/**
	 * New object ID already in use
	 */
	private static final short SW_OBJECT_EXISTS = (short)0x9C08;

	/**
	 * Algorithm specified is not correct
	 */
	private static final short SW_INCORRECT_ALG = (short)0x9C09;

	/**
	 * Incorrect P1 parameter
	 */
	private static final short SW_INCORRECT_P1 = (short)0x9C10;

	/**
	 * Incorrect P2 parameter
	 */
	private static final short SW_INCORRECT_P2 = (short)0x9C11;

	/**
	 * No more data available
	 */
	private static final short SW_SEQUENCE_END = (short)0x9C12;

	/**
	 * Invalid input parameter to command
	 */
	private static final short SW_INVALID_PARAMETER = (short)0x9C0F;

	/**
	 * Verify operation detected an invalid signature
	 */
	private static final short SW_SIGNATURE_INVALID = (short)0x9C0B;

	/**
	 * Operation has been blocked for security reason
	 */
	private static final short SW_IDENTITY_BLOCKED = (short)0x9C0C;

	// /**
	//  * Unspecified error
	//  */
	// private static final short SW_UNSPECIFIED_ERROR = (short)0x9C0D;

	/**
	 * For debugging purposes
	 */
	private static final short SW_INTERNAL_ERROR = (short)0x9CFF;

	private static final byte ALG_RSA = 0;
	private static final byte ALG_RSA_CRT = 1;
	private static final byte ALG_DSA = 2;
	private static final byte ALG_DES = 3;
	private static final byte ALG_3DES = 4;
	private static final byte ALG_3DES3 = 5;

	private static final byte KEY_RSA_PUBLIC = 1;
	private static final byte KEY_RSA_PRIVATE = 2;
	private static final byte KEY_RSA_PRIVATE_CRT = 3;
	private static final byte KEY_DSA_PUBLIC = 4;
	private static final byte KEY_DSA_PRIVATE = 5;
	private static final byte KEY_DES = 6;
	private static final byte KEY_3DES = 7;
	private static final byte KEY_3DES3 = 8;

	private static final byte BLOB_ENC_PLAIN = 0;

	private static final byte OP_INIT = 1;
	private static final byte OP_PROCESS = 2;
	private static final byte OP_FINALIZE = 3;

	private static final byte CD_SIGN = 1;
	private static final byte CD_VERIFY = 2;
	private static final byte CD_ENCRYPT = 3;
	private static final byte CD_DECRYPT = 4;

	private static final byte CM_RSA_NOPAD = 0;
	private static final byte CM_RSA_PAD_PKCS1 = 1;
	private static final byte CM_DSA_SHA = 16;
	private static final byte CM_DES_CBC_NOPAD = 32;
	private static final byte CM_DES_ECB_NOPAD = 33;

	private static final byte DL_APDU = 1;
	private static final byte DL_OBJECT = 2;

	/**
	 * List option
	 */
	private static final byte LIST_OPT_RESET = 0;
	private static final byte LIST_OPT_NEXT = 1;

	private static final byte OPT_DEFAULT = 0;
	private static final byte OPT_RSA_PUB_EXP = 1;
	private static final byte OPT_DSA_GPQ = 2;

	private static final short OFFSET_GENKEY_ALG = 5;
	private static final short OFFSET_GENKEY_SIZE = 6;
	private static final short OFFSET_GENKEY_PRV_ACL = 8;
	private static final short OFFSET_GENKEY_PUB_ACL = 14;
	private static final short OFFSET_GENKEY_OPTIONS = 20;
	private static final short OFFSET_GENKEY_RSA_PUB_EXP_LENGTH = 21;
	private static final short OFFSET_GENKEY_RSA_PUB_EXP_VALUE = 23;
	private static final short OFFSET_GENKEY_DSA_GPQ = 21;

	/**
	 * Instance variables declaration
	 */
	private MemoryManager mem;
	private ObjectManager om;
	private Key keys[];
	private byte keyACLs[];
	private byte keyTries[];
	private byte key_it;
	private boolean getChallengeDone;
	private Cipher ciphers[];
	private Signature signatures[];
	private byte ciph_dirs[];
	private KeyPair keyPairs[];
	private RandomData randomData;
	private OwnerPIN pins[];
	private OwnerPIN ublk_pins[];
	private short logged_ids;
	private boolean setupDone;
	private byte create_object_ACL;
	private byte create_key_ACL;
	private byte create_pin_ACL;

	private CardEdge(byte bArray[], short bOffset, byte bLength)
	{
		setupDone = false;
		PIN_INIT_VALUE = new byte[8];

		// the default PIN is "Muscle00"
		PIN_INIT_VALUE[0] = (byte)'M';
		PIN_INIT_VALUE[1] = (byte)'u';
		PIN_INIT_VALUE[2] = (byte)'s';
		PIN_INIT_VALUE[3] = (byte)'c';
		PIN_INIT_VALUE[4] = (byte)'l';
		PIN_INIT_VALUE[5] = (byte)'e';
		PIN_INIT_VALUE[6] = (byte)'0';
		PIN_INIT_VALUE[7] = (byte)'0';

		if (!CheckPINPolicy(PIN_INIT_VALUE, (short)0, (byte)PIN_INIT_VALUE.length))
			ISOException.throwIt((short)SW_INTERNAL_ERROR);

		ublk_pins = new OwnerPIN[MAX_NUM_PINS];
		pins = new OwnerPIN[MAX_NUM_PINS];
		pins[0] = new OwnerPIN((byte)3, (byte)pinMaxSize);
		pins[0].update(PIN_INIT_VALUE, (short)0, (byte)PIN_INIT_VALUE.length);
	}

	private void ChangePIN(APDU apdu, byte buffer[])
	{
		byte pin_nb = buffer[ISO7816.OFFSET_P1];

		if (pin_nb < 0 || pin_nb >= MAX_NUM_PINS)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		OwnerPIN pin = pins[pin_nb];
		if (pin == null)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short avail = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);
		if (apdu.setIncomingAndReceive() != avail)
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		if (avail < 4)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		byte pin_size = buffer[ISO7816.OFFSET_CDATA];
		if (avail < (short)(1 + pin_size + 1))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (!CheckPINPolicy(buffer, (short)6, pin_size))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		byte new_pin_size = buffer[(short)(6 + pin_size)];
		if (avail < (short)(1 + pin_size + 1 + new_pin_size))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (!CheckPINPolicy(buffer, (short)(6 + pin_size + 1), new_pin_size))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (pin.getTriesRemaining() == 0)
			ISOException.throwIt((short)SW_IDENTITY_BLOCKED);

		if (!pin.check(buffer, (short)6, pin_size))
		{
			LogoutIdentity(pin_nb);
			ISOException.throwIt((short)SW_AUTH_FAILED);
		}
		pin.update(buffer, (short)(6 + pin_size + 1), new_pin_size);
		logged_ids &= (short)(-1 ^ 1 << pin_nb);
	}

	/**
	 * Checks if PIN policies are satisfied for a PIN code
	 */
	private boolean CheckPINPolicy(byte pin_buffer[], short pin_offset, byte pin_size)
	{
		return pin_size >= pinMinSize && pin_size <= pinMaxSize;
	}

	/**
	 * OP Initialisation
	 */
 	private void OpInit(APDU apdu, byte buffer[], short bytesLeft,
		byte key_nb, byte op, Key key)
	{
		if (bytesLeft < 3)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		byte ciph_mode = buffer[ISO7816.OFFSET_CDATA];
		byte ciph_dir = buffer[ISO7816.OFFSET_CDATA+1];
		byte data_location = buffer[ISO7816.OFFSET_CDATA+2];
		byte src_buff[];
		short src_base;
		short src_avail;

		switch(data_location)
		{
		case 1:
			src_buff = buffer;
			src_base = 8;
			src_avail = (short)(bytesLeft - 3);
			break;

		case 2:
			src_buff = mem.getBuffer();
			src_base = om.getBaseAddress((short)-1, (short)-2);

			if (src_base == -1)
				ISOException.throwIt((short)SW_OBJECT_NOT_FOUND);

			src_avail = om.getSizeFromAddress(src_base);
			break;

		default:
			ISOException.throwIt((short)SW_INVALID_PARAMETER);
			return;
		}

		if (src_avail < 2)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		short size = Util.getShort(src_buff, src_base);

		if (src_avail < (short)(2 + size))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		switch(ciph_dir)
		{
		case CD_SIGN:
		case CD_VERIFY:
		{
			byte ciph_alg_id;

			switch(key.getType())
			{
			case KEY_DSA_PUBLIC:
			case KEY_DSA_PRIVATE:
				ciph_alg_id = Cipher.ALG_RSA_ISO9796;
				ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);
				break;

			case KEY_3DES:
			case KEY_3DES3:
				ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);
				return;

			case KEY_DES:
			default:
				ISOException.throwIt((short)SW_INCORRECT_ALG);
				return;
			}

			Signature sign = getSignature(key_nb, ciph_alg_id);
			if (size == 0)
				sign.init(key, (byte)(ciph_dir == 1 ? 1 : 2));
			else
				sign.init(key, (byte)(ciph_dir == 1 ? 1 : 2), src_buff, (short)(src_base + 2), size);

			ciph_dirs[key_nb] = ciph_dir;
			break;
		}

		case CD_ENCRYPT:
		case CD_DECRYPT:
		{
			byte ciph_alg_id;

			switch(key.getType())
			{
			case KEY_DSA_PUBLIC:
			case KEY_DSA_PRIVATE:
			case KEY_DES:
				if (ciph_mode == CM_RSA_NOPAD)
				{
					ciph_alg_id = Cipher.ALG_RSA_NOPAD;
					break;
				}
				if (ciph_mode == CM_RSA_PAD_PKCS1)
				{
					ciph_alg_id = Cipher.ALG_RSA_PKCS1;
				} else
				{
					ISOException.throwIt((short)SW_INVALID_PARAMETER);
					return;
				}
				break;

			case KEY_RSA_PRIVATE_CRT:
				if (ciph_mode == CM_DES_CBC_NOPAD)
				{
					ciph_alg_id = Cipher.ALG_DES_CBC_NOPAD;
					break;
				}
				if (ciph_mode == CM_DES_ECB_NOPAD)
				{
					ciph_alg_id = Cipher.ALG_DES_ECB_NOPAD;
				} else
				{
					ISOException.throwIt((short)SW_INVALID_PARAMETER);
					return;
				}
				break;

			case KEY_3DES:
			case KEY_3DES3:
				ISOException.throwIt((short)SW_INVALID_PARAMETER);
				return;

			default:
				ISOException.throwIt((short)SW_INTERNAL_ERROR);
				return;
			}

			Cipher ciph = getCipher(key_nb, ciph_alg_id);

			if (size == 0)
				ciph.init(key, (byte)(ciph_dir == 3 ? 2 : 1));
			else
				ciph.init(key, (byte)(ciph_dir == 3 ? 2 : 1), src_buff, (short)(src_base + 2), size);

			ciph_dirs[key_nb] = ciph_dir;
			break;
		}

		default:
		{
			ISOException.throwIt((short)SW_INVALID_PARAMETER);
			break;
		}
		}
	}

	/**
	 * OP Process or Finilize
	 */
	private void OpProcessFinalize(APDU apdu, byte buffer[],
		short bytesLeft, byte key_nb, byte op, Key key)
	{
		byte ciph_dir = ciph_dirs[key_nb];

		switch(ciph_dir)
		{
		case CD_SIGN:
		case CD_VERIFY:
		{
			Signature sign = signatures[key_nb];
			if (sign == null)
				ISOException.throwIt((short)ISO7816.SW_INCORRECT_P1P2);
			byte data_location = buffer[ISO7816.OFFSET_CDATA];
			byte src_buff[];
			short src_base;
			short src_avail;
			switch(data_location)
			{
			case DL_APDU:
				src_buff = mem.getBuffer();
				src_base = 6;
				src_avail = (short)(bytesLeft - 1);
				break;

			case DL_OBJECT:
				src_buff = mem.getBuffer();
				src_base = om.getBaseAddress((short)-1, (short)-2);
				if (src_base == -1)
					ISOException.throwIt((short)SW_OBJECT_NOT_FOUND);
				src_avail = om.getSizeFromAddress(src_base);
				break;

			default:
				ISOException.throwIt((short)SW_INVALID_PARAMETER);
				return;
			}
			if (src_avail < 2)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);
			short size = Util.getShort(src_buff, src_base);
			if (src_avail < (short)(2 + size))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);
			if (op == 2)
			{
				sign.update(src_buff, (short)(src_base + 2), size);
				return;
			}
			if (ciph_dir == 1)
			{
				om.destroyObject((short)-1, (short)-1, true);
				short dst_base = om.createObject((short)-1, (short)-1, (short)(sign.getLength() + 2), getCurrentACL(), (short)0);

				if (dst_base == -1)
					ISOException.throwIt((short)SW_NO_MEMORY_LEFT);

				short sign_size = sign.sign(src_buff, (short)(src_base + 2), size, mem.getBuffer(), (short)(dst_base + 2));

				if (sign_size > sign.getLength())
					ISOException.throwIt((short)SW_INTERNAL_ERROR);

				mem.setShort(dst_base, sign_size);
				if (data_location == 1)
				{
					sendData(apdu, mem.getBuffer(), dst_base, (short)(sign_size + 2));
					om.destroyObject((short)-1, (short)-1, true);
				}
				return;
			}
			if (src_avail < (short)(2 + size + 2))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			short sign_size = Util.getShort(src_buff, (short)(src_base + 2 + size));
			if (src_avail < (short)(2 + size + 2 + sign_size))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			if (sign_size != sign.getLength())
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			if (!sign.verify(src_buff, (short)(src_base + 2), size, src_buff, (short)(src_base + 2 + size + 2), sign_size))
				ISOException.throwIt((short)SW_SIGNATURE_INVALID);

			return;
		}

		case CD_ENCRYPT:
		case CD_DECRYPT:
		{
			Cipher ciph = ciphers[key_nb];

			if (ciph == null)
				ISOException.throwIt((short)ISO7816.SW_INCORRECT_P1P2);

			byte data_location = buffer[ISO7816.OFFSET_CDATA];
			byte src_buff[];
			short src_base;
			short src_avail;

			switch(data_location)
			{
			case DL_APDU:
				src_buff = buffer;
				src_base = 6;
				src_avail = (short)(bytesLeft - 1);
				break;

			case DL_OBJECT:
				src_buff = mem.getBuffer();
				src_base = om.getBaseAddress((short)-1, (short)-2);
				if (src_base == -1)
					ISOException.throwIt((short)SW_OBJECT_NOT_FOUND);
				src_avail = om.getSizeFromAddress(src_base);
				break;

			default:
				ISOException.throwIt((short)SW_INVALID_PARAMETER);
				return;
			}
			if (src_avail < 2)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			short size = Util.getShort(src_buff, src_base);
			if (src_avail < (short)(2 + size))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			om.destroyObject((short)-1, (short)-1, true);
			short dst_base = om.createObject((short)-1, (short)-1, (short)(size + 2), getCurrentACL(), (short)0);
			if (dst_base == -1)
				ISOException.throwIt((short)SW_NO_MEMORY_LEFT);

			mem.setShort(dst_base, size);
			if (op == 2)
				ciph.update(src_buff, (short)(src_base + 2), size, mem.getBuffer(), (short)(dst_base + 2));
			else
				ciph.doFinal(src_buff, (short)(src_base + 2), size, mem.getBuffer(), (short)(dst_base + 2));
			if (data_location == 1)
			{
				Util.arrayCopyNonAtomic(mem.getBuffer(), dst_base, buffer, (short)0, (short)(size + 2));
				om.destroyObject((short)-1, (short)-1, true);
				sendData(apdu, buffer, (short)0, (short)(size + 2));
			}
			break;
		}

		default:
		{
			ISOException.throwIt((short)SW_INTERNAL_ERROR);
			break;
		}
		}
	}


	/**
	 * APDU handlers
	 */
 	private void ComputeCrypt(APDU apdu, byte buffer[])
	{
		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		byte key_nb = buffer[ISO7816.OFFSET_P1];

		if (key_nb < 0 || key_nb >= MAX_NUM_KEYS || keys[key_nb] == null)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (!authorizeKeyUse(key_nb))
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		byte op = buffer[ISO7816.OFFSET_P2];
		Key key = keys[key_nb];

		switch(op)
		{
			case OP_INIT:
			{
				OpInit(apdu, buffer, bytesLeft, key_nb, op, key);
				break;
			}

			case OP_PROCESS:
			case OP_FINALIZE:
			{
				OpProcessFinalize(apdu, buffer, bytesLeft, key_nb, op, key);
				break;
			}

			default:
			{
				ISOException.throwIt((short)SW_INCORRECT_P2);
				break;
			}
		}
	}

	private void CreateObject(APDU apdu, byte buffer[])
	{
		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		if (create_object_ACL == -1 || (logged_ids & create_object_ACL) == 0 && create_object_ACL != 0)
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		if (bytesLeft != 14)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short obj_class = Util.getShort(buffer, (short)5);
		short obj_id = Util.getShort(buffer, (short)7);

		if (om.exists(obj_class, obj_id))
			ISOException.throwIt((short)SW_OBJECT_EXISTS);

		if (Util.getShort(buffer, (short)9) != 0 || buffer[11] < 0)
			ISOException.throwIt((short)SW_NO_MEMORY_LEFT);

		if (Util.getShort(buffer, (short)11) == 0)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		om.createObject(obj_class, obj_id, Util.getShort(buffer, (short)11), buffer, (short)13);
	}

	private void CreatePIN(APDU apdu, byte buffer[])
	{
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		byte num_tries = buffer[ISO7816.OFFSET_P2];

		if (create_pin_ACL == -1 || (logged_ids & create_pin_ACL) == 0 && create_pin_ACL != 0)
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		if (pin_nb < 0 || pin_nb >= MAX_NUM_PINS || pins[pin_nb] != null)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		short avail = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (apdu.setIncomingAndReceive() != avail)
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		if (avail < 4)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		byte pin_size = buffer[ISO7816.OFFSET_CDATA];

		if (avail < (short)(1 + pin_size + 1))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (!CheckPINPolicy(buffer, (short)6, pin_size))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		byte ucode_size = buffer[(short)(6 + pin_size)];

		if (avail != (short)(1 + pin_size + 1 + ucode_size))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (!CheckPINPolicy(buffer, (short)(6 + pin_size + 1), ucode_size))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		pins[pin_nb] = new OwnerPIN(num_tries, (byte)pinMaxSize);
		pins[pin_nb].update(buffer, (short)6, pin_size);
		ublk_pins[pin_nb] = new OwnerPIN((byte)3, (byte)pinMaxSize);
		pin_size = (byte)(6 + pin_size + 1);
		ublk_pins[pin_nb].update(buffer, pin_size, ucode_size);
	}

	private void DeleteObject(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (buffer[ISO7816.OFFSET_P2] != 0 && buffer[ISO7816.OFFSET_P2] != 1)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		if (bytesLeft != 4)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		short obj_class = Util.getShort(buffer, (short)5);
		short obj_id = Util.getShort(buffer, (short)7);
		short base = om.getBaseAddress(obj_class, obj_id);

		if (base == -1)
			ISOException.throwIt((short)SW_OBJECT_NOT_FOUND);

		if (!om.authorizeDeleteFromAddress(base, logged_ids))
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		om.destroyObject(obj_class, obj_id, buffer[ISO7816.OFFSET_P2] == 1);
	}

	private void ExportKey(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		byte key_nb = buffer[ISO7816.OFFSET_P1];

		if (key_nb < 0 || key_nb >= MAX_NUM_KEYS)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		Key key = keys[key_nb];

		if (key == null || !key.isInitialized())
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (!authorizeKeyRead(key_nb))
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		om.destroyObject((short)-1, (short)-1, true);
		short base = om.createObjectMax((short)-1, (short)-1, getCurrentACL(), (short)0);
		short buffer_size = om.getSizeFromAddress(base);
		short avail = buffer_size;

		if (buffer[ISO7816.OFFSET_CDATA] != 0)
			ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);

		if (avail < 4)
			ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

		mem.setByte(base, (byte)0);
		base++;
		byte key_type = key.getType();
		mem.setByte(base, getKeyType(key));
		base++;
		short key_size = key.getSize();
		mem.setShort(base, key_size);
		base += 2;
		avail -= 4;
		short bn_size = (short)(keys[key_nb].getSize() / 8 + 2);
		switch(key_type)
		{
		case KeyBuilder.TYPE_RSA_PUBLIC:
		{
			RSAPublicKey pub_key = (RSAPublicKey)key;

			if (avail < bn_size)
				ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

			short size = pub_key.getModulus(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);

			if (avail < bn_size)
				ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

			size = pub_key.getExponent(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);
			break;
		}

		case KeyBuilder.TYPE_RSA_PRIVATE:
		{
			RSAPrivateKey prv_key = (RSAPrivateKey)key;

			if (avail < bn_size)
				ISOException.throwIt((short)SW_NO_MEMORY_LEFT);

			short size = prv_key.getModulus(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);

			if (avail < bn_size)
				ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

			size = prv_key.getExponent(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);
			break;
		}

		case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
		{
			RSAPrivateCrtKey prv_key_crt = (RSAPrivateCrtKey)key;

			if (avail < bn_size)
				ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

			short size = prv_key_crt.getP(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);

			if (avail < bn_size)
				ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

			size = prv_key_crt.getQ(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);

			if (avail < bn_size)
				ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

			size = prv_key_crt.getPQ(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);

			if (avail < bn_size)
				ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

			size = prv_key_crt.getDP1(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);

			if (avail < bn_size)
				ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

			size = prv_key_crt.getDQ1(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);
			break;
		}

		case KeyBuilder.TYPE_DES:
		{
			DESKey des_key = (DESKey)key;

			if (avail < bn_size)
				ThrowDeleteObjects((short)SW_NO_MEMORY_LEFT);

			short size = des_key.getKey(mem.getBuffer(), (short)(base + 2));
			mem.setShort(base, size);
			base += (short)(2 + size);
			avail -= (short)(2 + size);
			break;
		}

		default:
		{
			ISOException.throwIt((short)SW_INVALID_PARAMETER);
			break;
		}
		}
		om.clampObject((short)-1, (short)-1, (short)(buffer_size - avail));
	}

	private void GenerateKeyPair(APDU apdu, byte buffer[])
	{
		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		byte alg_id = buffer[ISO7816.OFFSET_CDATA];

		switch(alg_id)
		{
		case ALG_RSA:
		case ALG_RSA_CRT:
			GenerateKeyPairRSA(buffer);
			break;

		case ALG_DSA:
			ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);
			break;

		default:
			ISOException.throwIt((short)SW_INCORRECT_ALG);
			break;
		}
	}

	private void GenerateKeyPairRSA(byte buffer[])
	{
		byte prv_key_nb = buffer[ISO7816.OFFSET_P1];

		if (prv_key_nb < 0 || prv_key_nb >= MAX_NUM_KEYS)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		byte pub_key_nb = buffer[ISO7816.OFFSET_P2];

		if (pub_key_nb < 0 || pub_key_nb >= MAX_NUM_KEYS)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		if (pub_key_nb == prv_key_nb)
			ISOException.throwIt((short)ISO7816.SW_INCORRECT_P1P2);

		byte alg_id = buffer[ISO7816.OFFSET_CDATA];
		short key_size = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+1));
		byte options = buffer[20];
		RSAPublicKey pub_key = (RSAPublicKey)getKey(pub_key_nb, KEY_RSA_PUBLIC, key_size);
		PrivateKey prv_key = (PrivateKey)getKey(prv_key_nb, (byte)(alg_id == 0 ? KEY_RSA_PRIVATE : KEY_RSA_PRIVATE_CRT), key_size);

		/* If we're going to overwrite a keyPair's contents, check ACL */
		if (pub_key.isInitialized() && !authorizeKeyWrite(pub_key_nb))
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		if (prv_key.isInitialized() && !authorizeKeyWrite(prv_key_nb))
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		/* Store private key ACL */
		Util.arrayCopy(buffer, OFFSET_GENKEY_PRV_ACL, keyACLs, (short)(prv_key_nb * KEY_ACL_SIZE), (short)KEY_ACL_SIZE);
		/* Store public key ACL */
		Util.arrayCopy(buffer, OFFSET_GENKEY_PUB_ACL, keyACLs, (short)(pub_key_nb * KEY_ACL_SIZE), (short)KEY_ACL_SIZE);

		switch(options)
		{
		case OPT_DEFAULT:
			/* As the default was specified, if public key already
			 * exist we have to invalidate it, otherwise its parameters
			 * would be used in place of the default ones */
			if (pub_key.isInitialized())
				pub_key.clearKey();
			break;

		case OPT_RSA_PUB_EXP:
			short exp_length = Util.getShort(buffer, (short)21);
			pub_key.setExponent(buffer, (short)23, exp_length);
			break;

		default:
			ISOException.throwIt((short)SW_INVALID_PARAMETER);
			break;
		}

		/* TODO: Migrate checks on KeyPair on the top, so we
		 *       avoid resource allocation on error conditions */

		/* If no keypair was previously used, ok.
		 * If different keypairs were used, or for 1 key
		 *   there is a keypair but the other key not, then error
		 * If the same keypair object was used previously,
		 *   check keypair size & type
		 */

		if (keyPairs[pub_key_nb] == null && keyPairs[prv_key_nb] == null)
		{
			keyPairs[pub_key_nb] = new KeyPair(pub_key, prv_key);
			keyPairs[prv_key_nb] = keyPairs[pub_key_nb];
		} else
		if (keyPairs[pub_key_nb] != keyPairs[prv_key_nb])
			ISOException.throwIt((short)SW_OPERATION_NOT_ALLOWED);
		KeyPair kp = keyPairs[pub_key_nb];

		if (kp.getPublic() != pub_key || kp.getPrivate() != prv_key)
			// This should never happen according with this Applet policies
			ISOException.throwIt((short)SW_INTERNAL_ERROR);

		// We Rely on genKeyPair() to make all necessary checks about types
		kp.genKeyPair();
	}

	private void GetChallenge(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		if (bytesLeft < 4)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		short size = Util.getShort(buffer, (short)5);
		short seed_size = Util.getShort(buffer, (short)7);

		if (bytesLeft != (short)(seed_size + 4))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		byte data_loc = buffer[ISO7816.OFFSET_P2];

		if (data_loc != 1 && data_loc != 2)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (randomData == null)
			randomData = RandomData.getInstance((byte)2);

		if (seed_size != 0)
			randomData.setSeed(buffer, (short)9, seed_size);

		if (size != 0)
		{
			short base = om.createObject((short)-1, (short)-1, (short)(size + 2), getRestrictedACL(), (short)0);
			mem.setShort(base, size);
			randomData.generateData(mem.getBuffer(), (short)(base + 2), size);
			getChallengeDone = true;
			if (data_loc == 1)
			{
				sendData(apdu, mem.getBuffer(), base, (short)(size + 2));
				om.destroyObject((short)-1, (short)-1, true);
			}
		}
	}

	private void GetStatus(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short pos = 0;

		buffer[pos++] = (byte)VERSION_PROTOCOL_MAJOR;
		buffer[pos++] = (byte)VERSION_PROTOCOL_MINOR;
		buffer[pos++] = (byte)VERSION_APPLET_MAJOR;
		buffer[pos++] = (byte)VERSION_APPLET_MINOR;

		// Total object memory
		Util.setShort(buffer, pos, (short)0);
		pos += 2;
		Util.setShort(buffer, pos, (short)mem.getBuffer().length);
		pos += 2;

		// Free object memory
		Util.setShort(buffer, pos, (short)0);
		pos += 2;
		Util.setShort(buffer, pos, mem.freemem());
		pos += 2;

		// Number of PINs used
		byte cnt = 0;
		for(short i = 0; i < pins.length; i++)
			if (pins[i] != null)
				cnt++;

		buffer[pos++] = cnt;

		// Number of keys used
		cnt = 0;
		for(short i = 0; i < keys.length; i++)
			if (keys[i] != null)
				cnt++;

		// Logged identities
		buffer[pos++] = cnt;
		Util.setShort(buffer, pos, logged_ids);
		pos += 2;
		apdu.setOutgoingAndSend((short)0, pos);
	}

	private void ImportKey(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		byte key_nb = buffer[ISO7816.OFFSET_P1];

		if (key_nb < 0 || key_nb >= MAX_NUM_KEYS)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (keys[key_nb] != null && keys[key_nb].isInitialized() && !authorizeKeyWrite(key_nb))
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		short base = om.getBaseAddress((short)-1, (short)-2);

		if (base == -1)
			ISOException.throwIt((short)SW_OBJECT_NOT_FOUND);

		short avail = om.getSizeFromAddress(base);

		if (avail < 4)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (mem.getByte(base) != 0)
			ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);

		base++;
		avail--;
		byte key_type = mem.getByte(base);
		base++;
		avail--;
		short key_size = mem.getShort(base);
		base += 2;
		avail -= 2;

		switch(key_type)
		{
		case KEY_RSA_PUBLIC:
		{
			RSAPublicKey rsa_pub_key = (RSAPublicKey)getKey(key_nb, key_type, key_size);
			if (avail < 2)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			short size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < (short)(size + 2))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			rsa_pub_key.setModulus(mem.getBuffer(), base, size);
			base += size;
			avail -= size;
			size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < size)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			rsa_pub_key.setExponent(mem.getBuffer(), base, size);

			base += size;
			avail -= size;

			// set the ACL value
			Util.arrayCopy(buffer, (short)5, keyACLs, (short)(key_nb * KEY_ACL_SIZE), (short)KEY_ACL_SIZE);
			break;
		}

		case KEY_RSA_PRIVATE:
		{
			RSAPrivateKey rsa_prv_key = (RSAPrivateKey)getKey(key_nb, key_type, key_size);
			if (avail < 2)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			short size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < (short)(size + 2))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			rsa_prv_key.setModulus(mem.getBuffer(), base, size);
			base += size;
			avail -= size;
			size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < size)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			rsa_prv_key.setExponent(mem.getBuffer(), base, size);

			base += size;
			avail -= size;

			// set the ACL value
			Util.arrayCopy(buffer, (short)5, keyACLs, (short)(key_nb * KEY_ACL_SIZE), (short)KEY_ACL_SIZE);

			break;
		}

		case KEY_RSA_PRIVATE_CRT:
		{
			RSAPrivateCrtKey rsa_prv_key_crt = (RSAPrivateCrtKey)getKey(key_nb, key_type, key_size);
			if (avail < 2)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			short size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < (short)(size + 2))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			rsa_prv_key_crt.setP(mem.getBuffer(), base, size);

			base += size;
			avail -= size;
			size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < (short)(size + 2))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			rsa_prv_key_crt.setQ(mem.getBuffer(), base, size);

			base += size;
			avail -= size;
			size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < (short)(size + 2))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			rsa_prv_key_crt.setPQ(mem.getBuffer(), base, size);

			base += size;
			avail -= size;
			size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < (short)(size + 2))
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			rsa_prv_key_crt.setDP1(mem.getBuffer(), base, size);

			base += size;
			avail -= size;
			size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < size)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);

			rsa_prv_key_crt.setDQ1(mem.getBuffer(), base, size);

			base += size;
			avail -= size;

			// set the ACL value
			Util.arrayCopy(buffer, (short)5, keyACLs, (short)(key_nb * KEY_ACL_SIZE), (short)KEY_ACL_SIZE);
			break;
		}

		case KEY_DSA_PUBLIC:
		case KEY_DSA_PRIVATE:
		{
			ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);
			// fall through
		}

		case KEY_DES:
		case KEY_3DES:
		case KEY_3DES3:
		{
			DESKey des_key = (DESKey)getKey(key_nb, key_type, key_size);
			if (avail < 2)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);
			short size = mem.getShort(base);
			base += 2;
			avail -= 2;
			if (avail < size)
				ISOException.throwIt((short)SW_INVALID_PARAMETER);
			des_key.setKey(mem.getBuffer(), base);
			base += size;
			avail -= size;
			break;
		}

		default:
		{
			ISOException.throwIt((short)SW_INCORRECT_ALG);
			break;
		}
		}
		om.destroyObject((short)-1, (short)-2, true);
	}

	private void ListKeys(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);
		short expectedBytes = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);
		if (expectedBytes != 11)
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);
		if (buffer[ISO7816.OFFSET_P1] == 0)
			key_it = 0;
		else
		if (buffer[ISO7816.OFFSET_P1] != 1)
			ISOException.throwIt((short)SW_INCORRECT_P1);
		for(; key_it < MAX_NUM_KEYS && (keys[key_it] == null || !keys[key_it].isInitialized()); key_it++);
		if (key_it < MAX_NUM_KEYS)
		{
			Key key = keys[key_it];
			buffer[0] = key_it;
			buffer[1] = getKeyType(key);
			buffer[2] = -1;
			Util.setShort(buffer, (short)3, key.getSize());
			Util.arrayCopyNonAtomic(keyACLs, (short)(key_it * KEY_ACL_SIZE), buffer, (short)5, (short)KEY_ACL_SIZE);
			key_it++;
			apdu.setOutgoingAndSend((short)0, (short)11);
		}
		else
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);
	}

	private void ListObjects(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		byte expectedBytes = buffer[ISO7816.OFFSET_LC];

		if (expectedBytes < 14)
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		boolean found = false;

		if (buffer[ISO7816.OFFSET_P1] == 0)
			found = om.getFirstRecord(buffer, (short)0);
		else
		if (buffer[ISO7816.OFFSET_P1] != 1)
			ISOException.throwIt((short)SW_INCORRECT_P1);
		else
			found = om.getNextRecord(buffer, (short)0);
		if (found)
			apdu.setOutgoingAndSend((short)0, (short)14);
		else
			ISOException.throwIt((short)SW_SEQUENCE_END);
	}

	private void ListPINs(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		byte expectedBytes = buffer[ISO7816.OFFSET_LC];

		if (expectedBytes != 2)
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		short mask = 0;

		for(short b = 0; b < MAX_NUM_PINS; b++)
			if (pins[b] != null)
				mask |= (short)(1 << b);

		Util.setShort(buffer, (short)0, mask);
		apdu.setOutgoingAndSend((short)0, (short)2);
	}

	private void LogOutAll()
	{
		logged_ids = 0;
		for(byte i = 0; i < MAX_NUM_PINS; i++)
			if (pins[i] != null)
				pins[i].reset();
	}

	/**
	 * Registers login of strong identity associated with a key number
	 */
	private void LoginStrongIdentity(byte key_nb)
	{
		logged_ids |= (short)(1 << key_nb + 8);
	}

	/**
	 * Registers logout of an identity.
	 *
	 * <p>This must be called anycase when a PIN verification or
	 * external authentication fail
	 * </p>
	 */
	private void LogoutIdentity(byte id_nb)
	{
		logged_ids &= (short)(~(1 << id_nb));
	}

	private void ReadObject(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		if (bytesLeft != 9)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		short obj_class = Util.getShort(buffer, (short)5);
		short obj_id = Util.getShort(buffer, (short)7);
		short offset = Util.getShort(buffer, (short)11);
		short size = Util.makeShort((byte)0, buffer[13]);
		short base = om.getBaseAddress(obj_class, obj_id);

		if (base == -1)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (!om.authorizeReadFromAddress(base, logged_ids))
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		if ((short)(offset + size) > om.getSizeFromAddress(base))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		sendData(apdu, mem.getBuffer(), (short)(base + offset), size);
	}

	/**
	 * Deletes and zeros the IO objects and throws the passed in
	 * exception
	 */
	private void ThrowDeleteObjects(short exception)
	{
		om.destroyObject((short)-1, (short)-2, true);
		om.destroyObject((short)-1, (short)-1, true);
		ISOException.throwIt(exception);
	}

	private void UnblockPIN(APDU apdu, byte buffer[])
	{
		byte pin_nb = buffer[ISO7816.OFFSET_P1];

		if (pin_nb < 0 || pin_nb >= MAX_NUM_PINS)
			ISOException.throwIt((short)SW_INCORRECT_P1);
		OwnerPIN pin = pins[pin_nb];
		OwnerPIN ublk_pin = ublk_pins[pin_nb];

		if (pin == null)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (ublk_pin == null)
			ISOException.throwIt((short)SW_INTERNAL_ERROR);

		if (pin.getTriesRemaining() != 0)
			ISOException.throwIt((short)SW_OPERATION_NOT_ALLOWED);

		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short numBytes = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (numBytes != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		if (!CheckPINPolicy(buffer, (short)5, (byte)numBytes))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (!ublk_pin.check(buffer, (short)5, (byte)numBytes))
			ISOException.throwIt((short)SW_AUTH_FAILED);

		pin.resetAndUnblock();
	}

	private void VerifyPIN(APDU apdu, byte buffer[])
	{
		byte pin_nb = buffer[ISO7816.OFFSET_P1];

		if (pin_nb < 0 || pin_nb >= MAX_NUM_PINS)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		OwnerPIN pin = pins[pin_nb];

		if (pin == null)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short numBytes = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (numBytes != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		if (!CheckPINPolicy(buffer, (short)5, (byte)numBytes))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (pin.getTriesRemaining() == 0)
			ISOException.throwIt((short)SW_IDENTITY_BLOCKED);

		if (!pin.check(buffer, (short)5, (byte)numBytes))
		{
			LogoutIdentity(pin_nb);
			ISOException.throwIt((short)SW_AUTH_FAILED);
		}
		logged_ids |= (short)(1 << pin_nb);
	}

	private void WriteObject(APDU apdu, byte buffer[])
	{
		if (buffer[ISO7816.OFFSET_P1] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P1);

		if (buffer[ISO7816.OFFSET_P2] != 0)
			ISOException.throwIt((short)SW_INCORRECT_P2);

		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		short obj_class = Util.getShort(buffer, (short)5);
		short obj_id = Util.getShort(buffer, (short)7);
		short offset = Util.getShort(buffer, (short)11);
		short size = Util.makeShort((byte)0, buffer[13]);
		short base = om.getBaseAddress(obj_class, obj_id);

		if (base == -1)
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (!om.authorizeWriteFromAddress(base, logged_ids))
			ISOException.throwIt((short)SW_UNAUTHORIZED);

		if ((short)(offset + size) > om.getSizeFromAddress(base))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		mem.setBytes(base, offset, buffer, (short)14, size);
	}

	/**
	 * Check from ACL if a key can be read
	 */
	boolean authorizeKeyRead(byte key_nb)
	{
		short acl_offset = (short)(key_nb * KEY_ACL_SIZE);
		short required_ids = Util.getShort(keyACLs, acl_offset);
		return required_ids != -1 && (short)(required_ids & logged_ids) == required_ids;
	}

	/**
	 * Check from ACL if a key can be used
	 */
	boolean authorizeKeyUse(byte key_nb)
	{
		short acl_offset = (short)(key_nb * KEY_ACL_SIZE + 4);
		short required_ids = Util.getShort(keyACLs, acl_offset);
		return required_ids != -1 && (short)(required_ids & logged_ids) == required_ids;
	}

	/**
	 * Check from ACL if a key can be overwritten
	 */
	boolean authorizeKeyWrite(byte key_nb)
	{
		short acl_offset = (short)(key_nb * KEY_ACL_SIZE + 2);
		short required_ids = Util.getShort(keyACLs, acl_offset);
		return required_ids != -1 && (short)(required_ids & logged_ids) == required_ids;
	}

	public void deselect()
	{
		if (setupDone)
		{
			om.destroyObject((short)-1, (short)-2, true);
			om.destroyObject((short)-1, (short)-1, true);
		}
		LogOutAll();
	}

	private Cipher getCipher(byte key_nb, byte alg_id)
	{
		if (ciphers[key_nb] == null)
			ciphers[key_nb] = Cipher.getInstance(alg_id, false);
		else
		if (ciphers[key_nb].getAlgorithm() != alg_id)
			ISOException.throwIt((short)SW_OPERATION_NOT_ALLOWED);
		return ciphers[key_nb];
	}

	/**
	 * Returns an ACL that requires current logged in identities.
	 */
	byte[] getCurrentACL()
	{
		if (acl == null)
			acl = new byte[6];
		for(byte i = 0; i < 6; i += 2)
			Util.setShort(acl, i, logged_ids);

		return acl;
	}

	/**
	 * Retrieves the Key object to be used w/ the specified key number,
	 * key type (KEY_XX) and size.
	 *
	 * <p>If exists, check it has the proper key type * If not, creates
	 * it.</p>
	 *
	 * @return Retrieved Key object
	 * @throws SW_UNATUTHORIZED
	 * @throws SW_OPERATION_NOT_ALLOWED
	 */
	private Key getKey(byte key_nb, byte key_type, short key_size)
	{
		byte jc_key_type = keyType2JCType(key_type);
		if (keys[key_nb] == null)
		{
			if (create_key_ACL == -1 || (logged_ids & create_key_ACL) == 0 && create_key_ACL != 0)
				ISOException.throwIt((short)SW_UNAUTHORIZED);
			keys[key_nb] = KeyBuilder.buildKey(jc_key_type, key_size, false);
		} else
		if (keys[key_nb].getSize() != key_size || keys[key_nb].getType() != jc_key_type)
			ISOException.throwIt((short)SW_OPERATION_NOT_ALLOWED);
		return keys[key_nb];
	}

	private byte getKeyType(Key key)
	{
		switch(key.getType())
		{
		case KeyBuilder.TYPE_RSA_PUBLIC:
			return KEY_RSA_PUBLIC;

		case KeyBuilder.TYPE_RSA_PRIVATE:
			return KEY_RSA_PRIVATE;

		case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
			return KEY_RSA_PRIVATE_CRT;

		case ALG_DES:
			if (key.getSize() == KeyBuilder.LENGTH_DES)
				return KEY_DES;
			if (key.getSize() == KeyBuilder.LENGTH_DES3_2KEY)
				return KEY_3DES;
			if (key.getSize() == KeyBuilder.LENGTH_DES3_3KEY)
				return KEY_3DES3;
			break;
		}
		ISOException.throwIt((short)SW_INTERNAL_ERROR);
		return 0;
	}

	/**
	 * Returns an ACL that disables all operations for the application.
	 */
	byte[] getRestrictedACL()
	{
		if (acl == null)
			acl = new byte[6];
		for(byte i = 0; i < 6; i += 2)
			Util.setShort(acl, i, (short)-1);

		return acl;
	}

	private Signature getSignature(byte key_nb, byte alg_id)
	{
		if (signatures[key_nb] == null)
			signatures[key_nb] = Signature.getInstance(alg_id, false);
		else
		if (signatures[key_nb].getAlgorithm() != alg_id)
			ISOException.throwIt((short)SW_OPERATION_NOT_ALLOWED);
		return signatures[key_nb];
	}

	public static void install(byte bArray[], short bOffset, byte bLength)
	{
		CardEdge wal = new CardEdge(bArray, bOffset, bLength);
		if (bArray[bOffset] == 0)
			wal.register();
		else
			wal.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
	}

	private byte keyType2JCType(byte key_type)
	{
		switch(key_type)
		{
		case KEY_RSA_PUBLIC:
			return KeyBuilder.TYPE_RSA_PUBLIC;

		case KEY_RSA_PRIVATE:
			return KeyBuilder.TYPE_RSA_PRIVATE;

		case KEY_RSA_PRIVATE_CRT:
			return KeyBuilder.TYPE_RSA_CRT_PRIVATE;

		case KEY_DSA_PUBLIC:
			ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);
			// fall through

		case KEY_DSA_PRIVATE: // '\005'
			ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);
			// fall through

		case KEY_DES:
			return KeyBuilder.TYPE_DES;

		case KEY_3DES:
		case KEY_3DES3:
			return KeyBuilder.TYPE_DES;

		default:
			ISOException.throwIt((short)SW_INVALID_PARAMETER);
			break;
		}
		return 0;
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
			ISOException.throwIt((short)ISO7816.SW_NO_ERROR);

		byte buffer[] = apdu.getBuffer();

		if (buffer[ISO7816.OFFSET_CLA] == 0 && buffer[ISO7816.OFFSET_INS] == (byte)0xA4)
			return;

		if (buffer[ISO7816.OFFSET_CLA] != (byte)CardEdge_CLA)
			ISOException.throwIt((short)ISO7816.SW_CLA_NOT_SUPPORTED);

		byte ins = buffer[ISO7816.OFFSET_INS];

		if (!setupDone && ins != (byte)INS_SETUP)
			ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);

		if (setupDone && ins == (byte)INS_SETUP)
			ISOException.throwIt((short)ISO7816.SW_INS_NOT_SUPPORTED);

		switch(ins)
		{
		case INS_SETUP:
			setup(apdu, buffer);
			break;

		case INS_GEN_KEYPAIR:
			GenerateKeyPair(apdu, buffer);
			break;

		case INS_IMPORT_KEY:
			ImportKey(apdu, buffer);
			break;

		case INS_EXPORT_KEY:
			ExportKey(apdu, buffer);
			break;

		case INS_COMPUTE_CRYPT:
			ComputeCrypt(apdu, buffer);
			break;

		case INS_VERIFY_PIN:
			VerifyPIN(apdu, buffer);
			break;

		case INS_CREATE_PIN:
			CreatePIN(apdu, buffer);
			break;

		case INS_CHANGE_PIN:
			ChangePIN(apdu, buffer);
			break;

		case INS_UNBLOCK_PIN:
			UnblockPIN(apdu, buffer);
			break;

		case INS_LOGOUT_ALL:
			LogOutAll();
			break;

		case INS_GET_CHALLENGE:
			GetChallenge(apdu, buffer);
			break;

		case INS_EXT_AUTH:
			ISOException.throwIt((short)SW_UNSUPPORTED_FEATURE);
			break;

		case INS_CREATE_OBJ:
			CreateObject(apdu, buffer);
			break;

		case INS_DELETE_OBJ:
			DeleteObject(apdu, buffer);
			break;

		case INS_READ_OBJ:
			ReadObject(apdu, buffer);
			break;

		case INS_WRITE_OBJ:
			WriteObject(apdu, buffer);
			break;

		case INS_LIST_PINS:
			ListPINs(apdu, buffer);
			break;

		case INS_LIST_OBJECTS:
			ListObjects(apdu, buffer);
			break;

		case INS_LIST_KEYS:
			ListKeys(apdu, buffer);
			break;

		case INS_GET_STATUS:
			GetStatus(apdu, buffer);
			break;

		default:
			ISOException.throwIt((short)ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}
	}

	public boolean select()
	{
		if (setupDone)
		{
			om.destroyObject((short)-1, (short)-2, true);
			om.destroyObject((short)-1, (short)-1, true);
		}
		LogOutAll();
		return true;
	}

	/**
	 * UTILITY FUNCTIONS
	 */
	private void sendData(APDU apdu, byte data[], short offset, short size)
	{
		if (size > 255)
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);
		Util.arrayCopyNonAtomic(data, offset, apdu.getBuffer(), (short)0, size);
		apdu.setOutgoingAndSend((short)0, size);
	}

	private void setup(APDU apdu, byte buffer[])
	{
		short bytesLeft = Util.makeShort((byte)0, buffer[ISO7816.OFFSET_LC]);

		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);

		short base = 5;
		byte numBytes = buffer[base++];
		OwnerPIN pin = pins[0];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		if (pin.getTriesRemaining() == 0)
			ISOException.throwIt((short)SW_IDENTITY_BLOCKED);

		if (!pin.check(buffer, base, numBytes))
			ISOException.throwIt((short)SW_AUTH_FAILED);

		base += numBytes;
		byte pin_tries = buffer[base++];
		byte ublk_tries = buffer[base++];
		numBytes = buffer[base++];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		pins[0] = new OwnerPIN(pin_tries, (byte)pinMaxSize);
		pins[0].update(buffer, base, numBytes);
		base += numBytes;
		numBytes = buffer[base++];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		ublk_pins[0] = new OwnerPIN(ublk_tries, (byte)pinMaxSize);
		ublk_pins[0].update(buffer, base, numBytes);
		base += numBytes;
		pin_tries = buffer[base++];
		ublk_tries = buffer[base++];
		numBytes = buffer[base++];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		pins[1] = new OwnerPIN(pin_tries, (byte)pinMaxSize);
		pins[1].update(buffer, base, numBytes);
		base += numBytes;
		numBytes = buffer[base++];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt((short)SW_INVALID_PARAMETER);

		ublk_pins[1] = new OwnerPIN(ublk_tries, (byte)pinMaxSize);
		ublk_pins[1].update(buffer, base, numBytes);
		base += numBytes;
		base += 2;
		short mem_size = Util.getShort(buffer, base);
		base += 2;
		create_object_ACL = buffer[base++];
		create_key_ACL = buffer[base++];
		create_pin_ACL = buffer[base++];
		mem = new MemoryManager(mem_size);
		om = new ObjectManager(mem);
		keys = new Key[MAX_NUM_KEYS];
		keyACLs = new byte[48];
		keyTries = new byte[MAX_NUM_KEYS];
		for(byte i = 0; i < MAX_NUM_KEYS; i++)
			keyTries[i] = MAX_KEY_TRIES;

		keyPairs = new KeyPair[MAX_NUM_KEYS];
		ciphers = new Cipher[MAX_NUM_KEYS];
		signatures = new Signature[MAX_NUM_KEYS];
		ciph_dirs = new byte[MAX_NUM_KEYS];
		for(byte i = 0; i < MAX_NUM_KEYS; i++)
			ciph_dirs[i] = -1;

		logged_ids = 0;
		getChallengeDone = false;
		randomData = null;
		STD_PUBLIC_ACL = new byte[6];
		for(byte i = 0; i < 6; i += 2)
			Util.setShort(STD_PUBLIC_ACL, i, (short)0);

		setupDone = true;
	}
}

