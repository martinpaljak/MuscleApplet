package com.sun.javacard.samples.CardEdge;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
public class CardEdge extends javacard.framework.Applet {
    private final static byte MAX_NUM_KEYS = (byte) 8;
    private final static byte MAX_NUM_PINS = (byte) 8;
    private final static byte MAX_NUM_AUTH_KEYS = (byte) 6;
    private final static byte PIN_POLICY_SIZE = (byte) 0x01;
    private final static byte PIN_POLICY_CHARSET = (byte) 0x02;
    private final static byte PIN_POLICY_MIXED = (byte) 0x04;
    private final static byte PIN_CHARSET_NUMBERS = (byte) 0x01;
    private final static byte PIN_CHARSET_UC_LETTERS = (byte) 0x02;
    private final static byte PIN_CHARSET_LC_LETTERS = (byte) 0x04;
    private final static byte PIN_CHARSET_PUNCT = (byte) 0x08;
    private final static byte PIN_CHARSET_OTHERS = (byte) 0x80;
    private final static byte PIN_MIXED_TWO = (byte) 0x01;
    private final static byte PIN_MIXED_CASE = (byte) 0x02;
    private final static byte PIN_MIXED_ALL = (byte) 0x04;
    private final static byte pinPolicies =
        (byte) (PIN_POLICY_SIZE | PIN_POLICY_CHARSET | PIN_POLICY_MIXED);
    private final static byte pinMinSize = (byte) 4;
    private final static byte pinMaxSize = (byte) 16;
    private final static byte MAX_KEY_TRIES = (byte) 5;
    private static byte[] PIN_INIT_VALUE;
    private final static short IN_OBJECT_CLA = (short) 0xFFFF;
    private final static short IN_OBJECT_ID = (short) 0xFFFE;
    private final static short OUT_OBJECT_CLA = (short) 0xFFFF;
    private final static short OUT_OBJECT_ID = (short) 0xFFFF;
    private final static byte KEY_ACL_SIZE = (byte) 6;
    private static byte[] STD_PUBLIC_ACL;
    private static byte[] acl;
    private final static byte CardEdge_CLA = (byte) 0xB0;
    private final static byte INS_SETUP = (byte) 0x2A;
    private final static byte INS_GEN_KEYPAIR = (byte) 0x30;
    private final static byte INS_IMPORT_KEY = (byte) 0x32;
    private final static byte INS_EXPORT_KEY = (byte) 0x34;
    private final static byte INS_COMPUTE_CRYPT = (byte) 0x36;
    private final static byte INS_CREATE_PIN = (byte) 0x40;
    private final static byte INS_VERIFY_PIN = (byte) 0x42;
    private final static byte INS_CHANGE_PIN = (byte) 0x44;
    private final static byte INS_UNBLOCK_PIN = (byte) 0x46;
    private final static byte INS_LOGOUT_ALL = (byte) 0x60;
    private final static byte INS_GET_CHALLENGE = (byte) 0x62;
    private final static byte INS_EXT_AUTH = (byte) 0x38;
    private final static byte INS_CREATE_OBJ = (byte) 0x5A;
    private final static byte INS_DELETE_OBJ = (byte) 0x52;
    private final static byte INS_READ_OBJ = (byte) 0x56;
    private final static byte INS_WRITE_OBJ = (byte) 0x54;
    private final static byte INS_LIST_OBJECTS =(byte) 0x58;
    private final static byte INS_LIST_PINS = (byte) 0x48;
    private final static byte INS_LIST_KEYS = (byte) 0x3A;
    private final static byte INS_GET_STATUS = (byte) 0x3C;
    private final static short SW_NO_MEMORY_LEFT = ObjectManager.SW_NO_MEMORY_LEFT;
    private final static short SW_AUTH_FAILED = (short) 0x9C02;
    private final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
    private final static short SW_UNSUPPORTED_FEATURE = (short) 0x9C05;
    private final static short SW_UNAUTHORIZED = (short) 0x9C06;
    private final static short SW_OBJECT_NOT_FOUND = (short) 0x9C07;
    private final static short SW_OBJECT_EXISTS = (short) 0x9C08;
    private final static short SW_INCORRECT_ALG = (short) 0x9C09;
    private final static short SW_INCORRECT_P1 = (short) 0x9C10;
    private final static short SW_INCORRECT_P2 = (short) 0x9C11;
    private final static short SW_SEQUENCE_END = (short) 0x9C12;
    private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;
    private final static short SW_SIGNATURE_INVALID = (short) 0x9C0B;
    private final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
    private final static short SW_UNSPECIFIED_ERROR = (short) 0x9C0D;
    private final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
    private final static byte ALG_RSA = (byte) 0x00;
    private final static byte ALG_RSA_CRT = (byte) 0x01;
    private final static byte ALG_DSA = (byte) 0x02;
    private final static byte ALG_DES = (byte) 0x03;
    private final static byte ALG_3DES = (byte) 0x04;
    private final static byte ALG_3DES3 = (byte) 0x05;
    private final static byte KEY_RSA_PUBLIC = (byte) 0x01;
    private final static byte KEY_RSA_PRIVATE = (byte) 0x02;
    private final static byte KEY_RSA_PRIVATE_CRT = (byte) 0x03;
    private final static byte KEY_DSA_PUBLIC = (byte) 0x04;
    private final static byte KEY_DSA_PRIVATE = (byte) 0x05;
    private final static byte KEY_DES = (byte) 0x06;
    private final static byte KEY_3DES = (byte) 0x07;
    private final static byte KEY_3DES3 = (byte) 0x08;
    private final static byte BLOB_ENC_PLAIN = (byte) 0x00;
    private final static byte OP_INIT = (byte) 0x01;
    private final static byte OP_PROCESS = (byte) 0x02;
    private final static byte OP_FINALIZE = (byte) 0x03;
    private final static byte CD_SIGN = (byte) 0x01;
    private final static byte CD_VERIFY = (byte) 0x02;
    private final static byte CD_ENCRYPT = (byte) 0x03;
    private final static byte CD_DECRYPT = (byte) 0x04;
    private final static byte CM_RSA_NOPAD = (byte) 0x00;
    private final static byte CM_RSA_PAD_PKCS1 =(byte) 0x01;
    private final static byte CM_DSA_SHA = (byte) 0x10;
    private final static byte CM_DES_CBC_NOPAD =(byte) 0x20;
    private final static byte CM_DES_ECB_NOPAD =(byte) 0x21;
    private final static byte DL_APDU = (byte) 0x01;
    private final static byte DL_OBJECT = (byte) 0x02;
    private final static byte LIST_OPT_RESET = (byte) 0x00;
    private final static byte LIST_OPT_NEXT = (byte) 0x01;
    private final static byte OPT_DEFAULT =
        (byte) 0x00;
    private final static byte OPT_RSA_PUB_EXP =
        (byte) 0x01;
    private final static byte OPT_DSA_GPQ =
        (byte) 0x02;
    private final static short OFFSET_GENKEY_ALG =
        (short) (ISO7816.OFFSET_CDATA);
    private final static short OFFSET_GENKEY_SIZE =
        (short) (ISO7816.OFFSET_CDATA + 1);
    private final static short OFFSET_GENKEY_PRV_ACL =
        (short) (ISO7816.OFFSET_CDATA + 3);
    private final static short OFFSET_GENKEY_PUB_ACL =
        (short) (OFFSET_GENKEY_PRV_ACL + KEY_ACL_SIZE);
    private final static short OFFSET_GENKEY_OPTIONS =
        (short) (OFFSET_GENKEY_PUB_ACL + KEY_ACL_SIZE);
    private final static short OFFSET_GENKEY_RSA_PUB_EXP_LENGTH =
        (short) (OFFSET_GENKEY_OPTIONS + 1);
    private final static short OFFSET_GENKEY_RSA_PUB_EXP_VALUE =
        (short) (OFFSET_GENKEY_RSA_PUB_EXP_LENGTH + 2);
    private final static short OFFSET_GENKEY_DSA_GPQ =
        (short) (OFFSET_GENKEY_OPTIONS + 1);
    private MemoryManager mem;
    private ObjectManager om;
    private Key[] keys;
    private byte[] keyACLs;
    private byte[] keyTries;
    private byte key_it;
    private boolean getChallengeDone;
    private Cipher[] ciphers;
    private Signature[] signatures;
    private byte[] ciph_dirs;
    private KeyPair[] keyPairs;
    private RandomData randomData;
    private OwnerPIN[] pins, ublk_pins;
    private short logged_ids;
    private boolean setupDone = false;
    private byte create_object_ACL;
    private byte create_key_ACL;
    private byte create_pin_ACL;
    private CardEdge (byte[] bArray, short bOffset,byte bLength){
        PIN_INIT_VALUE = new byte[8];
        PIN_INIT_VALUE[0] = (byte)'M';
        PIN_INIT_VALUE[1] = (byte)'u';
        PIN_INIT_VALUE[2] = (byte)'s';
        PIN_INIT_VALUE[3] = (byte)'c';
        PIN_INIT_VALUE[4] = (byte)'l';
        PIN_INIT_VALUE[5] = (byte)'e';
        PIN_INIT_VALUE[6] = (byte)'0';
        PIN_INIT_VALUE[7] = (byte)'0';
        if (!CheckPINPolicy(PIN_INIT_VALUE, (short) 0,
                            (byte) PIN_INIT_VALUE.length))
            ISOException.throwIt(SW_INTERNAL_ERROR);
        ublk_pins = new OwnerPIN[MAX_NUM_PINS];
        pins = new OwnerPIN[MAX_NUM_PINS];
        pins[0] = new OwnerPIN((byte) 3, pinMaxSize);
        pins[0].update(PIN_INIT_VALUE, (short) 0,
                       (byte) PIN_INIT_VALUE.length);
    }
    public static void install(byte[] bArray, short bOffset, byte bLength){
        CardEdge wal = new CardEdge (bArray, bOffset, bLength);
        if (bArray[bOffset] == 0)
            wal.register();
        else
            wal.register(bArray, (short) (bOffset + 1),
                         (byte)(bArray[bOffset]));
    }
    public boolean select() {
        if (setupDone) {
            om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
            om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
        }
        LogOutAll();
        return true;
    }
    public void deselect() {
        if (setupDone) {
            om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
            om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
        }
        LogOutAll();
    }
    public void process(APDU apdu) {
        if (selectingApplet())
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        byte[] buffer = apdu.getBuffer();
        if ((buffer[ISO7816.OFFSET_CLA] == 0) &&
            (buffer[ISO7816.OFFSET_INS] == (byte) 0xA4) )
            return;
        if (buffer[ISO7816.OFFSET_CLA] != CardEdge_CLA)
            ISOException.throwIt
                (ISO7816.SW_CLA_NOT_SUPPORTED);
        byte ins = buffer[ISO7816.OFFSET_INS];
        if (!setupDone && (ins != (byte) INS_SETUP))
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
        if (setupDone && (ins == (byte) INS_SETUP))
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        switch (ins) {
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
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
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
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        };
    }
    private void setup(APDU apdu, byte[] buffer) {
        short bytesLeft = Util.makeShort((byte) 0x00,
                            buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short base = (short) (ISO7816.OFFSET_CDATA);
        byte numBytes = buffer[base++];
        OwnerPIN pin = pins[0];
        if (!CheckPINPolicy(buffer, base, numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (pin.getTriesRemaining() == (byte) 0x00)
            ISOException.throwIt(SW_IDENTITY_BLOCKED);
        if (!pin.check(buffer, base, numBytes))
            ISOException.throwIt(SW_AUTH_FAILED);
        base += numBytes;
        byte pin_tries = buffer[base++];
        byte ublk_tries = buffer[base++];
        numBytes = buffer[base++];
        if (!CheckPINPolicy(buffer, base, numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        pins[0] = new OwnerPIN(pin_tries, pinMaxSize);
        pins[0].update(buffer, base, numBytes);
        base += numBytes;
        numBytes = buffer[base++];
        if (!CheckPINPolicy(buffer, base, numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        ublk_pins[0] = new OwnerPIN(ublk_tries, pinMaxSize);
        ublk_pins[0].update(buffer, base, numBytes);
        base += numBytes;
        pin_tries = buffer[base++];
        ublk_tries = buffer[base++];
        numBytes = buffer[base++];
        if (!CheckPINPolicy(buffer, base, numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        pins[1] = new OwnerPIN(pin_tries, pinMaxSize);
        pins[1].update(buffer, base, numBytes);
        base += numBytes;
        numBytes = buffer[base++];
        if (!CheckPINPolicy(buffer, base, numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        ublk_pins[1] = new OwnerPIN(ublk_tries, pinMaxSize);
        ublk_pins[1].update(buffer, base, numBytes);
        base += numBytes;
        base += (short) 2;
        short mem_size = Util.getShort(buffer, base);
        base += (short) 2;
        create_object_ACL = buffer[base++];
        create_key_ACL = buffer[base++];
        create_pin_ACL = buffer[base++];
        mem = new MemoryManager((short) mem_size);
        om = new ObjectManager(mem);
        keys = new Key[MAX_NUM_KEYS];
        keyACLs = new byte[(short) (MAX_NUM_KEYS * KEY_ACL_SIZE)];
        keyTries = new byte[MAX_NUM_KEYS];
        for (byte i = (byte) 0; i < (byte) MAX_NUM_KEYS; i++)
            keyTries[i] = MAX_KEY_TRIES;
        keyPairs = new KeyPair[MAX_NUM_KEYS];
        ciphers = new Cipher[MAX_NUM_KEYS];
        signatures = new Signature[MAX_NUM_KEYS];
        ciph_dirs = new byte[MAX_NUM_KEYS];
        for (byte i = (byte) 0; i < (byte) MAX_NUM_KEYS; i++)
            ciph_dirs[i] = (byte) 0xFF;
        logged_ids = 0x00;
        getChallengeDone = false;
        randomData = null;
        STD_PUBLIC_ACL = new byte[KEY_ACL_SIZE];
        for (byte i = (byte) 0; i < (byte) KEY_ACL_SIZE; i += (short) 2)
            Util.setShort(STD_PUBLIC_ACL, i, (short)0x0000);
        setupDone = true;
    }
    private void sendData(APDU apdu, byte[] data, short offset, short size) {
        if (size > 255)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopyNonAtomic(data, offset, apdu.getBuffer(), (short) 0, size);
        apdu.setOutgoingAndSend((short) 0, size);
    }
    private Cipher getCipher(byte key_nb, byte alg_id) {
        if (ciphers[key_nb] == null) {
            ciphers[key_nb] = Cipher.getInstance(alg_id, false);
        } else
            if (ciphers[key_nb].getAlgorithm() != alg_id)
                ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
        return ciphers[key_nb];
    }
    private Signature getSignature(byte key_nb, byte alg_id) {
        if (signatures[key_nb] == null) {
            signatures[key_nb] = Signature.getInstance(alg_id, false);
        } else
            if (signatures[key_nb].getAlgorithm() != alg_id)
                ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
        return signatures[key_nb];
    }
    private Key getKey(byte key_nb, byte key_type, short key_size) {
        byte jc_key_type = keyType2JCType(key_type);
        if (keys[key_nb] == null) {
            if ((create_key_ACL == (byte) 0xFF) ||
                (((logged_ids & create_key_ACL) == (short) 0x0000) &&
                (create_key_ACL != (byte) 0x00)))
                ISOException.throwIt(SW_UNAUTHORIZED);
            keys[key_nb] = KeyBuilder.buildKey(jc_key_type, key_size, false);
        } else {
            if ((keys[key_nb].getSize() != key_size)
                || (keys[key_nb].getType() != jc_key_type))
                ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
        }
        return keys[key_nb];
    }
    private byte keyType2JCType(byte key_type) {
        switch (key_type) {
        case KEY_RSA_PUBLIC:
            return KeyBuilder.TYPE_RSA_PUBLIC;
        case KEY_RSA_PRIVATE:
            return KeyBuilder.TYPE_RSA_PRIVATE;
        case KEY_RSA_PRIVATE_CRT:
            return KeyBuilder.TYPE_RSA_CRT_PRIVATE;
        case KEY_DSA_PUBLIC:
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
        case KEY_DSA_PRIVATE:
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
        case KEY_DES:
            return KeyBuilder.TYPE_DES;
        case KEY_3DES:
        case KEY_3DES3:
            return KeyBuilder.TYPE_DES;
        default:
            ISOException.throwIt(SW_INVALID_PARAMETER);
        }
        return (byte) 0;
    }
    private byte getKeyType(Key key) {
        switch (key.getType()) {
        case KeyBuilder.TYPE_RSA_PUBLIC:
            return KEY_RSA_PUBLIC;
        case KeyBuilder.TYPE_RSA_PRIVATE:
            return KEY_RSA_PRIVATE;
        case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
            return KEY_RSA_PRIVATE_CRT;
        case KeyBuilder.TYPE_DES:
            if (key.getSize() == (short) 64)
                return KEY_DES;
            if (key.getSize() == (short) 128)
                return KEY_3DES;
            if (key.getSize() == (short) 192)
                return KEY_3DES3;
        default:
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }
        return (byte) 0;
    }
    boolean authorizeKeyRead(byte key_nb) {
        short acl_offset = (short) (key_nb * KEY_ACL_SIZE);
        short required_ids = Util.getShort(keyACLs, acl_offset);
        return ((required_ids != (short) 0xFFFF)
                && ((short) (required_ids & logged_ids) == required_ids));
    }
    boolean authorizeKeyWrite(byte key_nb) {
        short acl_offset = (short) (key_nb * KEY_ACL_SIZE + 2);
        short required_ids = Util.getShort(keyACLs, acl_offset);
        return ((required_ids != (short) 0xFFFF)
                && ((short) (required_ids & logged_ids) == required_ids));
    }
    boolean authorizeKeyUse(byte key_nb) {
        short acl_offset = (short) (key_nb * KEY_ACL_SIZE + 4);
        short required_ids = Util.getShort(keyACLs, acl_offset);
        return ((required_ids != (short) 0xFFFF)
                && ((short) (required_ids & logged_ids) == required_ids));
    }
    byte[] getCurrentACL() {
        if (acl == null)
            acl = new byte[KEY_ACL_SIZE];
        byte i;
        for (i = (byte) 0; i < KEY_ACL_SIZE; i += (byte) 2)
            Util.setShort(acl, i, logged_ids);
        return acl;
    }
    byte[] getRestrictedACL() {
        if (acl == null)
            acl = new byte[KEY_ACL_SIZE];
        byte i;
        for (i = (byte) 0; i < KEY_ACL_SIZE; i += (byte) 2)
            Util.setShort(acl, i, (short) 0xFFFF);
        return acl;
    }
    private void LoginStrongIdentity(byte key_nb) {
        logged_ids |= (short) (((short) 0x01) << (key_nb + 8));
    }
    private void LogoutIdentity(byte id_nb) {
        logged_ids &= (short) ~(0x0001 << id_nb);
    }
    private void ThrowDeleteObjects(short exception) {
        om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
        om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
        ISOException.throwIt(exception);
    }
    private boolean CheckPINPolicy(byte[] pin_buffer, short pin_offset, byte pin_size) {
        if ((pinPolicies & PIN_POLICY_SIZE) != (byte) 0x00) {
            if ((pin_size < pinMinSize) || (pin_size > pinMaxSize))
                return false;
        }
        return true;
    }
    private void ComputeCrypt(APDU apdu, byte[] buffer) {
        short bytesLeft = Util.makeShort((byte) 0x00,
                            buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte key_nb = buffer[ISO7816.OFFSET_P1];
        if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS)
            || (keys[key_nb] == null))
            ISOException.throwIt(SW_INCORRECT_P1);
        if (! authorizeKeyUse(key_nb))
            ISOException.throwIt(SW_UNAUTHORIZED);
        byte op = buffer[ISO7816.OFFSET_P2];
        Key key = keys[key_nb];
        byte ciph_dir;
        byte data_location;
        byte[] src_buff;
        short src_base;
        short src_avail;
        short size;
        switch (op) {
        case OP_INIT:
            if (bytesLeft < 3)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            byte ciph_mode = buffer[ISO7816.OFFSET_CDATA];
            ciph_dir = buffer[(short) (ISO7816.OFFSET_CDATA + 1)];
            byte ciph_alg_id;
            data_location = buffer[(short) (ISO7816.OFFSET_CDATA + 2)];
            switch (data_location) {
            case DL_APDU:
                src_buff = buffer;
                src_base = (short) (ISO7816.OFFSET_CDATA + 3);
                src_avail = (short) (bytesLeft - 3);
                break;
            case DL_OBJECT:
                src_buff = mem.getBuffer();
                src_base = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
                if (src_base == mem.NULL_OFFSET)
                    ISOException.throwIt(SW_OBJECT_NOT_FOUND);
                src_avail = om.getSizeFromAddress(src_base);
                break;
            default:
                ISOException.throwIt(SW_INVALID_PARAMETER);
                return;
            }
            if (src_avail < 2)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            size = Util.getShort(src_buff, src_base);
            if (src_avail < (short) (2 + size))
                ISOException.throwIt(SW_INVALID_PARAMETER);
            switch (ciph_dir) {
            case CD_SIGN:
            case CD_VERIFY:
                switch (key.getType()) {
                case KeyBuilder.TYPE_RSA_PUBLIC:
                case KeyBuilder.TYPE_RSA_PRIVATE:
                    ciph_alg_id = Signature.ALG_RSA_MD5_PKCS1;
                    ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
                    break;
                case KeyBuilder.TYPE_DSA_PUBLIC:
                case KeyBuilder.TYPE_DSA_PRIVATE:
                    ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
                    return;
                default:
                    ISOException.throwIt(SW_INCORRECT_ALG);
                    return;
                }
                Signature sign = getSignature(key_nb, ciph_alg_id);
                if (size == (short) 0)
                    sign.init(key, (ciph_dir == CD_SIGN) ? Signature.MODE_SIGN : Signature.MODE_VERIFY);
                else
                    sign.init(key, (ciph_dir == CD_SIGN) ? Signature.MODE_SIGN : Signature.MODE_VERIFY,
                              src_buff, (short) (src_base + 2), size);
                ciph_dirs[key_nb] = ciph_dir;
                break;
            case CD_ENCRYPT:
            case CD_DECRYPT:
                switch (key.getType()) {
                case KeyBuilder.TYPE_RSA_PUBLIC:
                case KeyBuilder.TYPE_RSA_PRIVATE:
                case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
                    if (ciph_mode == CM_RSA_NOPAD)
                        ciph_alg_id = Cipher.ALG_RSA_NOPAD;
                    else if (ciph_mode == CM_RSA_PAD_PKCS1)
                        ciph_alg_id = Cipher.ALG_RSA_PKCS1;
                    else {
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                        return;
                    }
                    break;
                case KeyBuilder.TYPE_DES:
                    if (ciph_mode == CM_DES_CBC_NOPAD)
                        ciph_alg_id = Cipher.ALG_DES_CBC_NOPAD;
                    else if (ciph_mode == CM_DES_ECB_NOPAD)
                        ciph_alg_id = Cipher.ALG_DES_ECB_NOPAD;
                    else {
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                        return;
                    }
                    break;
                case KeyBuilder.TYPE_DSA_PUBLIC:
                case KeyBuilder.TYPE_DSA_PRIVATE:
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                    return;
                default:
                    ISOException.throwIt(SW_INTERNAL_ERROR);
                    return;
                }
                Cipher ciph = getCipher(key_nb, ciph_alg_id);
                if (size == (short) 0)
                    ciph.init(key, (ciph_dir == CD_ENCRYPT) ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT);
                else
                    ciph.init(key, (ciph_dir == CD_ENCRYPT) ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT,
                              src_buff, (short) (src_base + 2), size);
                ciph_dirs[key_nb] = ciph_dir;
                break;
            default:
                ISOException.throwIt(SW_INVALID_PARAMETER);
            }
            break;
        case OP_PROCESS:
        case OP_FINALIZE:
            ciph_dir = ciph_dirs[key_nb];
            switch (ciph_dir) {
            case CD_SIGN:
            case CD_VERIFY:
                Signature sign = signatures[key_nb];
                if (sign == null)
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                data_location = buffer[ISO7816.OFFSET_CDATA];
                switch (data_location) {
                case DL_APDU:
                    src_buff = mem.getBuffer();
                    src_base = (short) (ISO7816.OFFSET_CDATA + 1);
                    src_avail = (short) (bytesLeft - 1);
                    break;
                case DL_OBJECT:
                    src_buff = mem.getBuffer();
                    src_base = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
                    if (src_base == MemoryManager.NULL_OFFSET)
                        ISOException.throwIt(SW_OBJECT_NOT_FOUND);
                    src_avail = om.getSizeFromAddress(src_base);
                    break;
                default:
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                    return;
                }
                if (src_avail < 2)
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                size = Util.getShort(src_buff, src_base);
                if (src_avail < (short) (2 + size))
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                if (op == OP_PROCESS)
                    sign.update(src_buff, (short) (src_base + 2), size);
                else {
                    if (ciph_dir == CD_SIGN) {
                        om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
                        short dst_base = om.createObject(OUT_OBJECT_CLA, OUT_OBJECT_ID,
                                                         (short) (sign.getLength() + 2),
                                                         getCurrentACL(), (short) 0);
                        if (dst_base == MemoryManager.NULL_OFFSET)
                            ISOException.throwIt(SW_NO_MEMORY_LEFT);
                        short sign_size = sign.sign(src_buff, (short) (src_base + 2),
                                                    size, mem.getBuffer(), (short) (dst_base + 2));
                        if (sign_size > sign.getLength())
                            ISOException.throwIt(SW_INTERNAL_ERROR);
                        mem.setShort(dst_base, sign_size);
                        if (data_location == DL_APDU) {
                            sendData(apdu, mem.getBuffer(), dst_base, (short) (sign_size + 2));
                            om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
                        }
                    } else {
                        if (src_avail < (short) (2 + size + 2))
                            ISOException.throwIt(SW_INVALID_PARAMETER);
                        short sign_size = Util.getShort(src_buff, (short) (src_base + 2 + size));
                        if (src_avail < (short) (2 + size + 2 + sign_size))
                            ISOException.throwIt(SW_INVALID_PARAMETER);
                        if (sign_size != sign.getLength())
                            ISOException.throwIt(SW_INVALID_PARAMETER);
                        if (! sign.verify(src_buff, (short) (src_base + 2), size,
                                          src_buff, (short) (src_base + 2 + size + 2), sign_size))
                            ISOException.throwIt(SW_SIGNATURE_INVALID);
                    }
                }
                break;
            case CD_ENCRYPT:
            case CD_DECRYPT:
                Cipher ciph = ciphers[key_nb];
                if (ciph == null)
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                data_location = buffer[ISO7816.OFFSET_CDATA];
                switch (data_location) {
                case DL_APDU:
                    src_buff = buffer;
                    src_base = (short) (ISO7816.OFFSET_CDATA + 1);
                    src_avail = (short) (bytesLeft - 1);
                    break;
                case DL_OBJECT:
                    src_buff = mem.getBuffer();
                    src_base = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
                    if (src_base == MemoryManager.NULL_OFFSET)
                        ISOException.throwIt(SW_OBJECT_NOT_FOUND);
                    src_avail = om.getSizeFromAddress(src_base);
                    break;
                default:
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                        return;
                }
                if (src_avail < 2)
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                size = Util.getShort(src_buff, src_base);
                if (src_avail < (short) (2 + size))
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
                short dst_base = om.createObject(OUT_OBJECT_CLA, OUT_OBJECT_ID,
                                           (short) (size + 2),
                                           getCurrentACL(), (short) 0);
                if (dst_base == MemoryManager.NULL_OFFSET)
                    ISOException.throwIt(SW_NO_MEMORY_LEFT);
                mem.setShort(dst_base, size);
                if (op == OP_PROCESS)
                    ciph.update(src_buff, (short) (src_base + 2),
                                size, mem.getBuffer(), (short) (dst_base + 2));
                else
                    ciph.doFinal(src_buff, (short) (src_base + 2),
                                size, mem.getBuffer(), (short) (dst_base + 2));
                if (data_location == DL_APDU) {
                    Util.arrayCopyNonAtomic(mem.getBuffer(), dst_base,
                                            buffer, (short) 0, (short) (size + 2));
                    om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
                    sendData(apdu, buffer, (short) 0, (short) (size + 2));
                }
                break;
            default:
                ISOException.throwIt(SW_INTERNAL_ERROR);
            }
            break;
        default:
            ISOException.throwIt(SW_INCORRECT_P2);
        }
    }
    private void GenerateKeyPair(APDU apdu, byte[] buffer) {
        short bytesLeft = Util.makeShort((byte) 0x00,
                            buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte alg_id = buffer[OFFSET_GENKEY_ALG];
        switch (alg_id) {
        case ALG_RSA:
        case ALG_RSA_CRT:
            GenerateKeyPairRSA(buffer);
            break;
        case ALG_DSA:
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
            break;
        default:
            ISOException.throwIt(SW_INCORRECT_ALG);
        }
    }
    private void GenerateKeyPairRSA(byte[] buffer) {
        byte prv_key_nb = buffer[ISO7816.OFFSET_P1];
        if ((prv_key_nb < 0) || (prv_key_nb >= MAX_NUM_KEYS))
            ISOException.throwIt(SW_INCORRECT_P1);
        byte pub_key_nb = buffer[ISO7816.OFFSET_P2];
        if ((pub_key_nb < 0) || (pub_key_nb >= MAX_NUM_KEYS))
            ISOException.throwIt(SW_INCORRECT_P2);
        if (pub_key_nb == prv_key_nb)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        byte alg_id = buffer[OFFSET_GENKEY_ALG];
        short key_size = Util.getShort(buffer, OFFSET_GENKEY_SIZE);
        byte options = buffer[OFFSET_GENKEY_OPTIONS];
        RSAPublicKey pub_key = (RSAPublicKey)
            getKey(pub_key_nb, KEY_RSA_PUBLIC, key_size);
        PrivateKey prv_key = (PrivateKey) getKey(
          prv_key_nb,
          alg_id == ALG_RSA ? KEY_RSA_PRIVATE : KEY_RSA_PRIVATE_CRT,
          key_size);
        if (pub_key.isInitialized() && ! authorizeKeyWrite(pub_key_nb))
            ISOException.throwIt(SW_UNAUTHORIZED);
        if (prv_key.isInitialized() && ! authorizeKeyWrite(prv_key_nb))
            ISOException.throwIt(SW_UNAUTHORIZED);
        Util.arrayCopy(buffer, OFFSET_GENKEY_PRV_ACL, keyACLs,
                       (short) (prv_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
        Util.arrayCopy(buffer, OFFSET_GENKEY_PUB_ACL, keyACLs,
                       (short) (pub_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
        switch (options) {
        case OPT_DEFAULT:
            if (pub_key.isInitialized())
                pub_key.clearKey();
            break;
        case OPT_RSA_PUB_EXP:
            short exp_length =
                Util.getShort(buffer, OFFSET_GENKEY_RSA_PUB_EXP_LENGTH);
            pub_key.setExponent(buffer,
                                OFFSET_GENKEY_RSA_PUB_EXP_VALUE,
                                exp_length);
            break;
        default:
            ISOException.throwIt(SW_INVALID_PARAMETER);
        }
        if ((keyPairs[pub_key_nb] == null) && (keyPairs[prv_key_nb] == null)) {
            keyPairs[pub_key_nb] = new KeyPair(pub_key, prv_key);
            keyPairs[prv_key_nb] = keyPairs[pub_key_nb];
        } else if (keyPairs[pub_key_nb] != keyPairs[prv_key_nb])
            ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
        KeyPair kp = keyPairs[pub_key_nb];
        if ((kp.getPublic() != pub_key) || (kp.getPrivate() != prv_key))
            ISOException.throwIt(SW_INTERNAL_ERROR);
        kp.genKeyPair();
    }
    private void ImportKey(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short bytesLeft = Util.makeShort((byte) 0x00,
                            buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte key_nb = buffer[ISO7816.OFFSET_P1];
        if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
            ISOException.throwIt(SW_INCORRECT_P1);
        if ((keys[key_nb] != null)
            && keys[key_nb].isInitialized()
            && ! authorizeKeyWrite(key_nb))
            ISOException.throwIt(SW_UNAUTHORIZED);
        short base = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
        if (base == MemoryManager.NULL_OFFSET)
            ISOException.throwIt(SW_OBJECT_NOT_FOUND);
        short avail = om.getSizeFromAddress(base);
        if (avail < 4)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (mem.getByte(base) != BLOB_ENC_PLAIN)
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
        base++;
        avail--;
        byte key_type = mem.getByte(base);
        base++;
        avail--;
        short key_size = mem.getShort(base);
        base += (short) 2;
        avail -= (short) 2;
        short size;
        switch (key_type) {
        case KEY_RSA_PUBLIC:
            RSAPublicKey rsa_pub_key =
                (RSAPublicKey) getKey(key_nb, key_type, key_size);
            if (avail < 2)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < (short) (size + 2))
                ISOException.throwIt(SW_INVALID_PARAMETER);
            rsa_pub_key.setModulus(mem.getBuffer(), base, size);
            base += size;
            avail -= size;
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < size)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            rsa_pub_key.setExponent(mem.getBuffer(), base, size);
            base += size;
            avail -= size;
            break;
        case KEY_RSA_PRIVATE:
            RSAPrivateKey rsa_prv_key =
                (RSAPrivateKey) getKey(key_nb, key_type, key_size);
            if (avail < 2)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < (short) (size + 2))
                ISOException.throwIt(SW_INVALID_PARAMETER);
            rsa_prv_key.setModulus(mem.getBuffer(), base, size);
            base += size;
            avail -= size;
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < size)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            rsa_prv_key.setExponent(mem.getBuffer(), base, size);
            base += size;
            avail -= size;
            break;
        case KEY_RSA_PRIVATE_CRT:
            RSAPrivateCrtKey rsa_prv_key_crt =
                (RSAPrivateCrtKey) getKey(key_nb, key_type, key_size);
            if (avail < 2)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < (short) (size + 2))
                ISOException.throwIt(SW_INVALID_PARAMETER);
            rsa_prv_key_crt.setP(mem.getBuffer(), base, size);
            base += size;
            avail -= size;
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < (short) (size + 2))
                ISOException.throwIt(SW_INVALID_PARAMETER);
            rsa_prv_key_crt.setQ(mem.getBuffer(), base, size);
            base += size;
            avail -= size;
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < (short) (size + 2))
                ISOException.throwIt(SW_INVALID_PARAMETER);
            rsa_prv_key_crt.setPQ(mem.getBuffer(), base, size);
            base += size;
            avail -= size;
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < (short) (size + 2))
                ISOException.throwIt(SW_INVALID_PARAMETER);
            rsa_prv_key_crt.setDP1(mem.getBuffer(), base, size);
            base += size;
            avail -= size;
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < size)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            rsa_prv_key_crt.setDQ1(mem.getBuffer(), base, size);
            base += size;
            avail -= size;
            break;
        case KEY_DSA_PRIVATE:
        case KEY_DSA_PUBLIC:
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
        case KEY_DES:
        case KEY_3DES:
        case KEY_3DES3:
            DESKey des_key = (DESKey) getKey(key_nb, key_type, key_size);
            if (avail < 2)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            size = mem.getShort(base);
            base += (short) 2;
            avail -= (short) 2;
            if (avail < size)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            des_key.setKey(mem.getBuffer(), base);
            base += size;
            avail -= size;
            break;
        default:
            ISOException.throwIt(SW_INCORRECT_ALG);
        }
        om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
    }
    private void ExportKey(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short bytesLeft = Util.makeShort((byte) 0x00,
                            buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte key_nb = buffer[ISO7816.OFFSET_P1];
        if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
            ISOException.throwIt(SW_INCORRECT_P1);
        Key key = keys[key_nb];
        if ((key == null) || ! key.isInitialized())
            ISOException.throwIt(SW_INCORRECT_P1);
        if (! authorizeKeyRead(key_nb))
            ISOException.throwIt(SW_UNAUTHORIZED);
        om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
        short base = om.createObjectMax(OUT_OBJECT_CLA, OUT_OBJECT_ID,
                                     getCurrentACL(), (short) 0);
        short buffer_size = om.getSizeFromAddress(base);
        short avail = buffer_size;
        if (buffer[ISO7816.OFFSET_CDATA] != BLOB_ENC_PLAIN)
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
        if (avail < 4)
            ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
        mem.setByte(base, BLOB_ENC_PLAIN);
        base++;
        byte key_type = key.getType();
        mem.setByte(base, getKeyType(key));
        base++;
        short key_size = key.getSize();
        mem.setShort(base, key_size);
        base += (short) 2;
        avail -= (short) 4;
        short size;
        short bn_size = (short) (keys[key_nb].getSize() / 8 + 2);
        switch (key_type) {
        case KeyBuilder.TYPE_RSA_PUBLIC:
            RSAPublicKey pub_key = (RSAPublicKey) key;
            if (avail < bn_size)
                ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
            size = pub_key.getModulus(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            if (avail < bn_size)
                ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
            size = pub_key.getExponent(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            break;
        case KeyBuilder.TYPE_RSA_PRIVATE:
            RSAPrivateKey prv_key = (RSAPrivateKey) key;
            if (avail < bn_size)
                ISOException.throwIt(SW_NO_MEMORY_LEFT);
            size = prv_key.getModulus(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            if (avail < bn_size)
                ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
            size = prv_key.getExponent(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            break;
        case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
            RSAPrivateCrtKey prv_key_crt = (RSAPrivateCrtKey) key;
            if (avail < bn_size)
                ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
            size = prv_key_crt.getP(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            if (avail < bn_size)
                ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
            size = prv_key_crt.getQ(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            if (avail < bn_size)
                ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
            size = prv_key_crt.getPQ(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            if (avail < bn_size)
                ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
            size = prv_key_crt.getDP1(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            if (avail < bn_size)
                ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
            size = prv_key_crt.getDQ1(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            break;
        case KeyBuilder.TYPE_DES:
            DESKey des_key = (DESKey) key;
            if (avail < bn_size)
                ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
            size = des_key.getKey(mem.getBuffer(), (short) (base + 2));
            mem.setShort(base, size);
            base += (short) (2 + size);
            avail -= (short) (2 + size);
            break;
        default:
            ISOException.throwIt(SW_INVALID_PARAMETER);
        }
        om.clampObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, (short) (buffer_size - avail));
    }
    private void CreatePIN(APDU apdu, byte[] buffer) {
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        byte num_tries = buffer[ISO7816.OFFSET_P2];
        if ((create_pin_ACL == (byte) 0xFF) || (
            ((logged_ids & create_pin_ACL) == (short) 0x0000) &&
             (create_pin_ACL != (byte) 0x00)))
            ISOException.throwIt(SW_UNAUTHORIZED);
        if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS)
            || (pins[pin_nb] != null))
            ISOException.throwIt(SW_INCORRECT_P1);
        short avail = Util.makeShort((byte) 0x00,
                                buffer[ISO7816.OFFSET_LC]);
        if (apdu.setIncomingAndReceive() != avail)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (avail < 4)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte pin_size = buffer[ISO7816.OFFSET_CDATA];
        if (avail < (short) (1 + pin_size + 1))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (! CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte ucode_size = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pin_size)];
        if (avail != (short) (1 + pin_size + 1 + ucode_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (! CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), ucode_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        pins[pin_nb] = new OwnerPIN(num_tries, pinMaxSize);
        pins[pin_nb].update(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size);
        ublk_pins[pin_nb] = new OwnerPIN((byte) 3, pinMaxSize);
        pin_size = (byte) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1);
        ublk_pins[pin_nb].update(buffer, pin_size, ucode_size);
    }
    private void VerifyPIN(APDU apdu, byte[] buffer) {
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
            ISOException.throwIt(SW_INCORRECT_P1);
        OwnerPIN pin = pins[pin_nb];
        if (pin == null)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short numBytes = Util.makeShort((byte) 0x00,
                                buffer[ISO7816.OFFSET_LC]);
        if (numBytes != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (! CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (pin.getTriesRemaining() == (byte) 0x00)
            ISOException.throwIt(SW_IDENTITY_BLOCKED);
        if (! pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) numBytes)) {
            LogoutIdentity(pin_nb);
            ISOException.throwIt(SW_AUTH_FAILED);
        }
        logged_ids |= (short) (0x0001 << pin_nb);
    }
    private void ChangePIN(APDU apdu, byte[] buffer) {
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
            ISOException.throwIt(SW_INCORRECT_P1);
        OwnerPIN pin = pins[pin_nb];
        if (pin == null)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short avail = Util.makeShort((byte) 0x00,
                                buffer[ISO7816.OFFSET_LC]);
        if (apdu.setIncomingAndReceive() != avail)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (avail < 4)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte pin_size = buffer[ISO7816.OFFSET_CDATA];
        if (avail < (short) (1 + pin_size + 1))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (! CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte new_pin_size = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pin_size)];
        if (avail < (short) (1 + pin_size + 1 + new_pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (! CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (pin.getTriesRemaining() == (byte) 0x00)
            ISOException.throwIt(SW_IDENTITY_BLOCKED);
        if (! pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size)) {
            LogoutIdentity(pin_nb);
            ISOException.throwIt(SW_AUTH_FAILED);
        }
        pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size);
        logged_ids &= (short) ((short) 0xFFFF ^ (0x01 << pin_nb));
    }
    private void UnblockPIN(APDU apdu, byte[] buffer) {
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
            ISOException.throwIt(SW_INCORRECT_P1);
        OwnerPIN pin = pins[pin_nb];
        OwnerPIN ublk_pin = ublk_pins[pin_nb];
        if (pin == null)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (ublk_pin == null)
            ISOException.throwIt(SW_INTERNAL_ERROR);
        if (pin.getTriesRemaining() != 0)
            ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
        if (buffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short numBytes = Util.makeShort((byte) 0x00,
                                buffer[ISO7816.OFFSET_LC]);
        if (numBytes != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (! CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (! ublk_pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) numBytes))
            ISOException.throwIt(SW_AUTH_FAILED);
        pin.resetAndUnblock();
    }
    private void CreateObject(APDU apdu, byte[] buffer) {
        short bytesLeft = Util.makeShort((byte) 0x00,
                                 buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if ((create_object_ACL == (byte) 0xFF) || (
            ((logged_ids & create_object_ACL) == (short) 0x0000) &&
             (create_object_ACL != (byte) 0x00)))
            ISOException.throwIt(SW_UNAUTHORIZED);
        if (bytesLeft != (short) (4 + 4 + ObjectManager.OBJ_ACL_SIZE))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (buffer[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
        if (om.exists(obj_class, obj_id))
            ISOException.throwIt(SW_OBJECT_EXISTS);
        if ((Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 4)) != 0x0000)
            || (buffer[(short) (ISO7816.OFFSET_CDATA + 6)] < 0))
            ISOException.throwIt(SW_NO_MEMORY_LEFT);
        if (Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6)) == 0x0000)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        om.createObject(obj_class, obj_id,
                        Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6)),
                        buffer, (short) (ISO7816.OFFSET_CDATA + 8));
    }
    private void DeleteObject(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P1);
        if ((buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            && (buffer[ISO7816.OFFSET_P2] != (byte) 0x01))
            ISOException.throwIt(SW_INCORRECT_P2);
        short bytesLeft = Util.makeShort((byte) 0x00,
                                 buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (bytesLeft != (short) 0x04)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
        short base = om.getBaseAddress(obj_class, obj_id);
        if (base == MemoryManager.NULL_OFFSET)
            ISOException.throwIt(SW_OBJECT_NOT_FOUND);
        if (! om.authorizeDeleteFromAddress(base, logged_ids))
            ISOException.throwIt(SW_UNAUTHORIZED);
        om.destroyObject(obj_class, obj_id,
                         buffer[ISO7816.OFFSET_P2] == 0x01);
    }
    private void ReadObject(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short bytesLeft = Util.makeShort((byte) 0x00,
                                 buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (bytesLeft != (short) 9)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
        short offset = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 6));
        short size = Util.makeShort((byte) 0x00, buffer[(short) ISO7816.OFFSET_CDATA + (short) 8]);
        short base = om.getBaseAddress(obj_class, obj_id);
        if (base == MemoryManager.NULL_OFFSET)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (! om.authorizeReadFromAddress(base, logged_ids))
            ISOException.throwIt(SW_UNAUTHORIZED);
        if ((short) (offset + size) > om.getSizeFromAddress(base))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        sendData(apdu, mem.getBuffer(), (short) (base + offset), size);
    }
    private void WriteObject(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short bytesLeft = Util.makeShort((byte) 0x00,
                                 buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2));
        short offset = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6));
        short size = Util.makeShort((byte) 0x00, buffer[(short) (ISO7816.OFFSET_CDATA + 8)]);
        short base = om.getBaseAddress(obj_class, obj_id);
        if (base == MemoryManager.NULL_OFFSET)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (! om.authorizeWriteFromAddress(base, logged_ids))
            ISOException.throwIt(SW_UNAUTHORIZED);
        if ((short) (offset + size) > om.getSizeFromAddress(base))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        mem.setBytes(base, offset, buffer,
                     (short) (ISO7816.OFFSET_CDATA + 9),
                     size);
    }
    private void LogOutAll() {
        logged_ids = (short) 0x0000;
        byte i;
        for (i = (byte) 0; i < MAX_NUM_PINS; i++)
            if (pins[i] != null)
                pins[i].reset();
    }
    private void ListPINs(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        byte expectedBytes =
            (byte)(buffer[ISO7816.OFFSET_LC]);
        if (expectedBytes != (short) 2)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short mask = (short) 0x00;
        short b;
        for (b = (short) 0; b < MAX_NUM_PINS; b++)
            if (pins[b] != null)
                mask |= (short) (((short) 0x01) << b);
        Util.setShort(buffer, (short) 0, mask);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }
    private void ListObjects(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        byte expectedBytes =
            (byte)(buffer[ISO7816.OFFSET_LC]);
        if (expectedBytes < ObjectManager.RECORD_SIZE)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        boolean found = false;
        if (buffer[ISO7816.OFFSET_P1] == LIST_OPT_RESET)
            found = om.getFirstRecord(buffer, (short) 0);
        else if (buffer[ISO7816.OFFSET_P1] != LIST_OPT_NEXT)
            ISOException.throwIt(SW_INCORRECT_P1);
        else
            found = om.getNextRecord(buffer, (short) 0);
        if (found)
            apdu.setOutgoingAndSend((short) 0, (short) ObjectManager.RECORD_SIZE);
        else
            ISOException.throwIt(SW_SEQUENCE_END);
    }
    private void ListKeys(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short expectedBytes = Util.makeShort((byte) 0x00,
                                     buffer[ISO7816.OFFSET_LC]);
        if (expectedBytes != (short) 0x0B)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (buffer[ISO7816.OFFSET_P1] == LIST_OPT_RESET)
            key_it = (byte) 0;
        else if (buffer[ISO7816.OFFSET_P1] != LIST_OPT_NEXT)
            ISOException.throwIt(SW_INCORRECT_P1);
        while (
          (key_it < MAX_NUM_KEYS)
          && (
            (keys[key_it] == null)
            || ! keys[key_it].isInitialized()
          )
        )
            key_it++;
        if (key_it < MAX_NUM_KEYS) {
            Key key = keys[key_it];
            buffer[(short) 0] = key_it;
            buffer[(short) 1] = getKeyType(key);
            buffer[(short) 2] = (byte) 0xFF;
            Util.setShort(buffer, (short) 3, key.getSize());
            Util.arrayCopyNonAtomic(keyACLs, (short) (key_it * KEY_ACL_SIZE),
                                    buffer, (short) 5, KEY_ACL_SIZE);
            key_it++;
            apdu.setOutgoingAndSend((short) 0, (short) (5 + KEY_ACL_SIZE));
        }
    }
    private void GetChallenge(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P1);
        short bytesLeft = Util.makeShort((byte) 0x00,
                                 buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (bytesLeft < 4)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        short size = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        short seed_size = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2));
        if (bytesLeft != (short) (seed_size + 4))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte data_loc = buffer[ISO7816.OFFSET_P2];
        if ((data_loc != DL_APDU) && (data_loc != DL_OBJECT))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (randomData == null)
            randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (seed_size != (short) 0x0000)
            randomData.setSeed(buffer, (short) (ISO7816.OFFSET_CDATA + 4), seed_size);
        if (size != (short) 0x0000) {
            short base = om.createObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, (short) (size + 2), getRestrictedACL(), (short) 0);
            mem.setShort(base, size);
            randomData.generateData(mem.getBuffer(), (short) (base + 2), size);
            getChallengeDone = true;
            if (data_loc == DL_APDU) {
                sendData(apdu, mem.getBuffer(), base, (short) (size + 2));
                om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
            }
     }
 }
    private void GetStatus(APDU apdu, byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        short pos = (short) 0;
        buffer[pos++] = (byte) 0;
        buffer[pos++] = (byte) 1;
        buffer[pos++] = (byte) 0;
        buffer[pos++] = (byte) 5;
        Util.setShort(buffer, pos, (short) 0x00);
        pos += (short) 2;
        Util.setShort(buffer, pos, (short) mem.getBuffer().length);
        pos += (short) 2;
        Util.setShort(buffer, pos, (short) 0x00);
        pos += (short) 2;
        Util.setShort(buffer, pos, mem.freemem());
        pos += (short) 2;
        byte cnt = (byte) 0;
        for (short i = 0; i < pins.length; i++)
            if (pins[i] != null)
                cnt++;
        buffer[pos++] = cnt;
        cnt = (byte) 0;
        for (short i = 0; i < keys.length; i++)
            if (keys[i] != null)
                cnt++;
        buffer[pos++] = cnt;
        Util.setShort(buffer, pos, logged_ids);
        pos += (short) 2;
        apdu.setOutgoingAndSend((short) 0, pos);
    }
}
