package com.sun.javacard.samples.CardEdge;
import com.sun.javacard.samples.CardEdge.MemoryManager;
import javacard.framework.Util;
import javacard.framework.ISOException;
public class ObjectManager {
    public final static byte OBJ_ACL_SIZE = (byte) 6;
    private final static byte OBJ_HEADER_SIZE = (byte) (6 + OBJ_ACL_SIZE + 2);
    private final static byte OBJ_H_NEXT = (byte) 0;
    private final static byte OBJ_H_CLASS = (byte) 2;
    private final static byte OBJ_H_ID = (byte) 4;
    private final static byte OBJ_H_ACL = (byte) 6;
    private final static byte OBJ_H_SIZE = (byte) 12;
    private final static byte OBJ_H_DATA = (byte) 14;
    public final static short SW_NO_MEMORY_LEFT = (short) 0x9C01;
    public final static short RECORD_SIZE = (short) (4 + 4 + OBJ_ACL_SIZE);
    private short it;
    private MemoryManager mem = null;
    private short obj_list_head = MemoryManager.NULL_OFFSET;
    public ObjectManager(MemoryManager mem_ref) {
        mem = mem_ref;
        obj_list_head = MemoryManager.NULL_OFFSET;
    }
    public short createObject(short type, short id, short size,
                             byte[] acl_buf, short acl_offset) {
        short base = mem.alloc((short) (size + OBJ_HEADER_SIZE));
        if (base == MemoryManager.NULL_OFFSET)
            ISOException.throwIt(SW_NO_MEMORY_LEFT);
        mem.setShort(base, OBJ_H_NEXT, obj_list_head);
        mem.setShort(base, OBJ_H_CLASS, type);
        mem.setShort(base, OBJ_H_ID, id);
        mem.setShort(base, OBJ_H_SIZE, size);
        mem.setBytes(base, OBJ_H_ACL, acl_buf, acl_offset, OBJ_ACL_SIZE);
        obj_list_head = base;
        return (short) (base + OBJ_HEADER_SIZE);
    }
    public short createObjectMax(short type, short id,
                                 byte[] acl_buf, short acl_offset) {
        short obj_size = mem.getMaxSize();
        if (obj_size == (short) 0)
            ISOException.throwIt(SW_NO_MEMORY_LEFT);
        return createObject(type, id, (short) (obj_size - OBJ_HEADER_SIZE),
                            acl_buf, acl_offset);
    }
    public boolean clampObject(short type, short id, short new_size) {
        short base = getEntry(type, id);
        if (base == (short) MemoryManager.NULL_OFFSET)
            ISOException.throwIt((short) 0x9C07);
        if (mem.realloc(base, (short) (new_size + OBJ_HEADER_SIZE))) {
            mem.setShort(base, OBJ_H_SIZE, new_size);
            return true;
        }
        return false;
    }
    private void setACL(short type, short id, byte[] acl_buf, short acl_offset) {
        short base = getEntry(type, id);
        mem.setBytes(base, OBJ_H_ACL, acl_buf, acl_offset, OBJ_ACL_SIZE);
    }
    public boolean authorizeReadFromAddress(short base, short logged_ids) {
        return authorizeOp(mem.getShort(base, (short) (OBJ_H_ACL - OBJ_HEADER_SIZE)), logged_ids);
    }
    public boolean authorizeWriteFromAddress(short base, short logged_ids) {
        return authorizeOp(mem.getShort(base, (short) (OBJ_H_ACL + (short) 2 - OBJ_HEADER_SIZE)), logged_ids);
    }
    public boolean authorizeDeleteFromAddress(short base, short logged_ids) {
        return authorizeOp(mem.getShort(base, (short) (OBJ_H_ACL + (short) 4 - OBJ_HEADER_SIZE)), logged_ids);
    }
    private boolean authorizeOp(short required_ids, short logged_ids) {
        return (
                (required_ids != (short) 0xFFFF)
                && (((short) (required_ids & logged_ids)) == required_ids)
                );
    }
    public void destroyObject(short type, short id, boolean secure) {
        short base = obj_list_head;
        short prev = MemoryManager.NULL_OFFSET;
        boolean found = false;
        while ((! found) && (base != MemoryManager.NULL_OFFSET)) {
            if ((mem.getShort(base, OBJ_H_CLASS) == type)
                && (mem.getShort(base, OBJ_H_ID) == id))
                found = true;
            else {
                prev = base;
                base = mem.getShort(base, OBJ_H_NEXT);
            }
        }
        if (found) {
            if (prev != MemoryManager.NULL_OFFSET) {
                mem.setShort(prev, OBJ_H_NEXT, mem.getShort(base, OBJ_H_NEXT));
            } else {
                obj_list_head = mem.getShort(base, OBJ_H_NEXT);
            }
            if (secure)
                Util.arrayFillNonAtomic(mem.getBuffer(), (short) (base + OBJ_HEADER_SIZE),
                                        mem.getShort(base, OBJ_H_SIZE), (byte) 0x00);
            mem.free(base);
        }
    }
    private short getEntry(short type, short id) {
        short base = obj_list_head;
        while (base != MemoryManager.NULL_OFFSET) {
            if ((mem.getShort(base, OBJ_H_CLASS) == type)
                && (mem.getShort(base, OBJ_H_ID) == id))
                return base;
            base = mem.getShort(base, OBJ_H_NEXT);
        }
        return MemoryManager.NULL_OFFSET;
    }
    public short getBaseAddress(short type, short id) {
        short base = getEntry(type, id);
        if (base == MemoryManager.NULL_OFFSET)
            return MemoryManager.NULL_OFFSET;
        else
            return ((short) (base + OBJ_HEADER_SIZE));
    }
    public boolean exists(short type, short id) {
        short base = getEntry(type, id);
        return (base != MemoryManager.NULL_OFFSET);
    }
    public short getSizeFromAddress(short base) {
        return mem.getShort((short) (base - OBJ_HEADER_SIZE + OBJ_H_SIZE));
    }
    public boolean getFirstRecord(byte[] buffer, short offset) {
        it = obj_list_head;
        return getNextRecord(buffer, offset);
    }
    public boolean getNextRecord(byte[] buffer, short offset) {
        if (it == MemoryManager.NULL_OFFSET)
            return false;
        Util.setShort(buffer, offset, mem.getShort(it, OBJ_H_CLASS));
        Util.setShort(buffer, (short) (offset + 2), mem.getShort(it, OBJ_H_ID));
        Util.setShort(buffer, (short) (offset + 4), (short) 0);
        Util.setShort(buffer, (short) (offset + 6), mem.getShort(it, (short) OBJ_H_SIZE));
        Util.arrayCopyNonAtomic(mem.getBuffer(), (short) (it + OBJ_H_ACL),
                                buffer, (short) (offset + 8), OBJ_ACL_SIZE);
        it = mem.getShort(it, OBJ_H_NEXT);
        return true;
    }
    public boolean compareACLFromAddress(short base, byte[] acl) {
        return (Util.arrayCompare(mem.getBuffer(), (short) (base - OBJ_HEADER_SIZE + OBJ_H_ACL),
                                  acl, (short) 0, OBJ_ACL_SIZE) == (byte) 0);
    }
}
