package com.sun.javacard.samples.CardEdge;
import javacard.framework.Util;
public class MemoryManager {
    public final static short NULL_OFFSET = (short) 0xFFFF;
    private final static byte NODE_SIZE = (byte) 4;
    private byte ptr[] = null;
    private short free_head = NULL_OFFSET;
    public MemoryManager(short mem_size) {
        Init(mem_size);
    }
    private void Init(short mem_size) {
        if (ptr != null)
            return;
        ptr = new byte[mem_size];
        Util.setShort(ptr, (short) 0, (short) mem_size);
        Util.setShort(ptr, (short) 2, (short) NULL_OFFSET);
        free_head = (short) 0;
    }
    public short alloc(short size) {
        short offset = free_head;
        short prev = NULL_OFFSET;
        size = (short) (size + 2);
        if (size < NODE_SIZE)
            size = NODE_SIZE;
        while (offset != NULL_OFFSET) {
            short free_size = Util.getShort(ptr, offset);
            short next_offset = Util.getShort(ptr, (short) (offset + 2));
            if (free_size >= size) {
                short remain = (short) (free_size - size);
                if (remain >= NODE_SIZE) {
                    Util.setShort(ptr, offset, remain);
                } else {
                    size = free_size;
                    remain = (short) 0;
                    if (prev == NULL_OFFSET) {
                        free_head = next_offset;
                    } else {
                        Util.setShort(ptr, (short) (prev + 2), next_offset);
                    }
                }
                Util.setShort(ptr, (short) (offset + remain), size);
                return (short) (offset + remain + 2);
            } else {
                prev = offset;
                offset = next_offset;
            }
        }
        return NULL_OFFSET;
    }
    public short getMaxSize() {
        short max_size = 2;
        short base = free_head;
        while (base != NULL_OFFSET) {
            short size = Util.getShort(ptr, base);
            if (size > max_size)
                max_size = size;
            base = Util.getShort(ptr, (short) (base + 2));
        }
        return (short) (max_size - 2);
    }
    public void free(short offset) {
        offset -= 2;
        short size = Util.getShort(ptr, offset);
        short prev = NULL_OFFSET;
        short base = free_head;
        boolean found = false;
        short node_next = (short) 0;
        while (base != NULL_OFFSET) {
            node_next = Util.getShort(ptr, (short) (base + 2));
            if (offset < base) {
                found = true;
                break;
            }
            prev = base;
            base = node_next;
        }
        if (found && ((short) (offset + size) == base)) {
            size += Util.getShort(ptr, base);
            Util.setShort(ptr, offset, size);
            if (prev != NULL_OFFSET)
                Util.setShort(ptr, (short) (prev + 2), node_next);
            else
                free_head = node_next;
            base = node_next;
        }
        if (prev != NULL_OFFSET) {
            short prev_size = Util.getShort(ptr, prev);
            if ((short) (prev + prev_size) == offset) {
                Util.setShort(ptr, prev, (short) (prev_size + size));
            } else {
                Util.setShort(ptr, (short) (offset + 2), base);
                Util.setShort(ptr, (short) (prev + 2), offset);
            }
        } else {
            Util.setShort(ptr, (short) (offset + 2), base);
            free_head = offset;
        }
    }
    public short getBlockSize(short offset) {
        return (short) (Util.getShort(ptr, (short) (offset - 2)) - 2);
    }
    public short freemem() {
        short offset = free_head;
        short total = (short) 0;
        while (offset != NULL_OFFSET) {
            total = (short) (total + Util.getShort(ptr, offset) - 2);
            offset = Util.getShort(ptr, (short) (offset + 2));
        }
        return total;
    }
    public boolean realloc(short offset, short new_size) {
        short actual_size = Util.getShort(ptr, (short) (offset - 2));
        new_size += (short) 2;
        if ((new_size < (short) (1 + 2)) || ((short) (actual_size - new_size) < NODE_SIZE))
            return false;
        Util.setShort(ptr, (short) (offset - 2), new_size);
        Util.setShort(ptr, (short) (offset + new_size - 2), (short) (actual_size - new_size));
        free((short) (offset + new_size));
        return true;
    }
    public void setByte(short base, short offset, byte b) {
        ptr[(short) (base + offset)] = b;
    }
    public void setByte(short base, byte b) {
        ptr[base] = b;
    }
    public byte getByte(short base, short offset) {
        return ptr[(short) (base + offset)];
    }
    public byte getByte(short base) {
        return ptr[base];
    }
    public void setShort(short base, short offset, short b) {
        Util.setShort(ptr, (short) (base + offset), b);
    }
    public void setShort(short base, short b) {
        Util.setShort(ptr, base, b);
    }
    public short getShort(short base, short offset) {
        return Util.getShort(ptr, (short) (base + offset));
    }
    public short getShort(short base) {
        return Util.getShort(ptr, base);
    }
    public void setBytes(short dst_base, short dst_offset,
                                byte[] src_bytes, short src_offset,
                                short size) {
        Util.arrayCopy(src_bytes, src_offset,
                       ptr, (short) (dst_base + dst_offset),
                       size);
    }
    public void getBytes(byte[] dst_bytes, short dst_offset,
                                short src_base, short src_offset,
                                short size) {
        Util.arrayCopy(ptr, (short) (src_base + src_offset),
                       dst_bytes, dst_offset,
                       size);
    }
    public byte[] getBuffer() {
        return ptr;
    }
}
