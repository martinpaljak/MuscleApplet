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

import javacard.framework.ISOException;
import javacard.framework.Util;

// Referenced classes of package com.sun.javacard.samples.CardEdge:
//			MemoryManager

/**
 * Object Manager Class
 *
 * <p>Objects are linked in a list in the dynamic memory. No smart search
 * is done at the moment.</p>
 *
 * <p>TODO - Could we definitively avoid a map enforcing the ID (equal to
 * the memory address, i.e.) - security implications ?</p>
 *
 * Object fields:
 * <pre>
 *    short next
 *    short obj_class
 *    short obj_id
 *    short obj_size
 *    byte[] data
 * </pre>
 *
 * @author Tommaso Cucinotta
 * @author David Corcoran
 * @author Ludovic Rousseau
 *
 * @version 0.9.10
 */
public class ObjectManager
{
	public static final byte OBJ_ACL_SIZE = 6;

	private static final byte OBJ_HEADER_SIZE = 14;
	private static final byte OBJ_H_NEXT = 0;
	private static final byte OBJ_H_CLASS = 2;
	private static final byte OBJ_H_ID = 4;
	private static final byte OBJ_H_ACL = 6;
	private static final byte OBJ_H_SIZE = 12;
	private static final byte OBJ_H_DATA = 14;

	/**
	 * There have been memory problems on the card
	 */
	public static final short SW_NO_MEMORY_LEFT = (short)0x9C01;
	public static final short SW_OBJECT_NOT_FOUND = (short)0x9C07;

	/**
	 * Size of an Object Record filled by getFirstRecord() or
	 * getNextRecord(): ID, Size, ACL
	 */
	public static final short RECORD_SIZE = 14;

	/**
	 * Iterator on objects.
	 */
	private short it;

	/**
	 * The Memory Manager object
	 */
	private MemoryManager mem;

	/**
	 * Head of the objects' list
	 */
	private short obj_list_head;

	/**
	 * Constructor for the ObjectManager class.
	 *
	 * @param mem_ref The MemoryManager object to be used to allocate
	 * objects' memory.
	 */
	public ObjectManager(MemoryManager mem_ref)
	{
		mem = null;
		obj_list_head = -1;
		mem = mem_ref;
		obj_list_head = -1;
	}

	/**
	 * Allow or unallow delete on object given the logged identities
	 */
	public boolean authorizeDeleteFromAddress(short base, short logged_ids)
	{
		return authorizeOp(mem.getShort(base, (short)-4), logged_ids);
	}

	/**
	 * Check if logged in identities satisfy requirements for an
	 * operation
	 *
	 * @param required_ids The required identities as from an ACL short
	 * @param logged_ids The current logged in identities as stored in
	 * CardEdge.logged_ids
	 */
	private boolean authorizeOp(short required_ids, short logged_ids)
	{
		return required_ids != -1 && (short)(required_ids & logged_ids) == required_ids;
	}

	/**
	 * Allow or unallow read on object given the logged identities
	 *
	 * @param base The object base address as returned from
	 * getBaseAddress()
	 * @param logged_ids The current logged in identities as stored in
	 * CardEdge.logged_ids
	 */
	public boolean authorizeReadFromAddress(short base, short logged_ids)
	{
		return authorizeOp(mem.getShort(base, (short)-8), logged_ids);
	}

	/**
	 * Allow or unallow write on object given the logged identities
	 *
	 * @param base The object base address as returned from
	 * getBaseAddress()
	 * @param logged_ids The current logged in identities as stored in
	 * CardEdge.logged_ids
	 */
	public boolean authorizeWriteFromAddress(short base, short logged_ids)
	{
		return authorizeOp(mem.getShort(base, (short)-6), logged_ids);
	}

	/**
	 * Clamps an object freeing the unused memory
	 *
	 * @throws SW_NO_MEMORY_LEFT exception if cannot allocate the
	 * memory. Does not check if object exists.
	 *
	 * @param type Object Type
	 * @param id Object ID (Type and ID form a generic 4 bytes
	 * identifier)
	 * @param new_size The new object size (must be less than current
	 * size)
	 *
	 * @return True if clamp was possible, false otherwise
	 */
	public boolean clampObject(short type, short id, short new_size)
	{
		short base = getEntry(type, id);
		if(base == -1)
			ISOException.throwIt((short)SW_OBJECT_NOT_FOUND);
		if(mem.realloc(base, (short)(new_size + RECORD_SIZE)))
		{
			mem.setShort(base, (short)OBJ_H_SIZE, new_size);
			return true;
		} else
		{
			return false;
		}
	}

	/**
	 * Compare an object's ACL with the provided ACL.
	 *
	 * @param base The object base address, as returned from
	 * getBaseAddress()
	 * @param acl The buffer containing the ACL
	 *
	 * @return True if the ACLs are equal
	 */
	public boolean compareACLFromAddress(short base, byte acl[])
	{
		return Util.arrayCompare(mem.getBuffer(), (short)((base - 14) + OBJ_H_ACL), acl, (short)0, (short)OBJ_ACL_SIZE) == 0;
	}

	/**
	 * Creates an object with specified parameters.
	 *
	 * @throws SW_NO_MEMORY_LEFT exception if cannot allocate the
	 * memory. Does not check if object exists.
	 *
	 * @param type Object Type
	 * @param id Object ID (Type and ID form a generic 4 bytes
	 * identifier)
	 * @param acl_buf Java byte array containing the ACL for the new object
	 * @param acl_offset Offset at which the ACL starts in acl_buf[]
	 *
	 * @return The memory base address for the object. It can be used in
	 * successive calls to xxxFromAddress() methods.
	 *
	 */
	public short createObject(short type, short id, short size, byte acl_buf[], short acl_offset)
	{
		short base = mem.alloc((short)(size + 14));
		if(base == -1)
			ISOException.throwIt((short)SW_NO_MEMORY_LEFT);
		mem.setShort(base, (short)OBJ_H_NEXT, obj_list_head);
		mem.setShort(base, (short)OBJ_H_CLASS, type);
		mem.setShort(base, (short)OBJ_H_ID, id);
		mem.setShort(base, (short)OBJ_H_SIZE, size);
		mem.setBytes(base, (short)OBJ_H_ACL, acl_buf, acl_offset, (short)OBJ_ACL_SIZE);
		obj_list_head = base;
		return (short)(base + OBJ_H_DATA);
	}

	/**
	 * Creates an object with the maximum available size
	 */
	public short createObjectMax(short type, short id, byte acl_buf[], short acl_offset)
	{
		short obj_size = mem.getMaxSize();
		if(obj_size == 0)
			ISOException.throwIt((short)SW_NO_MEMORY_LEFT);
		return createObject(type, id, (short)(obj_size - 14), acl_buf, acl_offset);
	}

	/**
	 * Destroy the specified object
	 *
	 * @param type Object Type
	 * @param id Object ID (Type and ID form a generic 4 bytes
	 * identifier)
	 * @param secure If true, object memory is zeroed before being
	 * released.
	 */
	public void destroyObject(short type, short id, boolean secure)
	{
		short base = obj_list_head;
		short prev = -1;
		boolean found;
		for(found = false; !found && base != -1;)
			if(mem.getShort(base, (short)2) == type && mem.getShort(base, (short)4) == id)
			{
				found = true;
			} else
			{
				prev = base;
				base = mem.getShort(base, (short)0);
			}

		if(found)
		{
			if(prev != -1)
				mem.setShort(prev, (short)0, mem.getShort(base, (short)0));
			else
				obj_list_head = mem.getShort(base, (short)0);
			if(secure)
				Util.arrayFillNonAtomic(mem.getBuffer(), (short)(base + 14), mem.getShort(base, (short)12), (byte)0);
			mem.free(base);
		}
	}

	/**
	 * Checks if an object exists
	 *
	 * @param type The object type
	 * @param id The object ID
	 *
	 * @return true if object exists
	 */
	public boolean exists(short type, short id)
	{
		short base = getEntry(type, id);
		return base != -1;
	}

	/**
	 * Returns the data base address (offset) for an object.
	 *
	 * <p>The base address can be used for further calls to
	 * xxxFromAddress() methods</p>
	 *
	 * <p>This function should only be used if performance issue arise.
	 * setObjectData() and getObjectData() should be used, instead.</p>
	 *
	 * @param type Object Type
	 * @param id Object ID (Type and ID form a generic 4 bytes
	 * identifier)
	 *
	 * @return The starting offset of the object. At this location
	 */
	public short getBaseAddress(short type, short id)
	{
		short base = getEntry(type, id);
		if(base == -1)
			return -1;
		else
			return (short)(base + 14);
	}

	/**
	 * Returns the header base address (offset) for the specified
	 * object.
	 *
	 * <p>Object header is found at the returned offset, while object
	 * data starts right after the header.</p>
	 *
	 * <p>This performs a linear search, so performance issues could
	 * arise as the number of objects grows If object is not found,
	 * then returns NULL_OFFSET.</p>
	 *
	 * @param type Object Type
	 * @param id Object ID (Type and ID form a generic 4 bytes
	 * identifier)
	 *
	 * @return The starting offset of the object or NULL_OFFSET if the
	 * object is not found.
	 */
	private short getEntry(short type, short id)
	{
		for(short base = obj_list_head; base != -1; base = mem.getShort(base, (short)0))
			if(mem.getShort(base, (short)OBJ_H_CLASS) == type && mem.getShort(base, (short)OBJ_H_ID) == id)
				return base;

		return -1;
	}

	/**
	 * Resets the objects iterator and retrieves the information record
	 * of the first object, if any.
	 *
	 * @param buffer The byte array into which the record will be copied
	 * @param offset The offset in buffer[] at which the record will be
	 * copied
	 *
	 * @return True if an object was found. False if there are no
	 * objects.
	 *
	 * @see #getNextRecord(byte[], short)
	 */
	public boolean getFirstRecord(byte buffer[], short offset)
	{
		it = obj_list_head;
		return getNextRecord(buffer, offset);
	}

	/**
	 * Retrieves the information record of the next object, if any.
	 *
	 * @param buffer The byte array into which the record will be copied
	 * @param offset The offset in buffer[] at which the record will be
	 * copied
	 *
	 * @return True if an object was found. False if there are no more
	 * objects to inspect.
	 *
	 * @see #getFirstRecord(byte[], short)
	 */
	public boolean getNextRecord(byte buffer[], short offset)
	{
		if(it == -1)
		{
			return false;
		} else
		{
			Util.setShort(buffer, offset, mem.getShort(it, (short)2));
			Util.setShort(buffer, (short)(offset + 2), mem.getShort(it, (short)4));
			Util.setShort(buffer, (short)(offset + 4), (short)0);
			Util.setShort(buffer, (short)(offset + 6), mem.getShort(it, (short)12));
			Util.arrayCopyNonAtomic(mem.getBuffer(), (short)(it + 6), buffer, (short)(offset + 8), (short)6);
			it = mem.getShort(it, (short)0);
			return true;
		}
	}

	/**
	 * Returns object size from the base address
	 */
	public short getSizeFromAddress(short base)
	{
		return mem.getShort((short)((base - 14) + 12));
	}

	/**
	 * Set the object's ACL.
	 */
	private void setACL(short type, short id, byte acl_buf[], short acl_offset)
	{
		short base = getEntry(type, id);
		mem.setBytes(base, (short)OBJ_H_ACL, acl_buf, acl_offset, (short)OBJ_ACL_SIZE);
	}
}

