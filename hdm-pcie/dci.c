/*
 * dci.c - Direct Communication Interface for Medusa
 *
 * Copyright (C) 2015, Microchip Technology Germany II GmbH & Co. KG
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This file is licensed under GPLv2.
 */

/* Author: Andrey Shvetsov <andrey.shvetsov@k2l.de> */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/errno.h>
#include <mostcore.h>
#include "medusa.h"
#include "registers.h"


#define DCI_CH 31

#define DCI_OP_READ 0xA0
#define DCI_OP_WRITE 0xA1

#define DCI_EVENT_FLAGS	0x00000000

#define DCI_A_AVA	0x01000000
#define DCI_A_PCK_BW	0x01010000
#define DCI_A_NADDR	0x01020000
#define DCI_A_NPOS	0x01030000
#define DCI_A_MEP_FM	0x01400000

/* hash table is represented in the format "HT3 HT2 HT1 HT0" */
#define DCI_A_MEP_HT3	0x01410000
#define DCI_A_MEP_HT2	0x01420000
#define DCI_A_MEP_HT1	0x01430000
#define DCI_A_MEP_HT0	0x01440000

/*
 * if MAC address is represented as DA1:DA2:DA3:DA4:DA5:DA6 then
 * MADDRH == DA1 * 256 + DA2
 * MADDRM == DA3 * 256 + DA4
 * MADDRL == DA5 * 256 + DA6
 *
 * broadcast MAC address is FF:FF:FF:FF:FF:FF
 *
 * if lowest bit of DA1 is 1 then MAC address is multicast,
 * except it is broadcast
 */
#define DCI_A_MAC_H	0x01450000
#define DCI_A_MAC_M	0x01460000
#define DCI_A_MAC_L	0x01470000

#define DCI_DMA_FLAGS_LO        0x20000000
#define DCI_DMA_FLAGS_HI        0x20010000
#define DCI_PCI_PORT_FLAGS      0x20020000

#define DCI_DMA_CH_REG(i)       (0x21000000 + (i) * 0x00100000)

/* fields of DCI_DMA_CH_REGS */
#define DCI_DMA_CH_REG_SYNC_NEEDED(i)   (DCI_DMA_CH_REG(i) + 0x0)
#define DCI_DMA_CH_REG_SYNC_REQ(i)      (DCI_DMA_CH_REG(i) + 0x2)


/* Bit to mask makro. */
#define B2MASK(bit) ((u32)1 << (bit))


static int get_xvalue(unsigned char x)
{
	if (x >= '0' && x <= '9')
		return x - '0';

	x = tolower(x);
	if (x >= 'a' && x <= 'f')
		return  x - 'a' + 10;

	return -EINVAL;
}


struct dci_wall {
	struct medusa *mdev;
	int index;
};

static struct dci_wall *init_dci_wall(struct dci_wall *dci, struct medusa *mdev)
{
	dci->mdev = mdev;
	dci->index = 0;
	return dci;
}

static bool is_dci_wall_empty(struct dci_wall *dci)
{
	return dci->index == 0;
}

static void write_dci_wall(struct dci_wall *dci, u32 val)
{
	++dci->index;
	medusa_write_b1(dci->mdev, MAILBOX_REGISTER(dci->index), val);
}

static u16 read_dci_wall_u16(struct dci_wall *dci)
{
	++dci->index;
	return medusa_read_b1(dci->mdev, MAILBOX_REGISTER(dci->index));
}

static void read_dci_wall_byte_arr(struct dci_wall *dci, u8 *p)
{
	u16 v = read_dci_wall_u16(dci);

	p[0] = v >> 8;
	p[1] = v;
}

static void commit_dci_wall(struct dci_wall *dci, u8 op)
{
	medusa_write_b1(dci->mdev, MAILBOX_REGISTER(0),
			0xDC000000 + op * 0x10000 + dci->index * 0x100);
	medusa_write_b1(dci->mdev, IDBELL_REGISTER, B2MASK(IDBELL_IDB_BIT));
}

struct dci_attr {
	struct attribute attr;
	int state;
	ssize_t (*show)(struct medusa_dci *dci, char *buf);
	ssize_t (*store)(struct medusa_dci *dci, const char *buf, size_t count);
};

static ssize_t availability_show(struct medusa_dci *dci, char *buf)
{
	return sprintf(buf, "%d\n", dci->availability);
}

static ssize_t packet_bw_show(struct medusa_dci *dci, char *buf)
{
	if (dci->packet_bw == 0xFFFF)
		return sprintf(buf, "0xFFFF\n");
	return sprintf(buf, "%d\n", dci->packet_bw);
}

static ssize_t node_addr_show(struct medusa_dci *dci, char *buf)
{
	return sprintf(buf, "0x%X\n", dci->node_addr);
}

static ssize_t node_pos_show(struct medusa_dci *dci, char *buf)
{
	if (dci->node_pos == 0xFF)
		return sprintf(buf, "0xFF\n");
	return sprintf(buf, "%d\n", dci->node_pos);
}

static ssize_t sync_channels_show(struct medusa_dci *dci, char *buf)
{
	u32 i;

	for (i = 0; i < 32; i++)
		buf[i] = (dci->dma_sync_ch & B2MASK(i)) ? '+' : '-';
	buf[32] = '\n';
	buf[33] = 0;
	return 33; /* not include 0 */
}

static ssize_t mep_filter_mode_show(struct medusa_dci *dci, char *buf)
{
	return sprintf(buf, "0x%02X\n", dci->mep_filter_mode.val);
}

static ssize_t mep_filter_mode_store(struct medusa_dci *dci,
				     const char *buf, size_t count)
{
	int err;
	u8 value;

	/*
	 * kstrtou8() expects '\0' at the end of the buffer,
	 * that is put by configfs_write_file()
	 */
	BUG_ON(buf[count] != 0);

	err = kstrtou8(buf, 0, &value);
	if (err)
		return err;

	dci->mep_filter_mode.val = value;
	dci->mep_filter_mode.flush_pending = true;
	return count;
}

static ssize_t mep_hash_table_show(struct medusa_dci *dci, char *buf)
{
	const u16 *a16 = dci->mep_hash_table.arr16;

	return sprintf(buf, "%04X %04X %04X %04X\n",
		       a16[0], a16[1], a16[2], a16[3]);
}

static ssize_t mep_hash_table_store(struct medusa_dci *dci,
				    const char *buf, size_t count)
{
	enum { NUM = 4 };
	size_t rest = count;
	int i, v0, v1, v2, v3;
	u16 hash_table[NUM];

	for (i = 0; i < NUM; i++) {
		if (rest < 4)
			return -EINVAL;

		v0 = get_xvalue(buf[0]);
		v1 = get_xvalue(buf[1]);
		v2 = get_xvalue(buf[2]);
		v3 = get_xvalue(buf[3]);
		if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0)
			return -EINVAL;

		hash_table[i] = v0 << 12 | v1 << 8 | v2 << 4 | v3;
		buf += 4;
		rest -= 4;
		/* allow delimiter behind table to get simpler code */
		if (rest && (*buf == '-' || *buf == ':' || *buf == ' ')) {
			buf++;
			rest--;
		}
	}
	if (rest != 0 && *buf != '\n')
		return -EINVAL;
	memcpy(dci->mep_hash_table.arr16, hash_table, NUM * sizeof(*hash_table));
	dci->mep_hash_table.flush_pending = true;
	return count;
}

static ssize_t EUI48_show(struct medusa_dci *dci, char *buf)
{
	const u8 *a8 = dci->mac.arr8;

	return sprintf(buf, "%02X-%02X-%02X-%02X-%02X-%02X\n",
		       a8[0], a8[1], a8[2], a8[3], a8[4], a8[5]);
}

static ssize_t EUI48_store(struct medusa_dci *dci,
			   const char *buf, size_t count)
{
	enum { NUM = 6 };
	size_t rest = count;
	int i, v0, v1;
	u8 eui48[NUM];

	for (i = 0; i < NUM; i++) {
		if (rest < 2)
			return -EINVAL;

		v0 = get_xvalue(buf[0]);
		v1 = get_xvalue(buf[1]);
		if (v0 < 0 || v1 < 0)
			return -EINVAL;

		eui48[i] = v0 << 4 | v1;
		buf += 2;
		rest -= 2;
		/* allow delimiter behind address to get simpler code */
		if (rest && (*buf == '-' || *buf == ':' || *buf == ' ')) {
			buf++;
			rest--;
		}
	}
	if (rest != 0 && *buf != '\n')
		return -EINVAL;
	memcpy(dci->mac.arr8, eui48, NUM * sizeof(*eui48));
	dci->mac.flush_pending = true;
	return count;
}

static struct dci_attr dci_attrs[] = {
	MEDUSA_ATTR_RO(availability),
	MEDUSA_ATTR_RO(packet_bw),
	MEDUSA_ATTR_RO(node_addr),
	MEDUSA_ATTR_RO(node_pos),
	MEDUSA_ATTR_RO(sync_channels),
	MEDUSA_ATTR_RW(mep_filter_mode),
	MEDUSA_ATTR_RW(mep_hash_table),
	MEDUSA_ATTR_RW(EUI48),
};

static struct attribute *dci_default_attrs[] = {
	&dci_attrs[0].attr,
	&dci_attrs[1].attr,
	&dci_attrs[2].attr,
	&dci_attrs[3].attr,
	&dci_attrs[4].attr,
	&dci_attrs[5].attr,
	&dci_attrs[6].attr,
	&dci_attrs[7].attr,
	NULL,
};

#define NEGATIVE_IF_FALSE(c) ((c) ? 1 : -1)

struct check_array_match {
	char check_dci_default_attrs_size[
		NEGATIVE_IF_FALSE(
			ARRAY_SIZE(dci_default_attrs) ==
			ARRAY_SIZE(dci_attrs) + 1)];
};

static struct attribute_group dci_attr_group = {
	.attrs = dci_default_attrs,
};

static void dci_kobj_release(struct kobject *kobj)
{
}

static ssize_t dci_kobj_attr_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct medusa_dci *dci = container_of(kobj, struct medusa_dci, kobj_group);
	struct dci_attr *xattr = container_of(attr, struct dci_attr, attr);

	if (!dci->valid)
		return -EIO;
	if (!xattr->show)
		return -EIO;
	return xattr->show(dci, buf);
}

static ssize_t dci_kobj_attr_store(struct kobject *kobj, struct attribute *attr,
				   const char *buf, size_t count)
{
	ssize_t ret;
	struct medusa_dci *dci = container_of(kobj, struct medusa_dci, kobj_group);
	struct dci_attr *xattr = container_of(attr, struct dci_attr, attr);

	if (!xattr->store)
		return -EIO;
	ret = xattr->store(dci, buf, count);
	if (ret > 0)
		tasklet_schedule(&dci->tl);
	return ret;
}

static struct sysfs_ops const dci_kobj_sysfs_ops = {
	.show = dci_kobj_attr_show,
	.store = dci_kobj_attr_store,
};

static struct kobj_type dci_ktype = {
	.release = dci_kobj_release,
	.sysfs_ops = &dci_kobj_sysfs_ops,
};


/*
 * Functions starting with r0_ and w0_ do only access to Mailbox Registers.
 * No state managing is done here. See r_ and w_ functions below.
 *
 * Functions starting with w0_ have write access to Mailbox Registers.
 * These functions do write _and_ read requests to set and get DCI registers.
 *
 * Functions starting with r0_ have only read access to Mailbox Registers.
 */

static void w0_request_status(struct medusa *mdev)
{
	struct dci_wall wall;

	init_dci_wall(&wall, mdev);

	write_dci_wall(&wall, DCI_EVENT_FLAGS);
	write_dci_wall(&wall, DCI_DMA_FLAGS_LO);
	write_dci_wall(&wall, DCI_DMA_FLAGS_HI);

	write_dci_wall(&wall, DCI_A_AVA);

	write_dci_wall(&wall, DCI_A_PCK_BW);

	write_dci_wall(&wall, DCI_A_NADDR);

	write_dci_wall(&wall, DCI_A_NPOS);

	write_dci_wall(&wall, DCI_A_MEP_FM);

	write_dci_wall(&wall, DCI_A_MAC_H);
	write_dci_wall(&wall, DCI_A_MAC_M);
	write_dci_wall(&wall, DCI_A_MAC_L);

	write_dci_wall(&wall, DCI_A_MEP_HT3);
	write_dci_wall(&wall, DCI_A_MEP_HT2);
	write_dci_wall(&wall, DCI_A_MEP_HT1);
	write_dci_wall(&wall, DCI_A_MEP_HT0);

	commit_dci_wall(&wall, DCI_OP_READ);
}

static void r0_get_status(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;
	u16 *arr16;
	u8 *arr8;
	struct dci_wall wall;

	init_dci_wall(&wall, mdev);

	dci->event_flags = read_dci_wall_u16(&wall);
	dci->dma_flags_lo = read_dci_wall_u16(&wall);
	dci->dma_flags_hi = read_dci_wall_u16(&wall);

	dci->availability = read_dci_wall_u16(&wall);

	dci->packet_bw = read_dci_wall_u16(&wall);

	dci->node_addr = read_dci_wall_u16(&wall);

	dci->node_pos = read_dci_wall_u16(&wall);

	dci->mep_filter_mode.val = read_dci_wall_u16(&wall);
	dci->mep_filter_mode.flush_pending = false;

	arr8 = dci->mac.arr8;
	read_dci_wall_byte_arr(&wall, arr8 + 0);
	read_dci_wall_byte_arr(&wall, arr8 + 2);
	read_dci_wall_byte_arr(&wall, arr8 + 4);
	dci->mac.flush_pending = false;

	arr16 = dci->mep_hash_table.arr16;
	arr16[0] = read_dci_wall_u16(&wall);
	arr16[1] = read_dci_wall_u16(&wall);
	arr16[2] = read_dci_wall_u16(&wall);
	arr16[3] = read_dci_wall_u16(&wall);
	dci->mep_hash_table.flush_pending = false;
}

static void w0_clear_dma_ch_flags(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;
	struct dci_wall wall;

	init_dci_wall(&wall, mdev);
	write_dci_wall(&wall, DCI_DMA_FLAGS_LO | dci->dma_flags_lo);
	write_dci_wall(&wall, DCI_DMA_FLAGS_HI | dci->dma_flags_hi);
	commit_dci_wall(&wall, DCI_OP_WRITE);
}

static void w0_request_dma_ch_status(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;
	struct dci_wall wall;
	u32 reg, i;

	init_dci_wall(&wall, mdev);

	for (i = 0; i < 16; i++)
		if (dci->dma_flags_lo & B2MASK(i)) {
			reg = DCI_DMA_CH_REG_SYNC_NEEDED(i);
			write_dci_wall(&wall, reg);
		}

	for (i = 0; i < 16; i++)
		if (dci->dma_flags_hi & B2MASK(i)) {
			reg = DCI_DMA_CH_REG_SYNC_NEEDED(i + 16);
			write_dci_wall(&wall, reg);
		}

	if (!is_dci_wall_empty(&wall))
		commit_dci_wall(&wall, DCI_OP_READ);
}

static void r0_get_dma_ch_status(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;
	u32 val, i;
	struct dci_wall wall;

	init_dci_wall(&wall, mdev);

	dci->dma_sync_ch_lo = 0;
	for (i = 0; i < 16; i++)
		if (dci->dma_flags_lo & B2MASK(i)) {
			val = read_dci_wall_u16(&wall) & B2MASK(0);
			dci->dma_sync_ch_lo |= val << i;
		}
	dci->dma_sync_ch |= dci->dma_sync_ch_lo;

	dci->dma_sync_ch_hi = 0;
	for (i = 0; i < 16; i++)
		if (dci->dma_flags_hi & B2MASK(i)) {
			val = read_dci_wall_u16(&wall) & B2MASK(0);
			dci->dma_sync_ch_hi |= val << i;
		}
	dci->dma_sync_ch |= (u32)dci->dma_sync_ch_hi << 16;
}

static void w0_ack_dma_ch(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;
	struct dci_wall wall;
	u32 reg, i;

	init_dci_wall(&wall, mdev);

	for (i = 0; i < 16; i++)
		if (dci->dma_sync_ch_lo & B2MASK(i)) {
			reg = DCI_DMA_CH_REG_SYNC_NEEDED(i);
			write_dci_wall(&wall, reg | B2MASK(0));
		}

	for (i = 0; i < 16; i++)
		if (dci->dma_sync_ch_hi & B2MASK(i)) {
			reg = DCI_DMA_CH_REG_SYNC_NEEDED(i + 16);
			write_dci_wall(&wall, reg | B2MASK(0));
		}

	if (!is_dci_wall_empty(&wall))
		commit_dci_wall(&wall, DCI_OP_WRITE);
}

static void w0_flush_most_reset_ack(struct medusa_dci *dci,
				    struct dci_wall *wall)
{
	enum { MOST_RESET = 5 };

	if ((dci->event_flags & B2MASK(MOST_RESET)) != 0) {
		dci->event_flags &= ~B2MASK(MOST_RESET);
		write_dci_wall(wall, DCI_EVENT_FLAGS | B2MASK(MOST_RESET));
		write_dci_wall(wall, DCI_PCI_PORT_FLAGS | B2MASK(0));
	}

}

static void w0_flush_mep_fmode(struct medusa_dci *dci, struct dci_wall *wall)
{
	if (dci->mep_filter_mode.flush_pending) {
		dci->mep_filter_mode.flush_pending = false;
		write_dci_wall(wall, DCI_A_MEP_FM | dci->mep_filter_mode.val);
	}
}

static void w0_flush_mac(struct medusa_dci *dci, struct dci_wall *wall)
{
	if (dci->mac.flush_pending) {
		const u8 *arr8 = dci->mac.arr8;

		dci->mac.flush_pending = false;
		write_dci_wall(wall, DCI_A_MAC_H | (u16)arr8[0] << 8 | arr8[1]);
		write_dci_wall(wall, DCI_A_MAC_M | (u16)arr8[2] << 8 | arr8[3]);
		write_dci_wall(wall, DCI_A_MAC_L | (u16)arr8[4] << 8 | arr8[5]);
	}
}

static void w0_flush_mep_ht(struct medusa_dci *dci, struct dci_wall *wall)
{
	if (dci->mep_hash_table.flush_pending) {
		const u16 *arr16 = dci->mep_hash_table.arr16;

		dci->mep_hash_table.flush_pending = false;
		write_dci_wall(wall, DCI_A_MEP_HT3 | arr16[0]);
		write_dci_wall(wall, DCI_A_MEP_HT2 | arr16[1]);
		write_dci_wall(wall, DCI_A_MEP_HT1 | arr16[2]);
		write_dci_wall(wall, DCI_A_MEP_HT0 | arr16[3]);
	}
}

/*
 * State machine.
 *
 * Functions starting with w_ and r_ service DCI state machine.
 * These functions have no direct access to DCI registers and
 * instead of that call corresponding w0_ and r0_ functions.
 *
 * See also description of w0_ and r0_ functions.
 *
 * r_ functions have priority before w_ functions as they end transactions
 * started with w_ functions.
 */

static void w_service(struct medusa *mdev);
static void r_get_status(struct medusa *mdev);
static void w_request_dma_ch_status(struct medusa *mdev);
static void w_clear_dma_ch_flags(struct medusa *mdev);
static void r_get_dma_ch_status(struct medusa *mdev);
static void w_ack_dma_ch(struct medusa *mdev);

static void w_service(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;
	struct dci_wall wall;

	init_dci_wall(&wall, mdev);
	w0_flush_most_reset_ack(dci, &wall);
	w0_flush_mep_fmode(dci, &wall);
	w0_flush_mac(dci, &wall);
	w0_flush_mep_ht(dci, &wall);
	if (!is_dci_wall_empty(&wall)) {
		commit_dci_wall(&wall, DCI_OP_WRITE);
		return;
	}

	if (atomic_read(&dci->service_notification)) {
		atomic_set(&dci->service_notification, 0);
		w0_request_status(mdev);

		dci->read = r_get_status;
	}
}

static void r_get_status(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;

	r0_get_status(mdev);
	dci->valid = true;

	if (dci->dma_flags_lo || dci->dma_flags_hi)
		dci->write = w_clear_dma_ch_flags;
	else
		dci->write = w_service;
}

static void w_clear_dma_ch_flags(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;

	w0_clear_dma_ch_flags(mdev);

	dci->write = w_request_dma_ch_status;
}

static void w_request_dma_ch_status(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;

	w0_request_dma_ch_status(mdev);

	dci->read = r_get_dma_ch_status;
}

static void r_get_dma_ch_status(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;

	r0_get_dma_ch_status(mdev);

	if (dci->dma_sync_ch_lo || dci->dma_sync_ch_hi)
		dci->write = w_ack_dma_ch;
	else
		dci->write = w_service;
}

static void w_ack_dma_ch(struct medusa *mdev)
{
	struct medusa_dci *dci = &mdev->dci;

	w0_ack_dma_ch(mdev);

	dci->write = w_service;
}

static void service_dci_tl_fn(unsigned long param)
{
	struct medusa *mdev = (void *)param;
	struct medusa_dci *dci = &mdev->dci;

	if (atomic_read(&dci->service_cmd_complete)) {
		atomic_set(&dci->service_cmd_complete, 0);
		if (dci->read)
			dci->read(mdev);
		dci->read = NULL;
	}

	if (!dci->read) {
		u32 idbell = medusa_read_b1(mdev, IDBELL_REGISTER);
		bool writeable = (idbell & B2MASK(IDBELL_IDB_BIT)) == 0;

		if (writeable)
			dci->write(mdev);
	}
}

int dci_probe(struct medusa *mdev)
{
	int err;

	mdev->dci.write = w_service;
	atomic_set(&mdev->dci.service_notification, 1);
	atomic_set(&mdev->dci.service_cmd_complete, 0);
	tasklet_init(&mdev->dci.tl, service_dci_tl_fn, (unsigned long)mdev);

	kobject_init(&mdev->dci.kobj_group, &dci_ktype);
	err = kobject_add(&mdev->dci.kobj_group, mdev->parent_kobj, "dci");
	if (err) {
		pr_err("kobject_add() failed: %d\n", err);
		goto err_kobject_add;
	}

	err = sysfs_create_group(&mdev->dci.kobj_group, &dci_attr_group);
	if (err) {
		pr_err("sysfs_create_group() failed: %d\n", err);
		goto err_create_group;
	}

	return 0;

err_create_group:
	kobject_put(&mdev->dci.kobj_group);

err_kobject_add:
	return err;
}

void dci_run(struct medusa *mdev)
{
	tasklet_schedule(&mdev->dci.tl);
}

void dci_stop(struct medusa *mdev)
{
	tasklet_kill(&mdev->dci.tl);
}

void dci_destroy(struct medusa *mdev)
{
	kobject_put(&mdev->dci.kobj_group);
}

void dci_service_int(struct medusa *mdev)
{
	u32 const cmd_mask = B2MASK(PSTSN_ODB1_BIT);
	u32 const ntf_mask = B2MASK(PSTSN_ODB0_BIT);
	size_t offset = PSTSN + (4 * DCI_CH);
	u32 value = medusa_read_b1(mdev, offset) &
		    (cmd_mask | ntf_mask | B2MASK(PSTSN_ODBWR_BIT));

	if (value & ntf_mask)
		atomic_set(&mdev->dci.service_notification, 1);
	if (value & cmd_mask)
		atomic_set(&mdev->dci.service_cmd_complete, 1);

	medusa_write_b1(mdev, offset, value);
	tasklet_schedule(&mdev->dci.tl);
}
