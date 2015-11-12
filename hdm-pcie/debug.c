/*
 * debug.c - Medusa Debug Driver
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/debugfs.h>
#include <mostcore.h>
#include "medusa.h"
#include "registers.h"


struct debug_attr {
	struct attribute attr;
	int state;
	ssize_t (*show)(struct medusa *mdev, char *buf);
	ssize_t (*store)(struct medusa *mdev, const char *buf, size_t count);
};


static inline int dbg_read_u32(const char *buf, size_t count, u32 *res,
			       u32 max_val)
{
	int err;
	u32 val;

	/*
	 * kstrtouint() expects '\0' at the end of the buffer,
	 * that is put by configfs_write_file()
	 */
	BUG_ON(buf[count] != 0);

	err = kstrtou32(buf, 0, &val);
	if (err)
		return err;

	if (val > max_val)
		return -ERANGE;

	*res = val;
	return 0;
}

static ssize_t mbox79_show(struct medusa *mdev, char *buf)
{
	u32 mbox79 = medusa_read_b1(mdev, MAILBOX_REGISTER(79));

	return scnprintf(buf, PAGE_SIZE, "0x%08X\n", mbox79);
}

static ssize_t pdma_ct_store(struct medusa *mdev, const char *buf, size_t count)
{
	u32 val;
	u32 pdma;
	int err = dbg_read_u32(buf, count, &val, PDMA_CT_MASK);

	if (err)
		return err;

	pdma = medusa_read_b1(mdev, PDMA_REGISTER);
	pdma &= ~(PDMA_CT_MASK << PDMA_CT_OFFSET);
	pdma |= val << PDMA_CT_OFFSET;
	pr_info("PDMA.CT %d\n", val);
	medusa_write_b1(mdev, PDMA_REGISTER, pdma);
	return count;
}

static ssize_t pdma_db_store(struct medusa *mdev, const char *buf, size_t count)
{
	u32 val;
	u32 pdma;
	int err = dbg_read_u32(buf, count, &val, PDMA_DB_MASK);

	if (err)
		return err;

	pdma = medusa_read_b1(mdev, PDMA_REGISTER);
	pdma &= ~(PDMA_DB_MASK << PDMA_DB_OFFSET);
	pdma |= val << PDMA_DB_OFFSET;
	pr_info("PDMA.DB %d\n", val);
	medusa_write_b1(mdev, PDMA_REGISTER, pdma);
	return count;
}

static ssize_t pint_show(struct medusa *mdev, char *buf)
{
	u32 pint = medusa_read_b1(mdev, PINT);

	return scnprintf(buf, PAGE_SIZE, "0x%08X\n", pint);
}

static ssize_t pint_store(struct medusa *mdev, const char *buf, size_t count)
{
	u32 val;
	int err = dbg_read_u32(buf, count, &val, 0xFF);

	if (err)
		return err;

	medusa_write_b1(mdev, PINT, val);
	return count;
}

static ssize_t format_dump_bar(char *buf, size_t count,
			       size_t mem_size,
			       u32(*read_reg_fn)(size_t, void *),
			       void *data,
			       size_t *rolling_offset)
{
	enum { UNITS_PER_LINE = 8, UNIT_SIZE = 4 };

	enum { ADDR_LEN /* "%04X: " */ = 6, UNIT_LEN /* "%08X " */ = 9 };
	enum { STR_LEN = ADDR_LEN + UNITS_PER_LINE * UNIT_LEN + 1 /* "\n" */ };

	size_t const LINES = mem_size / (UNIT_SIZE * UNITS_PER_LINE);
	size_t const REST_UNITS = (mem_size % (UNIT_SIZE * UNITS_PER_LINE)) / UNIT_SIZE;

	size_t count0 = count;
	size_t offset = 0;
	int line, i;

	if (count < STR_LEN)
		return -EIO;

	for (line = 0; line < LINES; line++) {
		int w = scnprintf(buf, count, "%04X: ",
				  *rolling_offset + offset);
		for (i = 0; i < UNITS_PER_LINE; i++, offset += UNIT_SIZE)
			w += scnprintf(buf + w, count - w, "%08X ",
				       read_reg_fn(offset, data));
		w += scnprintf(buf + w, count - w, "\n");
		BUG_ON(w != STR_LEN);
		buf += w;
		count -= w;
		if (count < STR_LEN)
			goto out;
	}

	if (REST_UNITS) {
		size_t const LAST_STR_LEN =
			STR_LEN + (REST_UNITS - UNITS_PER_LINE) * UNIT_LEN;
		int w = scnprintf(buf, count, "%04X: ",
				  *rolling_offset + offset);
		for (i = 0; i < REST_UNITS; i++, offset += UNIT_SIZE)
			w += scnprintf(buf + w, count - w, "%08X ",
				       read_reg_fn(offset, data));
		w += scnprintf(buf + w, count - w, "\n");
		BUG_ON(w != LAST_STR_LEN);
		count -= w;
	}

out:
	*rolling_offset += offset;
	return count0 - count;
}

static ssize_t format_dump_mem(char *buf, size_t count,
			       const void *addr, size_t mem_size,
			       size_t *rolling_offset)
{
	enum { UNITS_PER_LINE = 4, UNIT_SIZE = 4 };

	enum { ADDR_LEN /* "%08X: " */ = 10, UNIT_LEN /* "%08X " */ = 9 };
	enum { STR_LEN = ADDR_LEN + UNITS_PER_LINE * UNIT_LEN + 1 /* "\n" */ };

	size_t const LINES = mem_size / (UNIT_SIZE * UNITS_PER_LINE);
	size_t const REST_UNITS = (mem_size % (UNIT_SIZE * UNITS_PER_LINE)) / UNIT_SIZE;

	size_t count0 = count;
	const u32 *ptr = addr;
	int line, i;

	if (count < STR_LEN)
		return -EIO;

	for (line = 0; line < LINES; line++) {
		int w = scnprintf(buf, count, "%08X: ", (u32)(size_t)ptr);

		for (i = 0; i < UNITS_PER_LINE; i++, ptr++)
			w += scnprintf(buf + w, count - w, "%08X ", *ptr);
		w += scnprintf(buf + w, count - w, "\n");
		BUG_ON(w != STR_LEN);
		buf += w;
		count -= w;
		if (count < STR_LEN)
			goto out;
	}

	if (REST_UNITS) {
		size_t const LAST_STR_LEN =
			STR_LEN + (REST_UNITS - UNITS_PER_LINE) * UNIT_LEN;
		int w = scnprintf(buf, count, "%08X: ", (u32)(size_t)ptr);

		for (i = 0; i < REST_UNITS; i++, ptr++)
			w += scnprintf(buf + w, count - w, "%08X ", *ptr);
		w += scnprintf(buf + w, count - w, "\n");
		BUG_ON(w != LAST_STR_LEN);
		count -= w;
	}

out:
	*rolling_offset += (void *)ptr - addr;
	return count0 - count;
}

static ssize_t current_channel_index_show(struct medusa *mdev, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", mdev->dbg.cur_channel_idx);
}

static ssize_t current_channel_index_store(struct medusa *mdev,
		const char *buf, size_t count)
{
	u32 val;
	int err = dbg_read_u32(buf, count, &val, 255);

	if (err)
		return err;

	mdev->dbg.cur_channel_idx = val;
	return count;
}

static ssize_t rolling_offset_show(struct medusa *mdev, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0x%X\n", (u32)mdev->dbg.rolling_offset);
}

static ssize_t rolling_offset_store(struct medusa *mdev,
				    const char *buf, size_t count)
{
	u32 val;
	int err = dbg_read_u32(buf, count, &val, 0xFFFF);

	if (err)
		return err;

	mdev->dbg.rolling_offset = (val / 4) * 4; /* round down to 4 bytes */
	return count;
}

struct read_reg_context {
	struct medusa *mdev;
	size_t base_offset;
};

static u32 read_reg_bar1(size_t offset, void *data)
{
	struct read_reg_context *ctx = data;

	return medusa_read_b1(ctx->mdev, ctx->base_offset + offset);
}

static u32 read_reg_bar2(size_t offset, void *data)
{
	struct read_reg_context *ctx = data;

	return medusa_read_b2(ctx->mdev, ctx->base_offset + offset);
}

static ssize_t dump_bar1_show(struct medusa *mdev, char *buf)
{
	size_t mem_size = 0x400;
	struct read_reg_context ctx = { .mdev = mdev };

	ctx.base_offset = min(mem_size, mdev->dbg.rolling_offset);
	mem_size -= ctx.base_offset;
	return format_dump_bar(buf, PAGE_SIZE, mem_size, read_reg_bar1, &ctx,
			       &mdev->dbg.rolling_offset);
}

static ssize_t dump_bar2_show(struct medusa *mdev, char *buf)
{
	size_t mem_size = 0x1000;
	struct read_reg_context ctx = { .mdev = mdev };

	ctx.base_offset = min(mem_size, mdev->dbg.rolling_offset);
	mem_size -= ctx.base_offset;
	return format_dump_bar(buf, PAGE_SIZE, mem_size, read_reg_bar2, &ctx,
			       &mdev->dbg.rolling_offset);
}

static ssize_t dump_descriptors_show(struct medusa *mdev, char *buf)
{
	u8 const ch_idx = mdev->dbg.cur_channel_idx;
	u8 *addr;
	size_t size;
	size_t skip;
	int ret = medusa_get_descriptors_mem(mdev, ch_idx, &addr, &size);

	if (!ret) {
		pr_err("bad " "current-channel-index" " [%d]\n", ch_idx);
		return -EIO;
	}

	if (!addr) {
		pr_err("error, channel [%d] is closed\n", ch_idx);
		return -EIO;
	}

	skip = min(size, mdev->dbg.rolling_offset);
	size -= skip;
	addr += skip;

	return format_dump_mem(buf, PAGE_SIZE, addr, size,
			       &mdev->dbg.rolling_offset);
}

static ssize_t pctrl_tc_show(struct medusa *mdev, char *buf)
{
	u8 const ch_idx = mdev->dbg.cur_channel_idx;
	u32 val, threshold;

	if (!medusa_get_descriptors_mem(mdev, ch_idx, 0, 0)) {
		pr_err("bad " "current-channel-index" " [%d]\n", ch_idx);
		return -EIO;
	}

	val = medusa_read_b1(mdev, PCTRL_REGISTER(ch_idx));
	threshold = (val >> PCTRL_TC_OFFSET) & PCTRL_TC_MASK;
	return scnprintf(buf, PAGE_SIZE, "%d\n", threshold);
}

static ssize_t pctrl_tc_store(struct medusa *mdev,
			      const char *buf, size_t count)
{
	u8 const ch_idx = mdev->dbg.cur_channel_idx;
	size_t const pctrl_reg = PCTRL_REGISTER(ch_idx);
	u32 val, pctrl, is_enabled;
	int err;

	if (!medusa_get_descriptors_mem(mdev, ch_idx, 0, 0)) {
		pr_err("bad " "current-channel-index" " [%d]\n", ch_idx);
		return -EIO;
	}

	err = dbg_read_u32(buf, count, &val, PCTRL_TC_MASK);
	if (err)
		return err;

	pctrl = medusa_read_b1(mdev, pctrl_reg);
	is_enabled = pctrl & ((u32)1u << PCTRL_EN_BIT);
	if (is_enabled) {
		pr_err("cannot change PCTRL.TC by enabled channel\n");
		return -EIO;
	}

	pctrl &= ~(PCTRL_TC_MASK << PCTRL_TC_OFFSET);
	pctrl |= val << PCTRL_TC_OFFSET;
	pr_info("PCTRL.TC[%d] %d\n", ch_idx, val);
	medusa_write_b1(mdev, pctrl_reg, pctrl);
	return count;
}

static ssize_t pctrl_dthr_show(struct medusa *mdev, char *buf)
{
	u8 const ch_idx = mdev->dbg.cur_channel_idx;
	u32 val, threshold;

	if (!medusa_get_descriptors_mem(mdev, ch_idx, 0, 0)) {
		pr_err("bad " "current-channel-index" " [%d]\n", ch_idx);
		return -EIO;
	}

	val = medusa_read_b1(mdev, PCTRL_REGISTER(ch_idx));
	threshold = (val >> PCTRL_DTHR_OFFSET) & PCTRL_DTHR_MASK;
	return scnprintf(buf, PAGE_SIZE, "%d" "\n", threshold);
}

static ssize_t pctrl_dthr_store(struct medusa *mdev,
				const char *buf, size_t count)
{
	u8 const ch_idx = mdev->dbg.cur_channel_idx;
	size_t const pctrl_reg = PCTRL_REGISTER(ch_idx);
	u32 val, pctrl, is_enabled;
	int err;

	if (!medusa_get_descriptors_mem(mdev, ch_idx, 0, 0)) {
		pr_err("bad " "current-channel-index" " [%d]\n", ch_idx);
		return -EIO;
	}

	err = dbg_read_u32(buf, count, &val, PCTRL_DTHR_MASK);
	if (err)
		return err;

	pctrl = medusa_read_b1(mdev, pctrl_reg);
	is_enabled = pctrl & ((u32)1u << PCTRL_EN_BIT);
	if (is_enabled) {
		pr_err("cannot change PCTRL.DTHR by enabled channel\n");
		return -EIO;
	}

	pctrl &= ~(PCTRL_DTHR_MASK << PCTRL_DTHR_OFFSET);
	pctrl |= val << PCTRL_DTHR_OFFSET;
	pr_info("PCTRL.DTHR[%d] %d\n", ch_idx, val);
	medusa_write_b1(mdev, pctrl_reg, pctrl);
	return count;
}

static struct debug_attr debug_attrs[] = {
	MEDUSA_ATTR_RW(current_channel_index),
	MEDUSA_ATTR_RW(rolling_offset),
	MEDUSA_ATTR_RO(dump_bar1),
	MEDUSA_ATTR_RO(dump_bar2),
	MEDUSA_ATTR_RO(dump_descriptors),
	MEDUSA_ATTR_RW(pint),
	MEDUSA_ATTR_WO(pdma_db),
	MEDUSA_ATTR_WO(pdma_ct),
	MEDUSA_ATTR_RO(mbox79),
	MEDUSA_ATTR_RW(pctrl_tc),
	MEDUSA_ATTR_RW(pctrl_dthr),
};

static struct attribute *debug_default_attrs[] = {
	&debug_attrs[0].attr,
	&debug_attrs[1].attr,
	&debug_attrs[2].attr,
	&debug_attrs[3].attr,
	&debug_attrs[4].attr,
	&debug_attrs[5].attr,
	&debug_attrs[6].attr,
	&debug_attrs[7].attr,
	&debug_attrs[8].attr,
	&debug_attrs[9].attr,
	&debug_attrs[10].attr,
	NULL,
};

#define NEGATIVE_IF_FALSE(c) ((c) ? 1 : -1)

struct check_array_match {
	char check_debug_default_attrs_size[
		NEGATIVE_IF_FALSE(
			ARRAY_SIZE(debug_default_attrs) ==
			ARRAY_SIZE(debug_attrs) + 1)];
};

static struct attribute_group debug_attr_group = {
	.attrs = debug_default_attrs,
};


static void dbg_kobj_release(struct kobject *kobj)
{
}

static ssize_t dbg_kobj_attr_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct medusa *mdev = container_of(kobj, struct medusa, dbg.kobj_group);
	struct debug_attr *xattr =
		container_of(attr, struct debug_attr, attr);

	if (!xattr->show)
		return -EIO;
	return xattr->show(mdev, buf);
}

static ssize_t dbg_kobj_attr_store(struct kobject *kobj, struct attribute *attr,
				   const char *buf, size_t count)
{
	struct medusa *mdev = container_of(kobj, struct medusa, dbg.kobj_group);
	struct debug_attr *xattr =
		container_of(attr, struct debug_attr, attr);

	if (!xattr->store)
		return -EIO;
	return xattr->store(mdev, buf, count);
}

static struct sysfs_ops const dbg_kobj_sysfs_ops = {
	.show = dbg_kobj_attr_show,
	.store = dbg_kobj_attr_store,
};

static struct kobj_type dbg_ktype = {
	.release = dbg_kobj_release,
	.sysfs_ops = &dbg_kobj_sysfs_ops,
};

int medusa_debug_probe(struct medusa *mdev)
{
	int err;

	kobject_init(&mdev->dbg.kobj_group, &dbg_ktype);
	err = kobject_add(&mdev->dbg.kobj_group, mdev->parent_kobj, "debug");
	if (err) {
		pr_err("kobject_add() failed: %d\n", err);
		goto err_kobject_add;
	}

	err = sysfs_create_group(&mdev->dbg.kobj_group, &debug_attr_group);
	if (err) {
		pr_err("sysfs_create_group() failed: %d\n", err);
		goto err_create_group;
	}

	mdev->dbg.cur_channel_idx = 255;

	return 0;

err_create_group:
	kobject_put(&mdev->dbg.kobj_group);

err_kobject_add:
	return err;
}

