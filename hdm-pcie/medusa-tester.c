/*
 * mostcore-simu.c - Medusa Testing Driver
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
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/hrtimer.h>
#include <linux/bug.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/io.h>
#include <mostcore.h>
#include "medusa.h"
#include "registers.h"


#define DMA_ALLOC_SIZE	512u

#define BYTES_PER_KEY  32u

#define NUM_TESTED_DMA_LOOPS 2

#define STOP_STRESS_BY_FAIL 1

#define SHIFT_DMA_BUFFER 0

#define HRTIMER_INTERVAL_NS (100 * NSEC_PER_USEC)


static enum hrtimer_restart hrt_fn(struct hrtimer *hrt);

enum { CDEV0, NUM_CDEVS };

enum { SST_IDLE, SST_RUNNING, SST_ERROR, SST_SUSPEND_HRT = 100, SST_TX_RX_TIMEOUT = 999 };

#define KEYS_PER_BUFFER  ((DMA_ALLOC_SIZE + (BYTES_PER_KEY - 1u)) / BYTES_PER_KEY)


static struct medusa fake_mdev = {};

struct globals {
	struct cdev cdev[NUM_CDEVS];
	dev_t most_dev_base;
	unsigned int most_major;
	struct class *most_class;
	struct most_interface *iface;
	struct medusa *mdev;
	struct hrtimer timer;
	struct kobject kobj_group;
	struct stress {
		int state;
		unsigned int tx[NUM_TESTED_DMA_LOOPS];
		unsigned int rx[NUM_TESTED_DMA_LOOPS];
		unsigned int rx_ok;
		unsigned int rx_bad;
	} stress;
	int empty_runs;
	unsigned last_counter;
};

static struct globals g = {
	.mdev = &fake_mdev,
};


#if 1 /* helpers from medusa */

static void *medusa_get_bus_addr(struct medusa *mdev, int chidx)
{
	if (!mdev || mdev == &fake_mdev)
		return 0;
	return (void *)mdev->dma_channels[chidx].desc_start_paddr;
}

static inline u32 medusa_read_reg(struct medusa *mdev, size_t offset)
{
	if (!mdev || mdev == &fake_mdev)
		return 0;
	return (u32)ioread32(mdev->hw_addr_bar1 + offset);
}

static inline void medusa_write_reg(struct medusa *mdev, size_t offset,
				    u32 value)
{
	if (mdev && mdev != &fake_mdev)
		iowrite32(value, mdev->hw_addr_bar1 + offset);
}

static inline u64 medusa_read_tail_address(struct medusa *mdev, u8 chidx)
{
	u64 tail_address;
	size_t offset;

	offset = TAIL_ADDR_HI_REG_BASE_ADDR + (chidx * 8);
	tail_address = medusa_read_reg(mdev, offset);
	tail_address = tail_address << 32;

	offset = TAIL_ADDR_LO_REG_BASE_ADDR + (chidx * 8);
	tail_address |= medusa_read_reg(mdev, offset);

	return tail_address;
}

#endif

#if 1 /* mostcore api */

struct kobject *most_register_interface(struct most_interface *iface)
{
	int i;
	struct most_channel_config cfg = {.data_type = MOST_CH_ISOC_AVP };
	struct medusa *mdev;

	if (!iface) {
		pr_err("bad instance pointer\n");
		return 0;
	}

	if (g.iface) {
		pr_err("no resources more\n");
		return 0;
	}

	mdev = container_of(iface, struct medusa, most_intf);
	if (mdev->dbg_magic_key != DBG_MAGIC_KEY) {
		pr_err("bad instance\n");
		return 0;
	}

	g.iface = iface;
	g.mdev = mdev;

	for (i = 0; i < NUM_TESTED_DMA_LOOPS * 2; i++) {
		g.iface->configure(g.iface, i, &cfg);
		pr_info("init_dma_channel(%d): first decriptor bus addr: %p\n",
			i, medusa_get_bus_addr(g.mdev, i));
	}

	return &g.kobj_group;
}
EXPORT_SYMBOL(most_register_interface);

void most_deregister_interface(struct most_interface *intf_instance)
{
	if (g.iface == intf_instance) {
		g.iface = 0;
		g.mdev = &fake_mdev;
	}
}
EXPORT_SYMBOL(most_deregister_interface);

void most_stop_enqueue(struct most_interface *iface, int id)
{
}
EXPORT_SYMBOL(most_stop_enqueue);

#endif

static unsigned int normalize_cnt(unsigned int cnt)
{
	return cnt & 0x00FFFFFFu;
}

static void trace_after_fail(void)
{
	int ch;

	for (ch = 0; ch < NUM_TESTED_DMA_LOOPS * 2; ch++)
		pr_err("PSTS%d: %08Xh\n", ch,
		       medusa_read_reg(g.mdev, PSTSN + (4 * ch)));
	for (ch = 0; ch < NUM_TESTED_DMA_LOOPS * 2; ch++)
		pr_err("tail_addr%d: %p\n", ch,
		       (void *)medusa_read_tail_address(g.mdev, ch));
	pr_err("DBG1: %08Xh\n", medusa_read_reg(g.mdev, 0x320));
	pr_err("DBG2: %08Xh\n", medusa_read_reg(g.mdev, 0x324));
}

static inline int is_rx_channel(int ch)
{
	return (ch % 2) == 0;
}

static void fill_rx_mbo(struct mbo *mbo, unsigned int pattern)
{
	u8 *ptr = mbo->virt_address;
	u32 len = mbo->buffer_length;
	unsigned int i;

	for (i = 0; i + 3 < len; i += 4) {
		ptr[i + 0] = pattern >> 24;
		ptr[i + 1] = pattern >> 16;
		ptr[i + 2] = pattern >> 8;
		ptr[i + 3] = pattern;
	}
}

static void fill_tx_mbo(struct mbo *mbo, unsigned int cnt, int ch)
{
	u8 *ptr = mbo->virt_address;
	u32 len = mbo->buffer_length;
	u32 const tag0 = 0x80000000u | ((u32)ch & 0xFEu) << 24;
	unsigned int i;

	for (i = 0; i < len; i++) {
		u32 const tag = tag0 | normalize_cnt(cnt + i / BYTES_PER_KEY);
		u32 const offset = i % BYTES_PER_KEY;

		switch (offset) {
		case 0:
			ptr[i] = tag >> 24;
			break;
		case 1:
			ptr[i] = tag >> 16;
			break;
		case 2:
			ptr[i] = tag >> 8;
			break;
		case 3:
			ptr[i] = tag;
			break;
		default:
			ptr[i] = tag + offset;
			break;
		}
	}
}

static int check_mbo(struct mbo *mbo, unsigned int cnt, int ch)
{
	u8 *ptr = mbo->virt_address;
	u32 len = mbo->buffer_length;
	u32 const tag0 = 0x80000000u | ((u32)ch & 0xFEu) << 24;
	unsigned int i, bad_idx;
	enum { MAX_NUM = BYTES_PER_KEY };
	unsigned char buffer[MAX_NUM * 3 + 10];

	for (i = 0; i < len; i++) {
		u8 v;
		u32 const tag = tag0 | normalize_cnt(cnt + i / BYTES_PER_KEY);
		u32 const offset = i % BYTES_PER_KEY;

		switch (offset) {
		case 0:
			v  = tag >> 24;
			break;
		case 1:
			v  = tag >> 16;
			break;
		case 2:
			v  = tag >> 8;
			break;
		case 3:
			v  = tag;
			break;
		default:
			v = tag + offset;
			break;
		}
		if (ptr[i] != v) {
			bad_idx = i;
			goto trace_error;
		}
	}

	return 1;

trace_error:
	pr_err("check_mbo(): bad payload, offset %d\n", bad_idx);

	for (i = 0; i < len; i++) {
		sprintf(buffer + (i % MAX_NUM) * 3,
			i == bad_idx ? "%02X!" : "%02X ", ptr[i]);
		if ((i % MAX_NUM) == MAX_NUM - 1) {
			pr_err("%s\n", buffer);
			buffer[0] = 0;
		}
	}
	pr_err("%s\n", buffer);

	return 0;
}

static void completion_routine(struct mbo *mbo)
{
	int ch = (int)(long)mbo->context;
	int goto_stop_stress = 0;
	int goto_free_mbo = 0;

	if (g.stress.state != SST_RUNNING)
		goto_free_mbo = 1;

	if (ch < 0 || ch > NUM_TESTED_DMA_LOOPS * 2) {
		pr_err("completion_routine: bad channel (%d), "
		       "stopping stress\n", ch);
		goto stop_stress;
	}

	if (mbo->status != MBO_SUCCESS) {
		pr_err("completion_routine: ch %d, bad mbo->status (%d)\n",
		       ch, mbo->status);
		goto_stop_stress = 1;
	}

	if (mbo->processed_length != mbo->buffer_length) {
		pr_err("completion_routine: ch %d, bad mbo->processed_length (%d)\n",
		       ch, mbo->processed_length);
		goto_stop_stress = 1;
	}

	if (is_rx_channel(ch)) {
		if (check_mbo(mbo, g.stress.rx[ch / 2], ch)) {
			g.stress.rx_ok++;
		} else {
			g.stress.rx_bad++;
			trace_after_fail();
		}
		g.stress.rx[ch / 2] =
			normalize_cnt(g.stress.rx[ch / 2] + KEYS_PER_BUFFER);
		fill_rx_mbo(mbo, 0xDEADBEEF);
	} else {
		fill_tx_mbo(mbo, g.stress.tx[ch / 2], ch);
		g.stress.tx[ch / 2] =
			normalize_cnt(g.stress.tx[ch / 2] + KEYS_PER_BUFFER);
	}

	if (goto_free_mbo)
		goto free_mbo;

#if STOP_STRESS_BY_FAIL
	if (g.stress.rx_bad)
		goto stop_stress;
#endif

	if (goto_stop_stress)
		goto stop_stress;

	if (!g.iface) {
		pr_err("completion_routine: false g.iface_channel.iface, "
		       "stopping stress\n");
		goto stop_stress;
	}

	if (g.iface->enqueue(g.iface, ch, mbo) != 0) {
		pr_err("completion_routine: ch %d, re-enqueue failed, "
		       "stopping stress\n", ch);
		goto stop_stress;
	}

	return;

stop_stress:
	g.stress.state = SST_ERROR;

free_mbo:
	dma_free_coherent(NULL, DMA_ALLOC_SIZE + SHIFT_DMA_BUFFER,
			  mbo->virt_address - SHIFT_DMA_BUFFER,
			  mbo->bus_address - SHIFT_DMA_BUFFER);
	pr_err("free mbo %p, ch %d\n", mbo, ch);
	kfree(mbo);
}

static int enq(int ch, unsigned int val)
{
	struct mbo *mbo;
	int ret = 0;

	if (!g.iface) {
		pr_err("false g.iface_channel.iface\n");
		return -ENOENT;
	}

	mbo = kzalloc(sizeof(struct mbo), GFP_KERNEL);
	if (!mbo)
		return -ENOMEM;

	pr_err("alloc mbo %p, ch %d\n", mbo, ch);

	mbo->context = (void *)(long)ch;
	mbo->complete = completion_routine;
	mbo->buffer_length = DMA_ALLOC_SIZE;
	mbo->virt_address = dma_alloc_coherent(NULL, DMA_ALLOC_SIZE + SHIFT_DMA_BUFFER,
					       &mbo->bus_address, GFP_KERNEL);
	if (!mbo->virt_address) {
		pr_err("No DMA coherent buffer.\n");
		ret = -ENOMEM;
		goto out_free;
	}

	mbo->virt_address += SHIFT_DMA_BUFFER;
	mbo->bus_address += SHIFT_DMA_BUFFER;

	if (is_rx_channel(ch))
		fill_rx_mbo(mbo, val);
	else
		fill_tx_mbo(mbo, val, ch);

	if (g.iface->enqueue(g.iface, ch, mbo)) {
		pr_err("enqueue failed\n");
		ret = -EIO;
		goto out_free_coherent;
	}

	return 0;

out_free_coherent:
	dma_free_coherent(NULL, DMA_ALLOC_SIZE + SHIFT_DMA_BUFFER,
			  mbo->virt_address - SHIFT_DMA_BUFFER,
			  mbo->bus_address - SHIFT_DMA_BUFFER);
out_free:
	pr_err("free mbo %p, ch %d\n", mbo, ch);
	kfree(mbo);

	return ret;
}

static ssize_t pci_stress_read(struct file *filp, char __user *buffer,
			       size_t count, loff_t *ppos)
{
	enum { LINE_WIDTH = 19 };
	int i;
	int len;
	char buf[LINE_WIDTH * NUM_TESTED_DMA_LOOPS * 2 + 100];
	const char *state = "";

	if (*ppos)
		return 0;

	switch (g.stress.state) {
	case SST_TX_RX_TIMEOUT:
		state = "rx timeout";
		break;
	case SST_RUNNING:
		state = "running";
		break;
	case SST_IDLE:
		state = "not running";
		break;
	default:
		state = "error";
		break;
	}
	for (i = 0; i < NUM_TESTED_DMA_LOOPS; i++) {
		sprintf(buf + LINE_WIDTH * 2 * i,
			" rx.%02d: 0x%08X\n" " tx.%02d: 0x%08X\n",
			i * 2, g.stress.rx[i], i * 2 + 1, g.stress.tx[i]);
	}
	sprintf(buf + LINE_WIDTH * NUM_TESTED_DMA_LOOPS * 2,
		" rx.ok: %10u\n" "rx.bad: %10u\n" "  test: %s" "\n" "\n",
		g.stress.rx_ok, g.stress.rx_bad, state);
	len = strlen(buf);
	copy_to_user(buffer, buf, len);
	*ppos = 1;

	return len;
}

static ssize_t pci_stress_write(struct file *filp, const char __user *buffer,
				size_t count, loff_t *ppos)
{
	char my[10 + 1];

	copy_from_user(my, buffer, count < 10 ? count : 10);
	my[10] = 0;

	if (my[0] == '0') {
		g.stress.state = SST_IDLE;
	} else if (my[0] == '1' && g.stress.state == SST_IDLE) {
		enum { MBOS_PER_SHOT = 20 };
		unsigned int i, im;

		g.mdev->dbg_disable_pcie_poll = 1;

		g.stress.rx_ok = 0;
		g.stress.rx_bad = 0;

		for (i = 0; i < NUM_TESTED_DMA_LOOPS; i++) {
			unsigned int tx = 0;

			g.stress.rx[i] = 0;

			for (im = 0; im < MBOS_PER_SHOT; im++) {
				if (enq(i * 2 + 1, normalize_cnt(KEYS_PER_BUFFER * im)))
					goto out;
				if (enq(i * 2 + 0, 0xDEADBEEF))
					goto out;
				tx = normalize_cnt(tx + KEYS_PER_BUFFER);
			}

			g.stress.tx[i] = tx;
		}

		g.mdev->dbg_disable_pcie_poll = 0;
		g.stress.state = SST_RUNNING;
	}
out:

	return count;
}

static enum hrtimer_restart hrt_fn(struct hrtimer *hrt)
{
	if (g.stress.state < SST_SUSPEND_HRT) {
		if (g.stress.state >= SST_ERROR)
			if (++g.stress.state >= SST_SUSPEND_HRT)
				g.mdev->dbg_disable_pcie_poll = 1;

		if (g.stress.state == SST_RUNNING) {
			int chidx;
			unsigned counter = 0;

			for (chidx = 0; chidx < NUM_TESTED_DMA_LOOPS; chidx++)
				counter += g.stress.rx[chidx];

			if (g.last_counter != counter) {
				g.last_counter = counter;
				g.empty_runs = 0;
			} else if (++g.empty_runs > 2000 * NUM_TESTED_DMA_LOOPS) {
				g.empty_runs = 0;
				g.stress.state = SST_TX_RX_TIMEOUT;
				pr_err("timeout\n");
				trace_after_fail();
			}
		}
	}

	hrtimer_forward(hrt, hrtimer_get_expires(hrt),
			ns_to_ktime(HRTIMER_INTERVAL_NS));
	return HRTIMER_RESTART;
}

static struct file_operations const pci_stress_fops = {
	.owner = THIS_MODULE,
	.read = pci_stress_read,
	.write = pci_stress_write,
};

static void tst_kobj_release(struct kobject *kobj)
{
}

static ssize_t tst_kobj_attr_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	return -EIO;
}

static ssize_t tst_kobj_attr_store(struct kobject *kobj, struct attribute *attr,
				   const char *buf, size_t count)
{
	return -EIO;
}

static struct sysfs_ops const tst_kobj_sysfs_ops = {
	.show = tst_kobj_attr_show,
	.store = tst_kobj_attr_store,
};

static struct kobj_type tst_ktype = {
	.release = tst_kobj_release,
	.sysfs_ops = &tst_kobj_sysfs_ops,
};

/**
 * medusa_test_init_module - Driver Registration Routine
 */
static int __init medusa_test_init_module(void)
{
	int err;

	pr_info("medusa_test_init_module()\n");

	if (alloc_chrdev_region(&g.most_dev_base, 0, NUM_CDEVS, "MOSTCORE") < 0)
		return -EIO;

	g.most_major = MAJOR(g.most_dev_base);

	/* create new class in  sysfs, udev mknods the new devices. */
	g.most_class = class_create(THIS_MODULE, "MOSTCORE");
	if (IS_ERR(g.most_class)) {
		pr_err("no udev support.\n");
		goto unreg_chrdev;
	}

	kobject_init(&g.kobj_group, &tst_ktype);
	err = kobject_add(&g.kobj_group, kernel_kobj, "medusa_device");
	if (err) {
		pr_err("kobject_add() failed: %d\n", err);
		goto destroy_class;
	}

	device_create(g.most_class, NULL, MKDEV(g.most_major, CDEV0), NULL,
		      "pcie-stress");

	cdev_init(g.cdev + CDEV0, &pci_stress_fops);
	g.cdev[CDEV0].owner = THIS_MODULE;
	cdev_add(g.cdev + CDEV0, MKDEV(g.most_major, CDEV0), 1);

	hrtimer_init(&g.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	g.timer.function = hrt_fn;

	hrtimer_start(&g.timer, ns_to_ktime(HRTIMER_INTERVAL_NS),
		      HRTIMER_MODE_REL);

	return 0;

destroy_class:
	class_destroy(g.most_class);

unreg_chrdev:
	unregister_chrdev_region(g.most_dev_base, NUM_CDEVS);
	return -EIO;
}

/**
 * medusa_test_exit_module - Driver Exit Cleanup Routine
 **/
static void __exit medusa_test_exit_module(void)
{
	pr_info("medusa_test_exit_module()\n");

	hrtimer_cancel(&g.timer);

	cdev_del(g.cdev + CDEV0);
	device_destroy(g.most_class, MKDEV(g.most_major, CDEV0));
	kobject_put(&g.kobj_group);
	class_destroy(g.most_class);
	unregister_chrdev_region(g.most_dev_base, NUM_CDEVS);
}

module_init(medusa_test_init_module);
module_exit(medusa_test_exit_module);

MODULE_AUTHOR("Andrey Shvetsov, K2L GmbH & Co. KG, <andrey.shvetsov@k2l.de>");
MODULE_DESCRIPTION("Medusa Testing Driver");
MODULE_LICENSE("GPL");

