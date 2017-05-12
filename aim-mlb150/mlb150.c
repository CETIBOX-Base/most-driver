/*
 * mlb160.c - Application interfacing module for character devices
 * emulating the interface provided by the Freescale MLB150 driver
 *
 * Copyright (C) 2017 Cetitec GmbH
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
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/kfifo.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include "mostcore.h"
#include "mlb150.h"
#include "mlb150_ext.h"

#define DRIVER_NAME "aim-mlb150"
/*
 * This driver emulates only sync and isoc interfaces of the mlb150, so this
 * excludes the first two minors of the original: ctrl and async (and opt3)
 */
#define MINOR_BASE (2)

/* default number of sync channels which is used
   if module is loaded without parameters. */
static uint number_sync_channels = 7;
module_param(number_sync_channels, uint, 0444);
u32 syncsound_get_num_devices(void)
{
	return number_sync_channels;
}
EXPORT_SYMBOL(syncsound_get_num_devices);

/* number of isochronous channels to provide by default */
static uint number_isoc_channels = 1;
module_param_named(isoc_channels, number_isoc_channels, uint, 0444);

static uint isoc_blk_sz = CH_ISOC_BLK_SIZE_DEFAULT;
static uint isoc_blk_num = CH_ISOC_BLK_NUM_DEFAULT;

static dev_t aim_devno;
static struct class aim_class = {
	.name = "mlb150",
	.owner = THIS_MODULE,
};
static struct cdev aim_cdev;

struct mostcore_channel;

struct aim_channel {
	char name[20 /* MLB_DEV_NAME_SIZE */];
	wait_queue_head_t wq;
	spinlock_t unlink;	/* synchronization lock to unlink channels */
	dev_t devno;
	struct device *dev;
	struct mutex io_mutex;
	struct mostcore_channel *most;
	u32 mlb150_caddr;
	unsigned mlb150_sync_buf_size;
	size_t mbo_offs;
	DECLARE_KFIFO_PTR(fifo, typeof(struct mbo *));
	int users;

	rwlock_t stat_lock;
	long long tx_bytes, rx_bytes, rx_pkts, tx_pkts;
	long long rx_drops, tx_drops;
	struct device_attribute stat_attr;
	struct device_attribute bufsize_attr;
	struct device_attribute dump_attr;
};

struct mostcore_param {
	int fpt; /* USB frames-per-transaction value */
};

static const struct mostcore_param def_sync_param[] = {
	[MLB_SYNC_MONO_RX    ] = { .fpt = 512 / 2 },
	[MLB_SYNC_MONO_TX    ] = { .fpt = 512 / 2 },
	[MLB_SYNC_STEREO_RX  ] = { .fpt = 512 / 4 },
	[MLB_SYNC_STEREO_TX  ] = { .fpt = 512 / 4 },
	[MLB_SYNC_51_RX      ] = { .fpt = 512 / 12 },
	[MLB_SYNC_51_TX      ] = { .fpt = 512 / 12 },
	[MLB_SYNC_51HQ_RX    ] = { .fpt = 512 / 18 },
	[MLB_SYNC_51HQ_TX    ] = { .fpt = 512 / 18 },
	[MLB_SYNC_STEREOHQ_RX] = { .fpt = 512 / 6 },
	[MLB_SYNC_STEREOHQ_TX] = { .fpt = 512 / 6 },
};

static const struct mostcore_param def_isoc_param[] = {
	[ISOC_FRMSIZ_188] = { .fpt = 512 / 188 },
	[ISOC_FRMSIZ_192] = { .fpt = 512 / 192 },
	[ISOC_FRMSIZ_196] = { .fpt = 512 / 196 },
};

struct mostcore_channel {
	struct most_interface *iface;
	struct most_channel_config *cfg;
	unsigned int channel_id;
	int started;
	struct aim_channel *aim;
	struct mostcore_channel *next; /* used by most->aim channel mapping */
	struct mostcore_param params[
		ARRAY_SIZE(def_sync_param) > ARRAY_SIZE(def_isoc_param) ?
		ARRAY_SIZE(def_sync_param) : ARRAY_SIZE(def_isoc_param)];
};

#define to_channel(d) container_of(d, struct aim_channel, cdev)
#define foreach_aim_channel(c) \
	for (c = aim_channels; (c) < aim_channels + used_minor_devices; ++c)

static struct mostcore_channel mlb_channels[MLB_LAST_CHANNEL + 1];
static struct aim_channel *aim_channels;
static uint used_minor_devices;
static struct most_aim aim; /* forward declaration */

static inline bool ch_not_found(const struct aim_channel *c)
{
	return c == aim_channels + used_minor_devices;
}

static DEFINE_SPINLOCK(aim_most_lock);
static struct mostcore_channel *aim_most[256];

static inline uint get_channel_pos(const struct most_interface *iface, int id)
{
	ulong v = (ulong)iface;

	v = (v & 0xff) ^ (v >> 8);
	v = (v & 0xff) ^ (v >> 8);
	v = (v & 0xff) ^ (v >> 8);
	v = (v & 0xff) ^ (v >> 8);
	if (BITS_PER_LONG == 64) {
		v = (v & 0xff) ^ (v >> 8);
		v = (v & 0xff) ^ (v >> 8);
		v = (v & 0xff) ^ (v >> 8);
		v = (v & 0xff) ^ (v >> 8);
	}
	return v ^ (id & 0xff);
}

static struct mostcore_channel *get_channel(struct most_interface *iface, int id)
{
	ulong flags;
	struct mostcore_channel *i;
	struct mostcore_channel **pos = aim_most;

	pos += get_channel_pos(iface, id) & 0xff;
	spin_lock_irqsave(&aim_most_lock, flags);
	for (i = *pos; i; i = i->next)
		if (i->channel_id == id && i->iface == iface)
			break;
	spin_unlock_irqrestore(&aim_most_lock, flags);
	return i;
}

static void remember_channel(struct most_interface *iface, int id,
			     struct mostcore_channel *i)
{
	ulong flags;
	struct mostcore_channel **pos = aim_most;

	i->iface = iface;
	i->channel_id = id;
	pos += get_channel_pos(iface, id) & 0xff;
	spin_lock_irqsave(&aim_most_lock, flags);
	i->next = *pos;
	*pos = i;
	spin_unlock_irqrestore(&aim_most_lock, flags);
}

static struct mostcore_channel *forget_channel(struct most_interface *iface, int id)
{
	ulong flags;
	struct mostcore_channel *most = NULL;
	struct mostcore_channel **pos = aim_most;

	pos += get_channel_pos(iface, id) & 0xff;
	spin_lock_irqsave(&aim_most_lock, flags);
	while (*pos) {
		if ((*pos)->channel_id &&
		    (*pos)->iface == iface) {
			most = *pos;
			*pos = (*pos)->next;
			break;
		}
		pos = &(*pos)->next;
	}
	spin_unlock_irqrestore(&aim_most_lock, flags);
	return most;
}

static inline bool ch_get_mbo(struct aim_channel *c, struct mbo **mbo)
{
	if (kfifo_peek(&c->fifo, mbo))
		return *mbo;

	*mbo = most_get_mbo(c->most->iface, c->most->channel_id, &aim);
	if (*mbo)
		kfifo_in(&c->fifo, mbo, 1);
	return *mbo;
}

static inline bool ch_has_mbo(const struct mostcore_channel *most)
{
	return channel_has_mbo(most->iface, most->channel_id, &aim) > 0;
}

static ssize_t aim_read(struct file *filp, char __user *buf,
			size_t count, loff_t *f_pos)
{
	ssize_t ret;
	size_t to_copy, not_copied;
	unsigned long flags;
	struct mbo *mbo;
	struct aim_channel *c = filp->private_data;

	mutex_lock(&c->io_mutex);
	if (!c->most || !c->most->started) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	while (c->most && !kfifo_peek(&c->fifo, &mbo)) {
		mutex_unlock(&c->io_mutex);
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(c->wq,
			(!kfifo_is_empty(&c->fifo) || !c->most)))
			return -ERESTARTSYS;
		mutex_lock(&c->io_mutex);
	}
	if (unlikely(!c->most)) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
		goto unlock;
	}
	write_lock_irqsave(&c->stat_lock, flags);
	c->rx_pkts++;
	c->rx_bytes += mbo->processed_length;
	write_unlock_irqrestore(&c->stat_lock, flags);
	to_copy = min_t(size_t, count, mbo->processed_length - c->mbo_offs);
	not_copied = copy_to_user(buf, mbo->virt_address + c->mbo_offs, to_copy);
	ret = to_copy - not_copied;
	c->mbo_offs += ret;
	if (c->mbo_offs >= mbo->processed_length) {
		kfifo_skip(&c->fifo);
		most_put_mbo(mbo);
		c->mbo_offs = 0;
	}
unlock:
	mutex_unlock(&c->io_mutex);
	return ret;
}

static ssize_t aim_write(struct file *filp, const char __user *buf,
			 size_t count, loff_t *f_pos)
{
	ssize_t ret;
	size_t to_copy, left;
	struct mbo *mbo = NULL;
	struct aim_channel *c = filp->private_data;

	mutex_lock(&c->io_mutex);
	if (!c->most || !c->most->started) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	while (c->most && !ch_get_mbo(c, &mbo)) {
		mutex_unlock(&c->io_mutex);
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(c->wq, ch_has_mbo(c->most) || !c->most))
			return -ERESTARTSYS;
		mutex_lock(&c->io_mutex);
	}
	if (unlikely(!c->most)) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	to_copy = min(count, c->most->cfg->buffer_size - c->mbo_offs);
	left = copy_from_user(mbo->virt_address + c->mbo_offs, buf, to_copy);
	if (left == to_copy) {
		ret = -EFAULT;
		goto unlock;
	}
	c->mbo_offs += to_copy - left;
	if (c->mbo_offs >= c->most->cfg->buffer_size ||
	    c->most->cfg->data_type == MOST_CH_CONTROL ||
	    c->most->cfg->data_type == MOST_CH_ASYNC) {
		unsigned long flags;

		kfifo_skip(&c->fifo);
		write_lock_irqsave(&c->stat_lock, flags);
		c->tx_pkts++;
		c->tx_bytes += mbo->buffer_length;
		write_unlock_irqrestore(&c->stat_lock, flags);
		mbo->buffer_length = c->mbo_offs;
		c->mbo_offs = 0;
		most_submit_mbo(mbo);
	}
	ret = to_copy - left;
unlock:
	mutex_unlock(&c->io_mutex);
	return ret;
}

static unsigned int aim_poll(struct file *filp, poll_table *wait)
{
	struct aim_channel *c = filp->private_data;
	unsigned int mask = 0;

	poll_wait(filp, &c->wq, wait);
	mutex_lock(&c->io_mutex);
	if (!c->most || !c->most->started)
		mask |= POLLIN|POLLOUT|POLLERR|POLLNVAL|POLLHUP;
	else if (c->most->cfg->direction == MOST_CH_RX) {
		if (!kfifo_is_empty(&c->fifo))
			mask |= POLLIN | POLLRDNORM;
	} else {
		if (!kfifo_is_empty(&c->fifo) || ch_has_mbo(c->most))
			mask |= POLLOUT | POLLWRNORM;
	}
	mutex_unlock(&c->io_mutex);
	return mask;
}

static int start_most(struct aim_channel *c)
	__must_hold(&c->io_mutex)
{
	int ret;

	ret = kfifo_alloc(&c->fifo, c->most->cfg->num_buffers, GFP_KERNEL);
	if (ret)
		return ret;
	c->mbo_offs = 0;
	ret = most_start_channel(c->most->iface, c->most->channel_id, &aim);
	if (!ret)
		c->most->started = 1;
	pr_debug("%s.%zd (%s) subbuffer_size %u, buffer_size %u ret %d\n",
		 c->name, c->most - mlb_channels,
		 c->most->cfg->direction == MOST_CH_RX ? "rx" : "tx",
		 c->most->cfg->subbuffer_size, c->most->cfg->buffer_size, ret);
	return ret;
}

static void stop_most(struct aim_channel *c)
	__must_hold(&c->io_mutex)
{
	struct mbo *mbo;

	pr_debug("%s.%zd (%s) shut down\n",
		 c->name, c->most - mlb_channels,
		 c->most->cfg->direction == MOST_CH_RX ? "rx" : "tx");
	if (c->most->started) {
		while (kfifo_out((struct kfifo *)&c->fifo, &mbo, 1))
			most_put_mbo(mbo);
		most_stop_channel(c->most->iface, c->most->channel_id, &aim);
	}
	kfifo_free(&c->fifo);
	INIT_KFIFO(c->fifo);
	c->most->started = 0;
	c->most = NULL;
}

static int __must_check valid_caddr(unsigned int caddr)
{
	unsigned int tx, rx;

	if (!caddr)
		return -EINVAL;
	tx = (caddr >> 16) & 0xffff;
	rx = caddr & 0xffff;
	/* This allows selection of the reserved System Channel (logical 0) */
	if (tx > MLB_LAST_CHANNEL || rx > MLB_LAST_CHANNEL)
		return -ERANGE;
	return 0;
}

static int mlb150_chan_setaddr(struct aim_channel *c, u32 caddr)
{
	const uint tx = (caddr >> 16) & 0xffff;
	const uint rx = caddr & 0xffff;
	int ret;

	mutex_lock(&c->io_mutex);
	if (c->most && c->most->started) {
		ret = -EBUSY;
		goto unlock;
	}
	pr_debug("caddr 0x%08x (%s %s%s)\n", caddr, c->name,
		 mlb_channels[rx].cfg ? "Rx" : "--",
		 mlb_channels[tx].cfg ? "Tx" : "--");
	c->mlb150_caddr = caddr;
	ret = 0;
unlock:
	mutex_unlock(&c->io_mutex);
	return ret;
}

static int mlb150_chan_startup(struct aim_channel *c, uint accmode)
{
	int ret;
	struct mostcore_channel *most;

	if (!(accmode == O_RDONLY || accmode == O_WRONLY))
		return -EINVAL;
	mutex_lock(&c->io_mutex);
	if (c->most) {
		ret = -EBUSY;
		goto unlock;
	}
	most = mlb_channels;
	most += (c->mlb150_caddr >> 16 * (accmode == O_WRONLY)) & 0xffff;
	if (!most->cfg || most->cfg->direction != (accmode == O_RDONLY ?
						   MOST_CH_RX : MOST_CH_TX)) {
		ret = -ENODEV;
		goto unlock;
	}
	if (most->cfg->data_type != MOST_CH_ISOC) {
		ret = -EINVAL;
		goto unlock;
	}

	most->aim = c;
	c->most = most;
	most->cfg->packets_per_xact = most->params[0].fpt;
	most->cfg->subbuffer_size = 188;
	most->cfg->buffer_size = 2*188;
	ret = start_most(c);
unlock:
	mutex_unlock(&c->io_mutex);
	return ret;
}

static int mlb150_sync_chan_startup(struct aim_channel *c, uint accmode,
				    uint startup_mode)
{
	int ret;
	uint bytes_per_frame;
	struct mostcore_channel *most;

	switch ((enum mlb_sync_ch_startup_mode)startup_mode) {
	case MLB_SYNC_MONO_RX:
	case MLB_SYNC_MONO_TX:
		bytes_per_frame = 1 * 2;
		break;
	case MLB_SYNC_STEREO_RX:
	case MLB_SYNC_STEREO_TX:
		bytes_per_frame = 2 * 2;
		break;
	case MLB_SYNC_51_RX:
	case MLB_SYNC_51_TX:
		bytes_per_frame = 6 * 2;
		break;
	case MLB_SYNC_51HQ_RX:
	case MLB_SYNC_51HQ_TX:
		bytes_per_frame = 6 * 3;
		break;
	case MLB_SYNC_STEREOHQ_RX:
	case MLB_SYNC_STEREOHQ_TX:
		bytes_per_frame = 2 * 3;
		break;
	default:
		return -EINVAL;
	}
	if (!(accmode == O_RDONLY || accmode == O_WRONLY))
		return -EINVAL;
	mutex_lock(&c->io_mutex);
	if (c->most) {
		ret = -EBUSY;
		goto unlock;
	}
	most = mlb_channels;
	most += (c->mlb150_caddr >> (16 * accmode == O_WRONLY)) & 0xffff;
	if (!most->cfg || most->cfg->direction != (accmode == O_RDONLY ?
						   MOST_CH_RX : MOST_CH_TX)) {
		ret = -ENODEV;
		goto unlock;
	}
	if (most->cfg->data_type != MOST_CH_SYNC) {
		ret = -EINVAL;
		goto unlock;
	}
	most->aim = c;
	c->most = most;
	most->cfg->packets_per_xact = most->params[startup_mode].fpt;
	most->cfg->subbuffer_size = bytes_per_frame;
	most->cfg->buffer_size = max(SYNC_BUFFER_DEP(bytes_per_frame),
				     c->mlb150_sync_buf_size);
	ret = start_most(c);
unlock:
	mutex_unlock(&c->io_mutex);
	return ret;
}

static int mlb150_chan_shutdown(struct aim_channel *c)
{
	int ret = 0;

	mutex_lock(&c->io_mutex);
	if (c->most)
		stop_most(c);
	else
		ret = -EBADF;
	mutex_unlock(&c->io_mutex);
	return ret;
}

static long aim_mlb150_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = -ENOTSUPP;
	struct aim_channel *c = filp->private_data;
	void __user *argp = (void __user *)arg;

	pr_debug("ioctl %s %s\n",
		 MLB_CHAN_SETADDR         == cmd ? "CHAN_SETADDR" :
		 MLB_CHAN_STARTUP         == cmd ? "CHAN_STARTUP" :
		 MLB_SET_FPS              == cmd ? "SET_FPS" :
		 MLB_GET_VER              == cmd ? "GET_VER" :
		 MLB_SET_DEVADDR          == cmd ? "SET_DEVADDR" :
		 MLB_CHAN_SHUTDOWN        == cmd ? "CHAN_SHUTDOWN" :
		 MLB_CHAN_GETEVENT        == cmd ? "CHAN_GETEVENT" :
		 MLB_SET_SYNC_QUAD        == cmd ? "SET_SYNC_QUAD" :
		 MLB_SYNC_CHAN_STARTUP    == cmd ? "SYNC_CHAN_STARTUP" :
		 MLB_GET_LOCK             == cmd ? "GET_LOCK":
		 MLB_GET_ISOC_BUFSIZE     == cmd ? "GET_ISOC_BUFSIZE" :
		 MLB_SET_ISOC_BLKSIZE_188 == cmd ? "SET_ISOC_BLKSIZE_188" :
		 MLB_SET_ISOC_BLKSIZE_196 == cmd ? "SET_ISOC_BLKSIZE_196" :
		 MLB_PAUSE_RX             == cmd ? "PAUSE_RX" :
		 MLB_RESUME_RX            == cmd ? "RESUME_RX" :
		 "unknown", c->name);
	switch (cmd) {
		uint val;
		u32 v32;

	case MLB_CHAN_SETADDR:
		ret = -EFAULT;
		if (copy_from_user(&val, argp, sizeof(val)))
			break;
		ret = valid_caddr(val);
		ret = ret ? ret : mlb150_chan_setaddr(c, val);
		break;

	case MLB_CHAN_STARTUP:
		ret = mlb150_chan_startup(c, filp->f_flags & O_ACCMODE);
		break;

	case MLB_SYNC_CHAN_STARTUP:
		ret = -EFAULT;
		if (copy_from_user(&val, argp, sizeof(val)))
			break;
		ret = mlb150_sync_chan_startup(c,
			filp->f_flags & O_ACCMODE, val);
		break;

	case MLB_CHAN_SHUTDOWN:
		ret = mlb150_chan_shutdown(c);
		break;

	case MLB_GET_LOCK:
		v32 = BIT(7); /* MLBC0.MLBLK */
		ret = copy_to_user(argp, &v32, sizeof(v32)) ? -EFAULT : 0;
		break;

	case MLB_GET_ISOC_BUFSIZE:
		/* return the size of this channel (recalculated in do_open()) */
		// TODO const unsigned int size = pdevinfo->isoc_blk_size * pdevinfo->isoc_blk_num;
		val = 0;
		ret = copy_to_user(argp, &val, sizeof(val)) ? -EFAULT : 0;
		break;

	case MLB_GET_VER:
		/*
		 * Return the last known mlb150 version with the
		 * C0.MLBLK set (used in own of diagnostic builds
		 */
		v32 = 0x03030003 | BIT(7);
		ret = copy_to_user(argp, &v32, sizeof(v32)) ? -EFAULT : 0;
		break;

	case MLB_SET_FPS:
	case MLB_SET_DEVADDR:
		pr_debug("ioctl ignored\n");
		return 0;
	}
	return ret;
}

static int aim_open(struct inode *inode, struct file *filp)
{
	int ret;
	enum most_channel_direction dir;
	struct aim_channel *c = aim_channels +
		MINOR(file_inode(filp)->i_rdev) - MINOR_BASE;

	switch (filp->f_flags & O_ACCMODE) {
	case O_RDONLY:
		dir = MOST_CH_RX;
		break;
	case O_WRONLY:
		dir = MOST_CH_TX;
		break;
	default:
		return -EINVAL;
	}
	filp->private_data = c;
	nonseekable_open(inode, filp);
	mutex_lock(&c->io_mutex);
	if (c->users) {
		ret = -EBUSY;
		goto unlock;
	}
	c->users++;
	ret = 0;
	pr_debug("%s (%s)\n", c->name, dir == MOST_CH_TX ? "tx" : "rx");
unlock:
	mutex_unlock(&c->io_mutex);
	return ret;
}

static int aim_release(struct inode *inode, struct file *filp)
{
	struct aim_channel *c = filp->private_data;

	mutex_lock(&c->io_mutex);
	if (c->most && c->most->started)
		stop_most(c);
	if (c->users)
		--c->users;
	mutex_unlock(&c->io_mutex);
	return 0;
}

static int aim_rx_completion(struct mbo *mbo)
{
	struct mostcore_channel *most;

	pr_debug("mbo %p\n", mbo);
	if (!mbo)
		return -EINVAL;
	most = get_channel(mbo->ifp, mbo->hdm_channel_id);
	if (!most)
		return -ENXIO;
	kfifo_in(&most->aim->fifo, &mbo, 1);
	wake_up_interruptible(&most->aim->wq);
	return 0;
}

static int aim_tx_completion(struct most_interface *iface, int channel_id)
{
	struct mostcore_channel *most;

	pr_debug("iface %p, channel_id %d\n", iface, channel_id);
	most = get_channel(iface, channel_id);
	if (!most)
		return -ENXIO;
	wake_up_interruptible(&most->aim->wq);
	return 0;
}

static int aim_disconnect_channel(struct most_interface *iface, int channel_id)
{
	struct mostcore_channel *most;

	pr_debug("iface %p, channel_id %d\n", iface, channel_id);
	most = forget_channel(iface, channel_id);
	if (!most)
		return -ENXIO;
	if (most->aim) {
		mutex_lock(&most->aim->io_mutex);
		most->aim->most = NULL;
		mutex_unlock(&most->aim->io_mutex);
	}
	most->cfg = NULL;
	most->iface = NULL;
	most->channel_id = 0;
	return 0;
}

static void parse_mostcore_channel_params(struct mostcore_channel *most, char *s)
{
	int mode;
	int fpt;
	const struct mostcore_param *params =
		most->cfg->data_type == MOST_CH_SYNC ? def_sync_param :
		most->cfg->data_type == MOST_CH_ISOC ? def_isoc_param : NULL;
	const uint size =
		most->cfg->data_type == MOST_CH_SYNC ? ARRAY_SIZE(def_sync_param) :
		most->cfg->data_type == MOST_CH_ISOC ? ARRAY_SIZE(def_isoc_param) : 0;

	if (!params)
		return;
	do {
		char *sp;

		mode = -1;
		if (most->cfg->data_type == MOST_CH_SYNC) {
			if (strncasecmp(s, "1x16,", 5) == 0)
				mode = most->cfg->direction == MOST_CH_RX ?
					MLB_SYNC_MONO_RX : MLB_SYNC_MONO_TX;
			else if (strncasecmp(s, "2x16,", 5) == 0)
				mode = most->cfg->direction == MOST_CH_RX ?
					MLB_SYNC_STEREO_RX : MLB_SYNC_STEREO_TX;
			else if (strncasecmp(s, "2x24,", 5) == 0)
				mode = most->cfg->direction == MOST_CH_RX ?
					MLB_SYNC_STEREOHQ_RX : MLB_SYNC_STEREOHQ_TX;
			else if (strncasecmp(s, "6x16,", 5) == 0)
				mode = most->cfg->direction == MOST_CH_RX ?
					MLB_SYNC_51_RX : MLB_SYNC_51_TX;
			else if (strncasecmp(s, "6x24,", 5) == 0)
				mode = most->cfg->direction == MOST_CH_RX ?
					MLB_SYNC_51HQ_RX : MLB_SYNC_51HQ_TX;
		} else if (most->cfg->data_type == MOST_CH_ISOC) {
			if (strncasecmp(s, "188,", 4) == 0)
				mode = ISOC_FRMSIZ_188;
			else if (strncasecmp(s, "192,", 4) == 0)
				mode = ISOC_FRMSIZ_192;
			else if (strncasecmp(s, "196,", 4) == 0)
				mode = ISOC_FRMSIZ_196;
		}
		s += 5;
		sp = s + strcspn(s, " \t\r\n");
		if (*sp)
			*sp++ = '\0';
		if ((uint)mode >= ARRAY_SIZE(most->params))
			return;
		if (kstrtoint(s, 0, &fpt)) {
			if ((uint)mode >= size)
				return;
			fpt = params[mode].fpt;
		}
		most->params[mode].fpt = fpt;
		/* pr_debug("mode %d fpt %d\n", (int)mode, fpt); */
		s = sp + strspn(sp, " \t\r\n");
	} while (*s);
}

static int aim_probe(struct most_interface *iface, int channel_id,
		     struct most_channel_config *cfg,
		     struct kobject *parent, char *name)
{
	struct mostcore_channel *most;
	int mlb150_id;
	int err = -EINVAL;
	char *s, *sp;

	pr_debug("%s.ch%d %s\n", iface->description, channel_id, name);
	if (!iface || !cfg || !name)
		goto fail;
	if (!(cfg->data_type == MOST_CH_SYNC ||
	      cfg->data_type == MOST_CH_ISOC))
		goto fail;
	s = name; /* mlb150 channel id */
	if (!*s)
		goto fail;
	sp = strchr(s, '/'); /* parameters */
	if (sp)
		*sp++ = '\0';
	if (kstrtoint(s, 0, &mlb150_id) ||
	    mlb150_id < MLB_FIRST_CHANNEL ||
	    mlb150_id > MLB_LAST_CHANNEL) {
		pr_debug("invalid mlb ch: %s\n", s);
		err = -ENXIO;
		goto fail;
	}
	most = mlb_channels + mlb150_id;
	err = -EBUSY;
	if (most->cfg)
		goto fail;
	err = 0;
	most->cfg = cfg;
	if (cfg->data_type == MOST_CH_SYNC)
		memcpy(most->params, def_sync_param, sizeof(def_sync_param));
	else if (cfg->data_type == MOST_CH_ISOC)
		memcpy(most->params, def_isoc_param, sizeof(def_isoc_param));
	remember_channel(iface, channel_id, most);
	if (sp)
		parse_mostcore_channel_params(most, sp);
	pr_debug("mlb150 %s ch %d linked to %s.ch%d\n",
		 cfg->data_type == MOST_CH_SYNC ? "sync" :
		 cfg->data_type == MOST_CH_ISOC ? "isoc" : "?",
		 mlb150_id, iface->description, channel_id);
fail:
	return err;
}

static ssize_t show_dev_stats(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct aim_channel *c = container_of(attr, struct aim_channel, stat_attr);
	unsigned long flags;
	ssize_t ret;

	read_lock_irqsave(&c->stat_lock, flags);
	ret = scnprintf(buf, PAGE_SIZE, "%lld %lld %lld %lld %lld %lld\n",
			c->rx_bytes, c->tx_bytes,
			c->rx_pkts,  c->tx_pkts,
			c->rx_drops, c->tx_drops);
	read_unlock_irqrestore(&c->stat_lock, flags);
	return ret;
}

static ssize_t show_buffer_size(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct aim_channel *c = container_of(attr, struct aim_channel, bufsize_attr);

	return snprintf(buf, PAGE_SIZE, "%u", c->mlb150_sync_buf_size);
}

static ssize_t store_buffer_size(struct device *dev, struct device_attribute *attr, const char *buf, size_t len)
{
	struct aim_channel *c = container_of(attr, struct aim_channel, bufsize_attr);
	unsigned val;
	ssize_t ret = kstrtouint(buf, 0, &val);

	if (ret == 0) {
		ret = len;
		c->mlb150_sync_buf_size = val;
	}
	return ret;
}

static ssize_t show_dev_dump(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "# write 1 to dump\n");
}

static ssize_t store_dev_dump(struct device *dev, struct device_attribute *attr, const char *buf, size_t len)
{
	struct aim_channel *c = container_of(attr, struct aim_channel, dump_attr);

	dev_info(dev, "%s dump\n", c->name);
	return len;
}

static int __init init_aim_channel_attrs(struct aim_channel *c)
{
	int ret;

	sysfs_attr_init(&c->stat_attr.attr);
	sysfs_attr_init(&c->dump_attr.attr);
	rwlock_init(&c->stat_lock);
	c->stat_attr.attr.mode = 0444;
	c->stat_attr.attr.name = "stat";
	c->stat_attr.show = show_dev_stats;
	ret = device_create_file(c->dev, &c->stat_attr);
	if (ret) {
		dev_err(c->dev, "cannot create attribute '%s': %d\n",
			c->stat_attr.attr.name, ret);
		goto fail;
	}
	c->dump_attr.attr.mode = 0600;
	c->dump_attr.attr.name = "dump";
	c->dump_attr.show = show_dev_dump;
	c->dump_attr.store = store_dev_dump;
	ret = device_create_file(c->dev, &c->dump_attr);
	if (ret) {
		dev_err(c->dev, "cannot create attribute '%s': %d\n",
			c->dump_attr.attr.name, ret);
		goto fail;
	}
	return 0;
fail:
	if (c->stat_attr.attr.mode)
		device_remove_file(c->dev, &c->stat_attr);
	c->stat_attr.attr.mode = 0;
	c->dump_attr.attr.mode = 0;
	return ret;
}

static int __init init_sync_channel_attrs(struct aim_channel *c)
{
	int ret;

	sysfs_attr_init(&c->bufsize_attr.attr);
	c->bufsize_attr.attr.mode = 0644;
	c->bufsize_attr.attr.name = "buffer_size";
	c->bufsize_attr.show = show_buffer_size;
	c->bufsize_attr.store = store_buffer_size;
	ret = device_create_file(c->dev, &c->bufsize_attr);
	if (ret) {
		dev_err(c->dev, "cannot create attribute '%s': %d\n",
			c->bufsize_attr.attr.name, ret);
		c->bufsize_attr.attr.mode = 0;
	}
	return ret;
}

static const struct file_operations aim_channel_fops = {
	.owner = THIS_MODULE,
	.open = aim_open,
	.release = aim_release,
	.unlocked_ioctl = aim_mlb150_ioctl,
	.read = aim_read,
	.write = aim_write,
	.poll = aim_poll,
};

static struct most_aim aim = {
	.name = "mlb150",
	.probe_channel = aim_probe,
	.disconnect_channel = aim_disconnect_channel,
	.rx_completion = aim_rx_completion,
	.tx_completion = aim_tx_completion,
};

static int sysfstouint(const char *buf, size_t count, uint *val)
{
	char tmp[32];

	tmp[strlcpy(tmp, buf, min_t(size_t, sizeof(tmp), count))] = '\0';
	return kstrtouint(tmp, 0, val);
}

static ssize_t isoc_blk_sz_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "%u\n", isoc_blk_sz);
}
static ssize_t isoc_blk_sz_store(struct device_driver *drv,
				 const char *buf, size_t count)
{
	int err;
	uint val;

	err = sysfstouint(buf, count, &val);
	if (err)
		;
	else if (val == 188 || val == 192 || val == 196)
		isoc_blk_sz = val;
	else
		err = -EINVAL;
	return err ? err : count;
}

static ssize_t isoc_blk_num_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "%u\n", isoc_blk_num);
}
static ssize_t isoc_blk_num_store(struct device_driver *drv,
				  const char *buf, size_t count)
{
	int err;
	uint val;

	err = sysfstouint(buf, count, &val);
	if (err)
		;
	else if (val >= CH_ISOC_BLK_NUM_MIN)
		isoc_blk_num = val;
	else
		err = -EINVAL;
	return err ? err : count;
}

static DRIVER_ATTR_RW(isoc_blk_sz);
static DRIVER_ATTR_RW(isoc_blk_num);
static struct attribute *aim_drv_attrs[] = {
	&driver_attr_isoc_blk_sz.attr,
	&driver_attr_isoc_blk_num.attr,
	NULL
};
ATTRIBUTE_GROUPS(aim_drv);
static struct platform_driver aim_platform_drv = {
	.driver = {
		.name = "mlb150",
		.owner = THIS_MODULE,
		.groups = aim_drv_groups,
	},
};

static int __init mod_init(void)
{
	int err;
	struct aim_channel *c;

	used_minor_devices =
		/* no control, no opt3, no async, no isoc-sync quirk */
		number_sync_channels + number_isoc_channels;

	pr_debug("\n");

	aim_channels = kzalloc(sizeof(*aim_channels) * used_minor_devices, GFP_KERNEL);
	if (!aim_channels)
		return -ENOMEM;
	err = alloc_chrdev_region(&aim_devno, MINOR_BASE,
				  used_minor_devices, "mlb150");
	if (err < 0)
		goto free_channels;
	cdev_init(&aim_cdev, &aim_channel_fops);
	aim_cdev.owner = THIS_MODULE;
	err = cdev_add(&aim_cdev, aim_devno, used_minor_devices);
	if (err)
		goto free_chrdev_reg;
	err = class_register(&aim_class);
	if (err)
		goto free_cdev;
	foreach_aim_channel(c) {
		int id = c - aim_channels;

		if (id < number_sync_channels)
			snprintf(c->name, sizeof(c->name), "sync%d", id);
		else if (number_isoc_channels > 1)
			snprintf(c->name, sizeof(c->name), "isoc%d",
				 id - number_sync_channels);
		else
			strlcpy(c->name, "isoc", sizeof(c->name));
		c->devno = MKDEV(MAJOR(aim_devno), MINOR_BASE + c - aim_channels);
		spin_lock_init(&c->unlink);
		INIT_KFIFO(c->fifo);
		init_waitqueue_head(&c->wq);
		mutex_init(&c->io_mutex);
		c->dev = device_create(&aim_class, NULL, c->devno, NULL, "%s", c->name);
		if (IS_ERR(c->dev)) {
			err = PTR_ERR(c->dev);
			pr_debug("%s: device_create failed %d\n", c->name, err);
			goto free_devices;
		}
		err = init_aim_channel_attrs(c);
		if (!err && id < number_sync_channels) {
			err = init_sync_channel_attrs(c);
			c->mlb150_sync_buf_size = SYNC_DMA_MIN_SIZE;
		}
		if (err)
			goto free_devices;
		kobject_uevent(&c->dev->kobj, KOBJ_ADD);
	}
	err = most_register_aim(&aim);
	if (err)
		goto free_devices;
	err = platform_driver_register(&aim_platform_drv);
	if (err < 0)
		goto free_devices;
	return 0;
free_devices:
	while (c-- > aim_channels) {
		if (c->stat_attr.attr.mode)
			device_remove_file(c->dev, &c->stat_attr);
		if (c->bufsize_attr.attr.mode)
			device_remove_file(c->dev, &c->bufsize_attr);
		if (c->dump_attr.attr.mode)
			device_remove_file(c->dev, &c->dump_attr);
		device_destroy(&aim_class, c->devno);
	}
	class_unregister(&aim_class);
free_cdev:
	cdev_del(&aim_cdev);
free_chrdev_reg:
	unregister_chrdev_region(aim_devno, used_minor_devices);
free_channels:
	kfree(aim_channels);
	return err;
}

static void __exit mod_exit(void)
{
	struct aim_channel *c;

	pr_debug("\n");

	platform_driver_unregister(&aim_platform_drv);
	most_deregister_aim(&aim);
	for (c = aim_channels + used_minor_devices; --c >= aim_channels;) {
		kfifo_free(&c->fifo);
		device_remove_file(c->dev, &c->stat_attr);
		if (c->bufsize_attr.attr.mode)
			device_remove_file(c->dev, &c->bufsize_attr);
		device_remove_file(c->dev, &c->dump_attr);
		device_destroy(&aim_class, c->devno);
	}
	class_unregister(&aim_class);
	cdev_del(&aim_cdev);
	unregister_chrdev_region(aim_devno, used_minor_devices);
	kfree(aim_channels);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Cetitec GmbH <support@cetitec.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Character device AIM (mlb150 interface) for mostcore");
