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
#include "mostcore.h"
#include "mlb150.h"

#define DRIVER_NAME "aim-mlb150"
/*
 * This driver emulates only sync and isoc interfaces of the mlb150, so this
 * excludes the first two minors of the original: ctrl and async (and opt3)
 */
#define MINOR_BASE (2)

#define MLB_FIRST_CHANNEL	(1)
#define MLB_LAST_CHANNEL	(63)

#define FCNT_VALUE 5

/* return the buffer depth for the given bytes-per-frame */
#define SYNC_BUFFER_DEP(bpf) (4 * (1 << FCNT_VALUE) * (bpf))

#define SYNC_MIN_FRAME_SIZE (2) /* mono, 16bit sample */
#define SYNC_DMA_MIN_SIZE       SYNC_BUFFER_DEP(SYNC_MIN_FRAME_SIZE) /* mono, 16bit sample */
#define SYNC_DMA_MAX_SIZE       (0x1fff + 1) /* system memory buffer size in ADT */

/* default number of sync channels which is used
   if module is loaded without parameters. */
uint number_sync_channels = 7;
module_param(number_sync_channels, uint, 0444);
u32 syncsound_get_num_devices(void)
{
	return number_sync_channels;
}
EXPORT_SYMBOL(syncsound_get_num_devices);

/* number of isochronous channels to provide by default */
uint number_isoc_channels = 1;
module_param_named(isoc_channels, number_isoc_channels, uint, 0444);

static dev_t aim_devno;
static struct class aim_class = {
	.name = "mlb150",
	.owner = THIS_MODULE,
};
static struct cdev aim_cdev;

struct aim_channel {
	char name[20 /* MLB_DEV_NAME_SIZE */];
	wait_queue_head_t wq;
	spinlock_t unlink;	/* synchronization lock to unlink channels */
	dev_t devno;
	struct device *dev;
	struct mutex io_mutex;
	/* mostcore channels associated with this mlb150 interface */
	struct list_head most;
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

struct mostcore_channel {
	struct list_head head;
	struct most_interface *iface;
	struct most_channel_config *cfg;
	unsigned int channel_id;
	int mlb150_id;
	int started;
	struct aim_channel *aim;
	struct mostcore_channel *next; /* used by most->aim channel mapping */
};

#define to_channel(d) container_of(d, struct aim_channel, cdev)
#define foreach_aim_channel(c) \
	for (c = aim_channels; (c) < aim_channels + used_minor_devices; ++c)

static struct aim_channel *aim_channels;
static uint used_minor_devices;
static struct most_aim aim; /* forward declaration */

static inline bool ch_not_found(const struct aim_channel *c)
{
	return c == aim_channels + used_minor_devices;
}

static inline struct mostcore_channel *ch_current(const struct aim_channel *c)
{
	return list_first_entry(&c->most, struct mostcore_channel, head);
}

static bool ch_is_started(const struct aim_channel *c)
{
	return ch_current(c)->started;
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
	struct mostcore_channel *most;

	if (kfifo_peek(&c->fifo, mbo))
		return *mbo;

	most = ch_current(c);
	*mbo = most_get_mbo(most->iface, most->channel_id, &aim);
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
	ssize_t copied;
	size_t to_copy, not_copied;
	unsigned long flags;
	struct mbo *mbo;
	struct aim_channel *c = filp->private_data;
	struct mostcore_channel *most;

	mutex_lock(&c->io_mutex);
	most = ch_current(c);
	if (!most->started) {
		copied = -ESHUTDOWN;
		goto unlock;
	}
	while (c->dev && !kfifo_peek(&c->fifo, &mbo)) {
		mutex_unlock(&c->io_mutex);
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(c->wq,
			(!kfifo_is_empty(&c->fifo) /* || !c->dev */)))
			return -ERESTARTSYS;
		mutex_lock(&c->io_mutex);
	}

	/* make sure we don't submit to gone devices */
	/*if (unlikely(!c->dev)) {
		copied = -ENODEV;
		goto unlock;
	}*/
	write_lock_irqsave(&c->stat_lock, flags);
	c->rx_pkts++;
	c->rx_bytes += mbo->processed_length;
	write_unlock_irqrestore(&c->stat_lock, flags);
	to_copy = min_t(size_t, count, mbo->processed_length - c->mbo_offs);
	not_copied = copy_to_user(buf, mbo->virt_address + c->mbo_offs, to_copy);
	copied = to_copy - not_copied;
	c->mbo_offs += copied;
	if (c->mbo_offs >= mbo->processed_length) {
		kfifo_skip(&c->fifo);
		most_put_mbo(mbo);
		c->mbo_offs = 0;
	}
unlock:
	mutex_unlock(&c->io_mutex);
	return copied;
}

static ssize_t aim_write(struct file *filp, const char __user *buf,
			 size_t count, loff_t *f_pos)
{
	ssize_t ret;
	size_t to_copy, left;
	struct mbo *mbo = NULL;
	struct mostcore_channel *most;
	struct aim_channel *c = filp->private_data;

	mutex_lock(&c->io_mutex);
	most = ch_current(c);
	if (!most->started) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	while (/*c->dev && */!ch_get_mbo(c, &mbo)) {
		mutex_unlock(&c->io_mutex);
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(c->wq, ch_has_mbo(most) /*|| !c->dev*/))
			return -ERESTARTSYS;
		mutex_lock(&c->io_mutex);
	}
/*
	if (unlikely(!c->dev)) {
		ret = -ENODEV;
		goto unlock;
	}
*/
	to_copy = min(count, most->cfg->buffer_size - c->mbo_offs);
	left = copy_from_user(mbo->virt_address + c->mbo_offs, buf, to_copy);
	if (left == to_copy) {
		ret = -EFAULT;
		goto unlock;
	}
	c->mbo_offs += to_copy - left;
	if (c->mbo_offs >= most->cfg->buffer_size ||
	    most->cfg->data_type == MOST_CH_CONTROL ||
	    most->cfg->data_type == MOST_CH_ASYNC) {
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
	struct mostcore_channel *most;
	unsigned int mask = 0;

	poll_wait(filp, &c->wq, wait);
	mutex_lock(&c->io_mutex);
	most = ch_current(c);
	if (!most->started)
		mask |= POLLIN|POLLOUT|POLLERR|POLLNVAL|POLLHUP;
	else if (most->cfg->direction == MOST_CH_RX) {
		if (!kfifo_is_empty(&c->fifo))
			mask |= POLLIN | POLLRDNORM;
	} else {
		if (!kfifo_is_empty(&c->fifo) || ch_has_mbo(most))
			mask |= POLLOUT | POLLWRNORM;
	}
	mutex_unlock(&c->io_mutex);
	return mask;
}

static int start_most(struct aim_channel *c, struct mostcore_channel *most)
{
	int ret;

	ret = kfifo_alloc(&c->fifo, most->cfg->num_buffers, GFP_KERNEL);
	if (ret)
		return ret;
	c->mbo_offs = 0;
	ret = most_start_channel(most->iface, most->channel_id, &aim);
	if (!ret)
		most->started = 1;
	pr_debug("subbuffer_size %u, buffer_size %u ret %d\n",
		 most->cfg->subbuffer_size, most->cfg->buffer_size, ret);
	return ret;
}

static void stop_most(struct aim_channel *c, struct mostcore_channel *most)
	__must_hold(&c->io_mutex)
{
	struct mbo *mbo;

	pr_debug("%s.%u (%s) shut down\n", c->name, most->mlb150_id,
		 most->cfg->direction == MOST_CH_RX ? "rx" : "tx");
	while (kfifo_out((struct kfifo *)&c->fifo, &mbo, 1))
		most_put_mbo(mbo);
	most_stop_channel(most->iface, most->channel_id, &aim);
	kfifo_free(&c->fifo);
	INIT_KFIFO(c->fifo);
	most->started = 0;
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
	struct mostcore_channel *most;
	const uint tx = (caddr >> 16) & 0xffff;
	const uint rx = caddr & 0xffff;
	int ret;

	mutex_lock(&c->io_mutex);
	if (ch_is_started(c)) {
		ret = -EBUSY;
		goto unlock;
	}
	list_for_each_entry(most, &c->most, head) {
		if (most->cfg->direction == MOST_CH_RX && most->mlb150_id == rx)
			break;
		if (most->cfg->direction == MOST_CH_TX && most->mlb150_id == tx)
			break;
	}
	if (&most->head == &c->most) {
		ret = -ENODEV;
		goto unlock;
	}
	pr_debug("caddr 0x%08x (%s.%u)\n", caddr, c->name, most->mlb150_id);
	c->mlb150_caddr = caddr;
	list_move(&most->head, &c->most);
	ret = 0;
unlock:
	mutex_unlock(&c->io_mutex);
	return ret;
}

static int mlb150_chan_startup(struct aim_channel *c, uint accmode)
{
	int ret;
	struct mostcore_channel *most;

	mutex_lock(&c->io_mutex);
	if (ch_is_started(c)) {
		ret = -EBUSY;
		goto unlock;
	}
	list_for_each_entry(most, &c->most, head) {
		if (accmode == O_RDONLY &&
		    most->cfg->direction == MOST_CH_RX &&
		    most->mlb150_id >= MLB_FIRST_CHANNEL)
			break;
		if (accmode == O_WRONLY &&
		    most->cfg->direction == MOST_CH_TX &&
		    most->mlb150_id >= MLB_FIRST_CHANNEL)
			break;
	}
	if (&most->head == &c->most) {
		ret = -ENODEV;
		goto unlock;
	}
	if (most->cfg->data_type == MOST_CH_SYNC) {
		ret = -EINVAL;
		goto unlock;
	}
	list_move(&most->head, &c->most);

	// TODO
	pr_debug("unimplemenented"); ret = -ENOTSUPP; goto unlock;
	//ret = mlb_chan_allocate_dmabufs(drvdata, pdevinfo, direction, 0);
	//return ret ? ret : mlb_chan_startup(pdevinfo, direction);

	most->started = 1;
	ret = 0;
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
	if (ch_is_started(c)) {
		ret = -EBUSY;
		goto unlock;
	}
	if (accmode == O_RDONLY) {
		list_for_each_entry(most, &c->most, head)
			if (most->cfg->direction == MOST_CH_RX &&
			    most->mlb150_id >= MLB_FIRST_CHANNEL)
				break;
	} else {
		list_for_each_entry(most, &c->most, head)
			if (most->cfg->direction == MOST_CH_TX &&
			    most->mlb150_id >= MLB_FIRST_CHANNEL)
				break;
	}
	if (&most->head == &c->most) {
		ret = -ENODEV;
		goto unlock;
	}
	if (most->cfg->data_type != MOST_CH_SYNC) {
		ret = -EINVAL;
		goto unlock;
	}
	list_move(&most->head, &c->most);
	most->cfg->subbuffer_size = bytes_per_frame;
	most->cfg->buffer_size = max(SYNC_BUFFER_DEP(bytes_per_frame),
				     c->mlb150_sync_buf_size);
	ret = start_most(c, most);
unlock:
	mutex_unlock(&c->io_mutex);
	return ret;
}

static int mlb150_chan_shutdown(struct aim_channel *c)
{
	struct mostcore_channel *most;

	mutex_lock(&c->io_mutex);
	most = ch_current(c);
	if (most->started)
		stop_most(c, most);
	else
		most = NULL;
	mutex_unlock(&c->io_mutex);
	return most ? 0 : -EBADF;
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
	struct mostcore_channel *most;
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
	list_for_each_entry(most, &c->most, head)
		if (most->cfg->direction == dir)
			break;
	if (&most->head == &c->most) {
		ret = -ENODEV;
		goto unlock;
	}
	/*
	 * Move the first found mostcore channel with the right
	 * direction to the head of the list of channels to
	 * speed up searches when starting the channel.
	 */
	list_move(&most->head, &c->most);
	c->users++;
	pr_debug("%s.%u (%s)\n", c->name, most->mlb150_id,
		 dir == MOST_CH_TX ? "tx" : "rx");
unlock:
	mutex_unlock(&c->io_mutex);
	return ret;
}

static int aim_release(struct inode *inode, struct file *filp)
{
	struct aim_channel *c = filp->private_data;
	struct mostcore_channel *most;

	mutex_lock(&c->io_mutex);
	list_for_each_entry(most, &c->most, head)
		if (most->started)
			stop_most(c, most);
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
	mutex_lock(&most->aim->io_mutex);
	list_del(&most->head);
	kfree(most);
	mutex_unlock(&most->aim->io_mutex);
	return 0;
}

static int aim_probe(struct most_interface *iface, int channel_id,
		     struct most_channel_config *cfg,
		     struct kobject *parent, char *name)
{
	struct mostcore_channel *most;
	struct aim_channel *c;
	int mlb150_id;
	int err = -EINVAL;
	char *s;

	pr_debug("iface %p, channel %d, cfg %p, parent %p, name %s\n",
		 iface, channel_id, cfg, parent, name);
	if (!iface || !cfg || !parent || !name)
		goto fail;
	if (!(cfg->data_type == MOST_CH_SYNC ||
	      cfg->data_type == MOST_CH_ISOC))
		goto fail;
	s = strchr(name, '.');
	if (!s || kstrtoint(s + 1, 0, &mlb150_id))
		goto fail;
	foreach_aim_channel(c)
		if (memcmp(name, c->name, s - name) == 0 &&
		    c->name[s - name] == '\0')
			break;
	if (ch_not_found(c)) {
		err = -ENXIO;
		goto fail;
	}
	err = -EBUSY;
	mutex_lock(&c->io_mutex);
	list_for_each_entry(most, &c->most, head)
		if (most->mlb150_id == mlb150_id)
			goto unlock;
	most = kzalloc(sizeof(*most), GFP_KERNEL);
	if (!most) {
		err = -ENOMEM;
		goto unlock;
	}
	most->mlb150_id = mlb150_id;
	most->cfg = cfg;
	most->aim = c;
	remember_channel(iface, channel_id, most);
	list_add(&most->head, &c->most);
	err = 0;
unlock:
	mutex_unlock(&c->io_mutex);
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
		else if (number_isoc_channels > 1) {
			id -= number_sync_channels;
			snprintf(c->name, sizeof(c->name), "isoc%d", id);
		} else
			strlcpy(c->name, "isoc", sizeof(c->name));
		c->devno = MKDEV(MAJOR(aim_devno), MINOR_BASE + c - aim_channels);
		INIT_LIST_HEAD(&c->most);
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
