/*
 * syncsound.c - ALSA Application Interface Module
 *
 * Copyright (C) 2017 Cetitec GmbH
 * Copyright (C) 2015 Microchip Technology Germany II GmbH & Co. KG
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
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/control.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/ctype.h>
#include "mostcore.h"
#include "mlb150_ext.h"

#define DRIVER_NAME "syncsound"
#define MAX_PERIOD_SIZE (8192) /* DIM2 restriction */

static struct list_head dev_list;
static struct most_aim aim; /* forward declaration */
static struct snd_card *card;

static u32 mlb_sync_channel_addresses[MLB_MAX_SYNC_DEVICES] = {
/*       Tx           Rx */
	(8  << 16) |  7,
	(10 << 16) |  9,
	(12 << 16) | 11,
	(14 << 16) | 13,
	(16 << 16) | 15,
	(18 << 16) | 17,
	(10 << 16) |  9 /* same as sync1 */
};

struct mostcore_channel {
	int channel_id;
	struct most_interface *iface;
	struct most_channel_config *cfg;
	bool started;
	int fpt[7 /* number of channels +1 */][5 /* sample size +1, bytes */];
};

static struct mostcore_channel mlb_channels[MLB_LAST_CHANNEL + 1];
static inline struct mostcore_channel *get_most(int syncsound_id,
						enum most_channel_direction d)
{
	u16 mlb150_id;

	if ((uint)syncsound_id >= ARRAY_SIZE(mlb_sync_channel_addresses))
		return NULL;
	mlb150_id = d == MOST_CH_RX ?
		mlb_sync_channel_addresses[syncsound_id]:
		mlb_sync_channel_addresses[syncsound_id] >> 16;
	if (mlb150_id >= ARRAY_SIZE(mlb_channels))
		return NULL;
	return &mlb_channels[mlb150_id];
}

struct channel {
	struct mostcore_channel *most;
	int syncsound_id;
	struct snd_pcm_substream *substream;
	struct snd_pcm_hardware pcm_hardware;
	struct list_head list;
	unsigned int period_pos;
	unsigned int buffer_pos;
	bool is_stream_running;
	int buffer_size;

	struct task_struct *playback_task;
	wait_queue_head_t playback_waitq;

	void (*copy_fn)(void *alsa, void *most, unsigned int bytes);
};

static void swap_copy16(u16 *dest, const u16 *source, unsigned int bytes)
{
	unsigned int i = 0;

	while (i < (bytes / 2)) {
		dest[i] = swab16(source[i]);
		i++;
	}
}

static void swap_copy24(u8 *dest, const u8 *source, unsigned int bytes)
{
	unsigned int i = 0;

	while (i < bytes - 2) {
		dest[i] = source[i + 2];
		dest[i + 1] = source[i + 1];
		dest[i + 2] = source[i];
		i += 3;
	}
}

static void swap_copy32(u32 *dest, const u32 *source, unsigned int bytes)
{
	unsigned int i = 0;

	while (i < bytes / 4) {
		dest[i] = swab32(source[i]);
		i++;
	}
}

static void alsa_to_most_memcpy(void *alsa, void *most, unsigned int bytes)
{
	memcpy(most, alsa, bytes);
}

static void alsa_to_most_copy16(void *alsa, void *most, unsigned int bytes)
{
	swap_copy16(most, alsa, bytes);
}

static void alsa_to_most_copy24(void *alsa, void *most, unsigned int bytes)
{
	swap_copy24(most, alsa, bytes);
}

static void alsa_to_most_copy32(void *alsa, void *most, unsigned int bytes)
{
	swap_copy32(most, alsa, bytes);
}

static void most_to_alsa_memcpy(void *alsa, void *most, unsigned int bytes)
{
	memcpy(alsa, most, bytes);
}

static void most_to_alsa_copy16(void *alsa, void *most, unsigned int bytes)
{
	swap_copy16(alsa, most, bytes);
}

static void most_to_alsa_copy24(void *alsa, void *most, unsigned int bytes)
{
	swap_copy24(alsa, most, bytes);
}

static void most_to_alsa_copy32(void *alsa, void *most, unsigned int bytes)
{
	swap_copy32(alsa, most, bytes);
}

static struct channel *get_channel(struct most_interface *iface,
				   int channel_id)
{
	struct channel *channel;

	list_for_each_entry(channel, &dev_list, list)
		if (channel->most &&
		    channel->most->iface == iface &&
		    channel->most->channel_id == channel_id)
			return channel;
	return NULL;
}

static bool copy_data(struct channel *channel, void *mbo_address, uint frames, uint frame_bytes)
{
	struct snd_pcm_runtime *const runtime = channel->substream->runtime;
	//unsigned int const frame_bytes = channel->cfg->subbuffer_size;
	unsigned int const buffer_size = runtime->buffer_size;
	unsigned int fr0;

	/*if (channel->cfg->direction & MOST_CH_RX)
		frames = mbo->processed_length / frame_bytes;
	else
		frames = mbo->buffer_length / frame_bytes;*/
	fr0 = min(buffer_size - channel->buffer_pos, frames);

	channel->copy_fn(runtime->dma_area + channel->buffer_pos * frame_bytes,
			 mbo_address,
			 fr0 * frame_bytes);

	if (frames > fr0) {
		/* wrap around at end of ring buffer */
		channel->copy_fn(runtime->dma_area,
				 mbo_address + fr0 * frame_bytes,
				 (frames - fr0) * frame_bytes);
	}

	channel->buffer_pos += frames;
	if (channel->buffer_pos >= buffer_size)
		channel->buffer_pos -= buffer_size;
	channel->period_pos += frames;
	if (channel->period_pos >= runtime->period_size) {
		channel->period_pos -= runtime->period_size;
		return true;
	}

	return false;
}

static int playback_thread(void *data)
{
	struct channel *const channel = data;

	while (!kthread_should_stop()) {
		struct mbo *mbo = NULL;
		bool period_elapsed = false;
		struct mostcore_channel *most = channel->most;
		int ret;

		ret = wait_event_interruptible(
			channel->playback_waitq,
			kthread_should_stop() ||
			(channel->is_stream_running && most &&
			 (mbo = most_get_mbo(most->iface, most->channel_id,
					     &aim))));
		if (ret || !mbo)
			continue;
		if (channel->is_stream_running)
			period_elapsed = copy_data(channel, mbo->virt_address,
				mbo->buffer_length / most->cfg->subbuffer_size,
				most->cfg->subbuffer_size);
		else
			memset(mbo->virt_address, 0, mbo->buffer_length);
		//pr_debug("%p %u\n", mbo, mbo->buffer_length);
		most_submit_mbo(mbo);
		if (period_elapsed)
			snd_pcm_period_elapsed(channel->substream);
	}

	return 0;
}

static void update_pcm_hw_from_cfg(struct channel *channel,
				   const struct most_channel_config *cfg)
{
	uint buf_size = channel->buffer_size == -1 ? MAX_PERIOD_SIZE : channel->buffer_size;

	channel->pcm_hardware.periods_min = 1;
	channel->pcm_hardware.periods_max = cfg->num_buffers;
	if (channel->buffer_size != -1)
		channel->pcm_hardware.period_bytes_min = buf_size;
	channel->pcm_hardware.period_bytes_max = buf_size;
	channel->pcm_hardware.buffer_bytes_max = buf_size * cfg->num_buffers;
}

static int pcm_open(struct snd_pcm_substream *substream,
		    enum most_channel_direction dir)
{
	struct mostcore_channel *most;
	struct channel *channel = substream->private_data;
	struct snd_pcm_runtime *runtime = substream->runtime;

	pr_debug("%d: %s\n", channel->syncsound_id, dir == MOST_CH_TX ? "tx" : "rx");
	if (channel->most)
		return -EBUSY;
	most = get_most(channel->syncsound_id, dir);
	if (!most || !most->cfg)
		return -ENOTCONN;
	pr_debug("%p (%zd) cfg %p\n", most, most - mlb_channels, most->cfg);
	channel->most = most;
	channel->substream = substream;
	update_pcm_hw_from_cfg(channel, most->cfg);
	runtime->hw = channel->pcm_hardware;
	return 0;
}

static int pcm_open_play(struct snd_pcm_substream *substream)
{
	return pcm_open(substream, MOST_CH_TX);
}

static int pcm_open_capture(struct snd_pcm_substream *substream)
{
	return pcm_open(substream, MOST_CH_RX);
}

static void stop_most(struct channel *channel)
{
	struct mostcore_channel *most = channel->most;

	if (most && most->started) {
		most_stop_channel(most->iface, most->channel_id, &aim);
		most->started = false;
	}
	channel->most = NULL;
}

static int pcm_close_play(struct snd_pcm_substream *substream)
{
	struct channel *channel = substream->private_data;

	pr_debug("\n");
	if (!IS_ERR_OR_NULL(channel->playback_task))
		kthread_stop(channel->playback_task);
	stop_most(channel);
	channel->substream = NULL;
	return 0;
}

static int pcm_close_capture(struct snd_pcm_substream *substream)
{
	struct channel *channel = substream->private_data;

	pr_debug("\n");
	stop_most(channel);
	channel->substream = NULL;
	return 0;
}

static void set_most_config(const struct channel *channel,
			    const struct mostcore_channel *most,
			    const struct snd_pcm_hw_params *hw_params)
{
	int width = snd_pcm_format_physical_width(params_format(hw_params));

	most->cfg->packets_per_xact =
		most->fpt[params_channels(hw_params)][width / BITS_PER_BYTE];
	most->cfg->subbuffer_size =
		width * params_channels(hw_params) / BITS_PER_BYTE;
	most->cfg->buffer_size = params_period_bytes(hw_params);
}

static int pcm_hw_params(struct snd_pcm_substream *substream,
			 struct snd_pcm_hw_params *hw_params)
{
	struct channel *channel = substream->private_data;

	if ((params_channels(hw_params) > channel->pcm_hardware.channels_max) ||
	    (params_channels(hw_params) < channel->pcm_hardware.channels_min)) {
		pr_err("Requested number of channels not supported.\n");
		return -EINVAL;
	}
	return snd_pcm_lib_alloc_vmalloc_buffer(substream, params_buffer_bytes(hw_params));
}

static int pcm_hw_params_play(struct snd_pcm_substream *substream,
			      struct snd_pcm_hw_params *hw_params)
{
	struct channel *channel = substream->private_data;
	int err;

	pr_debug("\n");
	err = pcm_hw_params(substream, hw_params);
	if (err < 0)
		return err;
	set_most_config(channel, channel->most, hw_params);
	return 0;
}

static int pcm_hw_params_capture(struct snd_pcm_substream *substream,
				 struct snd_pcm_hw_params *hw_params)
{
	struct channel *channel = substream->private_data;
	int err;

	pr_debug("\n");
	err = pcm_hw_params(substream, hw_params);
	if (err < 0)
		return err;
	set_most_config(channel, channel->most, hw_params);
	pr_debug("channels %d, buffer bytes %d, period bytes %d, frame size %d, sample size %d\n",
		 params_channels(hw_params),
		 params_buffer_bytes(hw_params),
		 params_period_bytes(hw_params),
		 channel->most->cfg->subbuffer_size,
		 snd_pcm_format_physical_width(params_format(hw_params)));
	return 0;
}

static int pcm_hw_free(struct snd_pcm_substream *substream)
{
	pr_debug("\n");
	return snd_pcm_lib_free_vmalloc_buffer(substream);
}

static int pcm_prepare_play(struct snd_pcm_substream *substream)
{
	int err;
	struct channel *channel = substream->private_data;
	struct mostcore_channel *most = channel->most;
	struct snd_pcm_runtime *runtime = substream->runtime;
	int width = snd_pcm_format_physical_width(runtime->format);

	pr_debug("\n");
	if (!most)
		return -ENXIO;
	if (most->started)
		return 0; /* underrun handling */
	channel->copy_fn = NULL;
	if (snd_pcm_format_big_endian(runtime->format) || width == 8)
		channel->copy_fn = alsa_to_most_memcpy;
	else if (width == 16)
		channel->copy_fn = alsa_to_most_copy16;
	else if (width == 24)
		channel->copy_fn = alsa_to_most_copy24;
	else if (width == 32)
		channel->copy_fn = alsa_to_most_copy32;
	if (!channel->copy_fn) {
		pr_err("unsupported format\n");
		return -EINVAL;
	}
	channel->period_pos = 0;
	channel->buffer_pos = 0;
	channel->playback_task = kthread_run(playback_thread, channel, "most");
	if (IS_ERR(channel->playback_task)) {
		err = PTR_ERR(channel->playback_task);
		pr_debug("kthread_run: %d\n", err);
		return -ENOMEM;
	}
	err = most_start_channel(most->iface, most->channel_id, &aim);
	if (err) {
		pr_debug("most_start_channel failed: %d\n", err);
		kthread_stop(channel->playback_task);
		channel->playback_task = NULL;
		return -EBUSY;
	}
	most->started = true;
	return 0;
}

static int pcm_prepare_capture(struct snd_pcm_substream *substream)
{
	struct channel *channel = substream->private_data;
	struct mostcore_channel *most = channel->most;
	struct snd_pcm_runtime *runtime = substream->runtime;
	int width = snd_pcm_format_physical_width(runtime->format);
	int err;

	pr_debug("\n");
	if (!most)
		return -ENXIO;
	if (most->started)
		return -EBUSY;
	channel->copy_fn = NULL;
	if (snd_pcm_format_big_endian(runtime->format) || width == 8)
		channel->copy_fn = most_to_alsa_memcpy;
	else if (width == 16)
		channel->copy_fn = most_to_alsa_copy16;
	else if (width == 24)
		channel->copy_fn = most_to_alsa_copy24;
	else if (width == 32)
		channel->copy_fn = most_to_alsa_copy32;
	if (!channel->copy_fn) {
		pr_err("unsupported format\n");
		return -EINVAL;
	}
	channel->period_pos = 0;
	channel->buffer_pos = 0;
	err = most_start_channel(most->iface, most->channel_id, &aim);
	if (err) {
		pr_debug("most_start_channel failed: %d\n", err);
		return -EBUSY;
	}
	most->started = true;
	return 0;
}

static int pcm_trigger(struct snd_pcm_substream *substream, int cmd)
{
	struct channel *channel = substream->private_data;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		pr_debug("start\n");
		channel->is_stream_running = true;
		wake_up_interruptible(&channel->playback_waitq);
		return 0;

	case SNDRV_PCM_TRIGGER_STOP:
		pr_debug("stop\n");
		channel->is_stream_running = false;
		return 0;

	default:
		pr_info("pcm_trigger(), invalid\n");
		return -EINVAL;
	}
	return 0;
}

static snd_pcm_uframes_t pcm_pointer(struct snd_pcm_substream *substream)
{
	struct channel *channel = substream->private_data;

	return channel->buffer_pos;
}

static const struct snd_pcm_ops play_ops = {
	.open       = pcm_open_play,
	.close      = pcm_close_play,
	.ioctl      = snd_pcm_lib_ioctl,
	.hw_params  = pcm_hw_params_play,
	.hw_free    = pcm_hw_free,
	.prepare    = pcm_prepare_play,
	.trigger    = pcm_trigger,
	.pointer    = pcm_pointer,
	.page       = snd_pcm_lib_get_vmalloc_page,
	.mmap       = snd_pcm_lib_mmap_vmalloc,
};
static const struct snd_pcm_ops capture_ops = {
	.open       = pcm_open_capture,
	.close      = pcm_close_capture,
	.ioctl      = snd_pcm_lib_ioctl,
	.hw_params  = pcm_hw_params_capture,
	.hw_free    = pcm_hw_free,
	.prepare    = pcm_prepare_capture,
	.trigger    = pcm_trigger,
	.pointer    = pcm_pointer,
	.page       = snd_pcm_lib_get_vmalloc_page,
	.mmap       = snd_pcm_lib_mmap_vmalloc,
};

static int rx_completion(struct mbo *mbo)
{
	struct channel *channel = get_channel(mbo->ifp, mbo->hdm_channel_id);
	struct most_channel_config *cfg;
	bool period_elapsed = false;

	if (!channel) {
		pr_debug("invalid channel %d\n", mbo->hdm_channel_id);
		return -EINVAL;
	}
	cfg = channel->most->cfg;
	if (channel->is_stream_running)
		period_elapsed = copy_data(channel, mbo->virt_address,
			mbo->processed_length / cfg->subbuffer_size,
			cfg->subbuffer_size);
	most_put_mbo(mbo);

	if (period_elapsed)
		snd_pcm_period_elapsed(channel->substream);
	return 0;
}

static int tx_completion(struct most_interface *iface, int channel_id)
{
	struct channel *channel = get_channel(iface, channel_id);

	if (!channel) {
		pr_debug("invalid channel %d\n", channel_id);
		return -EINVAL;
	}

	wake_up_interruptible(&channel->playback_waitq);
	pr_debug("TX\n");
	return 0;
}

static int disconnect_channel(struct most_interface *iface, int channel_id)
{
	struct channel *channel;

	channel = get_channel(iface, channel_id);
	if (!channel) {
		pr_err("sound_disconnect_channel(), invalid channel %d\n",
		       channel_id);
		return -EINVAL;
	}
	channel->most->started = false;
	channel->most->iface = NULL;
	channel->most->cfg = NULL;
	channel->most->channel_id = 0;
	channel->most = NULL;
	return 0;
}

static void parse_mostcore_channel_params(struct mostcore_channel *most, char *s)
{
	int fpt;

	do {
		char *sp;
		uint cn, ss;

		cn = (*s++) - '0';
		if (*s++ != 'x')
			return;
		ss = (s[0] - '0') * 10 + (s[1] - '0');
		ss /= 8;
		s += 2;
		if (*s++ != ',')
			return;
		sp = s + strcspn(s, " \t\r\n");
		if (*sp)
			*sp++ = '\0';
		if (kstrtoint(s, 0, &fpt))
			return;
		most->fpt[cn][ss / 8] = fpt;
		/* pr_debug("mode %dx%d fpt %d\n", cn, 8 * ss, fpt); */
		s = sp + strspn(sp, " \t\r\n");
	} while (*s);
}

static int probe_channel(struct most_interface *iface, int channel_id,
			 struct most_channel_config *cfg,
			 struct kobject *parent, char *args)
{
	int mlb150_id;
	struct mostcore_channel *most;
	char *sp;

	pr_debug("%s.ch%d %s\n", iface->description, channel_id, args);
	if (!iface)
		return -EINVAL;
	if (cfg->data_type != MOST_CH_SYNC) {
		pr_err("Incompatible channel type\n");
		return -EINVAL;
	}
	sp = strchr(args, '/');
	if (sp)
		*sp++ = '\0';
	else {
		for (sp = args; isdigit(*sp); ++sp);
		*sp = '\0';
	}
	if (kstrtoint(args, 0, &mlb150_id))
		return -EINVAL;
	if ((uint)mlb150_id >= ARRAY_SIZE(mlb_channels))
		return -EINVAL;
	most = &mlb_channels[mlb150_id];
	if (most->iface) {
		pr_err("MLB150 channel %d already linked to %s:%d\n", mlb150_id,
		       most->iface->description, most->channel_id);
		return -EBUSY;
	}
	most->iface = iface;
	most->channel_id = channel_id;
	most->cfg = cfg;
	parse_mostcore_channel_params(most, sp);
	pr_debug("mlb150 ch %d linked to %s.ch%d cfg %p\n", mlb150_id,
		 most->iface->description, most->channel_id, most->cfg);
	return 0;
}

/**
 * Initialization of the struct most_aim
 */
static struct most_aim aim = {
	.name = DRIVER_NAME,
	.rx_completion = rx_completion,
	.tx_completion = tx_completion,
	.disconnect_channel = disconnect_channel,
	.probe_channel = probe_channel,
};

extern u32 syncsound_get_num_devices(void); /* aim-mlb150 */

static __initconst const struct snd_pcm_hardware most_hardware = {
	.info = SNDRV_PCM_INFO_MMAP          |
		SNDRV_PCM_INFO_MMAP_VALID    |
		SNDRV_PCM_INFO_BATCH         |
		SNDRV_PCM_INFO_INTERLEAVED   |
		SNDRV_PCM_INFO_BLOCK_TRANSFER,
	.rates = SNDRV_PCM_RATE_48000,
	.rate_min = 48000,
	.rate_max = 48000,
	.buffer_bytes_max = 128 * MAX_PERIOD_SIZE,
	.period_bytes_min = 128,
	.period_bytes_max = MAX_PERIOD_SIZE, /* buffer_size */
	.periods_min = 1,
	.periods_max = 128, /* num_buffers */
	.channels_min = 1,
	.channels_max = 6,
	.formats = SNDRV_PCM_FMTBIT_S16_BE  |
		   SNDRV_PCM_FMTBIT_S16_LE  |
		   SNDRV_PCM_FMTBIT_S24_3BE |
		   SNDRV_PCM_FMTBIT_S24_3LE,
};

struct syncsound_attr {
	char name[32];
	struct channel *channel;
	struct device_attribute dev;
};
static ssize_t buffer_size_store(struct device *dev, struct device_attribute *dev_attr,
				      const char *buf, size_t count)
{
	struct syncsound_attr *attr = container_of(dev_attr, struct syncsound_attr, dev);
	int ret = kstrtoint(buf, 0, &attr->channel->buffer_size);

	return ret ? ret : count;
}
static ssize_t buffer_size_show(struct device *dev,
				     struct device_attribute *dev_attr,
				     char *buf)
{
	struct syncsound_attr *attr = container_of(dev_attr, struct syncsound_attr, dev);

	return sprintf(buf, "%d ", attr->channel->buffer_size);
}

static DEVICE_ATTR_RW(buffer_size);
static const struct device_attribute *syncsound_attrs[] = {
	&dev_attr_buffer_size,
};
static struct attribute *dev_attrs[SNDRV_CARDS * ARRAY_SIZE(syncsound_attrs) + 1];
static struct attribute_group dev_attr_group = {
	.name = "syncsound",
	.attrs = dev_attrs,
};

static void __init init_channel_attrs(int syncsound_id, struct syncsound_attr *attr, struct channel *channel)
{
	struct syncsound_attr *t;
	uint i, pos;

	pos = syncsound_id * ARRAY_SIZE(syncsound_attrs);
	attr += pos;
	for (i = 0, t = attr; i < ARRAY_SIZE(syncsound_attrs); ++i, ++t) {
		t->channel = channel;
		t->dev = *syncsound_attrs[i];
		snprintf(t->name, sizeof(t->name), "%s%d",
			 t->dev.attr.name, syncsound_id);
		t->dev.attr.name = t->name;
		dev_attrs[pos + (t - attr)] = &t->dev.attr;
	}
}

static int __init mod_init(void)
{
	int ret, i;
	uint max_pcms = min_t(uint, syncsound_get_num_devices(), SNDRV_CARDS);
	struct channel *channels;
	struct syncsound_attr *attr;

	pr_debug("\n");
	for (i = 0; i < ARRAY_SIZE(mlb_channels); ++i) {
		uint c, s;
		struct mostcore_channel *most = mlb_channels + i;

		for (s = 0; s < ARRAY_SIZE(most->fpt[0]); ++s)
			most->fpt[0][s] = 128;
		for (c = 1; c < ARRAY_SIZE(most->fpt); ++c) {
			most->fpt[c][0] = 128;
			for (s = 1; s < ARRAY_SIZE(most->fpt[0]); ++s)
				most->fpt[c][s] = 512 / (c * s * 8);
		}
	}
	INIT_LIST_HEAD(&dev_list);
	ret = snd_card_new(most_parent_device(), // FIXME: mostcore is a bad parent
			   -1, NULL, THIS_MODULE,
			   max_pcms * sizeof(*channels) +
			   max_pcms * sizeof(*attr) *
			   ARRAY_SIZE(syncsound_attrs),
			   &card);
	if (ret)
		return ret;
	channels = card->private_data;
	attr = (void *)&channels[max_pcms];
	for (i = 0; i < max_pcms; ++i) {
		struct snd_pcm *pcm;
		struct channel *channel = &channels[i];

		channel->most = NULL;
		channel->buffer_size = -1;
		channel->syncsound_id = i;
		channel->pcm_hardware = most_hardware;
		init_waitqueue_head(&channel->playback_waitq);
		strlcpy(card->driver, "MLB_Sync_Driver", sizeof(card->driver));
		strlcpy(card->shortname, "MLB_Sync_Audio", sizeof(card->shortname));
		strlcpy(card->longname, "Virtual soundcard over MLB synchronous channels", sizeof(card->longname));
		ret = snd_pcm_new(card, card->driver, i, 1, 1, &pcm);
		if (ret)
			goto err_free_card;
		init_channel_attrs(i, attr, channel);
		snprintf(pcm->name, sizeof(pcm->name), "MLB_SYNC%d", i);
		pcm->private_data = channel;
		snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_PLAYBACK, &play_ops);
		snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE, &capture_ops);
		list_add_tail(&channel->list, &dev_list);
	}
	ret = snd_card_add_dev_attr(card, &dev_attr_group);
	if (ret)
		goto err_free_card;
	ret = snd_card_register(card);
	if (ret)
		goto err_free_card;
	return most_register_aim(&aim);
err_free_card:
	snd_card_free(card);
	pr_debug("ret %d\n", ret);
	return ret;
}

static void __exit mod_exit(void)
{
	pr_info("exit()\n");
	snd_card_free(card);
	most_deregister_aim(&aim);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Cetitec GmbH <support@cetitec.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ALSA AIM (syncsound interface) for mostcore");

