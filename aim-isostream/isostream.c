/*
 * A driver for MOST video sending and receiving devices
 */

/*
 * TODO: According to http://linuxtv.org/downloads/v4l-dvb-apis/,
 * both capture and output V4L2 devices must support the "standards" ioctls,
 * but it looks like many drivers don't do that.
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/platform_device.h>
#include <media/videobuf2-vmalloc.h>
#include "mostcore.h"
#include "isostream.h"

MODULE_DESCRIPTION("MOST Video Driver");
MODULE_AUTHOR("Cetitec GmbH");
MODULE_LICENSE("GPL");
MODULE_VERSION(MOST_VIDEO_VERSION);

unsigned int memlimit = 100;
module_param_named(vid_limit, memlimit, uint, 0644);
MODULE_PARM_DESC(vid_limit, "Buffer memory limit in megabytes");

static unsigned debug;
module_param(debug, uint, 0644);
MODULE_PARM_DESC(debug, "activates V4L2 debugging log");

static unsigned vid_count = MLB_MAX_ISOC_DEVICES;
module_param(vid_count, uint, 0644);
MODULE_PARM_DESC(debug, "number of video devices to allocate (subject to the number of available isochronous channels)");

int vidioc_enum_framesizes(struct file *file, void *fh, struct v4l2_frmsizeenum *fsize)
{
	static const struct v4l2_frmsize_stepwise sizes = {
		.min_width  = 1,
		.max_width  = MAX_WIDTH,
		.step_width = 1,
		.min_height  = 1,
		.max_height  = MAX_HEIGHT,
		.step_height = 1
	};

	if (fsize->index > 0 || fsize->pixel_format != V4L2_PIX_FMT_MPEG)
		return -EINVAL;
	fsize->type = V4L2_FRMSIZE_TYPE_STEPWISE;
	fsize->stepwise = sizes;
	return 0;
}

int vidioc_enum_fmt(struct file *file, void  *priv, struct v4l2_fmtdesc *f)
{
	if (f->index > 0)
		return -EINVAL;

	strcpy(f->description, "MPEG-TS");
	f->pixelformat = V4L2_PIX_FMT_MPEG;
	f->flags = V4L2_FMT_FLAG_COMPRESSED;
	return 0;
}

#define MOST_VIDEO_CID_DTCP_MODE (V4L2_CID_USER_BASE + 0)

static int g_volatile_ctrl(struct v4l2_ctrl *ctrl)
{
	struct most_video_device *dev = container_of(ctrl->handler, struct most_video_device, ctrl_handler);
	pr_debug("%sctrl id 0x%x\n", ctrl == dev->dtcp_mode ? "dtcp_mode " : "", ctrl->id);
	return 0;
}

static int s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct most_video_device *dev = container_of(ctrl->handler, struct most_video_device, ctrl_handler);
	if (ctrl == dev->dtcp_mode)
		pr_debug("dtcp_mode ctrl %d (cur %d)\n", ctrl->val, ctrl->cur.val);
	return 0;
}

static const struct v4l2_ctrl_ops ctrl_ops = {
	.g_volatile_ctrl = g_volatile_ctrl,
	.s_ctrl = s_ctrl,
};

static const struct v4l2_ctrl_config ctrl_dtcp_mode = {
	.ops = &ctrl_ops,
	.id = MOST_VIDEO_CID_DTCP_MODE,
	.name = "DTCP mode",
	.type = V4L2_CTRL_TYPE_INTEGER,
	.min = 0,
	.max = 1,
	.step = 1,
	.def = 0,
};

int most_video_setup_ctrls(struct most_video_device *mvdev)
{
	int ret;
	struct v4l2_ctrl_handler *hdl = &mvdev->ctrl_handler;
	v4l2_ctrl_handler_init(hdl, 5 /* number of controls hint */);

	mvdev->dtcp_mode = v4l2_ctrl_new_custom(hdl, &ctrl_dtcp_mode, NULL);
	ret = hdl->error;

	if (ret) {
		pr_debug("v4l2_ctrl_new_custom: %d\n", ret);
		goto fail;
	}

	mvdev->mpeg_stream_type = v4l2_ctrl_new_std_menu(hdl, &ctrl_ops,
		V4L2_CID_MPEG_STREAM_TYPE,
		V4L2_MPEG_STREAM_TYPE_MPEG2_DVD, /* max */
		1,                               /* mask (?!) */
		V4L2_MPEG_STREAM_TYPE_MPEG2_TS); /* def (MPEG-TS) */
	ret = hdl->error;

	if (ret) {
		pr_debug("v4l2_ctrl_new_std_menu(MPEG_STREAM_TYPE): %d\n", ret);
		goto fail;
	}

	mvdev->mpeg_audio_encoding = v4l2_ctrl_new_std_menu(hdl, &ctrl_ops,
		V4L2_CID_MPEG_AUDIO_ENCODING,
		V4L2_MPEG_AUDIO_ENCODING_AC3,
		1,
		V4L2_MPEG_AUDIO_ENCODING_LAYER_1);
	ret = hdl->error;
	if (ret)
		pr_debug("v4l2_ctrl_new_std_menu(MPEG_AUDIO_ENCODING): %d\n", ret);

	mvdev->mpeg_audio_mute = v4l2_ctrl_new_std(hdl, &ctrl_ops,
		V4L2_CID_MPEG_AUDIO_MUTE, 0, 1, 1, 1 /* def (1 - muted) */);
	ret = hdl->error;

	if (ret)
		pr_debug("v4l2_ctrl_new_std_menu(MPEG_AUDIO_MUTE): %d\n", ret);

	mvdev->mpeg_video_encoding = v4l2_ctrl_new_std_menu(hdl, &ctrl_ops,
		V4L2_CID_MPEG_VIDEO_ENCODING,
		V4L2_MPEG_VIDEO_ENCODING_MPEG_4_AVC,
		1,
		V4L2_MPEG_VIDEO_ENCODING_MPEG_4_AVC); /* def (x264) */
	ret = hdl->error;

	if (ret)
		pr_debug("v4l2_ctrl_new_std_menu(MPEG_VIDEO_ENCODING): %d\n", ret);

	mvdev->dtcp_mode->flags |= V4L2_CTRL_FLAG_VOLATILE /* this is to get g_volatile_ctrl called */;
	mvdev->v4l2_dev.ctrl_handler = hdl;

	return 0;
fail:
	v4l2_ctrl_handler_free(hdl);
	return ret;
}

int most_video_queue_setup(struct vb2_queue *vq, const void *parg,
			   unsigned int *nbuffers, unsigned int *nplanes,
			   unsigned int sizes[], void *alloc_ctxs[])
{
	const struct v4l2_format *fmt = parg;
	struct most_video_device *dev = vb2_get_drv_priv(vq);
	unsigned size;

	// FIXME needs locking
	dev->mlb_frm_cnt = dev->ext->count;
	dev->mlb_frm_size = dev->ext->size;
	if (fmt)
		size = fmt->fmt.pix.sizeimage;
	else if (dev->vbsize)
		size = dev->vbsize;
	else
		size = dev->mlb_frm_size;
	pr_debug("count=%d, size=%u (%u x %u, limit %uMiB)\n", *nbuffers, size,
		 dev->mlb_frm_cnt, dev->mlb_frm_size, memlimit);
	/*
	 * At the moment supporting either one MPEG-TS frame or a full MLB
	 * buffer of the frames, just to keep the frame copy code simple.
	 */
	if (!(size == dev->mlb_frm_size ||
	      size == dev->mlb_frm_cnt * dev->mlb_frm_size))
		return -EINVAL;
	if (0 == *nbuffers)
		*nbuffers = 3;
	while (size * *nbuffers > memlimit * 1024 * 1024)
		(*nbuffers)--;
	*nplanes = 1;
	sizes[0] = size;
	alloc_ctxs[0] = dev->allocator_ctx;
	return 0;
}

int most_video_g_fmt(struct file *file, void *priv, struct v4l2_format *f)
{
	f->fmt.pix.width        = 1280;
	f->fmt.pix.height       = 720;
	f->fmt.pix.field        = V4L2_FIELD_NONE;
	f->fmt.pix.pixelformat  = V4L2_PIX_FMT_MPEG;
	f->fmt.pix.bytesperline = 0;
	f->fmt.pix.colorspace   = V4L2_COLORSPACE_SRGB;
	f->fmt.pix.sizeimage    = 0;
	return 0;
}

int most_video_try_fmt(struct file *file, void *priv, struct v4l2_format *f)
{
	struct most_video_device *dev = video_drvdata(file);
	uint sizeimage = 0;

	if (f->fmt.pix.pixelformat == V4L2_PIX_FMT_MPEG)
		sizeimage = f->fmt.pix.sizeimage;
	most_video_g_fmt(file, priv, f);
	if (sizeimage == dev->mlb_frm_size ||
	    sizeimage == dev->mlb_frm_size * dev->mlb_frm_cnt)
		f->fmt.pix.sizeimage = sizeimage;
	return 0;
}

static inline char fourcc_ch(u8 c)
{
	return 33u <= c && c <= 126u ? c : '?';
}

int most_video_s_fmt(struct file *file, void *priv, struct v4l2_format *f)
{
	struct most_video_device *dev = video_drvdata(file);
	struct vb2_queue *q = &dev->vb_vidq;
	int ret;

	pr_debug("fourcc %c%c%c%c sizeimage %u\n",
		 fourcc_ch(f->fmt.pix.pixelformat),
		 fourcc_ch(f->fmt.pix.pixelformat >> 8),
		 fourcc_ch(f->fmt.pix.pixelformat >> 16),
		 fourcc_ch(f->fmt.pix.pixelformat >> 24),
		 f->fmt.pix.sizeimage);
	ret = most_video_try_fmt(file, priv, f);
	if (ret < 0)
		goto done;
	ret = -EBUSY;
	if (vb2_is_busy(q))
		goto done;
	ret = 0;
	dev->vbsize = f->fmt.pix.sizeimage;
done:
	return ret;
}

int most_video_g_inout(struct file *file, void *priv, unsigned int *i)
{
	*i = 0;
	return 0;
}

int most_video_s_inout(struct file *file, void *priv, unsigned int i)
{
	if (i != 0)
		return -EINVAL;
	return 0;
}

void most_video_wait_finish(struct vb2_queue *vq)
{
	struct most_video_device *dev = vb2_get_drv_priv(vq);

	mutex_lock(&dev->mutex);
}

void most_video_wait_prepare(struct vb2_queue *vq)
{
	struct most_video_device *dev = vb2_get_drv_priv(vq);

	mutex_unlock(&dev->mutex);
}

int most_video_buf_prepare(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vb4 = to_vb2_v4l2_buffer(vb);
	struct frame *buf = container_of(vb4, struct frame, vb4);

	pr_debug("[%p/%d]\n", buf, buf->vb4.vb2_buf.index);
	buf->plane0 = vb2_plane_vaddr(vb, 0);
	return buf->plane0 ? 0 : -ENOMEM;
}

static void cleanup_frameq(struct most_video_device *mvdev)
{
	struct frame_queue *vidq;
	unsigned long flags;

	spin_lock_irqsave(&mvdev->slock, flags);
	vidq = &mvdev->vidq;
	/* Release all todo buffers */
	while (!list_empty(&vidq->todo)) {
		struct frame *buf;

		buf = list_entry(vidq->todo.next, struct frame, list);
		list_del(&buf->list);
		vb2_buffer_done(&buf->vb4.vb2_buf, VB2_BUF_STATE_ERROR);
		pr_debug("[%p/%d] released\n", buf, buf->vb4.vb2_buf.index);
	}
	/* return all withheld mbos */
	while (!list_empty(&vidq->input)) {
		struct mbo *mbo = list_entry(vidq->input.next,
					     struct mbo, list);

		list_del(&mbo->list);
		most_put_mbo(mbo);
	}
	vidq->offset = 0;
	spin_unlock_irqrestore(&mvdev->slock, flags);
}

void most_video_stop_streaming(struct vb2_queue *vq)
{
	struct most_video_device *dev = vb2_get_drv_priv(vq);

	pr_debug("%s: stopping streaming\n", video_device_node_name(&dev->vdev));
	mlb150_lock_channel(dev->ext, false);
	atomic_set(&dev->running, 0);
	cleanup_frameq(dev);
}

static int probe(struct platform_device *pdev)
{
	pr_debug("%s\n", __func__);
	return 0; /* TODO look for mlb driver and attach to isochronous channels */
}
static int remove(struct platform_device *pdev)
{
	pr_debug("%s\n", __func__);
	return 0; /* TODO detach from mlb driver */
}
static void shutdown(struct platform_device *pdev)
{
	pr_debug("%s\n", __func__);
	/* TODO */
}
static int suspend(struct platform_device *pdev, pm_message_t state)
{
	pr_debug("%s\n", __func__);
	return -1; /* TODO */
}
static int resume(struct platform_device *pdev)
{
	pr_debug("%s\n", __func__);
	return 0; /* TODO */
}

static struct platform_driver driver = {
	.probe = probe,
	.remove = remove,
	.shutdown = shutdown,
	.suspend = suspend,
	.resume = resume,
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
	},
};

int most_video_init_device(struct most_video_device *dev,
			   enum v4l2_buf_type vidq_buf_type,
			   unsigned vidq_io_modes,
			   const struct vb2_ops *vb_ops,
			   const struct video_device *device_template)
{
	struct video_device *vfd;
	struct vb2_queue *q;
	int ret;

	ret = v4l2_device_register(NULL, &dev->v4l2_dev);
	if (ret) {
		pr_debug("v4l2_device_register: %d\n", ret);
		return ret;
	}
	atomic_set(&dev->running, 0);
	spin_lock_init(&dev->slock);
	dev->frame_sequence = 0;
	ret = most_video_setup_ctrls(dev);
	if (ret) {
		pr_debug("most_video_setup_ctrls: %d\n", ret);
		goto unreg_dev;
	}
	/* initialize queue */
	q = &dev->vb_vidq;
	q->type = vidq_buf_type;
	q->io_modes = vidq_io_modes;
	q->timestamp_flags |= V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
	q->drv_priv = dev;
	q->buf_struct_size = sizeof(struct frame);
	q->ops = vb_ops;
	q->mem_ops = &vb2_vmalloc_memops;
	ret = vb2_queue_init(q);
	if (ret) {
		pr_debug("vb2_queue_init: %d\n", ret);
		goto unreg_dev;
	}
	mutex_init(&dev->mutex);
	/* The video buffer and mbo queues */
	INIT_LIST_HEAD(&dev->vidq.todo);
	INIT_LIST_HEAD(&dev->vidq.input);
	dev->vidq.offset = 0;
	vfd = &dev->vdev;
	*vfd = *device_template;
	vfd->v4l2_dev = &dev->v4l2_dev;
	vfd->queue = q;

	/*
	 * Provide a mutex to v4l2 core. It will be used to protect
	 * all fops and v4l2 ioctls.
	 */
	vfd->lock = &dev->mutex;
	video_set_drvdata(vfd, dev);

	return 0;

unreg_dev:
	v4l2_device_unregister(&dev->v4l2_dev);
	return ret;
}

void most_video_destroy_device(struct most_video_device *dev)
{
	video_unregister_device(&dev->vdev);
	v4l2_device_unregister(&dev->v4l2_dev);
	v4l2_ctrl_handler_free(&dev->ctrl_handler);
}

static int isostream_setup(struct mlb150_ext *ext, struct device *mlbdev)
{
	struct isostream_mlb150_ext *isoext = container_of(ext, struct isostream_mlb150_ext, ext);
	struct most_video_device *cap_dev;
	struct most_video_device *out_dev;

	cap_dev = create_capture_device(NULL /* mlbdev? */, 0);

	if (unlikely(IS_ERR(cap_dev)))
		return PTR_ERR(cap_dev);

	cap_dev->mlb_frm_cnt = ext->count;
	cap_dev->mlb_frm_size = ext->size;

	out_dev = create_output_device(NULL, 0);

	if (unlikely(IS_ERR(out_dev))) {
		release_capture_device(cap_dev); /* cleanup */
		return PTR_ERR(out_dev);
	}

	out_dev->mlb_frm_cnt = ext->count;
	out_dev->mlb_frm_size = ext->size;

	cap_dev->ext = ext;
	// cap_dev->vdev.debug = debug; FIXME
	pr_info(DRIVER_NAME ": capture device: %s, MLB device %s, minor %d\n",
		video_device_node_name(&cap_dev->vdev),
		mlbdev ? dev_name(mlbdev) : "(none)", ext->minor);

	out_dev->ext = ext;
	//out_dev->vdev.debug = debug; FIXME
	pr_info(DRIVER_NAME ": output device: %s\n",
		video_device_node_name(&out_dev->vdev));

	isoext->capture = cap_dev;
	isoext->output = out_dev;

	return 0;
}

static void isostream_cleanup(struct mlb150_ext *ext)
{
	struct isostream_mlb150_ext *isoext = container_of(ext, struct isostream_mlb150_ext, ext);

	if (isoext->capture) {
		pr_debug("cleanup capture of %s\n",
			 video_device_node_name(&isoext->capture->vdev));
		cleanup_frameq(isoext->capture);
	}
	if (isoext->output) {
		pr_debug("cleanup output of %s\n",
			 video_device_node_name(&isoext->output->vdev));
		cleanup_frameq(isoext->output);
	}
}

static struct isostream_mlb150_ext isoext[MLB_MAX_ISOC_DEVICES] = {
	[0 ... MLB_MAX_ISOC_DEVICES - 1] = {
		.ext = {
			.minor = -1,
			.ctype = MLB150_CTYPE_ISOC,
			.setup = isostream_setup,
			.rx    = isostream_rx_isr,
			.tx    = isostream_tx_isr,
			.cleanup = isostream_cleanup,
		}
	}
};

#ifdef MODULE
#define IF_MODULE(a, b) \
	(a)
#else
#define IF_MODULE(a, b) \
	(b)
#endif

static int __init most_video_init(void)
{
	uint i, maxdev = min(vid_count, mlb150_ext_get_isoc_channel_count());
	int ret;

	ret = platform_driver_register(&driver);
	if (ret < 0) {
		pr_err(DRIVER_NAME ": driver registration error %d\n", ret);
		return ret;
	}
	pr_info(DRIVER_NAME " version %s %s, allocating %u devices\n",
		IF_MODULE(THIS_MODULE->version, MOST_VIDEO_VERSION),
		IF_MODULE(THIS_MODULE->srcversion, ""),
		maxdev);
	for (i = 0; i < maxdev; ++i) {
		isoext[i].ext.minor = i;
		ret = mlb150_ext_register(&isoext[i].ext);
		if (ret < 0) {
			pr_err(DRIVER_NAME": mlb150 registration failed: %d\n",
			       ret);
			goto err_reg;
		}
	}
	return ret;
err_reg:
	while (i--)
		mlb150_ext_unregister(&isoext[i].ext);

	platform_driver_unregister(&driver);
	return ret;
}

static void __exit most_video_exit(void)
{
	uint i;

	for (i = ARRAY_SIZE(isoext); i--; )
		if (isoext[i].ext.minor != -1) {
			mlb150_ext_unregister(&isoext[i].ext);
			if (isoext[i].capture) {
				pr_info("removing capture %s\n",
					video_device_node_name(&isoext[i].capture->vdev));
				release_capture_device(isoext[i].capture);
			}
			if (isoext[i].output) {
				pr_info("removing output %s\n",
					video_device_node_name(&isoext[i].output->vdev));
				release_output_device(isoext[i].output);
			}
		}
	platform_driver_unregister(&driver);
}

module_init(most_video_init);
module_exit(most_video_exit);

