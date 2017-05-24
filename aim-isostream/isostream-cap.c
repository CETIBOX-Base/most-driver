/*
 * A driver for MOST video sending and receiving devices
 * The V4L2 capture interface implementation.
 */
#include <linux/errno.h>
#include <linux/mutex.h>
#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf2-v4l2.h>
#include "mostcore.h"
#include "isostream.h"

/* Copy frames from the input dmabuf queue to the video buffers in vidq.todo */
static void copy_frames(struct most_video_device *dev, struct list_head *free)
	__must_hold(&dev->slock)
{
	const uint frmcount = dev->mlb_frm_cnt,
	      frmsize = dev->mlb_frm_size;
	struct mbo *mbo, *next;
	struct frame_queue *vidq = &dev->vidq;

	list_for_each_entry_safe(mbo, next, &vidq->input, list) {
		const void *datap = mbo->virt_address + vidq->offset,
		      *data_end = mbo->virt_address + frmcount * frmsize;

		while (!list_empty(&vidq->todo)) {
			struct frame *buf = list_entry(vidq->todo.next,
						       struct frame, list);
			ulong size = min_t(ulong, vb2_plane_size(&buf->vb4.vb2_buf, 0),
					   frmsize);

			__list_del_entry(&buf->list);
			buf->vb4.sequence = dev->frame_sequence++;
			memcpy(buf->plane0, datap, size);
			datap += size;
			vb2_set_plane_payload(&buf->vb4.vb2_buf, 0, size);
			v4l2_get_timestamp(&buf->vb4.timestamp);
			vb2_buffer_done(&buf->vb4.vb2_buf, VB2_BUF_STATE_DONE);
			if (datap == data_end)
				goto next_dmab;
		}
		if (datap < data_end) {
			vidq->offset = datap - mbo->virt_address;
			break;
		}
	next_dmab:
		vidq->offset = 0;
		list_move(&mbo->list, free);
	}
}

static void mlb_recv_data(struct most_video_device *dev, struct mbo *mbo)
{
	struct mbo *next;
	LIST_HEAD(free);
	unsigned long flags;

	spin_lock_irqsave(&dev->slock, flags);
	list_add_tail(&mbo->list, &dev->vidq.input);
	if (!list_empty(&dev->vidq.todo))
		copy_frames(dev, &free);
	spin_unlock_irqrestore(&dev->slock, flags);
	list_for_each_entry_safe(mbo, next, &free, list)
		most_put_mbo(mbo);
}

/* ------------------------------------------------------------------
	Interrupt handler
   ------------------------------------------------------------------*/

void isostream_rx_isr(struct mlb150_ext *ext, struct mbo *mbo)
{
	struct most_video_device *dev =
		container_of(ext, struct isostream_mlb150_ext, ext)->capture;
	int running = atomic_read(&dev->running);

	pr_debug("RX on %s%s\n", video_device_node_name(&dev->vdev),
		 running ? " running" : "");
	if (running)
		mlb_recv_data(dev, mbo);
	else
		most_put_mbo(mbo);
}

static void buf_queue(struct vb2_buffer *vb)
{
	struct most_video_device *dev = vb2_get_drv_priv(vb->vb2_queue);
	struct vb2_v4l2_buffer *vb4 = to_vb2_v4l2_buffer(vb);
	struct frame *buf = container_of(vb4, struct frame, vb4);
	struct frame_queue *vidq = &dev->vidq;
	struct mbo *mbo, *next;
	LIST_HEAD(free);
	unsigned long flags;

	pr_debug("[%p/%d] todo\n", buf, buf->vb4.vb2_buf.index);
	spin_lock_irqsave(&dev->slock, flags);
	list_add_tail(&buf->list, &vidq->todo);
	if (!list_empty(&vidq->input))
		copy_frames(dev, &free);
	spin_unlock_irqrestore(&dev->slock, flags);
	list_for_each_entry_safe(mbo, next, &free, list)
		most_put_mbo(mbo);
}

static int start_streaming(struct vb2_queue *vq, unsigned int count)
{
	struct most_video_device *dev = vb2_get_drv_priv(vq);

	atomic_set(&dev->running, true);

	return 0;
}

static struct vb2_ops vb_ops = {
	.queue_setup		= most_video_queue_setup,
	.buf_prepare		= most_video_buf_prepare,
	.buf_queue		= buf_queue,
	.start_streaming	= start_streaming,
	.stop_streaming		= most_video_stop_streaming,
	.wait_prepare		= most_video_wait_prepare,
	.wait_finish		= most_video_wait_finish,
};

/* ------------------------------------------------------------------
	V4L2 ioctls
   ------------------------------------------------------------------*/

static const struct video_device device_template;

static int vidioc_querycap(struct file *file, void  *priv, struct v4l2_capability *cap)
{
	struct most_video_device *dev = video_drvdata(file);

	strcpy(cap->driver, DRIVER_NAME);
	strcpy(cap->card, device_template.name);
	snprintf(cap->bus_info, sizeof(cap->bus_info), "platform:%s", dev->v4l2_dev.name);
	cap->version = MOST_VIDEO_KVERSION;
	cap->device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING | V4L2_CAP_READWRITE;
	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;
	return 0;
}

static int vidioc_enum_input(struct file *file, void *priv, struct v4l2_input *inp)
{
	if (inp->index != 0)
		return -EINVAL;
	inp->type = V4L2_INPUT_TYPE_CAMERA;
	snprintf(inp->name, sizeof(inp->name), "Video In %u", inp->index);
	return 0;
}

static int vidioc_g_parm(struct file *file, void *fh, struct v4l2_streamparm *a)
{
	if (a->type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
		return -EINVAL;
	return 0;
}

static int vidioc_s_parm(struct file *file, void *fh, struct v4l2_streamparm *a)
{
	if (a->type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
		return -EINVAL;

	return 0;
}

static const struct v4l2_file_operations file_ops = {
	.owner		= THIS_MODULE,
	.open           = most_video_fh_open,
	.release        = most_video_fh_release,
	.read           = vb2_fop_read,
	.poll		= vb2_fop_poll,
	.unlocked_ioctl = video_ioctl2,
	.mmap           = vb2_fop_mmap,
};

static const struct v4l2_ioctl_ops ioctl_ops = {
	.vidioc_querycap      = vidioc_querycap,
	.vidioc_enum_fmt_vid_cap  = vidioc_enum_fmt,
	.vidioc_g_fmt_vid_cap     = most_video_g_fmt,
	.vidioc_try_fmt_vid_cap   = most_video_try_fmt,
	.vidioc_s_fmt_vid_cap     = most_video_s_fmt,
	.vidioc_enum_framesizes   = vidioc_enum_framesizes,
	.vidioc_reqbufs       = vb2_ioctl_reqbufs,
	.vidioc_create_bufs   = vb2_ioctl_create_bufs,
	.vidioc_prepare_buf   = vb2_ioctl_prepare_buf,
	.vidioc_querybuf      = vb2_ioctl_querybuf,
	.vidioc_qbuf          = vb2_ioctl_qbuf,
	.vidioc_dqbuf         = vb2_ioctl_dqbuf,
	.vidioc_enum_input    = vidioc_enum_input,
	.vidioc_g_input       = most_video_g_inout,
	.vidioc_s_input       = most_video_s_inout,
	.vidioc_streamon      = vb2_ioctl_streamon,
	.vidioc_streamoff     = vb2_ioctl_streamoff,
	.vidioc_log_status    = v4l2_ctrl_log_status,
	.vidioc_subscribe_event = v4l2_ctrl_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
	.vidioc_g_parm = vidioc_g_parm,
	.vidioc_s_parm = vidioc_s_parm,
};

static const struct video_device device_template = {
	.name      = "most-video-in",
	.fops      = &file_ops,
	.ioctl_ops = &ioctl_ops,
	.release   = video_device_release_empty,
};

/* ------------------------------------------------------------------
	Device (de-)initialization
   ------------------------------------------------------------------*/

void release_capture_device(struct most_video_device *dev)
{
	most_video_destroy_device(dev);
	kfree(dev);
}

struct most_video_device *create_capture_device(struct device *dmadev, int inst)
{
	struct most_video_device *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);
	snprintf(dev->v4l2_dev.name, sizeof(dev->v4l2_dev.name), "%s-%d",
		 device_template.name, inst);
	ret = most_video_init_device(dev, V4L2_BUF_TYPE_VIDEO_CAPTURE,
				     VB2_MMAP | VB2_READ, &vb_ops,
				     &device_template);
	if (ret)
		goto free_dev;
	ret = video_register_device(&dev->vdev, VFL_TYPE_GRABBER, -1);
	if (ret < 0)
		goto destroy_dev;
	return dev;
destroy_dev:
	most_video_destroy_device(dev);
free_dev:
	kfree(dev);
	return ERR_PTR(ret);
}

