/*
 * A driver for MOST video sending and receiving devices
 * The V4L2 video output interface implementation.
 */
#include <linux/errno.h>
#include <linux/mutex.h>
#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf2-v4l2.h>
#include "mostcore.h"
#include "isostream.h"

/* Copy frames from the list of video buffers (vidq.todo) to the mbos */
static void copy_frames(struct most_video_device *dev, struct list_head *submit)
	__must_hold(&dev->slock)
{
	const uint frmcount = dev->mlb_frm_cnt,
	      frmsize = dev->mlb_frm_size;
	struct mbo *mbo, *next;
	struct frame_queue *vidq = &dev->vidq;
	int ret = mlb150_ext_get_tx_mbo(dev->ext, &mbo);

	if (!(ret == 0 || ret == -EAGAIN))
		return;
	if (ret != -EAGAIN)
		list_add(&mbo->list, &vidq->input);
	list_for_each_entry_safe(mbo, next, &vidq->input, list) {
		void *datap = mbo->virt_address + vidq->offset,
		      *data_end = mbo->virt_address + frmcount * frmsize;

		while (!list_empty(&vidq->todo)) {
			struct frame *buf = list_entry(vidq->todo.next,
						       struct frame, list);
			ulong size = min_t(ulong,
				vb2_plane_size(&buf->vb4.vb2_buf, 0),
				frmsize);

			__list_del_entry(&buf->list);
			buf->vb4.sequence = dev->frame_sequence++;
			memcpy(datap, buf->plane0, size);
			datap += size;
			vb2_set_plane_payload(&buf->vb4.vb2_buf, 0, size);
			v4l2_get_timestamp(&buf->vb4.timestamp);
			vb2_buffer_done(&buf->vb4.vb2_buf, VB2_BUF_STATE_DONE);
			if (datap == data_end)
				goto next_mbo;
		}
		if (datap < data_end) {
			vidq->offset = datap - mbo->virt_address;
			break;
		}
	next_mbo:
		vidq->offset = 0;
		list_del(&mbo->list);
		list_add_tail(&mbo->list, &submit);
	}
}

void isostream_tx_isr(struct mlb150_ext *ext)
{
	struct most_video_device *dev =
		container_of(ext, struct isostream_mlb150_ext, ext)->output;

	pr_debug("TX on %s\n", video_device_node_name(&dev->vdev));
	if (atomic_read(&dev->running)) {
		LIST_HEAD(submit);
		struct mbo *mbo, *next;
		ulong flags;

		spin_lock_irqsave(&dev->slock, flags);
		copy_frames(dev, &submit);
		spin_unlock_irqrestore(&dev->slock, flags);
		list_for_each_entry_safe(mbo, next, &submit, list)
			most_submit_mbo(mbo);
	}
}

static void buf_queue(struct vb2_buffer *vb)
{
	struct most_video_device *dev = vb2_get_drv_priv(vb->vb2_queue);
	struct vb2_v4l2_buffer *vb4 = to_vb2_v4l2_buffer(vb);
	struct frame *buf = container_of(vb4, struct frame, vb4);
	struct frame_queue *vidq = &dev->vidq;
	LIST_HEAD(submit);
	struct mbo *mbo, *next;
	unsigned long flags;

	pr_debug("[%p/%d] todo\n", buf, buf->vb4.vb2_buf.index);
	spin_lock_irqsave(&dev->slock, flags);
	list_add_tail(&buf->list, &vidq->todo);
	copy_frames(dev, &submit);
	spin_unlock_irqrestore(&dev->slock, flags);
	list_for_each_entry_safe(mbo, next, &submit, list)
		most_submit_mbo(mbo);
}

static int start_streaming(struct vb2_queue *vq, unsigned int count)
{
	struct most_video_device *dev = vb2_get_drv_priv(vq);
	LIST_HEAD(submit);
	struct mbo *mbo, *next;

	pr_debug("Start streaming with count=%u\n", count);
	atomic_set(&dev->running, 1);
	copy_frames(dev, &submit);
	list_for_each_entry_safe(mbo, next, &submit, list)
		most_submit_mbo(mbo);
	return 0;
}

static const struct vb2_ops vb_ops = {
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
	cap->device_caps = V4L2_CAP_VIDEO_OUTPUT | V4L2_CAP_STREAMING | V4L2_CAP_READWRITE;
	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;
	return 0;
}

static int vidioc_enum_output(struct file *file, void *priv, struct v4l2_output *outp)
{
	if (outp->index > 0)
		return -EINVAL;
	outp->capabilities = 0;
	outp->type = V4L2_OUTPUT_TYPE_ANALOG;
	snprintf(outp->name, sizeof(outp->name), "Video Out %u", outp->index);
	return 0;
}

static int vidioc_g_parm(struct file *file, void *fh, struct v4l2_streamparm *a)
{
	if (a->type != V4L2_BUF_TYPE_VIDEO_OUTPUT)
		return -EINVAL;
	return 0;
}

static int vidioc_s_parm(struct file *file, void *fh, struct v4l2_streamparm *a)
{
	if (a->type != V4L2_BUF_TYPE_VIDEO_OUTPUT)
		return -EINVAL;
	return 0;
}

static ssize_t wrap_vb2_fop_write(struct file *file, const char __user *buf,
			size_t count, loff_t *ppos)
{
	return vb2_fop_write(file, (char __user *)buf, count, ppos);
}

static const struct v4l2_file_operations file_ops = {
	.owner		= THIS_MODULE,
	.open           = most_video_fh_open,
	.release        = most_video_fh_release,
	.write          = wrap_vb2_fop_write,
	.poll		= vb2_fop_poll,
	.unlocked_ioctl = video_ioctl2,
	.mmap           = vb2_fop_mmap,
};

static const struct v4l2_ioctl_ops ioctl_ops = {
	.vidioc_querycap          = vidioc_querycap,
	.vidioc_enum_fmt_vid_out  = vidioc_enum_fmt,
	.vidioc_g_fmt_vid_out     = most_video_g_fmt,
	.vidioc_try_fmt_vid_out   = most_video_try_fmt,
	.vidioc_s_fmt_vid_out     = most_video_s_fmt,
	.vidioc_enum_framesizes   = vidioc_enum_framesizes,
	.vidioc_reqbufs       = vb2_ioctl_reqbufs,
	.vidioc_create_bufs   = vb2_ioctl_create_bufs,
	.vidioc_prepare_buf   = vb2_ioctl_prepare_buf,
	.vidioc_querybuf      = vb2_ioctl_querybuf,
	.vidioc_qbuf          = vb2_ioctl_qbuf,
	.vidioc_dqbuf         = vb2_ioctl_dqbuf,
	.vidioc_enum_output   = vidioc_enum_output,
	.vidioc_g_output      = most_video_g_inout,
	.vidioc_s_output      = most_video_s_inout,
	.vidioc_streamon      = vb2_ioctl_streamon,
	.vidioc_streamoff     = vb2_ioctl_streamoff,
	.vidioc_g_parm        = vidioc_g_parm,
	.vidioc_s_parm        = vidioc_s_parm,
	.vidioc_log_status    = v4l2_ctrl_log_status,
	.vidioc_subscribe_event = v4l2_ctrl_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
};

static const struct video_device device_template = {
	.name      = "most-video-out",
	.fops      = &file_ops,
	.ioctl_ops = &ioctl_ops,
	.release   = video_device_release_empty,
};

void release_output_device(struct most_video_device *dev)
{
	most_video_destroy_device(dev);
	kfree(dev);
}

struct most_video_device *create_output_device(struct device *dmadev, int inst)
{
	struct most_video_device *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);
	snprintf(dev->v4l2_dev.name, sizeof(dev->v4l2_dev.name), "%s-%d",
		 device_template.name, inst);
	ret = most_video_init_device(dev, V4L2_BUF_TYPE_VIDEO_OUTPUT,
				     VB2_MMAP | VB2_WRITE, &vb_ops,
				     &device_template);
	if (ret)
		goto free_dev;
	/*
	 * vfl_dir is set to get the default set of ioctls set for an output
	 * video device. Otherwise the format enumeration ioctls are not set.
	 */
	dev->vdev.vfl_dir = VFL_DIR_TX;
	ret = video_register_device(&dev->vdev, VFL_TYPE_GRABBER, -1);
	if (ret < 0)
		goto destroy_dev;
	return dev;
destroy_dev:
	v4l2_device_unregister(&dev->v4l2_dev);
free_dev:
	kfree(dev);
	return ERR_PTR(ret);
}

