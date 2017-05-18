/*
 * A driver for MOST video sending and receiving devices
 */
#ifndef _ISOSTREAM_H_
#define _ISOSTREAM_H_

#include <linux/list.h>
#include <linux/videodev2.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-common.h>
#include <media/videobuf2-core.h>

#include "mlb150_ext.h"

/* Ultra HD, just for sanity checking */
#define MAX_WIDTH 7680
#define MAX_HEIGHT 4320

#define DRIVER_NAME "most-video"
#define MOST_VIDEO_VERSION "1.0.0"
#define MOST_VIDEO_KVERSION KERNEL_VERSION(1, 0, 0)

struct video_fmt_info {
	u32   fourcc;          /* v4l2 format id */
	u16   sizeimage;
	u8    depth;
	u8    is_yuv:1;
	u8    compressed:1;
};

extern unsigned int memlimit;

struct most_video_device *create_capture_device(struct device *dmadev, int inst);
struct most_video_device *create_output_device(struct device *dmadev, int inst);
void release_capture_device(struct most_video_device *dev);
void release_output_device(struct most_video_device *dev);

int vidioc_enum_fmt(struct file *, void  *, struct v4l2_fmtdesc *);
int vidioc_enum_framesizes(struct file *, void *, struct v4l2_frmsizeenum *);

/* buffer for one video frame */
struct frame {
	/* common v4l buffer stuff -- must be first */
	struct vb2_buffer	     vb;
	struct list_head	     list; /* used to queue the frames */
	void *plane0;
};

struct frame_queue {
	/* todo is protected by slock in the container */
	struct list_head           todo;
	struct list_head           input; /* dmabufs retrieved from mlb150 */
	unsigned int               offset; /* how much of the first dmabuf has been used */
};

struct most_video_device {
	struct v4l2_device         v4l2_dev;
	struct video_device        vdev;
	struct v4l2_ctrl_handler   ctrl_handler;
	void                       *allocator_ctx;
	struct mlb150_ext          *ext;
	unsigned int               vbsize; /* size of the video buffer if not 0 */
	unsigned int               mlb_frm_cnt;  /* protected by slock */
	unsigned int               mlb_frm_size; /* protected by slock */

	u32                        frame_sequence;

	spinlock_t                 slock;
	struct mutex               mutex;

	atomic_t                   running;
	struct frame_queue         vidq;
	struct vb2_queue	   vb_vidq;

	/* controls */
	struct v4l2_ctrl	   *mpeg_stream_type;
	struct v4l2_ctrl	   *mpeg_audio_mute;
	struct v4l2_ctrl	   *mpeg_audio_encoding;
	struct v4l2_ctrl	   *mpeg_video_encoding;
	struct v4l2_ctrl	   *dtcp_mode;
};

int most_video_init_device(struct most_video_device *,
			   enum v4l2_buf_type vidq_buf_type,
			   unsigned vidq_io_modes,
			   const struct vb2_ops *,
			   const struct video_device *device_template);
void most_video_destroy_device(struct most_video_device *);
int most_video_setup_ctrls(struct most_video_device *);
int most_video_queue_setup(struct vb2_queue *, const struct v4l2_format *,
			   unsigned int *nbuffers, unsigned int *nplanes,
			   unsigned int sizes[], void *alloc_ctxs[]);
int most_video_g_fmt(struct file *, void *priv, struct v4l2_format *);
int most_video_try_fmt(struct file *, void *priv, struct v4l2_format *);
int most_video_s_fmt(struct file *, void *priv, struct v4l2_format *);
int most_video_g_inout(struct file *, void *priv, unsigned int *i);
int most_video_s_inout(struct file *, void *priv, unsigned int i);
int most_video_buf_prepare(struct vb2_buffer *);
void most_video_wait_prepare(struct vb2_queue *);
void most_video_wait_finish(struct vb2_queue *);
int most_video_stop_streaming(struct vb2_queue *);

struct isostream_mlb150_ext {
	struct most_video_device *capture;
	struct most_video_device *output;
	struct mlb150_ext ext;
};

struct mlb150_io_buffers;
void isostream_rx_isr(struct mlb150_ext *, struct mlb150_io_buffers *);
void isostream_tx_isr(struct mlb150_ext *);

/* v4l2_get_timestamp was officially introduced in 3.9 */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
#include <linux/ktime.h>
static inline void v4l2_get_timestamp(struct timeval *tv)
{
	struct timespec ts;

	ktime_get_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / NSEC_PER_USEC;
}
#endif

#endif /* _ISOSTREAM_H_ */

