#ifndef _MLB150_EXT_H_
#define _MLB150_EXT_H_

#include <linux/list.h>

#define MLB_MAX_SYNC_DEVICES	7
#define MLB_MAX_ISOC_DEVICES	4

#define MLB_FIRST_CHANNEL	(1)
#define MLB_LAST_CHANNEL	(63)

#define FCNT_VALUE 5

/* return the buffer depth for the given bytes-per-frame */
#define SYNC_BUFFER_DEP(bpf) (4 * (1 << FCNT_VALUE) * (bpf))

#define SYNC_MIN_FRAME_SIZE (2) /* mono, 16bit sample */
#define SYNC_DMA_MIN_SIZE       SYNC_BUFFER_DEP(SYNC_MIN_FRAME_SIZE) /* mono, 16bit sample */
#define SYNC_DMA_MAX_SIZE       (0x1fff + 1) /* system memory buffer size in ADT */

u32 syncsound_get_num_devices(void);
unsigned int mlb150_ext_get_isoc_channel_count(void);

enum {
	ISOC_FRMSIZ_188,
	ISOC_FRMSIZ_192,
	ISOC_FRMSIZ_196,
	ISOC_FRMSIZ_206,
};

#define CH_ISOC_BLK_NUM_MIN     (3)
#define CH_ISOC_BLK_NUM_DEFAULT	(8)
#define CH_ISOC_BLK_SIZE_MIN	(188)
#define CH_ISOC_BLK_SIZE_MAX	(206)
#define CH_ISOC_BLK_SIZE_DEFAULT CH_ISOC_BLK_SIZE_MIN

enum mlb150_channel_type {
	MLB150_CTYPE_CTRL,
	MLB150_CTYPE_ASYNC,
	MLB150_CTYPE_ISOC,
	MLB150_CTYPE_SYNC,
};

enum channelmode {
	MLB_RDONLY,
	MLB_WRONLY,
	MLB_RDWR,
	MLB_CHANNEL_UNDEFINED = -1
};

struct aim_channel;
struct mbo;

struct mlb150_ext {
	struct list_head head;
	enum mlb150_channel_type ctype;
	int minor;
	unsigned int size, count;
	int (*setup)(struct mlb150_ext *, struct device *);
	void (*rx)(struct mlb150_ext *, struct mbo *);
	void (*tx)(struct mlb150_ext *);
	void (*cleanup)(struct mlb150_ext *);
	struct aim_channel *aim;
};

int mlb150_ext_get_tx_mbo(struct mlb150_ext *, struct mbo **);
int mlb150_ext_submit_mbo(struct mlb150_ext *, struct mbo *);
int mlb150_ext_register(struct mlb150_ext *);
void mlb150_ext_unregister(struct mlb150_ext *);
int mlb150_lock_channel(struct mlb150_ext *, bool lock);

#endif /* _MLB150_EXT_H_ */

