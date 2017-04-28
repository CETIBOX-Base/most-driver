#ifndef _MLB150_EXT_H_
#define _MLB150_EXT_H_

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

#endif /* _MLB150_EXT_H_ */

