/*
 * medusa.h - Medusa API for testing and tracing modules
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

#ifndef MEDUSA_H
#define	MEDUSA_H


#include <mostcore.h>

/*
 * Enables Medusa DMA interrupts if defined as 1 or
 * enables hrtimer if defined as 0
 */
#define ENABLE_MEDUSA_DMA_INTERRUPTS 0

/*
 * Static Configuration Values
 */
#define NUM_DMA_CHANNELS 32

/*
 * Magic key used to assure compatibility of the medusa driver
 * with the medusa testing driver.
 */
enum { DBG_MAGIC_KEY = 0x2A3E0F9C };

/*
 * Data structure per Medusa DMA Channel
 * */
struct medusa_dma_channel {

	/* channel state (enum channel_state) */
	int state;

	/* channel index */
	int idx;

	/* direction */
	bool is_tx;

	/* function returning message length */
	u32(*get_message_length)(const u8 *data, u32 buffer_length);

	/* start of the descriptor ring in the system memory
	 * (bus address) */
	dma_addr_t desc_start_paddr;

	/* indicator for long tail addresses (more than 32 bit) */
	int long_addresses;

	/* start of the descriptor ring in the system memory
	 * (virtual address) */
	u8 *desc_start_vaddr;

	/* size of the descriptor memory in bytes, the size contains buffer
	 * and jump descriptor */
	size_t desc_mem_size;

	/* indexes to walk through the descriptors like fifo */
	volatile unsigned int in;
	volatile unsigned int out;

	/* interrupt type, see INTR_SEL of SGDMA Buffer Descriptor */
	u32 intr_sel;

	/* mbos */
	struct list_head mbo_list;
	spinlock_t list_lock;

	/* used to wait until tail address becomes reliable */
	struct descriptor_timeout {
		/* timer for the tail address */
		struct hrtimer timer;
		/* tail address */
		dma_addr_t tail_address;
	} dt;

	/* tasklet to reduce race conditions around service_dma_channel() */
	struct tasklet_struct service_tasklet;
};

#define MEDUSA_ATTR(_name, _mode, _show, _store) { \
	.attr = {.name = __stringify(_name), .mode = _mode }, \
	.show = _show, \
	.store = _store, \
}

#define MEDUSA_ATTR_RO(_name) \
	MEDUSA_ATTR(_name, S_IRUGO, _name##_show, NULL)

#define MEDUSA_ATTR_WO(_name) \
	MEDUSA_ATTR(_name, S_IWUSR, NULL, _name##_store)

#define MEDUSA_ATTR_RW(_name) \
	MEDUSA_ATTR(_name, S_IRUGO | S_IWUSR, _name##_show, _name##_store)


struct dci_mac_value {
	bool flush_pending;
	u8 arr8[6];
};

struct dci_mep_ht_value {
	bool flush_pending;
	u16 arr16[4];
};

struct dci_mep_fm_value {
	bool flush_pending;
	u16 val;
};

struct medusa;

struct medusa_dci {
	atomic_t service_notification;
	atomic_t service_cmd_complete;
	bool valid;
	void (*read)(struct medusa *mdev);
	void (*write)(struct medusa *mdev);
	struct kobject kobj_group;
	struct tasklet_struct tl;
	u16 event_flags;
	u16 dma_flags_lo;
	u16 dma_flags_hi;
	u16 dma_sync_ch_lo;
	u16 dma_sync_ch_hi;
	u32 dma_sync_ch;
	u16 availability; /* 0x100 [0..1] */
	u16 packet_bw; /* 0x101 [0..372, 0xFFFF] */
	u16 node_addr; /* 0x102 [0..0xFFFF]*/
	u16 node_pos; /* 0x103 [0..63, 0xFF]*/
	struct dci_mep_fm_value mep_filter_mode; /* 0x140 [0..63] */
	struct dci_mep_ht_value mep_hash_table; /* 0x141 - 0x144 */
	struct dci_mac_value mac; /* 0x147 - 0x145 */
};

struct medusa_debug {
	struct kobject kobj_group;
	u8 cur_channel_idx;
	size_t rolling_offset;
};

/*
 *  Medusa Device Structure
 *
 *  Medusa PCIe Device Instance specific data
 *  structure
 */
struct medusa {
	u32 dbg_magic_key;
	int dbg_disable_pcie_poll;
	struct kobject *parent_kobj;
	struct medusa_dci dci;
	struct medusa_debug dbg;

	char name[100];

	void __iomem *hw_addr_bar1;
	void __iomem *hw_addr_bar2;

	struct medusa_dma_channel dma_channels[NUM_DMA_CHANNELS];

#if !ENABLE_MEDUSA_DMA_INTERRUPTS
	struct hrtimer int_simu_timer;
#endif
	struct hrtimer rsm_timer;

	struct most_interface most_intf;
	struct most_channel_capability channel_vector[NUM_DMA_CHANNELS];
};

/* Medusa API */
u32 medusa_read_b1(struct medusa *mdev, size_t offset);
void medusa_write_b1(struct medusa *mdev, size_t offset, u32 value);

u32 medusa_read_b2(struct medusa *mdev, size_t offset);
void medusa_write_b2(struct medusa *mdev, size_t offset, u32 value);

int medusa_get_descriptors_mem(struct medusa *mdev, int chidx,
			       u8 **addr_ptr, size_t *size_ptr);


#endif	/* MEDUSA_H */

