/*
 * medusa.c - Medusa PCIe Verification Driver
 *
 * Copyright (C) 2013-2015, Microchip Technology Germany II GmbH & Co. KG
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
#include <linux/types.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/hrtimer.h>
#include <linux/bug.h>
#include <linux/list.h>
#include <linux/io.h>
#include <mostcore.h>
#include "medusa.h"
#include "registers.h"

static const char driver_name[] = "medusa driver";

#define DCI_CH 15

/*
 * Useful macros to trace diverse things in case of problems.
 * Enables additional traces if defined as 1.
 * Has no effect if defined as 0.
 */
#define T_ENQUEUE_COMPLETE_POISON 0
#define T_LIST_ADD_REMOVE 0

/*
 * Minimal number of buffers per DMA Channel.
 * Real number of buffers may be more through the stuffing.
 */
#define MIN_CHANNEL_BUFFERS 31

/*
 * As workaround for a bug in the first Medusa release we use a block based
 * descriptor layout. Each block of size "DESCR_BLOCK_SIZE" contains
 * "DESCR_BLOCK_BUFFERS_NUM" descriptors used for buffers and one jump
 * descriptor pointing to the first buffer descriptor of the next block.
 * The rest of descriptors in the block, if any, is not used.
 *
 * The define DESCR_BLOCK_SIZE shall be a power of 2 because of
 * index calculation.
 *
 * CONFIGURATION EXAMPLES
 *
 * Error permissive configuration:
 *   #define DESCR_BLOCK_SIZE 8
 *   #define DESCR_BLOCK_BUFFERS_NUM 1
 *
 * Space effective configuration:
 *   #define DESCR_BLOCK_SIZE 32
 *   #define DESCR_BLOCK_BUFFERS_NUM 31
 */
#define DESCR_BLOCK_SIZE 8
#define DESCR_BLOCK_BUFFERS_NUM 1

/*
 * ! Below is not user configurable area.
 */

#if (DESCR_BLOCK_SIZE & (DESCR_BLOCK_SIZE - 1)) != 0
#error DESCR_BLOCK_SIZE shall be power of 2
#endif

#if DESCR_BLOCK_BUFFERS_NUM >= DESCR_BLOCK_SIZE
#error DESCR_BLOCK_BUFFERS_NUM shall be less than DESCR_BLOCK_SIZE
#endif

#define BLOCKS_NUM(x, s)  (((x)+(s)-1)/(s))
#define DESCR_BLOCKS_NUMBER  BLOCKS_NUM(MIN_CHANNEL_BUFFERS, DESCR_BLOCK_BUFFERS_NUM)
#define MIN_CHANNEL_DESCRIPTORS  (DESCR_BLOCKS_NUMBER * DESCR_BLOCK_SIZE)

#if MIN_CHANNEL_DESCRIPTORS <= 8
#define CHANNEL_DESCRIPTORS_NUM 8u
#elif MIN_CHANNEL_DESCRIPTORS <= 16
#define CHANNEL_DESCRIPTORS_NUM 16u
#elif MIN_CHANNEL_DESCRIPTORS <= 32
#define CHANNEL_DESCRIPTORS_NUM 32u
#elif MIN_CHANNEL_DESCRIPTORS <= 64
#define CHANNEL_DESCRIPTORS_NUM 64u
#elif MIN_CHANNEL_DESCRIPTORS <= 128
#define CHANNEL_DESCRIPTORS_NUM 128u
#elif MIN_CHANNEL_DESCRIPTORS <= 256
#define CHANNEL_DESCRIPTORS_NUM 256u
#elif MIN_CHANNEL_DESCRIPTORS <= 512
#define CHANNEL_DESCRIPTORS_NUM 512u
#elif MIN_CHANNEL_DESCRIPTORS <= 1024
#define CHANNEL_DESCRIPTORS_NUM 1024u
#elif MIN_CHANNEL_DESCRIPTORS <= 2048
#define CHANNEL_DESCRIPTORS_NUM 2048u
#elif MIN_CHANNEL_DESCRIPTORS <= 4096
#define CHANNEL_DESCRIPTORS_NUM 4096u
#else
#error too many channel buffers or too discharged block configuration
#endif


#define DESCRIPTOR_SIZE 16u	/* Size in Bytes */

/* Maximal accepted buffer size. */
#define MAX_MEDUSA_BUFFER_SIZE (DESC_CTRL_BUFDEPTH_MASK + 1)


/* Bit to mask macro. */
#define B2MASK(bit) ((u32)1u << (bit))

enum channel_state {
	/*
	 * Channel is closed, default state.
	 * The configure() callback is accepted only in this state.
	 */
	ST_CLOSED,

	/*
	 * Channel is configured and running in an ordinary way.
	 * Set by the configure() callback.
	 * The enqueue() callback is accepted only in this state.
	 * The poison_channel() callback is accepted only in this state.
	 */
	ST_OPEN,

	/*
	 * Channel is configured, but running only to send
	 * all Tx MBOs enqueued before the poison_channel() call.
	 * The channel will be closed after all MBOs are sent or
	 * the PCI device callback remove() is called.
	 * Set by the poison_channel() callback.
	 * The new enqueue() callbacks are rejected in this state.
	 */
	ST_FLUSH,

	/*
	 * Used to close the channel in case of errors.
	 * Prevents multiple error output for the same channel.
	 */
	ST_ERROR,

	/*
	 * Used short before closing the channel
	 * to reject the new enqueue() callbacks, may happen when the HDM
	 * calls completion routines.
	 */
	ST_CLOSING,
};

/* Helping macro. */
#define IS_RUNNING(state) ((state) != ST_CLOSED && (state) != ST_CLOSING)

/*
 * Time [ns] used for waiting before accept Tx tail descriptor as reliable.
 * Used to work around the feature of the Medusa where the Tx buffer may be
 * marked as done before it is released.
 */
static ulong tail_descriptor_delay_ns = 1 * NSEC_PER_MSEC;
module_param(tail_descriptor_delay_ns, ulong, 0);
MODULE_PARM_DESC(tail_descriptor_delay_ns,
		 "Time [ns] used for waiting before accept Tx tail descriptor as reliable");

#if !ENABLE_MEDUSA_DMA_INTERRUPTS
static ulong polling_interval_ns = 100 * NSEC_PER_USEC;
module_param(polling_interval_ns, ulong, 0);
MODULE_PARM_DESC(polling_interval_ns,
		 "Polling interval [ns] used for simulation of channel interrupts");
#endif
static ulong rsm_interval_us = 20;
module_param(rsm_interval_us, ulong, 0400);
MODULE_PARM_DESC(rsm_interval_us,
		 "Interval [us] used for cyclic DMA channel resume");


int dci_probe(struct medusa *mdev);
void dci_run(struct medusa *mdev);
void dci_stop(struct medusa *mdev);
void dci_destroy(struct medusa *mdev);
void dci_service_int(struct medusa *mdev);

int medusa_debug_probe(struct medusa *mdev);


/**
 * Write 32Bit value to Medusa MMIO Register Space (BAR1)
 *
 * @offset: offset in bytes, from begin of BAR1
 * @value:  32Bit value to write
 */
void medusa_write_b1(struct medusa *mdev, size_t offset, u32 value)
{
	iowrite32(value, mdev->hw_addr_bar1 + offset);
}
EXPORT_SYMBOL(medusa_write_b1);

void medusa_write_b2(struct medusa *mdev, size_t offset, u32 value)
{
	iowrite32(value, mdev->hw_addr_bar2 + offset);
}
EXPORT_SYMBOL(medusa_write_b2);

/**
 * Read 32Bit value from Medusa MMIO Register Space (BAR1)
 *
 * @param offset offset in bytes, from the start of BAR1
 * @return 32Bit value read from Medusa MMIO (BAR1)
 */
u32 medusa_read_b1(struct medusa *mdev, size_t offset)
{
	return ioread32(mdev->hw_addr_bar1 + offset);
}
EXPORT_SYMBOL(medusa_read_b1);

u32 medusa_read_b2(struct medusa *mdev, size_t offset)
{
	return ioread32(mdev->hw_addr_bar2 + offset);
}
EXPORT_SYMBOL(medusa_read_b2);

static void set_sgdma_descriptor_format(struct medusa *mdev, int format)
{
	u32 pdma = medusa_read_b1(mdev, PDMA_REGISTER);

	if (format == 0)
		pdma &= ~B2MASK(PDMA_DCF_BIT);
	else
		pdma |= B2MASK(PDMA_DCF_BIT);
	medusa_write_b1(mdev, PDMA_REGISTER, pdma);
}

/*
 * Helper Functions for accessing the Descriptor
 * Ring in System Memory
 */

static inline volatile u32 *desc_ctrl_ptr(u8 *desc_addr)
{
	return (volatile u32 *)(desc_addr + DESC_CONTROL_OFFSET);
}

/** Invalidate a Descriptor into System Memory
 *  @param desc_addr: virtual address of the descriptor in system memory
 */
static inline void invalidate_descriptor(u8 *desc_addr)
{
	u32 value = *desc_ctrl_ptr(desc_addr);

	value &= ~B2MASK(DESC_CTRL_VALID_BIT);

	/* memory barrier to avoid that a reordered mmio access may
	 * overwrite the invalidation */
	smp_wmb();
	*desc_ctrl_ptr(desc_addr) = value;
}

/** Validate a Descriptor into System Memory
 * @param desc_addr: virtual address of the descriptor in system memory
 */
static inline void validate_descriptor(u8 *desc_addr)
{
	u32 value = *desc_ctrl_ptr(desc_addr);

	value |= B2MASK(DESC_CTRL_VALID_BIT);

	/* memory barrier to avoid issues that that the valid bit
	   is written before the remaining descriptor is written */
	smp_wmb();
	*desc_ctrl_ptr(desc_addr) = value;
}

static inline void write_desc_address(u8 *desc_addr, u64 addr)
{
	*((volatile u32 *)(desc_addr + DESC_ADDR_HI_OFFSET)) = addr >> 32;
	*((volatile u32 *)(desc_addr + DESC_ADDR_LO_OFFSET)) = (u32)addr;
}

/**
 *  Write a Jump Descriptor into System Memory
 *
 *  Note: The valid bit will not be changed
 *
 *  @param desc_addr: virtual address of the descriptor in system memory
 *  @param jump_addr:  Bus Address of the Descriptor to jump to
 */
static inline void write_jump_desc(u8 *desc_addr, dma_addr_t jump_addr)
{
	u32 value;

	write_desc_address(desc_addr, jump_addr);

	/* write descriptor control part */
	value = B2MASK(DESC_CTRL_VALID_BIT) | B2MASK(DESC_CTRL_JUMP_BIT);

	smp_wmb();
	*desc_ctrl_ptr(desc_addr) = value;
}

/** Write a Buffer Descriptor into System Memory
 *
 *  Note: The valid  bit will not be changed
 *
 * @desc_addr: virtual address of the descriptor in system memory
 * @dma_buffer_addr:  Bus Address of the DMA Buffer for data
 * @dma_buffer_depth: Buffer Depth of the DMA Buffer in bytes
 */
static inline void write_buffer_desc(u8 *desc_addr, dma_addr_t dma_buffer_addr,
				     size_t dma_buffer_length, u32 intr_sel_val)
{
	u32 value;
	/* buffer descriptor needs buffer depth as "length - 1" */
	size_t const buffer_depth = dma_buffer_length - 1;

	write_desc_address(desc_addr, dma_buffer_addr);

	WARN_ON(buffer_depth > DESC_CTRL_BUFDEPTH_MASK);
	WARN_ON(intr_sel_val > DESC_CTRL_INTR_SEL_MASK);

	/* write descriptor control part */
	value =
		B2MASK(DESC_CTRL_VALID_BIT) |
		(buffer_depth << DESC_CTRL_BUFDEPTH_OFFSET) |
		(intr_sel_val << DESC_CTRL_INTR_SEL_OFFSET);

	/* memory barrier to avoid issues that that the valid bit
	   is written before the remaining descriptor is written into
	   System Memory because of instruction reordering */
	smp_wmb();
	*desc_ctrl_ptr(desc_addr) = value;
}

/**
 * Hit the Resume Bit in the PSTS register
 * to signal the Medusa DMA to reload the
 * Descriptor Chain from System Memory
 *
 * @mdev: medusa device instance
 * @chidx: channel index [0..31]
 */
static inline void pstsn_resume(struct medusa *mdev, u8 chidx)
{
	size_t offset = PSTSN + (4 * chidx);
	u32 value = B2MASK(PSTSN_RSM_BIT);

	medusa_write_b1(mdev, offset, value);
}

/**
 * Clear all interrupt status flags per channel in the
 * PSTSn register
 *
 * Note:
 * The resume bit in the PSTSn register will always read
 * as zero (Medusa REV1)
 *
 * @mdev: medusa device instance
 * @chidx: channel index [0..31]
 */
static inline void pstsn_clear_int_status_flags(struct medusa *mdev, u8 chidx)
{
	size_t offset = PSTSN + (4 * chidx);
	u32 value = medusa_read_b1(mdev, offset);

	/* clear all except ODBn and RSM */
	value &= ~((PSTSN_ODBN_MASK << PSTSN_ODBN_OFFSET) | B2MASK(PSTSN_RSM_BIT));

	if (value)
		medusa_write_b1(mdev, offset, value);
}

static inline u32 pstsn_get_value(struct medusa *mdev, u8 chidx)
{
	size_t offset = PSTSN + (4 * chidx);

	return medusa_read_b1(mdev, offset);
}

static inline int pstsn_status_is_error(u32 value)
{
	value &=
		B2MASK(PSTSN_TIMEOUT_BIT) |
		B2MASK(PSTSN_EP_BIT) |
		B2MASK(PSTSN_CSCA_BIT) |
		B2MASK(PSTSN_DMA_FERR_BIT) |
		B2MASK(PSTSN_FIFO0UFLW_BIT);

	return value != 0;
}

/**
 * Enable the DMA Channel by setting the Enable Bit in
 * the PCTRL register
 *
 * @mdev: medusa device instance
 * @chidx: channel index [0..31]
 */
static inline void pctrl_enable_channel(struct medusa *mdev, u8 chidx)
{
	u32 value = medusa_read_b1(mdev, PCTRL_REGISTER(chidx));

	value |= B2MASK(PCTRL_EN_BIT);
	medusa_write_b1(mdev, PCTRL_REGISTER(chidx), value);
}

/**
 * Disable the DMA Channel by clearing the Enable Bit in
 * the PCTRL register
 * @mdev: medusa device instance
 * @chidx: channel index [0..31]
 */
static inline void pctrl_disable_channel(struct medusa *mdev, u8 chidx)
{
	u32 value = medusa_read_b1(mdev, PCTRL_REGISTER(chidx));

	value &= ~B2MASK(PCTRL_EN_BIT);
	medusa_write_b1(mdev, PCTRL_REGISTER(chidx), value);
}

/**
 * Enable the Streaming Socket Manager for the DMA Channel
 * by setting the corresponding Bit in the SSM register
 *
 * Enabling the SSM is required for Synchronous data.
 *
 * @mdev: medusa device instance
 * @chidx: channel index [0..31]
 */
static inline void ssm_enable_channel(struct medusa *mdev, u8 chidx)
{
	u32 value = medusa_read_b1(mdev, SSM_REGISTER);

	value |= B2MASK(chidx);
	medusa_write_b1(mdev, SSM_REGISTER, value);
}

/**
 * Disable the Streaming Socket Manager for a DMA Channel by clearing
 * the corresponding Bit in the SSM register Read 32Bit value from
 * the Medusa MMIO Register Space (BAR1)
 *
 * @mdev: medusa device instance
 * @chidx: channel index [0..31]
 */
static inline void ssm_disable_channel(struct medusa *mdev, u8 chidx)
{
	u32 value = medusa_read_b1(mdev, SSM_REGISTER);

	value &= ~B2MASK(chidx);
	medusa_write_b1(mdev, SSM_REGISTER, value);
}

/**
 * Enable the Non-Streaming Socket Manager for the DMA Channel
 * by setting the corresponding Bit in the NSM register
 *
 * Enabling the NSM is required for AV Packetized, Control and Isochronous data.
 *
 * @mdev: medusa device instance
 * @chidx: channel index [0..31]
 */
static inline void nsm_enable_channel(struct medusa *mdev, u8 chidx)
{
	u32 value = medusa_read_b1(mdev, NSM_REGISTER);

	value |= B2MASK(chidx);
	medusa_write_b1(mdev, NSM_REGISTER, value);
}

/**
 * Disable the Non-Streaming Socket Manager for a DMA Channel by clearing
 * the corresponding Bit in the NSM register Read 32Bit value from
 * the Medusa MMIO Register Space (BAR1)
 *
 * @mdev: medusa device instance
 * @chidx: channel index [0..31]
 */
static inline void nsm_disable_channel(struct medusa *mdev, u8 chidx)
{
	u32 value = medusa_read_b1(mdev, NSM_REGISTER);

	value &= ~B2MASK(chidx);
	medusa_write_b1(mdev, NSM_REGISTER, value);
}

static void pmsk_enable_int(struct medusa *mdev, int chidx, int bit)
{
	u32 value = medusa_read_b1(mdev, PMSK_REGISTER(chidx));

	value &= ~B2MASK(bit);
	medusa_write_b1(mdev, PMSK_REGISTER(chidx), value);
}

static void pmsk_disable_int(struct medusa *mdev, int chidx, int bit)
{
	u32 value = medusa_read_b1(mdev, PMSK_REGISTER(chidx));

	value |= B2MASK(bit);
	medusa_write_b1(mdev, PMSK_REGISTER(chidx), value);
}

/**
 *  Read 64bit tail address
 *
 *  @mdev: medusa device instance
 *  @chidx: channel index [0..31]
 *
 *  Returns the 64Bit tail address pointing to the DMA descriptor
 *  which will be processed next by the DMA.
 */
static inline u64 read_tail_address(struct medusa *mdev, u8 chidx)
{
	u64 tail_address = 0;
	size_t offset;

	if (mdev->dma_channels[chidx].long_addresses) {
		offset = TAIL_ADDR_HI_REG_BASE_ADDR + (chidx * 8);
		tail_address = medusa_read_b1(mdev, offset);
		tail_address = tail_address << 32;
	}

	offset = TAIL_ADDR_LO_REG_BASE_ADDR + (chidx * 8);
	tail_address |= medusa_read_b1(mdev, offset);

	return tail_address;
}

/**
 *  Write 64bit tail address
 *
 *  @mdev: medusa device instance
 *  @chidx: channel index [0..31]
 *  @tail_address: 64bit tail address value which will be written
 *   into the according tail address register in the DMA Channel
 *
 *  Returns: None
 *
 *  Note: The tail address register must not be written while
 *  the DMA channel is enabled. This may cause unpredictable behavior
 *
 */
static inline void write_tail_address(struct medusa *mdev, u8 chidx,
				      u64 tail_address)
{
	u32 reg_offset;

	if (mdev->dma_channels[chidx].long_addresses) {
		reg_offset = TAIL_ADDR_HI_REG_BASE_ADDR + (chidx * 8);
		medusa_write_b1(mdev, reg_offset, (u32)(tail_address >> 32));
	}

	reg_offset = TAIL_ADDR_LO_REG_BASE_ADDR + (chidx * 8);
	medusa_write_b1(mdev, reg_offset, (u32)tail_address);
}

static inline unsigned int q_is_empty(
	unsigned int didx_in, unsigned int didx_out)
{
	return didx_in == didx_out;
}

static inline unsigned int q_is_full(
	unsigned int didx_in, unsigned int didx_out)
{
	return didx_in >= didx_out + CHANNEL_DESCRIPTORS_NUM;
}

static inline unsigned int normalize_index(unsigned int didx)
{
	return didx & (CHANNEL_DESCRIPTORS_NUM - 1u);
}

static inline int is_jump_index(unsigned int didx)
{
	return (normalize_index(didx) % DESCR_BLOCK_SIZE) == DESCR_BLOCK_BUFFERS_NUM;
}

static inline unsigned int next_index(unsigned int didx)
{
	unsigned int delta = 1;

	if (is_jump_index(didx))
		delta = DESCR_BLOCK_SIZE - DESCR_BLOCK_BUFFERS_NUM;
	return didx + delta;
}

static inline u8 *get_descr_virt_addr(
	struct medusa_dma_channel *channel, unsigned int didx)
{
	return channel->desc_start_vaddr +
	       DESCRIPTOR_SIZE * normalize_index(didx);
}

static inline dma_addr_t get_descr_bus_addr(
	const struct medusa_dma_channel *channel, unsigned int didx)
{
	return channel->desc_start_paddr +
	       DESCRIPTOR_SIZE * normalize_index(didx);
}

/**
 * list_first_mbo - get the first mbo from a list
 * @ptr:	the list head to take the mbo from.
 */
#define list_first_mbo(ptr) \
	list_first_entry(ptr, struct mbo, list)

static dma_addr_t get_prev_tail_addr(struct medusa_dma_channel *channel,
				     dma_addr_t tail_address)
{
	u32 didx = (tail_address - channel->desc_start_paddr) / DESCRIPTOR_SIZE;
	unsigned int delta = 1;

	if (tail_address == channel->desc_start_paddr)
		tail_address += channel->desc_mem_size;

	if ((didx % DESCR_BLOCK_SIZE) == 0)
		delta = DESCR_BLOCK_SIZE - DESCR_BLOCK_BUFFERS_NUM;

	return tail_address - DESCRIPTOR_SIZE * delta;
}

/**
 * Retrieves memory for descriptors of the channel.
 * Address of memory for descriptors is NULL <==> channel is closed.
 * @param chidx
 * @param addr_ptr
 * @param size_ptr
 * @return 0 in case of bad index or missing device, otherwise 1.
 */
int medusa_get_descriptors_mem(struct medusa *mdev, int chidx,
			       u8 **addr_ptr, size_t *size_ptr)
{
	const struct medusa_dma_channel *ch;

	if (chidx < 0)
		return 0;

	if (chidx >= NUM_DMA_CHANNELS)
		return 0;

	ch = mdev->dma_channels + chidx;
	if (addr_ptr)
		*addr_ptr = ch->desc_start_vaddr;
	if (size_ptr)
		*size_ptr = ch->desc_mem_size;
	return 1;
}
EXPORT_SYMBOL(medusa_get_descriptors_mem);

/*
 * Services DMA Channel.
 * This function may be called from the interrupt context.
 *
 * Returns true if HW queue is empty.
 */
static int service_dma_channel(struct medusa *mdev, int chidx)
{
	struct medusa_dma_channel *channel;
	u64 tail_address;
	u64 prev_tail_address;
	unsigned long flags;
	u8 *desc_addr;
	struct mbo *mbo;
	int closing;

	WARN_ON(chidx >= NUM_DMA_CHANNELS);

	channel = mdev->dma_channels + chidx;
	WARN_ON(channel->state == ST_CLOSED);

	closing = channel->state == ST_CLOSING;
	tail_address = read_tail_address(mdev, chidx);

	if (channel->is_tx && !closing) {
		prev_tail_address = get_prev_tail_addr(channel, tail_address);
		if (channel->dt.tail_address != tail_address) {
			/* tail address is fresh and not yet reliable */
			hrtimer_cancel(&channel->dt.timer);
			channel->dt.tail_address = tail_address;
			hrtimer_start(&channel->dt.timer,
				      ns_to_ktime(tail_descriptor_delay_ns),
				      HRTIMER_MODE_REL);
		} else {
			/* tail address is not changed since last call */
			if (!hrtimer_active(&channel->dt.timer))
				/* after timeout the tail address is reliable */
				prev_tail_address = tail_address;
		}
	} else {
		/*
		 * the tail address is not relevant by closing the channel
		 * and is always reliable for the rx channels
		 */
		prev_tail_address = tail_address;
	}

	while (channel->state != ST_ERROR &&
	       !q_is_empty(channel->in, channel->out)) {
		dma_addr_t bus_addr = get_descr_bus_addr(channel, channel->out);

		if (!closing && (bus_addr == tail_address ||
				 bus_addr == prev_tail_address))
			break;

		if (is_jump_index(channel->out)) {
			channel->out = next_index(channel->out);
			smp_wmb();
			continue;
		}

		WARN_ON(list_empty(&channel->mbo_list));
		spin_lock_irqsave(&channel->list_lock, flags);
		mbo = list_first_mbo(&channel->mbo_list);
		spin_unlock_irqrestore(&channel->list_lock, flags);

		WARN_ON(!mbo);
		WARN_ON(!mbo->complete);

#if T_LIST_ADD_REMOVE
		pr_err("list-remove(%d): mbo %p\n", chidx, mbo);
#endif
		spin_lock_irqsave(&channel->list_lock, flags);
		list_del(&mbo->list);
		spin_unlock_irqrestore(&channel->list_lock, flags);

		desc_addr = get_descr_virt_addr(channel, channel->out);
		invalidate_descriptor(desc_addr);

		channel->out = next_index(channel->out);
		smp_wmb();

		/* call completion routine after index increment
		 * to prevent "overflow" in enqueue callback
		 * because of outdated index
		 */

		if (closing) {
			mbo->status = MBO_E_CLOSE;
			mbo->processed_length = 0;
		} else {
			u32 const pstn_value = pstsn_get_value(mdev, chidx);

			if (pstsn_status_is_error(pstn_value)) {
				channel->state = ST_ERROR;
				most_stop_enqueue(&mdev->most_intf, chidx);
				mbo->status = MBO_E_INVAL;
				mbo->processed_length = 0;
				pr_err("STOP CHANNEL %d: PSTSn is 0x%08X\n",
				       chidx, pstn_value);
			} else {
				typeof(channel->get_message_length) fn =
					channel->get_message_length;
				mbo->status = MBO_SUCCESS;
				mbo->processed_length = fn(mbo->virt_address,
							   mbo->buffer_length);
			}
		}

#if T_ENQUEUE_COMPLETE_POISON
		pr_err("complete-%s(%d): mbo %p, len %d\n",
		       closing ? "close" : "ok",
		       chidx, mbo, mbo->processed_length);
#endif
		mbo->complete(mbo);
	}

	pstsn_clear_int_status_flags(mdev, chidx);
	return q_is_empty(channel->in, channel->out);
}

static void destroy_dma_channel(struct medusa *mdev, int chidx)
{
	struct medusa_dma_channel *channel = mdev->dma_channels + chidx;

	WARN_ON(chidx >= NUM_DMA_CHANNELS);
	WARN_ON(!IS_RUNNING(channel->state));

	channel->state = ST_CLOSING;

	pctrl_disable_channel(mdev, chidx);
	pmsk_disable_int(mdev, chidx, PMSK_BUFDNE_BIT);
	ssm_disable_channel(mdev, chidx);
	nsm_disable_channel(mdev, chidx);
	service_dma_channel(mdev, chidx);
	WARN_ON(!list_empty(&channel->mbo_list));
	pci_free_consistent(NULL, channel->desc_mem_size,
			    channel->desc_start_vaddr,
			    channel->desc_start_paddr);
	channel->desc_start_vaddr = NULL;
	channel->desc_start_paddr = 0;

	channel->state = ST_CLOSED;
}

static enum hrtimer_restart channel_descr_timeout_hrt_fn(struct hrtimer *hrt)
{
	struct medusa_dma_channel *channel =
		container_of(hrt, struct medusa_dma_channel, dt.timer);

	/* service the last remaining descriptor */
	tasklet_hi_schedule(&channel->service_tasklet);

	return HRTIMER_NORESTART;
}

static void service_channel_tl_fn(unsigned long param)
{
	struct medusa_dma_channel *channel = (void *)param;
	struct medusa *mdev = container_of(channel, struct medusa,
					   dma_channels[channel->idx]);

	int const hw_queue_is_empty = service_dma_channel(mdev, channel->idx);

	if ((channel->state == ST_ERROR) ||
	    (hw_queue_is_empty && channel->state == ST_FLUSH)) {
		hrtimer_cancel(&channel->dt.timer);
		destroy_dma_channel(mdev, channel->idx);
	}
}

static u32 get_buffer_length(const u8 *data, u32 buffer_length)
{
	return buffer_length;
}

static u32 get_rx_packet_message_length(const u8 *data, u32 buffer_length)
{
	if (buffer_length < 2)
		return buffer_length;

	return min(((u32)data[0] << 8 | data[1]) + 2, buffer_length);
}

static int init_dma_channel(struct medusa *mdev, int chidx,
			    enum most_channel_data_type data_type,
			    enum most_channel_direction direction)
{
	struct medusa_dma_channel *channel = mdev->dma_channels + chidx;
	u64 end_descr_addr;
	typeof(channel->in) didx;

	channel->idx = chidx;

	channel->is_tx = (direction == MOST_CH_TX);
	if (direction == MOST_CH_RX &&
	    (data_type == MOST_CH_CONTROL || data_type == MOST_CH_ASYNC))
		channel->get_message_length = get_rx_packet_message_length;
	else
		channel->get_message_length = get_buffer_length;

	channel->in = 0;
	channel->out = 0;

#if ENABLE_MEDUSA_DMA_INTERRUPTS
	if (data_type == MOST_CH_ISOC_AVP || data_type == MOST_CH_SYNC)
		channel->intr_sel = DESC_CTRL_INTR_SEL_VAL_BUFF_CMPL;
	else
		channel->intr_sel = DESC_CTRL_INTR_SEL_VAL_PACK_CMPL;
#else
	channel->intr_sel = DESC_CTRL_INTR_SEL_VAL_NONE;
#endif

	INIT_LIST_HEAD(&channel->mbo_list);
	spin_lock_init(&channel->list_lock);

	channel->desc_mem_size = CHANNEL_DESCRIPTORS_NUM * DESCRIPTOR_SIZE;

	/* ToDo: change from consistent for streaming memory */
	channel->desc_start_vaddr =
		pci_alloc_consistent(NULL, channel->desc_mem_size,
				     &channel->desc_start_paddr);

	if (channel->desc_start_vaddr == NULL) {
		pr_err("init_dma_channel(): pci_alloc_consistent() failed\n");
		return -ENOMEM;
	}

	WARN_ON(!channel->desc_start_paddr);

	end_descr_addr = channel->desc_start_paddr + channel->desc_mem_size;
	channel->long_addresses = (end_descr_addr >> 32) != 0;

	memset(channel->desc_start_vaddr, 0, channel->desc_mem_size);

	didx = 0;
	do {
		typeof(didx) next_didx = next_index(didx);

		if (is_jump_index(didx)) {
			write_jump_desc(get_descr_virt_addr(channel, didx),
					get_descr_bus_addr(channel, next_didx));
		}
		didx = next_didx;
	} while (normalize_index(didx) != 0);

	write_tail_address(mdev, chidx, channel->desc_start_paddr);

	channel->dt.tail_address = 0;
	hrtimer_init(&channel->dt.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	channel->dt.timer.function = channel_descr_timeout_hrt_fn;

	tasklet_init(&channel->service_tasklet, service_channel_tl_fn,
		     (unsigned long)channel);

	channel->state = ST_OPEN;

	if (data_type == MOST_CH_SYNC)
		ssm_enable_channel(mdev, chidx);
	else
		nsm_enable_channel(mdev, chidx);

	pmsk_enable_int(mdev, chidx, PMSK_BUFDNE_BIT);

	smp_wmb();
	pctrl_enable_channel(mdev, chidx);

	return 0;
}

static void medusa_service_int(struct medusa *mdev, u32 pint_value)
{
	u16 chidx;

	dci_service_int(mdev);

	for (chidx = 0; chidx < NUM_DMA_CHANNELS; chidx++) {
		struct medusa_dma_channel *channel = mdev->dma_channels + chidx;

		if ((pint_value & B2MASK(chidx)) == 0)
			continue;

		if (IS_RUNNING(channel->state))
			tasklet_hi_schedule(&channel->service_tasklet);
	}
}

#if ENABLE_MEDUSA_DMA_INTERRUPTS

/**
 * Interrupt Handler
 *
 * The interrupt handler is tailored to be used with a edge
 * triggered interrupt like a MSI(-X) interrupt.
 * Level triggered interrupts like legacy PCI interrupt
 * and multiple interrupts are not supported.
 *
 */
static irqreturn_t isr_fn(int irq, void *dev)
{
	/* ToDo think about bottom half locks
	 * spin_lock_bh(lock);
	 * spin_unlock_bh(lock);
	 */
	u32 pint_value;
	struct medusa *mdev = pci_get_drvdata(dev);

	WARN_ON(!mdev);

	pr_err("isr_fn()\n");

	/* ToDo: check if there is a saver solution to provide
	 * the medusa interface instance to the tasklet.
	 */

	/* read medusa interrupt status register PINT */
	pint_value = medusa_read_b1(mdev, PINT);
	/* write back the PINT value to clear the interrupt
	 * status bits */
	medusa_write_b1(mdev, PINT, pint_value);

	medusa_service_int(mdev, pint_value);

	return IRQ_HANDLED;
}

#else /* ENABLE_MEDUSA_DMA_INTERRUPTS */

static enum hrtimer_restart int_simu_hrt_fn(struct hrtimer *hrt)
{
	struct medusa *mdev = container_of(hrt, struct medusa, int_simu_timer);

	if (!mdev->dbg_disable_pcie_poll)
		medusa_service_int(mdev, DMA_BIT_MASK(32));

	hrtimer_forward(hrt, hrtimer_get_expires(hrt),
			ns_to_ktime(polling_interval_ns));
	return HRTIMER_RESTART;
}

#endif /* ENABLE_MEDUSA_DMA_INTERRUPTS */

static enum hrtimer_restart rsm_hrt_fn(struct hrtimer *hrt)
{
	u16 chidx;
	struct medusa *mdev = container_of(hrt, struct medusa, rsm_timer);

	for (chidx = 0; chidx < NUM_DMA_CHANNELS; chidx++) {
		struct medusa_dma_channel *channel = mdev->dma_channels + chidx;

		if (IS_RUNNING(channel->state))
			pstsn_resume(mdev, chidx);
	}

	hrtimer_forward(hrt, hrtimer_get_expires(hrt),
			ns_to_ktime(rsm_interval_us * NSEC_PER_USEC));
	return HRTIMER_RESTART;
}

static int medusa_configure_channel(struct most_interface *inst_ptr,
				    int chidx,
				    struct most_channel_config *channel_config)
{
	struct medusa *mdev = container_of(inst_ptr, struct medusa, most_intf);

	if (chidx >= NUM_DMA_CHANNELS) {
		pr_err("medusa_configure_channel(%d): "
		       "bad channel index\n", chidx);
		return -1;	/* MBO_CONFIGURE_E_NOT_AVAILIBLE */
	}

	if (mdev->dma_channels[chidx].state != ST_CLOSED) {
		pr_err("medusa_configure_channel(%d): "
		       "channel is not closed\n", chidx);
		return -EPERM;
	}

	switch (channel_config->data_type) {
	case MOST_CH_CONTROL:
	case MOST_CH_ASYNC:
	case MOST_CH_ISOC_AVP:
	case MOST_CH_SYNC:
		/* supported data types */
		init_dma_channel(mdev, chidx, channel_config->data_type,
				 channel_config->direction);
		return 0;	/* MBO_CONFIGURE_SUCCESS */
	default:
		pr_err("medusa_configure_channel(%d): "
		       "bad data type: %d\n", chidx,
		       channel_config->data_type);
		return -2;	/* MBO_CONFIGURE_E_NOT_DATA_TYPE_NOT_SUPPORTED */
	}
}

static int medusa_enqueue(struct most_interface *inst_ptr,
			  int chidx, struct mbo *mbo)
{
	struct medusa *mdev = container_of(inst_ptr, struct medusa, most_intf);
	struct medusa_dma_channel *channel;
	unsigned long flags;
	u8 *desc_addr;

	if (chidx >= NUM_DMA_CHANNELS) {
		pr_err("medusa_enqueue(%d): bad channel index\n", chidx);
		return -EINVAL;
	}

	if (mbo == NULL || mbo->complete == NULL) {
		pr_err("medusa_enqueue(%d): "
		       "bad mbo or complete routine\n", chidx);
		return -EINVAL;
	}

	if (mbo->buffer_length > MAX_MEDUSA_BUFFER_SIZE) {
		pr_err("medusa_enqueue(%d): " "bad buffer_length\n", chidx);
		return -EINVAL;
	}

	channel = mdev->dma_channels + chidx;

	if (channel->state != ST_OPEN) {
		pr_err("medusa_enqueue(%d): "
		       "channel is poisoned or not configured\n", chidx);
		return -EPERM;
	}
#if T_ENQUEUE_COMPLETE_POISON
	pr_err("enqueue(%d): mbo %p, len %d\n", chidx, mbo,
	       mbo->buffer_length);
#endif

	if (q_is_full(channel->in, channel->out))
		goto err;

	if (is_jump_index(channel->in)) {
		channel->in = next_index(channel->in);
		if (q_is_full(channel->in, channel->out))
			goto err;
	}
#if T_LIST_ADD_REMOVE
	pr_err("list-add(%d): mbo %p\n", chidx, mbo);
#endif
	spin_lock_irqsave(&channel->list_lock, flags);
	list_add_tail(&mbo->list, &channel->mbo_list);
	spin_unlock_irqrestore(&channel->list_lock, flags);

	/* get descriptor address before index is incremented */
	desc_addr = get_descr_virt_addr(channel, channel->in);
	channel->in = next_index(channel->in);
	smp_wmb();

	/* write descriptor after index is incremented,
	 * otherwise completion call may hold */
	write_buffer_desc(desc_addr, mbo->bus_address, mbo->buffer_length,
			  channel->intr_sel);

	smp_wmb();
	pstsn_resume(mdev, chidx);

	return 0;

err:
	pr_err("medusa_enqueue(%d): out of hw descriptors\n", chidx);
	return -ENOMEM;
}

static int medusa_poison_channel(struct most_interface *inst_ptr, int chidx)
{
	struct medusa *mdev = container_of(inst_ptr, struct medusa, most_intf);
	struct medusa_dma_channel *channel;

	if (chidx >= NUM_DMA_CHANNELS) {
		pr_err("medusa_poison_channel(%d): bad channel index\n",
		       chidx);
		return -EINVAL;
	}

	channel = mdev->dma_channels + chidx;

	/*
	 * In case of hardware error the channel state goes
	 * over the values ST_ERROR, ST_CLOSING and ST_CLOSED and
	 * channel is closed automatically.
	 * For this case just return 0 (no error) if channel is not opened.
	 */
	if (channel->state != ST_OPEN)
		return 0;

#if T_ENQUEUE_COMPLETE_POISON
	pr_err("poison(%d):\n", chidx);
#endif

	if (channel->is_tx) {
		channel->state = ST_FLUSH;
	} else {
#if !ENABLE_MEDUSA_DMA_INTERRUPTS
		hrtimer_cancel(&mdev->int_simu_timer);
#endif
		hrtimer_cancel(&mdev->rsm_timer);
		hrtimer_cancel(&channel->dt.timer);
		tasklet_kill(&channel->service_tasklet);
		destroy_dma_channel(mdev, chidx);
#if !ENABLE_MEDUSA_DMA_INTERRUPTS
		hrtimer_start(&mdev->int_simu_timer,
			      ns_to_ktime(polling_interval_ns), HRTIMER_MODE_REL);
#endif
		if (rsm_interval_us)
			hrtimer_start(&mdev->rsm_timer,
				      ns_to_ktime(rsm_interval_us * NSEC_PER_USEC),
				      HRTIMER_MODE_REL);
	}

	return 0;
}

/**
 * Explicitly truncates large integer @value to be fit for @var of type u16.
 * This macro also works if the type of @var will be later changed to u32.
 */
#define TRUNCATE_TO_TYPE_SIZE(value, var)  \
	((sizeof(var) > sizeof(u16) || (value) <= USHRT_MAX) ? \
		(value) : USHRT_MAX)

/**
 * Allocates and initializes Most Interface Instance
 *
 * Returns pointer to Interface Instance
 */
static void init_most_interface(struct medusa *mdev)
{
	struct most_interface *const inst_ptr = &mdev->most_intf;
	int chidx;

	inst_ptr->channel_vector = mdev->channel_vector;
	inst_ptr->interface = ITYPE_PCIE;
	inst_ptr->description = mdev->name;
	inst_ptr->num_channels = NUM_DMA_CHANNELS;

	inst_ptr->enqueue = medusa_enqueue;
	inst_ptr->configure = medusa_configure_channel;
	inst_ptr->poison_channel = medusa_poison_channel;

	for (chidx = 0; chidx < NUM_DMA_CHANNELS; chidx++) {
		struct most_channel_capability *capability =
					inst_ptr->channel_vector + chidx;

		capability->data_type =
			MOST_CH_CONTROL | MOST_CH_ASYNC | MOST_CH_ISOC_AVP;

		capability->direction = MOST_CH_RX | MOST_CH_TX;
		/* Maximum number of buffers and buffer size supported
		 * by this channel for packet data types (Async,Control,QoS) */

		capability->num_buffers_packet = MIN_CHANNEL_BUFFERS;
		capability->buffer_size_packet =
			TRUNCATE_TO_TYPE_SIZE(MAX_MEDUSA_BUFFER_SIZE,
					      capability->buffer_size_packet);

		capability->num_buffers_streaming = MIN_CHANNEL_BUFFERS;
		capability->buffer_size_streaming =
			TRUNCATE_TO_TYPE_SIZE(MAX_MEDUSA_BUFFER_SIZE,
					      capability->buffer_size_streaming);
	}
}

/**
 * pci_ers_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 *
 * Returns 0 on success, negative on failure
 *
 * pci_ers_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int medusa_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int err;
	struct medusa *mdev;
	resource_size_t mmio_bar_start;
	resource_size_t mmio_bar_len;

	pr_info("medusa_probe()\n");

	/* Allocate memory for the PCIe device (Medusa PCIe interface) internal
	 * data structures */
	mdev = kzalloc(sizeof(struct medusa), GFP_KERNEL);
	if (!mdev) {
		err = -ENOMEM;
		goto out;
	}

	err = pci_enable_device_mem(pdev);
	if (err) {
		pr_err("pci_enable_device_mem failed: %d\n", err);
		goto out_kfree;
	}

	/* save pointer to the Medusa PCIe interface structure in the pci_dev
	 * structure*/
	pci_set_drvdata(pdev, mdev);

	/* ID format: "pcie-domain:bus:slot.func" */
	snprintf(mdev->name, sizeof(mdev->name), "pcie-%04x:%02x:%02x.%x",
		 pci_domain_nr(pdev->bus), pdev->bus->number,
		 PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

	err = pci_request_selected_regions_exclusive(
		      pdev, pci_select_bars(pdev, IORESOURCE_MEM), mdev->name);

	if (err) {
		pr_err("pci_request_selected_regions_exclusive failed: %d\n",
		       err);
		goto out_pci_disable_device;
	}

	/* AER (Advanced Error Reporting) hooks */
	/* pci_enable_pcie_error_reporting(pdev); */
	/* Enable Medusa as Bus Maseter */
	pci_set_master(pdev);

	mmio_bar_start = pci_resource_start(pdev, 1);
	mmio_bar_len = pci_resource_len(pdev, 1);
	mdev->hw_addr_bar1 = ioremap(mmio_bar_start, mmio_bar_len);

	if (!mdev->hw_addr_bar1) {
		pr_err("ioremap1 failed\n");
		err = -ENOMEM;
		goto out_pci_release_selected_regions;
	}

	mmio_bar_start = pci_resource_start(pdev, 2);
	mmio_bar_len = pci_resource_len(pdev, 2);
	mdev->hw_addr_bar2 = ioremap(mmio_bar_start, mmio_bar_len);

	if (!mdev->hw_addr_bar2) {
		pr_err("ioremap2 failed\n");
		err = -ENOMEM;
		goto out_iounmap1;
	}
#if ENABLE_MEDUSA_DMA_INTERRUPTS
	/* ToDo improve to support additional 64Bit addresses */
	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
	if (err) {
		pr_err("pci_set_dma_mask failed: %d\n", err);
		goto out_iounmap2;
	}

	/* Enable MSI Interrupt
	 * Legacy Interrupts are level triggered and more difficult to
	 * handle like MSI interrupts for Medusa.
	 */
	err = pci_enable_msi(pdev);
	if (err) {
		pr_err("pci_enable_msi failed :%d\n", err);
		err = -ENOMEM;
		goto out_iounmap2;
	}

	/* Request IRQ */
	err = request_irq(pdev->irq, isr_fn, IRQF_TRIGGER_NONE, "medusa", pdev);
	if (err) {
		pr_err("request_irq failed: %d\n", err);
		goto out_pci_disable_msi;
	}
	pmsk_enable_int(mdev, DCI_CH, PMSK_ODB0_BIT);
	pmsk_enable_int(mdev, DCI_CH, PMSK_ODB1_BIT);
#endif /* ENABLE_MEDUSA_DMA_INTERRUPTS */

	set_sgdma_descriptor_format(mdev, SGDMA_DESCR_FORMAT);
	init_most_interface(mdev);

	mdev->dbg_magic_key = DBG_MAGIC_KEY;
	mdev->parent_kobj = most_register_interface(&mdev->most_intf);
	if (IS_ERR(mdev->parent_kobj)) {
		err = PTR_ERR(mdev->parent_kobj);
		pr_err("most_register_interface failed: %d\n", err);
		goto out_free_irq;
	}

	(void)medusa_debug_probe(mdev);

	err = dci_probe(mdev);
	if (err) {
		pr_err("dci_init() failed: %d\n", err);
		goto out_most_deregister_interface;
	}

#if !ENABLE_MEDUSA_DMA_INTERRUPTS
	hrtimer_init(&mdev->int_simu_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	mdev->int_simu_timer.function = int_simu_hrt_fn;

	hrtimer_start(&mdev->int_simu_timer, ns_to_ktime(polling_interval_ns),
		      HRTIMER_MODE_REL);
#endif
	hrtimer_init(&mdev->rsm_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	mdev->rsm_timer.function = rsm_hrt_fn;

	if (rsm_interval_us)
		hrtimer_start(&mdev->rsm_timer,
			      ns_to_ktime(rsm_interval_us * NSEC_PER_USEC),
			      HRTIMER_MODE_REL);

	dci_run(mdev);

	return 0;

#if 0
out_destroy_dci:
	dci_destroy(mdev);
#endif

out_most_deregister_interface:
	most_deregister_interface(&mdev->most_intf);

out_free_irq:
#if ENABLE_MEDUSA_DMA_INTERRUPTS
	pmsk_disable_int(mdev, DCI_CH, PMSK_ODB1_BIT);
	pmsk_disable_int(mdev, DCI_CH, PMSK_ODB0_BIT);
	free_irq(pdev->irq, pdev);

out_pci_disable_msi:
	pci_disable_msi(pdev);

out_iounmap2:
#endif
	iounmap(mdev->hw_addr_bar2);

out_iounmap1:
	iounmap(mdev->hw_addr_bar1);

out_pci_release_selected_regions:
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));

out_pci_disable_device:
	pci_disable_device(pdev);

out_kfree:
	kfree(mdev);

out:
	return err;
}

/**
 * pci_ers_remove - Device Removal Routine
 * @pdev: PCI device information struct
 **/
static void medusa_remove(struct pci_dev *pdev)
{
	struct medusa *mdev = pci_get_drvdata(pdev);
	u32 chidx;
	struct most_interface *inst_ptr;

	pr_info("medusa_remove()\n");

	WARN_ON(!mdev);

	inst_ptr = &mdev->most_intf;

#if !ENABLE_MEDUSA_DMA_INTERRUPTS
	hrtimer_cancel(&mdev->int_simu_timer);
#endif
	hrtimer_cancel(&mdev->rsm_timer);
	dci_stop(mdev);

	for (chidx = 0; chidx < NUM_DMA_CHANNELS; chidx++) {
		struct medusa_dma_channel *channel = mdev->dma_channels + chidx;

		if (IS_RUNNING(channel->state)) {
			most_stop_enqueue(inst_ptr, chidx);
			hrtimer_cancel(&channel->dt.timer);
			tasklet_kill(&channel->service_tasklet);
			destroy_dma_channel(mdev, chidx);
		}
	}

	dci_destroy(mdev);
	most_deregister_interface(inst_ptr);
#if ENABLE_MEDUSA_DMA_INTERRUPTS
	pmsk_disable_int(mdev, DCI_CH, PMSK_ODB1_BIT);
	pmsk_disable_int(mdev, DCI_CH, PMSK_ODB0_BIT);
	free_irq(pdev->irq, pdev);
	pci_disable_msi(pdev);
#endif
	iounmap(mdev->hw_addr_bar2);
	iounmap(mdev->hw_addr_bar1);
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
	pci_disable_device(pdev);
	kfree(mdev);
}

static const struct pci_device_id medusa_pcie_tbl[] = {
	{ PCI_DEVICE(0x1055, 0xC115) },
	{} /* terminate list */
};

MODULE_DEVICE_TABLE(pci, medusa_pcie_tbl);

/**
 *PCI Device API Driver
 */
static struct pci_driver medusa_driver = {
	.name = driver_name,
	.id_table = medusa_pcie_tbl,
	.probe = medusa_probe,
	.remove = medusa_remove,
};

/**
 * medusa_init_module - Driver Registration Routine
 */
static int __init medusa_init_module(void)
{
	int ret;

	pr_info("medusa_init_module()\n");

	ret = pci_register_driver(&medusa_driver);
	return ret;
}

/**
 * medusa_exit_module - Driver Exit Cleanup Routine
 **/
static void __exit medusa_exit_module(void)
{
	pci_unregister_driver(&medusa_driver);
	pr_info("medusa_exit_module()\n");
}

module_init(medusa_init_module);
module_exit(medusa_exit_module);

MODULE_AUTHOR("Sebastian Graf, Microchip Technology Germany GmbH, "
	      "<sebastian.graf@microchip.com>");
MODULE_AUTHOR("Andrey Shvetsov, K2L GmbH & Co. KG, <andrey.shvetsov@k2l.de>");
MODULE_DESCRIPTION("Medusa Verification Driver");
MODULE_LICENSE("GPL");

