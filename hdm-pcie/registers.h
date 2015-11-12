/*
 * registers.h - Medusa Registers
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

#ifndef MEDUSA_REGISTERS_H
#define	MEDUSA_REGISTERS_H


/*
 * PCTRL Register
 */
#define PCTRL 0x0000
#define PCTRL_REGISTER(channel) (PCTRL + (channel * 4))

/* Channel Enable*/
#define PCTRL_EN_BIT 0

#define PCTRL_TC_OFFSET 8
#define PCTRL_TC_MASK ((u32)0x7)

#define PCTRL_DTHR_OFFSET 4
#define PCTRL_DTHR_MASK ((u32)0x7)

/* DMA Event Map
 * 5Bit field mapping the DMA Events of a Channel to one
 * of 32 interrupt vectors
 */
#define PCTRL_DMAP_OFFSET 16
#define PCTRL_DMAP_MASK   0x1Fu

/*
 * Interrupt Status
 */
#define PINT 0x0304

/*
 * SSM Register
 * Streaming Socket Manager
 */
#define SSM_REGISTER 0x328

/*
 * Inbound Doorbell Register
 */
#define IDBELL_REGISTER 0x31C
#define IDBELL_IDB_BIT 0

/*
 * NSM Register
 * Non-Streaming Socket Manager
 */
#define NSM_REGISTER 0x32C


/*
 *  PSTSn Register
 *  n = 0..31
 *  SGDMA Channel N Status Register
 *
 *  Provides Status Informations and contains
 *  the Resume Bit. One Register per DMA Channel
 */
#define PSTSN 0x80

/* PSTSn Bits */
#define PSTSN_TIMEOUT_BIT 16
#define PSTSN_EP_BIT 15
#define PSTSN_CSCA_BIT 14
#define PSTSN_DMA_FERR_BIT 11
#define PSTSN_FIFO0UFLW_BIT 6
#define PSTSN_ODBN_OFFSET 2
#define PSTSN_ODBN_MASK 0xF
#define PSTSN_ODB1_BIT 3
#define PSTSN_ODB0_BIT 2
#define PSTSN_ODBWR_BIT 1
#define PSTSN_RSM_BIT 0


/*
 * SGDMA Channel N Status Mask Register (PMSKn register)
 * N = 0..31
 */
#define PMSK_REGISTER(chidx) (0x200 + ((chidx) * 4))

#define PMSK_BUFDNE_BIT 31
#define PMSK_ODB3_BIT 5
#define PMSK_ODB2_BIT 4
#define PMSK_ODB1_BIT 3
#define PMSK_ODB0_BIT 2


/* Descriptor Control Values*/
#define DESC_CTRL_JUMP_BIT 30

#define DESC_CTRL_INTR_SEL_OFFSET 28
#define DESC_CTRL_INTR_SEL_MASK 3u
#define DESC_CTRL_INTR_SEL_VAL_NONE 0u
#define DESC_CTRL_INTR_SEL_VAL_BUFF_CMPL 1u
#define DESC_CTRL_INTR_SEL_VAL_PACK_CMPL 2u

#define DESC_CTRL_VALID_BIT 31

#define DESC_CTRL_BUFDEPTH_OFFSET 0
#define DESC_CTRL_BUFDEPTH_MASK 0x3FFFFu

#if SGDMA_DESCR_FORMAT == 0
/* Offsets in bytes from the start of the Descriptor for the Format 0 */
#define DESC_CONTROL_OFFSET 0
#define DESC_ADDR_HI_OFFSET 8
#define DESC_ADDR_LO_OFFSET 12
#else
/* Offsets in bytes from the start of the Descriptor for the Format 1 */
#define DESC_ADDR_HI_OFFSET 0
#define DESC_ADDR_LO_OFFSET 4
#define DESC_CONTROL_OFFSET 12
#endif

/* Register definitions*/

/* Start Address of the Tail Address Low Registers
 * Channel 0 Tail Address Low Register Address: BAR1 - 0x100
 * Channel 1 Tail Address Low Register Address: BAR1 - 0x108
 * ...
 * Channel 31 Tail Address Register Address: BAR1 - ...
 */

#define TAIL_ADDR_LO_REG_BASE_ADDR 0x100
#define TAIL_ADDR_HI_REG_BASE_ADDR 0x104

/* PCIe Interrupt Register
 *  Bit 0 -> Interrupt for Channel 0 pending
 *  Bit 1 -> Interrupt for Channel 1 pending
 *  ...
 *  Bit 3 -> Interrupt for Channel 3 pending
 *
 *  '1': Interrupt pending
 *  '0': Interrupt not pending
 *
 * */

#define PCIE_INT_REG_BASE_ADDR 0x304


/*
 *  PDMA Control Register
 */
#define PDMA_REGISTER 0x330
#define PDMA_CT_OFFSET 0
#define PDMA_CT_MASK ((u32)0xFF)
#define PDMA_DB_OFFSET 8
#define PDMA_DB_MASK ((u32)0x3)
#define PDMA_DCF_BIT 10

#define MAILBOX_REGISTER(reg) (0x800 + ((reg) * 4))


#endif	/* MEDUSA_REGISTERS_H */

