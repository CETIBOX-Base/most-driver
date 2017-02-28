/*
 * i2s_hdm.h - I2S HDM Header
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

#ifndef I2S_HDM_H
#define	I2S_HDM_H

#include <linux/types.h>

/* I2S register addresses */
#define REG_DCCRA       0x00
#define REG_DCCRB       0x01
#define REG_DSCR        0x02
#define REG_CCRn        0x08
#define REG_BFTRn       0x09
#define REG_BETRn       0x0A
#define REG_CBBARn      0x0B
#define REG_NBBARn      0x0D
#define REG_NBEARn      0x0E
#define REG_CSRn        0x0F

#define UNDEFINED       0xFFFFFFFF

/* I2S Configuration Parameters */
#define PORT_RST        0x00010000
#define PORT_EN         0x00020000

#define IO_MODE         0x00000200
#define DMA_MODE        0x00000100

#define QUADLETS_511    0x000001FF
#define QUADLETS_508    0x000001FC
#define QUADLETS_256    0x00000100
#define QUADLETS_128    0x00000080
#define QUADLETS_384    0x00000180
#define QUADLETS_32     0x00000020
#define QUADLETS_0      0x00000000

#define CHANNEL_RESET   0x01000000
#define CHANNEL_EN      0x00800000

#define TX_INT_MASK     0xFFFFFFD7
#define RX_INT_MASK     0xFFFFFFE7
#define TX_INT_UNMASK   0x00000020
#define RX_INT_UNMASK   0x00000010
#define UNMASK_ALL      0x000000FF

#define RX_SERV_REQ_INT         0x00000002
#define TX_SERV_REQ_INT         0x00000004
#define FIFO_OVERFLOW_INT       0x00000008
#define FIFO_UNDERFLOW_INT      0x00000010

#define I2S_REG_DATA_SEQ     0x00001000 /* Sequential */
#define I2S_REG_DATA_DEL     0x00000800 /* Delayed-Bit */
#define I2S_REG_DATA_DEL_SEQ 0x00001800 /* Delayed Sequential-Bit */
#define I2S_REG_DATA_LEFT    0x00000400 /* Left Justified */
#define I2S_REG_DATA_RIGHT   0x00000000 /* Right Justified */

#define I2S_SEQ_SHIFT       10U
#define I2S_LEFT_SHIFT      10U
#define I2S_RIGHT_SHIFT     16U

#define I2S_SEQ_MASK    0x0001FC00
#define I2S_LEFT_MASK   0x0000FC00
#define I2S_RIGHT_MASK  0x003F0000


#define I2S_REG_CLKMODE_MASTER 0x00008000 /* Port Master */
#define I2S_REG_CLKMODE_SLAVE  0x00000000 /* Port Slave */

#define I2S_REG_CLK_8FS      0x00000000  /* 8 Clock Cycles per Frame   */
#define I2S_REG_CLK_16FS     0x00040000  /* 16 Clock Cycles per Frame  */
#define I2S_REG_CLK_32FS     0x00080000  /* 32 Clock Cycles per Frame  */
#define I2S_REG_CLK_64FS     0x000C0000  /* 64 Clock Cycles per Frame  */
#define I2S_REG_CLK_128FS    0x00100000  /* 128 Clock Cycles per Frame */
#define I2S_REG_CLK_256FS    0x00140000  /* 256 Clock Cycles per Frame */
#define I2S_REG_CLK_512FS    0x00180000  /* 512 Clock Cycles per Frame */

enum i2s_clk_mode {
	I2S_CLKMODE_UDEF        = UNDEFINED,                 /* Undefined*/
	I2S_CLKMODE_MASTER      = I2S_REG_CLKMODE_MASTER,    /* IP is Clock Master */
	I2S_CLKMODE_SLAVE       = I2S_REG_CLKMODE_SLAVE,     /* IP is Clock Slave*/
};


enum i2s_clk_speed {
	I2S_CLK_UDEF   = UNDEFINED,             /* Undefined*/
	I2S_CLK_8FS    = I2S_REG_CLK_8FS,       /* 8 Clock Cycles per Frame (typ. 8*48 kHz)*/
	I2S_CLK_16FS   = I2S_REG_CLK_16FS,      /* 16 Clock Cycles per Frame (typ. 16*48 kHz)*/
	I2S_CLK_32FS   = I2S_REG_CLK_32FS,      /* 32 Clock Cycles per Frame (typ. 32*48 kHz)*/
	I2S_CLK_64FS   = I2S_REG_CLK_64FS,      /* 64 Clock Cycles per Frame (typ. 64*48 kHz)*/
	I2S_CLK_128FS  = I2S_REG_CLK_128FS,     /* 128 Clock Cycles per Frame (typ. 128*48 kHz)*/
	I2S_CLK_256FS  = I2S_REG_CLK_256FS,     /* 256 Clock Cycles per Frame (typ. 256*48 kHz)*/
	I2S_CLK_512FS  = I2S_REG_CLK_512FS,     /* 512 Clock Cycles per Frame (typ. 512*48 kHz)*/
};


enum i2s_data_format {
	I2S_DATA_UDEF           = UNDEFINED,    /* Undefined*/
	I2S_DATA_SEQ            = 0x1,          /* Sequential*/
	I2S_DATA_DEL_SEQ        = 0x2,          /* Delayed Sequential-Bit*/
	I2S_DATA_DEL            = 0x3,          /* Delayed-Bit*/
	I2S_DATA_LEFT_MONO      = 0x4,          /* Left Justified - Mono*/
	I2S_DATA_LEFT_STEREO    = 0x5,          /* Left Justified - Mono*/
	I2S_DATA_RIGHT_MONO     = 0x6,          /* Left Justified - Mono*/
	I2S_DATA_RIGHT_STEREO   = 0x7,          /* Right Justified - Mono*/
};



#endif
