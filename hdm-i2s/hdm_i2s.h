/*
 * hdm_i2s.h - I2S HDM Header
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

#ifndef HDM_I2S_H
#define	HDM_I2S_H

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


/* I2S Configuration Parameters */
#define PORT_RST        0x00010000
#define PORT_EN         0x00020000

#define OMM             0x00008000 /* Port Master */
#define OMS             0x00000000 /* Port Slave */

#define IO_MODE         0x00000200
#define DMA_MODE        0x00000100

#define CLK_8FS         0x00000000
#define CLK_16FS        0x00040000
#define CLK_32FS        0x00080000
#define CLK_64FS        0x000C0000
#define CLK_128FS       0x00100000
#define CLK_256FS       0x00140000
#define CLK_512FS       0x00180000

#define SEQ_SDF         0x00001000 /* Sequential */
#define DEL_SDF         0x00000800 /* Delayed-Bit */
#define LEFT_SDF        0x00000400 /* Left Justified */
#define RIGHT_SDF       0x00000000 /* Right Justified */

#define SEQ_4BYTE       0x00001000

#define QUADLETS_511    0x000001FF
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

/* Clock Generator Register addresses */
#define REG_CFG         0x00 /* Clock Generation IP Configuration register */
#define REG_DIV         0x01 /* Clock Generation IP Div register */

/* Clock Generator Configuration Parameters */
#define RST_CLR         0x00000000
#define SW_RST          0x80000000
#define DCM0_RST        0x40000000
#define DCM1_RST        0x20000000
#define CLK_SEL_MASK    0x1C000000

#define PHY1_RMCK0      0x00000000
#define PHY1_RMCK1      0x04000000
#define PHY2_RMCK0      0x08000000
#define PHY2_RMCK1      0x0C000000
#define DBG_CLK         0x10000000
#define OSC1_CLK        0x14000000
#define OSC2_CLK        0x18000000
#define OSC3_CLK        0x1C000000

#define DEN             0x02000000 /* Dynamic port enable */
#define DWE             0x01000000 /* Dynamic port write enable */
#define DADDR_MULTIPLY  0x00500000 /* Dynamic port ADDRE MULTIPLIER SETTING */
#define DADDR_DIVIDER   0x00520000 /* Dynamic port ADDRE DIVIDER SETTING */

#endif	/* HDM_I2S_H */

