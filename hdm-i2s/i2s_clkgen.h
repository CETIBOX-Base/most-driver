/*
 * i2s_clkgen.h - I2S Clockgen Access functions
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

#ifndef I2S_CLKGEN_H
#define	I2S_CLKGEN_H

#include <linux/types.h>

/* Clock Generator Register addresses */
#define REG_CFG         0x00 /* Clock Generation IP Configuration register */
#define REG_DIV         0x04 /* Clock Generation IP Div register */

/* Clock Generator Configuration Parameters */
#define RST_CLR         0x00000000
#define SW_RST          0x80000000
#define MMCM_RESET      0x20000000
#define CLK_SEL_MASK    0x1C000000

#define MMCM_LOCKED     0x40000000
#define MMCM_CLKIN_STOP 0x20000000

#define DEN             0x02000000 /* Dynamic port enable */
#define DWE             0x01000000 /* Dynamic port write enable */
#define DRDY            0x00800000

#define DADDR_MULTIPLY  0x00500000 /* Dynamic port ADDRE MULTIPLIER SETTING */
#define DADDR_DIVIDER   0x00520000 /* Dynamic port ADDRE DIVIDER SETTING */

enum i2s_clk_source {
	PHY1_RMCK0 = 0x00000000,
	PHY1_RMCK1 = 0x04000000,
	PHY2_RMCK0 = 0x08000000,
	PHY2_RMCK1 = 0x0C000000,
	DBG_CLK    = 0x10000000,
	OSC1_CLK   = 0x14000000,
	OSC2_CLK   = 0x18000000,
	OSC3_CLK   = 0x1C000000,
};

int try_lock_clk_gen(u32 *base_addr, enum i2s_clk_source source);
int check_if_clk_gen_locked(u32 *base_addr, enum i2s_clk_source source);

#endif
