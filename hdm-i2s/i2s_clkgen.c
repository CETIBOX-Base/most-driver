/*
 * i2s_clkgen.c - I2S Clockgen Access functions
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/io.h>

#include "i2s_clkgen.h"


/**
 * write_reg_clkgen - write value to a register on clock generator
 * @dev: private data
 * @reg_offset: offset of the register
 * @value: value to write
 */

static inline void write_reg_clkgen(u32 *base_addr,
				    unsigned long reg_offset,
				    uint32_t value)
{
	iowrite32(value, base_addr + reg_offset);
}

/**
 * read_reg_clkgen - read value of a register on clock generator
 * @dev: private data
 * @reg_offset: offset of the register
 */
static inline uint32_t read_reg_clkgen(u32 *base_addr,
				       unsigned long reg_offset)
{
	return ioread32(base_addr + reg_offset);
}

int try_lock_clk_gen(u32 *base_addr, enum i2s_clk_source clk_source)
{
	int locking_successful = -ETIME;
	u32 clk_cfg_reg = 0x0;
	u8 i = 0;

	/* Master mode */

	/* Configure the clock divider */
	write_reg_clkgen(base_addr, REG_DIV, 0);

	pr_info("Reset MMCM\n");
	/* Set clock source (needs to be stable for a while before resetting) */
	write_reg_clkgen(base_addr, REG_CFG, clk_source);
	udelay(200);

	/* Reset the clock Generator */
	write_reg_clkgen(base_addr, REG_CFG, MMCM_RESET | clk_source);
	udelay(10);
	write_reg_clkgen(base_addr, REG_CFG, RST_CLR | clk_source);
	udelay(200);

	/* Try locking the MMCM */
	for (i = 0; i < 5; i++) {
		clk_cfg_reg = read_reg_clkgen(base_addr, REG_CFG);
		if (MMCM_LOCKED & clk_cfg_reg) {
			pr_info("MMCM Locked\n");
			locking_successful = 0;
			break;
		} else {
			pr_info("MMCM UnLock!!!! CFG Reg:0x%08x\n", clk_cfg_reg);
			write_reg_clkgen(base_addr, REG_CFG, MMCM_RESET | clk_source);
			udelay(10);
			write_reg_clkgen(base_addr, REG_CFG, RST_CLR | clk_source);
			udelay(200);
		}
	}
	if (locking_successful != 0)
		pr_warning("Could not lock MMCM\n");
	return locking_successful;
}

int check_if_clk_gen_locked(u32 *base_addr, enum i2s_clk_source clk_source)
{
	u32 clk_cfg_reg = 0x0;
	clk_cfg_reg = read_reg_clkgen(base_addr, REG_CFG);
	/* If clock gen is not locked, try to lock it */
	if (!(MMCM_LOCKED & clk_cfg_reg)) {
		;

		if (try_lock_clk_gen(base_addr, clk_source) != 0) {
			pr_err("Could not enable I2S channel, MMCM not locked CFG Reg:0x%08x\n",
			       clk_cfg_reg);
			return -ENODEV;
		}
	}

	return 0;
}
