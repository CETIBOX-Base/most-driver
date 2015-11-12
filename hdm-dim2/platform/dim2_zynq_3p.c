/*
 * dim2_zynq_3p.c - Platform device for 3 pin MediaLB DIM2 interface on ZYNQ
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
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/io.h>

#include "../dim2_hdm.h"
#include "../dim2_hal.h"

#define MLB_IOREG_BASE  0x75C20000
#define MLB_IOREG_END   0x75C2FFFF
#define MLB_AHB0_INT    35


static struct platform_device *pdev;

static int __init mlb_platform_init(void)
{
	int ret;

	struct resource res[] = {
		{
			.start	= MLB_IOREG_BASE,
			.end	= MLB_IOREG_END,
			.flags	= IORESOURCE_MEM,
		},
		{
			.start	= MLB_AHB0_INT,
			.end	= MLB_AHB0_INT,
			.flags	= IORESOURCE_IRQ,
		},
	};

	pr_info("mlb_platform_init()\n");

	pdev = platform_device_alloc("medialb_dim2", 0);
	if (!pdev) {
		pr_err("Failed to allocate platform device\n");
		return -ENOMEM;
	}

	ret = platform_device_add_resources(pdev, res, ARRAY_SIZE(res));
	if (ret) {
		pr_err("Failed to add resources\n");
		goto out_free_pdev;
	}

	ret = platform_device_add(pdev);
	if (ret) {
		pr_err("Failed to add platform device\n");
		goto out_free_pdev;
	}

	return 0;

out_free_pdev:
	platform_device_put(pdev);
	return ret;
}

static void __exit mlb_platform_exit(void)
{
	pr_info("mlb_platform_exit()\n");
	platform_device_unregister(pdev);
}

module_init(mlb_platform_init);
module_exit(mlb_platform_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrey Shvetsov <andrey.shvetsov@k2l.de>");
MODULE_DESCRIPTION("ZYNQ MediaLB DIM2 3 pin Platform Device");
