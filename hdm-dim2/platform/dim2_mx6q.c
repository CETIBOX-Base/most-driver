/*
 * dim2_mx6q.c - Platform device for MediaLB DIM2 interface
 * on Freescale IMX6Q
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

#define MLB_IOREG_BASE  0x218C000
#define MLB_IOREG_END   0x218CFFF
#define MLB_AHB0_INT    149

#define REG_MLBPC1      0x38
#define MLBPC1_VAL      0x888

struct dim2_platform_extra_data {
	struct platform_device *pdev;
	struct clk *clk_mlb3p;
	struct clk *clk_mlb6p;
	int clk_speed;
};

static struct dim2_platform_extra_data pd;


static int init(struct dim2_platform_data *pdata, void *io_base, int clk_speed);
static void destroy(struct dim2_platform_data *pdata);

struct dim2_platform_data pd_callbacks = {
	.init = init,
	.destroy = destroy,
};


static int init(struct dim2_platform_data *pdata, void *io_base, int clk_speed)
{
	struct device *dev = &pd.pdev->dev;

	pd.clk_mlb3p = clk_get(dev, "mlb150_clk");
	if (IS_ERR_OR_NULL(pd.clk_mlb3p)) {
		pr_err("unable to get mlb clock\n");
		return -EFAULT;
	}
	clk_prepare_enable(pd.clk_mlb3p);

	pd.clk_speed = clk_speed;

	if (clk_speed >= CLK_2048FS) { /* enable pll */
		pd.clk_mlb6p = clk_get(dev, "pll6");
		if (IS_ERR_OR_NULL(pd.clk_mlb6p)) {
			pr_err("unable to get mlb pll clock\n");
			clk_disable_unprepare(pd.clk_mlb3p);
			clk_put(pd.clk_mlb3p);
			return -EFAULT;
		}

		writel(MLBPC1_VAL, io_base + REG_MLBPC1);
		clk_prepare_enable(pd.clk_mlb6p);
	}

	return  0;
}

static void destroy(struct dim2_platform_data *pdata)
{
	if (pd.clk_speed >= CLK_2048FS) {
		clk_disable_unprepare(pd.clk_mlb6p);
		clk_put(pd.clk_mlb6p);
	}

	clk_disable_unprepare(pd.clk_mlb3p);
	clk_put(pd.clk_mlb3p);
}


static int __init mlb_platform_init(void)
{
	struct platform_device *pdev;
	int ret;

	struct resource res[] = {
		{
			.flags = IORESOURCE_MEM,
			.start = MLB_IOREG_BASE,
			.end = MLB_IOREG_END,
		},
		{
			.flags = IORESOURCE_IRQ,
			.start = MLB_AHB0_INT,
			.end = MLB_AHB0_INT,
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

	pd.pdev = pdev;
	ret = platform_device_add_data(pdev, &pd_callbacks,
				       sizeof(pd_callbacks));
	if (ret) {
		pr_err("Failed to add platform data\n");
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
	platform_device_unregister(pd.pdev);
}

module_init(mlb_platform_init);
module_exit(mlb_platform_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jain Roy Ambi <JainRoy.Ambi@microchip.com>");
MODULE_AUTHOR("Andrey Shvetsov <andrey.shvetsov@k2l.de>");
MODULE_DESCRIPTION("IMX6Q MediaLB DIM2 Platform Device");
