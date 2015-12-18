/*
 * dim2_mx6q_dt.c - Platform device for MediaLB DIM2 interface
 * on Renesas R-Car H2
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
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include "../dim2_hdm.h"
#include "../dim2_hal.h"


#define REG_MLBPC1      0x38
#define REG_PHYCTRL     0x600
#define MLBPC1_VAL      0x888

struct dim2_platform_extra_data {
	struct platform_device *pdev;
	struct device *dev;
	struct clk *clk;
	void *io_base;
	int clk_speed;
};

static struct dim2_platform_extra_data pd;


static int init(struct dim2_platform_data *pdata, void *io_base, int clk_speed);
static void destroy(struct dim2_platform_data *pdata);

static struct dim2_platform_data pd_callbacks = {
	.init = init,
	.destroy = destroy,
};


static int init(struct dim2_platform_data *pdata, void *io_base, int clk_speed)
{
	/* enable clock */
	pd.clk = devm_clk_get(pd.dev, NULL);
	if (IS_ERR(pd.clk)) {
		dev_err(pd.dev, "cannot get clock\n");
		return PTR_ERR(pd.clk);
	}
	clk_prepare_enable(pd.clk);

	pd.clk_speed = clk_speed;
	pd.io_base = io_base;

	/* BBCR  = 0b11 */
	writel(0x3, io_base + 0x500);
	writel(0x0002FF02, io_base + 0x508);

	if (clk_speed >= CLK_2048FS) {
		/* enable MLP pll and LVDS drivers */
		writel(0x03, io_base + REG_PHYCTRL);
		/* set bias */
		writel(MLBPC1_VAL, io_base + REG_MLBPC1);
	} else {
		/* enable MLB pll */
		writel(0x04, io_base + REG_PHYCTRL);
	}

	dev_info(pd.dev, "initialized successfully\n");
	return  0;
}

static void destroy(struct dim2_platform_data *pdata)
{
	/* disable PLLs and LVDS drivers */
	writel(0x0, pd.io_base + REG_PHYCTRL);

	clk_disable_unprepare(pd.clk);
	devm_clk_put(pd.dev, pd.clk);
}


static int dim2_dt_probe(struct platform_device *pdev_dt)
{
	struct platform_device *pdev;
	struct device_node *const node = pdev_dt->dev.of_node;
	struct resource res[2] = {};
	int ret;

	enum { AHB0_INT_IDX = 0 };

	pr_debug("\n");

	if (pd.pdev)
		return -ENOMEM;

	ret = of_address_to_resource(node, 0, &res[0]);
	if (ret) {
		pr_err("failed to get memory region\n");
		return ret;
	}

	if (!of_irq_to_resource(node, AHB0_INT_IDX, &res[1])) {
		pr_err("failed to get irq\n");
		return -ENOENT;
	}

	pdev = platform_device_alloc("medialb_dim2", 0);
	if (!pdev) {
		pr_err("failed to allocate platform device\n");
		return -ENOMEM;
	}

	ret = platform_device_add_resources(pdev, res, ARRAY_SIZE(res));
	if (ret) {
		pr_err("failed to add resources\n");
		goto out_free_pdev;
	}

	pd.pdev = pdev;
	pd.dev = &pdev_dt->dev;
	ret = platform_device_add_data(pdev, &pd_callbacks,
				       sizeof(pd_callbacks));
	if (ret) {
		pr_err("failed to add platform data\n");
		goto out_free_pdev;
	}

	ret = platform_device_add(pdev);
	if (ret) {
		pr_err("failed to add platform device\n");
		goto out_free_pdev;
	}

	return 0;

out_free_pdev:
	platform_device_put(pdev);
	pd.pdev = 0;
	return ret;
}

static int dim2_dt_remove(struct platform_device *pdev_dt)
{
	platform_device_unregister(pd.pdev);
	pd.pdev = 0;
	return 0;
}

static const struct of_device_id dim2_imx_dt_ids[] = {
	{ .compatible = "renesas,mlp" },
	{},
};

static struct platform_driver dim2_driver = {
	.probe = dim2_dt_probe,
	.remove = dim2_dt_remove,
	.driver = {
		.name = "dim2-dt-stub-driver",
		.owner = THIS_MODULE,
		.of_match_table = dim2_imx_dt_ids,
	},
};

MODULE_DEVICE_TABLE(of, dim2_imx_dt_ids);

static int __init mlb_platform_init(void)
{
	pr_info("mlb_platform_init()\n");
	return platform_driver_register(&dim2_driver);
}

static void __exit mlb_platform_exit(void)
{
	pr_info("mlb_platform_exit()\n");
	platform_driver_unregister(&dim2_driver);
}

module_init(mlb_platform_init);
module_exit(mlb_platform_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrey Shvetsov <andrey.shvetsov@k2l.de>");
MODULE_DESCRIPTION("Renesas R-Car H2 MediaLB DIM2 dt-friendly Platform Device");
