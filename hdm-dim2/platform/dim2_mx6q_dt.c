/*
 * dim2_mx6q_dt.c - Platform device for MediaLB DIM2 interface
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
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include "../dim2_hdm.h"
#include "../dim2_hal.h"


#define REG_MLBPC1      0x38
#define MLBPC1_VAL      0x888

struct dim2_platform_extra_data {
	struct platform_device *pdev;
	struct device *dev;
	struct clk *clk_mlb3p;
	struct clk *clk_mlb6p;
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
	pd.clk_mlb3p = clk_get(pd.dev, "mlb");
	if (IS_ERR_OR_NULL(pd.clk_mlb3p)) {
		pr_err("unable to get mlb clock\n");
		return -EFAULT;
	}
	clk_prepare_enable(pd.clk_mlb3p);

	pd.clk_speed = clk_speed;

	if (clk_speed >= CLK_2048FS) { /* enable pll */
		pd.clk_mlb6p = clk_get(pd.dev, "pll8_mlb");
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


static int dim2_dt_probe(struct platform_device *pdev_dt)
{
	struct platform_device *pdev;
	struct device_node *const node = pdev_dt->dev.of_node;
	struct resource res[3];
	int ret;

	enum dt_interrupts_order { MLB_INT_DT_IDX, AHB0_INT_DT_IDX };

	if (pd.pdev)
		return -ENOMEM;

	ret = of_address_to_resource(node, 0, &res[0]);
	if (ret) {
		pr_err("failed to get memory region\n");
		return ret;
	}

	if (!of_irq_to_resource(node, AHB0_INT_DT_IDX, &res[1])) {
		pr_err("failed to get ahb0_int resource\n");
		return -ENOENT;
	}

	if (!of_irq_to_resource(node, MLB_INT_DT_IDX, &res[2])) {
		pr_err("failed to get mlb_int resource\n");
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
	{ .compatible = "fsl,imx6q-mlb150" },
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
MODULE_DESCRIPTION("IMX6Q MediaLB DIM2 dt-friendly Platform Device");
