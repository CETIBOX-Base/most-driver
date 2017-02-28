/*
 * dim2_arwen_mlb3.c - Platform device for 3 pin MediaLB DIM2 interface on Arwen
 *
 * Copyright (C) 2015-2016, Microchip Technology Germany II GmbH & Co. KG
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
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include "../dim2_hdm.h"
#include "../dim2_hal.h"

struct dim2_arwen_platform_data {
	struct platform_device *pdev;
	struct device *dev;
};

static const struct of_device_id dim2_arwen_dt_ids[] = {
	{ .compatible = "xlnx,axi4-os62420_3pin-1.00.a" },
	{},
};


static struct dim2_arwen_platform_data arwen_pdata;


static int dim2_dt_probe(struct platform_device *pdev_dt)
{
	struct device_node *of_node = pdev_dt->dev.of_node;
	struct platform_device *pdev;
	struct resource res[3];
	int ret;
	int rc;

	enum dt_interrupts_order { AHB0_INT_DT_IDX, MLB_INT_DT_IDX };

	rc = of_address_to_resource(of_node, 0, &res[0]);
	if (rc) {
		pr_err("failed to get memory region\n");
		return -EFAULT;
	}

	if (!of_irq_to_resource(of_node, AHB0_INT_DT_IDX, &res[1])) {
		pr_err("failed to get ahb0_int resource\n");
		return -EFAULT;
	}

	if (!of_irq_to_resource(of_node, MLB_INT_DT_IDX, &res[2])) {
		pr_err("failed to get mlb_int resource\n");
		return -EFAULT;
	}

	if (arwen_pdata.pdev)
		return -ENOMEM;

	pdev = platform_device_alloc("medialb_dim2", 0);
	if (!pdev)
		return -ENOMEM;

	ret = platform_device_add_resources(pdev, res, ARRAY_SIZE(res));
	if (ret) {
		pr_err("Failed to add resources\n");
		goto out_free_pdev;
	}

	arwen_pdata.pdev = pdev;
	arwen_pdata.dev = &pdev_dt->dev;

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

static int dim2_dt_remove(struct platform_device *pdev_dt)
{
	platform_device_unregister(arwen_pdata.pdev);
	arwen_pdata.pdev = 0;
	return 0;
}

static struct platform_driver dim2_driver = {
	.probe = dim2_dt_probe,
	.remove = dim2_dt_remove,
	.driver = {
		.name = "dim2-dt-mlb3",
		.owner = THIS_MODULE,
		.of_match_table = dim2_arwen_dt_ids,
	},
};

MODULE_DEVICE_TABLE(of, dim2_arwen_dt_ids);

static int __init arwen_mlb_init(void)
{
	pr_info("arwen_mlb_init()\n");
	return platform_driver_register(&dim2_driver);
}

static void __exit arwen_mlb_exit(void)
{
	pr_info("arwen_mlb_exit()\n");
	platform_driver_unregister(&dim2_driver);
}

module_init(arwen_mlb_init);
module_exit(arwen_mlb_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrey Shvetsov <andrey.shvetsov@k2l.de>");
MODULE_DESCRIPTION("Arwen MediaLB DIM2 3 PIN Configuration dt-friendly Platform Device");
