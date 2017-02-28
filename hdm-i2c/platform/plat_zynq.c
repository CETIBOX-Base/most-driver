/*
 * plat_zynq.c - ZYNQ Platform Dependent Module for I2C Interface
 *
 * Copyright (C) 2014-2015, Microchip Technology Germany II GmbH & Co. KG
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
#include <linux/i2c.h>
#include <linux/of_irq.h>

/* Platform Specific */
#define ZYNQ_INIC_I2C_BUS  1

static struct i2c_board_info inic_i2c_board_info = {
	I2C_BOARD_INFO("most_i2c", 0x20)
};

struct i2c_client *client;

static int __init zynq_i2c_init(void)
{
	struct i2c_adapter *i2c_adapter;
	struct device_node *glue_logic_node;
	int ret = -ENODEV;

	pr_info("zynq_i2c_init()\n");

	i2c_adapter = i2c_get_adapter(ZYNQ_INIC_I2C_BUS);
	if (!i2c_adapter) {
		pr_err("Failed to get i2c adapter %d\n", ZYNQ_INIC_I2C_BUS);
		return ret;
	}

	glue_logic_node = of_find_compatible_node(NULL, NULL,
						  "xlnx,axi4-glue-logic-1.01.a");
	if (!glue_logic_node) {
		pr_err("Cannot find glue_logic module\n");
		goto error;
	}

	inic_i2c_board_info.irq = irq_of_parse_and_map(glue_logic_node, 1);
	if (inic_i2c_board_info.irq <= 0) {
		pr_err("Failed to get IRQ\n");
		goto error;
	}

	client = i2c_new_device(i2c_adapter, &inic_i2c_board_info);
	if (!client) {
		pr_err("Failed to get allocate new i2c device\n");
		goto error;
	}

	ret = 0;
error:
	i2c_put_adapter(i2c_adapter);
	return ret;
}

static void __exit zynq_i2c_exit(void)
{
	pr_info("zynq_i2c_exit()\n");

	i2c_unregister_device(client);
}

module_init(zynq_i2c_init);
module_exit(zynq_i2c_exit);

MODULE_DESCRIPTION("I2C Platform Dependent Module");
MODULE_LICENSE("GPL");
