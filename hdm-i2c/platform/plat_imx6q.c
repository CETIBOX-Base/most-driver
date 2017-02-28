/*
 * plat_imx6q.c - IMX6Q Platform Dependent Module for I2C Interface
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
#include <linux/interrupt.h>
#include <linux/gpio.h>
#include <linux/i2c.h>

/* Platform Specific */
#define IMX_GPIO_NR(bank, nr)	(((bank) - 1) * 32 + (nr))
#define IMX6Q_INIC_INT	IMX_GPIO_NR(4, 9)
#define IMX6Q_INIC_I2C_BUS  2

static struct i2c_board_info inic_i2c_board_info = {
	I2C_BOARD_INFO("most_i2c", 0x20)
};

struct i2c_client *client;

static int __init imx6q_i2c_init(void)
{
	struct i2c_adapter *i2c_adapter;
	int ret = -ENODEV;

	pr_info("imx6q_i2c_init()\n");

	i2c_adapter = i2c_get_adapter(IMX6Q_INIC_I2C_BUS);
	if (!i2c_adapter) {
		pr_err("Failed to get i2c adapter %d\n", IMX6Q_INIC_I2C_BUS);
		return ret;
	}

	inic_i2c_board_info.irq = gpio_to_irq(IMX6Q_INIC_INT);
	if (!inic_i2c_board_info.irq) {
		pr_err("Failed to get IRQ number %d\n", IMX6Q_INIC_INT);
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

static void __exit imx6q_i2c_exit(void)
{
	pr_info("imx6q_i2c_exit()\n");

	i2c_unregister_device(client);
}

module_init(imx6q_i2c_init);
module_exit(imx6q_i2c_exit);

MODULE_DESCRIPTION("I2C Platform Dependent Module");
MODULE_LICENSE("GPL");
