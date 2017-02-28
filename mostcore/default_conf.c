/*
 * default_conf.c - Default configuration for the MOST channels.
 *
 * Copyright (C) 2017, Microchip Technology Germany II GmbH & Co. KG
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This file is licensed under GPLv2.
 */

#include "mostcore.h"
#include <linux/module.h>

static struct most_config_probe config_probes[] = {
	/* MediaLB */
	{
		.ch_name = "ca2",
		.cfg = {
			.direction = MOST_CH_RX,
			.data_type = MOST_CH_CONTROL,
			.num_buffers = 16,
			.buffer_size = 64,
		},
		.aim_name = "cdev",
		.aim_param = "inic-mlb-crx",
	},
	{
		.ch_name = "ca4",
		.cfg = {
			.direction = MOST_CH_TX,
			.data_type = MOST_CH_CONTROL,
			.num_buffers = 16,
			.buffer_size = 64,
		},
		.aim_name = "cdev",
		.aim_param = "inic-mlb-ctx",
	},
	{
		.ch_name = "ca6",
		.cfg = {
			.direction = MOST_CH_RX,
			.data_type = MOST_CH_ASYNC,
			.num_buffers = 20,
			.buffer_size = 1522,
		},
		.aim_name = "cdev",
		.aim_param = "inic-mlb-arx",
	},
	{
		.ch_name = "ca8",
		.cfg = {
			.direction = MOST_CH_TX,
			.data_type = MOST_CH_ASYNC,
			.num_buffers = 20,
			.buffer_size = 1522,
		},
		.aim_name = "cdev",
		.aim_param = "inic-mlb-atx",
	},

	/* USB */
	{
		.ch_name = "ep8f",
		.cfg = {
			.direction = MOST_CH_RX,
			.data_type = MOST_CH_CONTROL,
			.num_buffers = 16,
			.buffer_size = 64,
		},
		.aim_name = "cdev",
		.aim_param = "inic-usb-crx",
	},
	{
		.ch_name = "ep0f",
		.cfg = {
			.direction = MOST_CH_TX,
			.data_type = MOST_CH_CONTROL,
			.num_buffers = 16,
			.buffer_size = 64,
		},
		.aim_name = "cdev",
		.aim_param = "inic-usb-ctx",
	},
	{
		.ch_name = "ep8e",
		.cfg = {
			.direction = MOST_CH_RX,
			.data_type = MOST_CH_ASYNC,
			.num_buffers = 20,
			.buffer_size = 1522,
		},
		.aim_name = "cdev",
		.aim_param = "inic-usb-arx",
	},
	{
		.ch_name = "ep0e",
		.cfg = {
			.direction = MOST_CH_TX,
			.data_type = MOST_CH_ASYNC,
			.num_buffers = 20,
			.buffer_size = 1522,
		},
		.aim_name = "cdev",
		.aim_param = "inic-usb-atx",
	},
	{
		.ch_name = "ep81",
		.cfg = {
			.direction = MOST_CH_RX,
			.data_type = MOST_CH_ISOC,
			.num_buffers = 20,
			.buffer_size = 188 * 8,
			.subbuffer_size = 188,
			.packets_per_xact = 2,
		},
		.aim_name = "v4l",
		.aim_param = "ep81",
	},
	{
		.ch_name = "ep82",
		.cfg = {
			.direction = MOST_CH_RX,
			.data_type = MOST_CH_SYNC,
			.num_buffers = 20,
			.buffer_size = 8192,
			.subbuffer_size = 4,
			.packets_per_xact = 128,
		},
		.aim_name = "sound",
		.aim_param = "ep82.2x16",
	},

	/* sentinel */
	{}
};

static struct most_config_set config_set = {
	.probes = config_probes
};

static int __init mod_init(void)
{
	most_register_config_set(&config_set);
	return 0;
}

static void __exit mod_exit(void)
{
	most_deregister_config_set(&config_set);
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrey Shvetsov <andrey.shvetsov@k2l.de>");
MODULE_DESCRIPTION("Default configuration for the MOST channels");
