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

static const char AIM_CDEV[] = "cdev";
static const char AIM_NETWORKING[] = "networking";

static const struct most_channel_config ctrl_rx_cfg = {
	.direction = MOST_CH_RX,
	.data_type = MOST_CH_CONTROL,
	.num_buffers = 8,
	.buffer_size = 128,
};

static const struct most_channel_config ctrl_tx_cfg = {
	.direction = MOST_CH_TX,
	.data_type = MOST_CH_CONTROL,
	.num_buffers = 8,
	.buffer_size = 128,
};

static const struct most_channel_config async_rx_cfg = {
	.direction = MOST_CH_RX,
	.data_type = MOST_CH_ASYNC,
	.num_buffers = 32,
	.buffer_size = 1548,
};

static const struct most_channel_config async_tx_cfg = {
	.direction = MOST_CH_TX,
	.data_type = MOST_CH_ASYNC,
	.num_buffers = 32,
	.buffer_size = 1548,
};

static struct most_config_probe config_probes_cdev[] = {
	{
		.ch_name = "ep8f",
		.cfg = &ctrl_rx_cfg,
		.aim_name = AIM_CDEV,
		.aim_param = "inic-ctrl-rx",
	},
	{
		.ch_name = "ep0f",
		.cfg = &ctrl_tx_cfg,
		.aim_name = AIM_CDEV,
		.aim_param = "inic-ctrl-tx",
	},
	{
		.ch_name = "ep8e",
		.cfg = &async_rx_cfg,
		.aim_name = AIM_CDEV,
		.aim_param = "inic-async-rx",
	},
	{
		.ch_name = "ep0e",
		.cfg = &async_tx_cfg,
		.aim_name = AIM_CDEV,
		.aim_param = "inic-async-tx",
	},
	{}
};
static struct most_config_probe config_probes_net[] = {
	{
		.ch_name = "ep8e",
		.cfg = &async_rx_cfg,
		.aim_name = AIM_NETWORKING,
		.aim_param = "",
	},
	{
		.ch_name = "ep0e",
		.cfg = &async_tx_cfg,
		.aim_name = AIM_NETWORKING,
		.aim_param = "",
	},
	{}
};

static const struct most_channel_config sync_rx_cfg = {
	.direction = MOST_CH_RX,
	.data_type = MOST_CH_SYNC,
	.num_buffers = 16,
	.buffer_size = 512,
};

static const struct most_channel_config sync_tx_cfg = {
	.direction = MOST_CH_TX,
	.data_type = MOST_CH_SYNC,
	.num_buffers = 16,
	.buffer_size = 512,
};

static const char AIM_MLB150[] = "mlb150";
static const char AIM_SYNCSOUND[] = "syncsound";

#define SYNC_FMT_CFG "1x16,128 2x16,128 2x24,128 6x16,64 6x24,16"
static struct most_config_probe config_probes_mlb150[] = {
	{
		.ch_name = "ep01",
		.cfg = &sync_tx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "8/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep02",
		.cfg = &sync_tx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "10/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep03",
		.cfg = &sync_tx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "12/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep04",
		.cfg = &sync_tx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "14/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep05",
		.cfg = &sync_tx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "16/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep06",
		.cfg = &sync_tx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "18/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep81",
		.cfg = &sync_rx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "7/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep82",
		.cfg = &sync_rx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "9/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep83",
		.cfg = &sync_rx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "11/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep84",
		.cfg = &sync_rx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "13/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep85",
		.cfg = &sync_rx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "15/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep86",
		.cfg = &sync_rx_cfg,
		.aim_name = AIM_MLB150,
		.aim_param = "17/" SYNC_FMT_CFG,
	},
	{}
};
static struct most_config_probe config_probes_syncsound[] = {
	{
		.ch_name = "ep01",
		.cfg = &sync_tx_cfg,
		.aim_name = AIM_SYNCSOUND,
		.aim_param = "MLB_SYNC0/" SYNC_FMT_CFG,
	},
	{
		.ch_name = "ep81",
		.cfg = &sync_rx_cfg,
		.aim_name = AIM_SYNCSOUND,
		.aim_param = "MLB_SYNC0/" SYNC_FMT_CFG,
	},
	{}
};

static struct most_config_set config_set[] = {
	{ .probes = config_probes_cdev },
	{ .probes = config_probes_net },
	{ .probes = config_probes_mlb150 },
	{ .probes = config_probes_syncsound },
};

static int __init mod_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(config_set); ++i)
		most_register_config_set(config_set + i);
	return 0;
}

static void __exit mod_exit(void)
{
	int i;

	for (i = ARRAY_SIZE(config_set); --i >= 0;)
		most_deregister_config_set(config_set + i);
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cetitec Development <info@cetitec.com>");
MODULE_DESCRIPTION("Default configuration of the MOST driver for Honda USB INIC prototype");
