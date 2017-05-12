/*
 * isostream.c - Application interfacing module for V4L2 devices
 * emulating the interface provided by the isostream driver
 *
 * Copyright (C) 2017 Cetitec GmbH
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
#include "mostcore.h"
#include "mlb150.h"
#include "mlb150_ext.h"

#define DRIVER_NAME "aim-isostream"


static int __init mod_init(void)
{
	mlb150_lock_channel(1, true);
	return -ENOTSUPP;
}

static void __exit mod_exit(void)
{
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Cetitec GmbH <support@cetitec.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("V4L2 device AIM (isostream interface) for mostcore");
