/*
 * i2s_hdm.c - Hardware Dependent Module for I2S
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
#include <linux/kobject.h>

#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/stat.h>

#include <mostcore.h>

#include "i2s_clkgen.h"
#include "i2s_hdm.h"



#define DRIVER_NAME "hdm_i2s"
#define DRIVER_VERSION "0.5.0"

/*
 * We use 4 channels per port.
 * So channels 0..3 belong to port A and channels 4..7 belong to port B.
 */
#define DMA_CHANNELS_PER_PORT 4
#define DMA_CHANNELS (DMA_CHANNELS_PER_PORT * 2)

#define QUADLETS_THRESHOLD 496U /* QUADLETS_511 */

#define FIFO_WIDTH 4096
#define MAX_BUFFERS_STREAMING 32
#define MAX_BUF_SIZE_STREAMING (QUADLETS_THRESHOLD * 4)
/* Defines how many buffers have to be written before the channel is enabled */
#define INITAL_WR_BEFORE_EN (FIFO_WIDTH / MAX_BUF_SIZE_STREAMING)

/**
 * struct i2s_channel - private structure to keep channel specific data
 * @is_initialized: identifier to know whether the channel is initialized
 * @bytes_per_frame: user configurable frame size
 * @direction: channel direction (TX or RX)
 * @pending_list: list head to hold MBOs received from mostcore
 * @ready: indicates a channel is ready to transfer data
 * @fifo_overflow: set when there is a fifo overflow in hardware
 * @fifo_underflow: set when there is a fifo underflow in hardware
 */
struct i2s_channel {
	bool is_initialized;
	bool is_enabled;
	u8 bytes_per_frame;
	enum most_channel_direction direction;
	struct list_head pending_list;
	volatile bool ready;
	bool fifo_overflow;
	bool fifo_underflow;
	u8 mbo_count;
};

/**
 * struct i2s_port - private structure to keep i2s port specific data
 * @clk_mode: clock mode to identify master or slave
 * @clk_speed: clock speed (8FS to 512FS)
 * @data_format: data format (left/right justified, sequential, delayed-bit)
 * @is_enabled: identifier to know whether the port is enabled by user
 */
struct i2s_port {
	enum i2s_clk_mode clk_mode;
	enum i2s_clk_speed clk_speed;
	enum i2s_data_format data_format;
	u8 is_enabled;
};

struct i2s_bus_obj;

/**
 * struct hdm_i2s - private structure to keep interface specific data
 * @ch: an array of channel specific data
 * @capabilites: an array of channel supported Data Types and directions
 * @most_iface: most interface object
 * @port_a: port A configuration
 * @port_b: port B configuration
 * @irq: IRQ number used by the interface
 * @i2s_base: I/O register base address for I2S IP
 * @clk_gen_base: I/O register base address for clock generator IP
 * @clock_source: clock input signal
 * @completed_list: list head to hold completed MBOs from all channels
 */
struct hdm_i2s {
	struct i2s_channel ch[DMA_CHANNELS];
	struct most_channel_capability capabilites[DMA_CHANNELS];
	struct most_interface most_iface;
	struct i2s_port port_a;
	struct i2s_port port_b;
	unsigned int irq;
	void *i2s_base;
	void *clk_gen_base;
	enum i2s_clk_source clk_source;
	u8 is_enabled;
	struct i2s_bus_obj *bus;
};

#define iface_to_hdm(iface) container_of(iface, struct hdm_i2s, most_iface)

/**
 * struct i2s_bus_obj - Direct Communication Interface
 * @kobj: kobject structure object
 * @dev: hdm private structure
 */
struct i2s_bus_obj {
	struct kobject kobj;
	struct hdm_i2s *dev;
};
#define to_bus_obj(p) container_of(p, struct i2s_bus_obj, kobj)

static DEFINE_SPINLOCK(i2s_lock);

static void i2s_tasklet_fn(unsigned long data);
static DECLARE_TASKLET(i2s_tasklet, i2s_tasklet_fn, 0);

static int i2s_enable(struct hdm_i2s *dev);
static void i2s_disable(struct hdm_i2s *dev);
static void complete_all_mbos(struct list_head *head);

/**
 * struct i2s_bus_attribute
 * @attr: attribute structure object
 * @show: pointer to show function
 * @store: pointer to store function
 *
 */
struct i2s_bus_attribute {
	struct attribute attr;
	ssize_t (*show)(struct i2s_bus_obj *d,
			struct i2s_bus_attribute *attr,
			char *buf);
	ssize_t (*store)(struct i2s_bus_obj *d,
			 struct i2s_bus_attribute *attr,
			 const char *buf,
			 size_t count);
};

#define I2S_BUS_ATTR(_name) \
	struct i2s_bus_attribute i2s_bus_attr_##_name = \
		__ATTR_RW(_name);

#define to_bus_attr(a) container_of(a, struct i2s_bus_attribute, attr)


/**
 * bus_attr_show - show function for bus object
 * @kobj: pointer to kobject
 * @attr: pointer to attribute struct
 * @buf: buffer
 */
static ssize_t bus_attr_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct i2s_bus_attribute *bus_attr = to_bus_attr(attr);
	struct i2s_bus_obj *bus_obj = to_bus_obj(kobj);

	if (!bus_attr->show)
		return -EIO;

	return bus_attr->show(bus_obj, bus_attr, buf);
}

/**
 * bus_attr_store - store function for bus object
 * @kobj: pointer to kobject
 * @attr: pointer to attribute struct
 * @buf: buffer
 * @len: length of buffer
 */
static ssize_t bus_attr_store(struct kobject *kobj,
			      struct attribute *attr,
			      const char *buf,
			      size_t len)
{
	struct i2s_bus_attribute *bus_attr = to_bus_attr(attr);
	struct i2s_bus_obj *bus_obj = to_bus_obj(kobj);

	if (!bus_attr->store)
		return -EIO;

	return bus_attr->store(bus_obj, bus_attr, buf, len);
}

static const struct sysfs_ops i2s_bus_sysfs_ops = {
	.show = bus_attr_show,
	.store = bus_attr_store,
};

/**
 * i2s_bus_release - release function for bus object
 * @kobj: pointer to kobject
 *
 * This frees the memory allocated for the bus object
 */
static void i2s_bus_release(struct kobject *kobj)
{
	struct i2s_bus_obj *bus_obj = to_bus_obj(kobj);

	kfree(bus_obj);
}


/* Store SysFS functions */
static ssize_t clock_source_store(struct i2s_bus_obj *bus_obj,
				  struct i2s_bus_attribute *attr,
				  const char *buf, size_t count)
{
	struct hdm_i2s *dev = bus_obj->dev;

	if (strcmp(buf, "phy1_rmck0\n") == 0) {
		dev->clk_source = PHY1_RMCK0;
	} else if (strcmp(buf, "phy1_rmck1\n") == 0) {
		dev->clk_source = PHY1_RMCK1;
	} else if (strcmp(buf, "phy2_rmck0\n") == 0) {
		dev->clk_source = PHY2_RMCK0;
	} else if (strcmp(buf, "phy2_rmck1\n") == 0) {
		dev->clk_source = PHY2_RMCK1;
	} else if (strcmp(buf, "dbg_clk\n") == 0) {
		dev->clk_source = DBG_CLK;
	} else if (strcmp(buf, "osc1_clk\n") == 0) {
		dev->clk_source = OSC1_CLK;
	} else if (strcmp(buf, "osc2_clk\n") == 0) {
		dev->clk_source = OSC2_CLK;
	} else if (strcmp(buf, "osc3_clk\n") == 0) {
		dev->clk_source = OSC3_CLK;
	} else {
		pr_info("Unknown value for I2S clock source\n");
		return -EIO;
	}
	return count;
}

static ssize_t port_a_enable_store(struct i2s_bus_obj *bus_obj,
				   struct i2s_bus_attribute *attr,
				   const char *buf, size_t count)
{
	struct i2s_port *port = &bus_obj->dev->port_a;

	if (strcmp(buf, "1\n") == 0) {
		port->is_enabled = 1;
	} else if (strcmp(buf, "0\n") == 0) {
		port->is_enabled = 0;
	} else {
		pr_info("Unknown value for I2S Port A Enable\n");
		return -EIO;
	}
	return count;
}

static ssize_t port_a_clock_speed_store(struct i2s_bus_obj *bus_obj,
					struct i2s_bus_attribute *attr,
					const char *buf, size_t count)
{
	struct i2s_port *port = &bus_obj->dev->port_a;
	if (strcmp(buf, "8fs\n") == 0) {
		port->clk_speed = I2S_CLK_8FS;
	} else if (strcmp(buf, "16fs\n") == 0) {
		port->clk_speed = I2S_CLK_16FS;
	} else if (strcmp(buf, "32fs\n") == 0) {
		port->clk_speed = I2S_CLK_32FS;
	} else if (strcmp(buf, "64fs\n") == 0) {
		port->clk_speed = I2S_CLK_64FS;
	} else if (strcmp(buf, "128fs\n") == 0) {
		port->clk_speed = I2S_CLK_128FS;
	} else if (strcmp(buf, "256fs\n") == 0) {
		port->clk_speed = I2S_CLK_256FS;
	} else if (strcmp(buf, "512fs\n") == 0) {
		port->clk_speed = I2S_CLK_512FS;
	} else {
		port->clk_speed = I2S_CLK_UDEF;
		pr_info("Unknown value for I2S Port B Clock Speed\n");
	}
	return count;
}

static ssize_t port_a_clock_mode_store(struct i2s_bus_obj *bus_obj,
				       struct i2s_bus_attribute *attr,
				       const char *buf, size_t count)
{
	struct i2s_port *port = &bus_obj->dev->port_a;
	if (strcmp(buf, "master\n") == 0) {
		port->clk_mode = I2S_CLKMODE_MASTER;
	} else if (strcmp(buf, "slave\n") == 0) {
		port->clk_mode = I2S_CLKMODE_SLAVE;
	} else {
		port->clk_mode = I2S_CLKMODE_UDEF;
		pr_info("Unknown value for I2S Port A Clock Mode\n");
	}
	return count;
}

static ssize_t port_a_data_format_store(struct i2s_bus_obj *bus_obj,
					struct i2s_bus_attribute *attr,
					const char *buf, size_t count)
{
	struct i2s_port *port = &bus_obj->dev->port_a;
	if (strcmp(buf, "delayed\n") == 0) {
		port->data_format = I2S_DATA_DEL;
	} else if (strcmp(buf, "delayed_seq\n") == 0) {
		port->data_format = I2S_DATA_DEL_SEQ;
	} else if (strcmp(buf, "seq\n") == 0) {
		port->data_format = I2S_DATA_SEQ;
	} else if (strcmp(buf, "left_mono\n") == 0) {
		port->data_format = I2S_DATA_LEFT_MONO;
	} else if (strcmp(buf, "left_stereo\n") == 0) {
		port->data_format = I2S_DATA_LEFT_STEREO;
	} else if (strcmp(buf, "right_mono\n") == 0) {
		port->data_format = I2S_DATA_RIGHT_MONO;
	} else if (strcmp(buf, "right_stereo\n") == 0) {
		port->data_format = I2S_DATA_RIGHT_STEREO;
	} else {
		port->data_format = I2S_DATA_UDEF;
		pr_info("Unknown value for I2S Port B data format\n");
	}
	return count;
}

static ssize_t port_b_enable_store(struct i2s_bus_obj *bus_obj,
				   struct i2s_bus_attribute *attr,
				   const char *buf, size_t count)
{
	struct i2s_port *port = &bus_obj->dev->port_b;

	if (strcmp(buf, "1\n") == 0) {
		port->is_enabled = 1;
	} else if (strcmp(buf, "0\n") == 0) {
		port->is_enabled = 0;
	} else {
		pr_info("Unknown value for I2S Port B Enable\n");
		return -EIO;
	}
	return count;
}
static ssize_t port_b_clock_speed_store(struct i2s_bus_obj *bus_obj,
					struct i2s_bus_attribute *attr,
					const char *buf, size_t count)
{
	struct i2s_port *port = &bus_obj->dev->port_b;
	if (strcmp(buf, "8fs\n") == 0) {
		port->clk_speed = I2S_CLK_8FS;
	} else if (strcmp(buf, "16fs\n") == 0) {
		port->clk_speed = I2S_CLK_16FS;
	} else if (strcmp(buf, "32fs\n") == 0) {
		port->clk_speed = I2S_CLK_32FS;
	} else if (strcmp(buf, "64fs\n") == 0) {
		port->clk_speed = I2S_CLK_64FS;
	} else if (strcmp(buf, "128fs\n") == 0) {
		port->clk_speed = I2S_CLK_128FS;
	} else if (strcmp(buf, "256fs\n") == 0) {
		port->clk_speed = I2S_CLK_256FS;
	} else if (strcmp(buf, "512fs\n") == 0) {
		port->clk_speed = I2S_CLK_512FS;
	} else {
		port->clk_speed = I2S_CLK_UDEF;
		pr_info("Unknown value for I2S Port B Clock Speed\n");
	}
	return count;
}
static ssize_t port_b_clock_mode_store(struct i2s_bus_obj *bus_obj,
				       struct i2s_bus_attribute *attr,
				       const char *buf, size_t count)
{
	struct i2s_port *port = &bus_obj->dev->port_b;
	if (strcmp(buf, "master\n") == 0) {
		port->clk_mode = I2S_CLKMODE_MASTER;
	} else if (strcmp(buf, "slave\n") == 0) {
		port->clk_mode = I2S_CLKMODE_SLAVE;
	} else {
		port->clk_mode = I2S_CLKMODE_UDEF;
		pr_info("Unknown value for I2S Port B Clock Mode\n");
	}
	return count;
}

static ssize_t port_b_data_format_store(struct i2s_bus_obj *bus_obj,
					struct i2s_bus_attribute *attr,
					const char *buf, size_t count)
{
	struct i2s_port *port = &bus_obj->dev->port_b;
	if (strcmp(buf, "delayed\n") == 0) {
		port->data_format = I2S_DATA_DEL;
	} else if (strcmp(buf, "delayed_seq\n") == 0) {
		port->data_format = I2S_DATA_DEL_SEQ;
	} else if (strcmp(buf, "seq\n") == 0) {
		port->data_format = I2S_DATA_SEQ;
	} else if (strcmp(buf, "left_mono\n") == 0) {
		port->data_format = I2S_DATA_LEFT_MONO;
	} else if (strcmp(buf, "left_stereo\n") == 0) {
		port->data_format = I2S_DATA_LEFT_STEREO;
	} else if (strcmp(buf, "right_mono\n") == 0) {
		port->data_format = I2S_DATA_RIGHT_MONO;
	} else if (strcmp(buf, "right_stereo\n") == 0) {
		port->data_format = I2S_DATA_RIGHT_STEREO;
	} else {
		port->data_format = I2S_DATA_UDEF;
		pr_info("Unknown value for I2S Port B data format\n");
	}
	return count;
}

static ssize_t bus_enable_store(struct i2s_bus_obj *bus_obj,
				struct i2s_bus_attribute *attr,
				const char *buf, size_t count)
{
	struct hdm_i2s *dev = bus_obj->dev;
	if (strcmp(buf, "1\n") == 0 && dev->is_enabled == 0) {
		if (i2s_enable(dev) == 0)
			dev->is_enabled = 1;
	} else if (strcmp(buf, "0\n") == 0 && dev->is_enabled == 1) {
		i2s_disable(dev);
		dev->is_enabled = 0;
	} else {
		pr_info("Unknown value for I2S bus enable\n");
	}
	return count;
}

/* Show SysFS functions */

static ssize_t clock_source_show(struct i2s_bus_obj *bus_obj,
				 struct i2s_bus_attribute *attr,
				 char *buf)
{
	struct hdm_i2s *dev = bus_obj->dev;

	if (dev->clk_source == PHY1_RMCK0)
		strcat(buf, "phy1_rmck0\n");
	else if (dev->clk_source == PHY1_RMCK1)
		strcat(buf, "phy1_rmck1\n");
	else if (dev->clk_source == PHY2_RMCK0)
		strcat(buf, "phy2_rmck0\n");
	else if (dev->clk_source == PHY2_RMCK1)
		strcat(buf, "phy2_rmck1\n");
	else if (dev->clk_source == DBG_CLK)
		strcat(buf, "dbg_clk\n");
	else if (dev->clk_source == OSC1_CLK)
		strcat(buf, "osc1_clk\n");
	else if (dev->clk_source == OSC2_CLK)
		strcat(buf, "osc2_clk\n");
	else if (dev->clk_source == OSC3_CLK)
		strcat(buf, "osc3_clk\n");
	else
		strcat(buf, "undefined\n");
	return strlen(buf) + 1;
}

static ssize_t port_a_enable_show(struct i2s_bus_obj *bus_obj,
				  struct i2s_bus_attribute *attr,
				  char *buf)
{
	struct i2s_port port = bus_obj->dev->port_a;
	if (port.is_enabled == 1)
		strcat(buf, "enabled\n");
	else
		strcat(buf, "disabled\n");
	return strlen(buf) + 1;
}

static ssize_t port_a_clock_speed_show(struct i2s_bus_obj *bus_obj,
				       struct i2s_bus_attribute *attr,
				       char *buf)
{
	struct i2s_port port = bus_obj->dev->port_a;
	if (port.clk_speed == I2S_CLK_8FS)
		strcat(buf, "8fs\n");
	else if (port.clk_speed == I2S_CLK_16FS)
		strcat(buf, "16fs\n");
	else if (port.clk_speed == I2S_CLK_32FS)
		strcat(buf, "32fs\n");
	else if (port.clk_speed == I2S_CLK_64FS)
		strcat(buf, "64fs\n");
	else if (port.clk_speed == I2S_CLK_128FS)
		strcat(buf, "128fs\n");
	else if (port.clk_speed == I2S_CLK_256FS)
		strcat(buf, "256fs\n");
	else if (port.clk_speed == I2S_CLK_512FS)
		strcat(buf, "512fs\n");
	else
		strcat(buf, "undefined\n");
	return strlen(buf) + 1;
}

static ssize_t port_a_clock_mode_show(struct i2s_bus_obj *bus_obj,
				      struct i2s_bus_attribute *attr,
				      char *buf)
{
	struct i2s_port port = bus_obj->dev->port_a;
	if (port.clk_mode == I2S_CLKMODE_MASTER)
		strcat(buf, "master\n");
	else if (port.clk_mode == I2S_CLKMODE_SLAVE)
		strcat(buf, "slave\n");
	else
		strcat(buf, "undefined\n");
	return strlen(buf) + 1;
}

static ssize_t port_a_data_format_show(struct i2s_bus_obj *bus_obj,
				       struct i2s_bus_attribute *attr,
				       char *buf)
{
	struct i2s_port port = bus_obj->dev->port_a;
	if (port.data_format == I2S_DATA_DEL)
		strcat(buf, "delayed\n");
	else if (port.data_format == I2S_DATA_DEL_SEQ)
		strcat(buf, "delayed_seq\n");
	else if (port.data_format == I2S_DATA_SEQ)
		strcat(buf, "seq\n");
	else if (port.data_format == I2S_DATA_LEFT_MONO)
		strcat(buf, "left_mono\n");
	else if (port.data_format == I2S_DATA_LEFT_STEREO)
		strcat(buf, "left_stereo\n");
	else if (port.data_format == I2S_DATA_RIGHT_MONO)
		strcat(buf, "right_mono\n");
	else if (port.data_format == I2S_DATA_RIGHT_STEREO)
		strcat(buf, "right_stereo\n");
	else
		strcat(buf, "undefined\n");
	return strlen(buf) + 1;
}

static ssize_t port_b_enable_show(struct i2s_bus_obj *bus_obj,
				  struct i2s_bus_attribute *attr,
				  char *buf)
{
	struct i2s_port port = bus_obj->dev->port_b;
	if (port.is_enabled == 1)
		strcat(buf, "enabled\n");
	else
		strcat(buf, "disabled\n");
	return strlen(buf) + 1;
}

static ssize_t port_b_clock_speed_show(struct i2s_bus_obj *bus_obj,
				       struct i2s_bus_attribute *attr,
				       char *buf)
{
	struct i2s_port port = bus_obj->dev->port_b;
	if (port.clk_speed == I2S_CLK_8FS)
		strcat(buf, "8fs\n");
	else if (port.clk_speed == I2S_CLK_16FS)
		strcat(buf, "16fs\n");
	else if (port.clk_speed == I2S_CLK_32FS)
		strcat(buf, "32fs\n");
	else if (port.clk_speed == I2S_CLK_64FS)
		strcat(buf, "64fs\n");
	else if (port.clk_speed == I2S_CLK_128FS)
		strcat(buf, "128fs\n");
	else if (port.clk_speed == I2S_CLK_256FS)
		strcat(buf, "256fs\n");
	else if (port.clk_speed == I2S_CLK_512FS)
		strcat(buf, "512fs\n");
	else
		strcat(buf, "undefined\n");
	return strlen(buf) + 1;
}

static ssize_t port_b_clock_mode_show(struct i2s_bus_obj *bus_obj,
				      struct i2s_bus_attribute *attr,
				      char *buf)
{
	struct i2s_port port = bus_obj->dev->port_b;
	if (port.clk_mode == I2S_CLKMODE_MASTER)
		strcat(buf, "master\n");
	else if (port.clk_mode == I2S_CLKMODE_SLAVE)
		strcat(buf, "slave\n");
	else
		strcat(buf, "undefined\n");
	return strlen(buf) + 1;
}

static ssize_t port_b_data_format_show(struct i2s_bus_obj *bus_obj,
				       struct i2s_bus_attribute *attr,
				       char *buf)
{
	struct i2s_port port = bus_obj->dev->port_b;
	if (port.data_format == I2S_DATA_DEL)
		strcat(buf, "delayed\n");
	else if (port.data_format == I2S_DATA_DEL_SEQ)
		strcat(buf, "delayed_seq\n");
	else if (port.data_format == I2S_DATA_SEQ)
		strcat(buf, "seq\n");
	else if (port.data_format == I2S_DATA_LEFT_MONO)
		strcat(buf, "left_mono\n");
	else if (port.data_format == I2S_DATA_LEFT_STEREO)
		strcat(buf, "left_stereo\n");
	else if (port.data_format == I2S_DATA_RIGHT_MONO)
		strcat(buf, "right_mono\n");
	else if (port.data_format == I2S_DATA_RIGHT_STEREO)
		strcat(buf, "right_stereo\n");
	else
		strcat(buf, "undefined\n");
	return strlen(buf) + 1;
}

static ssize_t bus_enable_show(struct i2s_bus_obj *bus_obj,
			       struct i2s_bus_attribute *attr,
			       char *buf)
{
	struct hdm_i2s *dev = bus_obj->dev;
	if (dev->is_enabled == 1)
		strcat(buf, "enabled\n");
	else
		strcat(buf, "disabled\n");
	return strlen(buf) + 1;
}

static I2S_BUS_ATTR(clock_source);
static I2S_BUS_ATTR(port_a_enable);
static I2S_BUS_ATTR(port_a_clock_mode);
static I2S_BUS_ATTR(port_a_clock_speed);
static I2S_BUS_ATTR(port_a_data_format);
static I2S_BUS_ATTR(port_b_enable);
static I2S_BUS_ATTR(port_b_clock_mode);
static I2S_BUS_ATTR(port_b_clock_speed);
static I2S_BUS_ATTR(port_b_data_format);
static I2S_BUS_ATTR(bus_enable);

/**
 * i2s_bus_def_attrs - array of default attribute files of the bus object
 */
static struct attribute *i2s_bus_def_attrs[] = {
	&i2s_bus_attr_clock_source.attr,
	&i2s_bus_attr_port_a_enable.attr,
	&i2s_bus_attr_port_a_clock_mode.attr,
	&i2s_bus_attr_port_a_clock_speed.attr,
	&i2s_bus_attr_port_a_data_format.attr,
	&i2s_bus_attr_port_b_enable.attr,
	&i2s_bus_attr_port_b_clock_mode.attr,
	&i2s_bus_attr_port_b_clock_speed.attr,
	&i2s_bus_attr_port_b_data_format.attr,
	&i2s_bus_attr_bus_enable.attr,
	NULL,
};

/**
 * bus ktype
 */
static struct kobj_type i2s_bus_ktype = {
	.sysfs_ops = &i2s_bus_sysfs_ops,
	.release = i2s_bus_release,
	.default_attrs = i2s_bus_def_attrs,
};


/**
 * create_i2s_bus_obj - allocates a bus object
 * @parent: parent kobject
 *
 * This creates a bus object and registers it with sysfs.
 * Returns a pointer to the object or NULL when something went wrong.
 */
static struct
i2s_bus_obj *create_i2s_bus_obj(struct kobject *parent)
{
	struct i2s_bus_obj *i2s_bus;
	int retval;

	i2s_bus = kzalloc(sizeof(*i2s_bus), GFP_KERNEL);
	if (!i2s_bus)
		return NULL;

	retval = kobject_init_and_add(&i2s_bus->kobj, &i2s_bus_ktype, parent,
				      "bus");
	if (retval) {
		kobject_put(&i2s_bus->kobj);
		return NULL;
	}

	return i2s_bus;
}

/**
 * destroy_i2s_bus_obj - bus object release function
 * @p: pointer to bus object
 *
 * This decrements the reference counter of the bus object.
 * If the reference count turns zero, its release function is called.
 */
static void destroy_i2s_bus_obj(struct i2s_bus_obj *p)
{
	kobject_put(&p->kobj);
}

/**
 * write_reg_i2s - write value to an I2S register
 * @dev: private data
 * @reg_offset: offset of the register
 * @value: value to write
 */
static inline void write_reg_i2s(struct hdm_i2s *dev, unsigned long reg_offset,
				 uint32_t value)
{
	__raw_writel(value, (u32 *)(dev->i2s_base) + reg_offset);
}

/**
 * read_reg_i2s - read value of an I2S register
 * @dev: private data
 * @reg_offset: offset of the register
 */
static inline uint32_t read_reg_i2s(struct hdm_i2s *dev,
				    unsigned long reg_offset)
{
	return __raw_readl((u32 *)(dev->i2s_base) + reg_offset);
}

static inline int is_port_a(int ch_idx)
{
	return ch_idx < DMA_CHANNELS_PER_PORT;
}


static int start_data_transfer(struct hdm_i2s *dev, int ch_idx)
{
	struct i2s_channel *ch = dev->ch + ch_idx;
	struct list_head *head = &ch->pending_list;
	unsigned long offset = ch_idx * 0x08;
	unsigned long i, noofquadlet;
	unsigned long flags;
	struct mbo *mbo;
	u32 *qptr;

	spin_lock_irqsave(&i2s_lock, flags);
	if (list_empty(head)) {
		pr_err("No MBO, ch: %d\n", ch_idx);
		spin_unlock_irqrestore(&i2s_lock, flags);
		return -EAGAIN;
	}
	/* Get highest MBO and remove it from pending list */
	mbo = list_entry(head->next, struct mbo, list);


	qptr = (u32 *)mbo->virt_address;
	noofquadlet = mbo->buffer_length / 4;

	if (ch->direction == MOST_CH_RX) {
		unsigned long reg = REG_CBBARn + offset;
		for (i = 0; i < noofquadlet; i++)
			qptr[i] = read_reg_i2s(dev, reg);
	} else {
		unsigned long reg = REG_NBBARn + offset;
		for (i = 0; i < noofquadlet; i++)
			write_reg_i2s(dev, reg, qptr[i]);
	}
	list_del(head->next);
	mbo->processed_length = mbo->buffer_length;
	mbo->status = MBO_SUCCESS;
	mbo->complete(mbo);

	/* Reset ready flag and reenable interrupts */
	ch->ready = false;
	if (ch->direction == MOST_CH_TX) {
		/* Clear TX Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, TX_SERV_REQ_INT);
		/* Re-enable Tx Interrupts (mask interrupts again) */
		write_reg_i2s(dev, REG_CCRn + offset,
			      read_reg_i2s(dev, REG_CCRn + offset) & TX_INT_MASK);
	} else {
		/* Clear RX Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, RX_SERV_REQ_INT);
		/* Re-enable Rx Interrupts (mask interrupts again) */
		write_reg_i2s(dev, REG_CCRn + offset,
			      read_reg_i2s(dev, REG_CCRn + offset) & RX_INT_MASK);
	}

	spin_unlock_irqrestore(&i2s_lock, flags);

	return 0;
}

static u32 get_byte_count_reg_val(struct hdm_i2s *dev, int ch_idx)
{
	u32 regValue;
	struct i2s_channel *i2s_ch = &dev->ch[ch_idx];
	struct i2s_port    *i2s_port;
	if (is_port_a(ch_idx))
		i2s_port = &dev->port_a;
	else
		i2s_port = &dev->port_b;

	if (i2s_port->data_format == I2S_DATA_UDEF)
		regValue = 0x0;
	else if (i2s_port->data_format == I2S_DATA_LEFT_MONO)
		regValue = (i2s_ch->bytes_per_frame << I2S_LEFT_SHIFT) & I2S_LEFT_MASK;
	else if (i2s_port->data_format == I2S_DATA_RIGHT_MONO)
		regValue = (i2s_ch->bytes_per_frame << I2S_RIGHT_SHIFT) & I2S_RIGHT_MASK;
	else if (i2s_port->data_format == I2S_DATA_RIGHT_STEREO ||
		 i2s_port->data_format == I2S_DATA_LEFT_STEREO)
		regValue = (((i2s_ch->bytes_per_frame / 2) << I2S_LEFT_SHIFT) & I2S_LEFT_MASK) |
			   (((i2s_ch->bytes_per_frame / 2) << I2S_RIGHT_SHIFT) & I2S_RIGHT_MASK);
	else
		regValue = (i2s_ch->bytes_per_frame << I2S_SEQ_SHIFT) & I2S_SEQ_MASK;
	return regValue;

}

static void init_i2s_channel(struct hdm_i2s *dev, int ch_idx, bool is_tx)
{
	u32 temp;
	u32 byte_count_reg_val = 0x0;
	unsigned long offset = ch_idx * 0x08;
	unsigned int data_dir = is_tx ? 0x400000 : 0;

	/* reset channel */
	write_reg_i2s(dev, REG_CCRn + offset, CHANNEL_RESET);

	/* release reset */
	write_reg_i2s(dev, REG_CCRn + offset, 0);

	/* Get correct byte count value for the current channel/port config */
	byte_count_reg_val = get_byte_count_reg_val(dev, ch_idx);
	/* Set direction and Byte Counter */
	write_reg_i2s(dev, REG_CCRn + offset,
		      data_dir | byte_count_reg_val | UNMASK_ALL);

	temp = read_reg_i2s(dev, REG_CCRn + offset);

	/* Mask interrupts */
	temp = read_reg_i2s(dev, REG_CCRn + offset);
	if (is_tx)
		write_reg_i2s(dev, REG_CCRn + offset, temp & TX_INT_MASK);
	else
		write_reg_i2s(dev, REG_CCRn + offset, temp & RX_INT_MASK);

	/* Set FIFO threshold */
	write_reg_i2s(dev, REG_BFTRn + offset, QUADLETS_THRESHOLD);
	write_reg_i2s(dev, REG_BETRn + offset, QUADLETS_THRESHOLD);
}

static void enable_i2s_channel(struct hdm_i2s *dev, int ch_idx)
{
	unsigned long temp;
	unsigned long offset = ch_idx * 0x08;
	unsigned int port_ch_mask;
	unsigned long flags;
	u8 i = 0;
	/* for tx the fifo has to be filled before enabling it */
	/* otherwise one would get an underflow immediately */
	if (dev->ch[ch_idx].direction == MOST_CH_TX) {

		for (i = 0; i < INITAL_WR_BEFORE_EN; i++) {
			spin_lock_irqsave(&i2s_lock, flags);
			dev->ch[ch_idx].ready = true;
			spin_unlock_irqrestore(&i2s_lock, flags);
			start_data_transfer(dev, ch_idx);
		}
	}
	/* clear interrupts of channel */
	write_reg_i2s(dev, REG_CSRn + offset, 0x000000FF);

	if (is_port_a(ch_idx)) {
		/* enable channel interrupt at port a */
		port_ch_mask = 1 << ch_idx;
		temp = read_reg_i2s(dev, REG_DCCRA);
		write_reg_i2s(dev, REG_DCCRA, temp | port_ch_mask);
	} else {
		/* enable channel interrupt at port b */
		port_ch_mask = 1 << (ch_idx - DMA_CHANNELS_PER_PORT);
		temp = read_reg_i2s(dev, REG_DCCRB);
		write_reg_i2s(dev, REG_DCCRB, temp | port_ch_mask);
	}

	/* enable channel */
	temp = read_reg_i2s(dev, REG_CCRn + offset);
	write_reg_i2s(dev, REG_CCRn + offset, temp | CHANNEL_EN);

	dev->ch[ch_idx].is_enabled = true;
}

static void disable_i2s_channel(struct hdm_i2s *dev, int ch_idx)
{
	unsigned long temp;
	unsigned long offset = ch_idx * 0x08;
	unsigned int port_ch_mask;

	/* clear interrupts of channel */
	write_reg_i2s(dev, REG_CCRn + offset + 0x07, 0x000000FF);

	if (is_port_a(ch_idx)) {
		/* disable channel interrupt at port a */
		port_ch_mask = 1 << ch_idx;
		temp = read_reg_i2s(dev, REG_DCCRA);
		write_reg_i2s(dev, REG_DCCRA, temp & ~port_ch_mask);
	} else {
		/* disable channel interrupt at port b */
		port_ch_mask = 1 << (ch_idx - DMA_CHANNELS_PER_PORT);
		temp = read_reg_i2s(dev, REG_DCCRB);
		write_reg_i2s(dev, REG_DCCRB, temp & ~port_ch_mask);
	}

	/* disable channel */
	temp = read_reg_i2s(dev, REG_CCRn + offset);
	write_reg_i2s(dev, REG_CCRn + offset, temp & ~CHANNEL_EN);
}

static u32 get_i2s_dataformat_reg_val(enum i2s_data_format format)
{
	u32 result;
	if (format == I2S_DATA_DEL)
		result = I2S_REG_DATA_DEL;
	else if (format == I2S_DATA_DEL_SEQ)
		result = I2S_REG_DATA_DEL_SEQ;
	else if (format == I2S_DATA_SEQ)
		result = I2S_REG_DATA_SEQ;
	else if (format == I2S_DATA_LEFT_MONO)
		result = I2S_REG_DATA_LEFT;
	else if (format == I2S_DATA_LEFT_STEREO)
		result = I2S_REG_DATA_LEFT;
	else if (format == I2S_DATA_RIGHT_MONO)
		result = I2S_REG_DATA_RIGHT;
	else if (format == I2S_DATA_RIGHT_STEREO)
		result = I2S_REG_DATA_RIGHT;
	else
		result = UNDEFINED;
	return result;
}

/**
 * i2s_enable - initialize I2S interface and configure the clock generator module
 * @dev: private data
 *
 */
static int i2s_enable(struct hdm_i2s *dev)
{
	u8 cfg_success = 0;
	int result = -1;
	u32 data_format_val = 0;

	if ((dev->port_a.is_enabled && dev->port_a.clk_mode == I2S_CLKMODE_MASTER) ||
	    (dev->port_b.is_enabled && dev->port_b.clk_mode == I2S_CLKMODE_MASTER))
		result = try_lock_clk_gen((u32 *)dev->clk_gen_base, dev->clk_source);
	else
		result = 0;

	if (result) {
		pr_info("MMCM not locked");
		return result;
	}

	if (dev->port_a.is_enabled) {
		data_format_val = get_i2s_dataformat_reg_val(dev->port_a.data_format);
		if (data_format_val != UNDEFINED &&
		    dev->port_a.clk_speed != I2S_CLK_UDEF &&
		    dev->port_a.clk_mode != I2S_CLKMODE_UDEF) {
			write_reg_i2s(dev, REG_DCCRA, 0x00000000);
			write_reg_i2s(dev, REG_DCCRA, PORT_RST);
			write_reg_i2s(dev, REG_DCCRA, 0x00000000);
			write_reg_i2s(dev, REG_DCCRA, PORT_EN);
			write_reg_i2s(dev, REG_DCCRA,
				      PORT_EN | IO_MODE | dev->port_a.clk_mode |
				      dev->port_a.clk_speed | data_format_val);
			cfg_success = 1;
		}
		data_format_val = read_reg_i2s(dev, REG_DCCRA);
	}

	if (dev->port_b.is_enabled) {
		data_format_val = get_i2s_dataformat_reg_val(dev->port_b.data_format);
		if (data_format_val != UNDEFINED &&
		    dev->port_b.clk_speed != I2S_CLK_UDEF &&
		    dev->port_b.clk_mode != I2S_CLKMODE_UDEF) {
			write_reg_i2s(dev, REG_DCCRB, 0x00000000);
			write_reg_i2s(dev, REG_DCCRB, PORT_RST);
			write_reg_i2s(dev, REG_DCCRB, 0x00000000);
			write_reg_i2s(dev, REG_DCCRB, PORT_EN);
			write_reg_i2s(dev, REG_DCCRB,
				      PORT_EN | IO_MODE | dev->port_b.clk_mode |
				      dev->port_b.clk_speed | data_format_val);
			cfg_success = 1;
		}
	}

	if (cfg_success != 1) {
		pr_info("No channel enabled");
		return -ENODEV;
	}

	return 0;
}


/**
 * i2s_disable - disable the I2S interface
 * @dev: private data
 */
static void i2s_disable(struct hdm_i2s *dev)
{
	if (dev->port_a.is_enabled) {
		write_reg_i2s(dev, REG_DCCRA, 0x00000000);
		write_reg_i2s(dev, REG_DCCRA, PORT_RST);
		write_reg_i2s(dev, REG_DCCRA, 0x00000000);
	}
	if (dev->port_b.is_enabled) {
		write_reg_i2s(dev, REG_DCCRB, 0x00000000);
		write_reg_i2s(dev, REG_DCCRB, PORT_RST);
		write_reg_i2s(dev, REG_DCCRB, 0x00000000);
	}
}

static void i2s_tasklet_fn(unsigned long data)
{
	struct hdm_i2s *dev = (struct hdm_i2s *)data;
	u32 ch_idx;
	/* for each channel which had a tx/rx interrupt
	   start a data transfer */
	for (ch_idx = 0 ; ch_idx < DMA_CHANNELS ; ch_idx++) {
		if (dev->ch[ch_idx].ready)
			(void)start_data_transfer(dev, ch_idx);
	}
}

static void service_ch_irq(struct hdm_i2s *dev, int ch_idx)
{
	unsigned long offset = ch_idx * 0x08;
	unsigned int channel_status;
	unsigned int channel_control;
	unsigned int dccr = is_port_a(ch_idx) ? REG_DCCRA : REG_DCCRB;
	unsigned long flags;

	channel_status = read_reg_i2s(dev, REG_CSRn + offset);

	if (channel_status & FIFO_OVERFLOW_INT) {
		pr_err("FIFO_OVERFLOW_INT, ch_idx: %d\n", ch_idx);

		write_reg_i2s(dev, dccr, 0x00000000);
		write_reg_i2s(dev, REG_CCRn + offset, 0x00000000);

		/* Clear FIFO Overflow Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, FIFO_OVERFLOW_INT);
		spin_lock_irqsave(&i2s_lock, flags);
		dev->ch[ch_idx].ready = true;
		spin_unlock_irqrestore(&i2s_lock, flags);
	}

	if (channel_status & FIFO_UNDERFLOW_INT) {

		pr_err("FIFO_UNDERFLOW_INT, ch_idx: %d\n", ch_idx);
		write_reg_i2s(dev, dccr, 0x00000000);
		write_reg_i2s(dev, REG_CCRn + offset, 0x00000000);

		/* Clear FIFO Underflow Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, FIFO_UNDERFLOW_INT);
		spin_lock_irqsave(&i2s_lock, flags);
		dev->ch[ch_idx].fifo_underflow = true;
		spin_unlock_irqrestore(&i2s_lock, flags);
	}

	if (channel_status & RX_SERV_REQ_INT) {
		/* Disable RX Interrupt to read FIFO data (unmask RX Interrupt) */
		channel_control = read_reg_i2s(dev, REG_CCRn + offset);
		write_reg_i2s(dev, REG_CCRn + offset, channel_control | RX_INT_UNMASK);

		/* Clear RX Service Request Interrupt */
		/* write_reg_i2s(dev, REG_CSRn + offset, RX_SERV_REQ_INT); */
		spin_lock_irqsave(&i2s_lock, flags);
		dev->ch[ch_idx].ready = true;
		spin_unlock_irqrestore(&i2s_lock, flags);
	}

	if (channel_status & TX_SERV_REQ_INT) {
		/* Disable TX Interrupt to transmit data to the FIFOs (unmask TX Interrupt) */
		channel_control = read_reg_i2s(dev, REG_CCRn + offset);
		write_reg_i2s(dev, REG_CCRn + offset, channel_control | TX_INT_UNMASK);

		/* Clear TX Service Request Interrupt */
		/* write_reg_i2s(dev, REG_CSRn + offset, TX_SERV_REQ_INT); */
		spin_lock_irqsave(&i2s_lock, flags);
		dev->ch[ch_idx].ready = true;
		spin_unlock_irqrestore(&i2s_lock, flags);
	}
}

static irqreturn_t i2s_isr(int irq, void *_dev)
{
	struct hdm_i2s *dev = (struct hdm_i2s *)_dev;
	unsigned int interrupt_reg;
	int ch_idx;
	/* read interrupt status */
	interrupt_reg = read_reg_i2s(dev, REG_DSCR);
	/* for each channel check which interrupt was fired */
	for (ch_idx = 0 ; ch_idx < DMA_CHANNELS ; ch_idx++) {
		if (interrupt_reg & (1 << ch_idx))
			service_ch_irq(dev, ch_idx);
	}
	i2s_tasklet.data = (unsigned long)dev;
	tasklet_hi_schedule(&i2s_tasklet);

	return IRQ_HANDLED;
}

static int configure_channel(struct most_interface *most_iface, int ch_idx,
			     struct most_channel_config *channel_config)
{
	struct hdm_i2s *dev = iface_to_hdm(most_iface);
	struct i2s_channel *ch = dev->ch + ch_idx;

	if (ch_idx < 0 || ch_idx >= DMA_CHANNELS) {
		pr_err("configure_channel(), bad index: %d\n", ch_idx);
		return -ECHRNG;
	}

	if (ch->is_initialized)
		return -EPERM;

	if (channel_config->data_type != MOST_CH_SYNC) {
		pr_err("bad data type for channel %d\n", ch_idx);
		return -EPERM;
	}

	if (channel_config->buffer_size != MAX_BUF_SIZE_STREAMING) {
		pr_err("Buffer size should be %d bytes\n", MAX_BUF_SIZE_STREAMING);
		return -EINVAL;
	}

	if (check_if_clk_gen_locked((u32 *)dev->clk_gen_base, dev->clk_source) < 0)
		return -ENODEV;

	ch->bytes_per_frame = channel_config->subbuffer_size;
	ch->direction = channel_config->direction;

	init_i2s_channel(dev, ch_idx, channel_config->direction == MOST_CH_TX);

	ch->is_initialized = true;
	ch->is_enabled = false;
	ch->mbo_count = 0;

	return 0;
}

static int enqueue(struct most_interface *most_iface, int ch_idx,
		   struct mbo *mbo)
{
	struct hdm_i2s *dev = iface_to_hdm(most_iface);
	struct i2s_channel *ch = dev->ch + ch_idx;
	unsigned long flags;

	if (ch_idx < 0 || ch_idx >= DMA_CHANNELS)
		return -ECHRNG;

	if (!ch->is_initialized)
		return -EPERM;

	if (mbo->bus_address == 0)
		return -EFAULT;
	/* Check if buffer length is quadlet aligned */
	if ((mbo->buffer_length & 0x3) != 0) {
		pr_warning("Buffer length: %u not quadlet aligned", mbo->buffer_length);
		return -EINVAL;
	}

	spin_lock_irqsave(&i2s_lock, flags);
	list_add_tail(&mbo->list, &ch->pending_list);
	spin_unlock_irqrestore(&i2s_lock, flags);


	if (ch->is_enabled == false) {
		ch->mbo_count++;
		if (ch->mbo_count >= INITAL_WR_BEFORE_EN)
			enable_i2s_channel(dev, ch_idx);
	}
	return 0;
}

static int poison_channel(struct most_interface *most_iface, int ch_idx)
{
	unsigned long flags;
	struct hdm_i2s *dev = iface_to_hdm(most_iface);
	struct i2s_channel *ch = dev->ch + ch_idx;

	if (ch_idx < 0 || ch_idx >= DMA_CHANNELS) {
		pr_err("poison_channel(), bad index: %d\n", ch_idx);
		return -ECHRNG;
	}

	if (!ch->is_initialized)
		return -EPERM;

	pr_info("poison_channel(), ch_idx: %d\n", ch_idx);

	spin_lock_irqsave(&i2s_lock, flags);
	disable_i2s_channel(dev, ch_idx);
	ch->is_initialized = false;
	spin_unlock_irqrestore(&i2s_lock, flags);

	complete_all_mbos(&ch->pending_list);
	pr_info("poison_channel%d done!\n", ch_idx);
	return 0;
}

static struct of_device_id i2s_id[] = {
	{ .compatible = "xlnx,axi4-i2s-1.00.b", },
	{},
};


/**
 * complete_all_mbos - complete MBO's in a list
 * @head: list head
 *
 * Delete all the entries in list and return back MBO's to mostcore using
 * completion call back.
 */
static void complete_all_mbos(struct list_head *head)
{
	unsigned long flags;
	struct mbo *mbo;
	uint8_t mbo_cnt = 0;
	for (;;) {
		spin_lock_irqsave(&i2s_lock, flags);
		if (list_empty(head)) {
			spin_unlock_irqrestore(&i2s_lock, flags);
			break;
		}
		mbo_cnt++;
		mbo = list_entry(head->next, struct mbo, list);
		list_del(head->next);
		spin_unlock_irqrestore(&i2s_lock, flags);

		mbo->processed_length = 0;
		mbo->status = MBO_E_CLOSE;
		mbo->complete(mbo);
	}
	pr_info("Returned %u mbos", mbo_cnt);
}



MODULE_DEVICE_TABLE(of, i2s_id);

/*
 * i2s_probe - driver probe handler
 * @pdev - platform device
 *
 * Register the i2s interface with mostcore and initialize it.
 * Return 0 on success, negative on failure.
 */
static int i2s_probe(struct platform_device *pdev)
{
	struct device_node *clk_gen_node;
	struct resource res_clkgen;
	struct hdm_i2s *dev;
	phys_addr_t taddr;
	const u32 *reg;
	u32 naddr = 3;
	int ret, i;
	struct kobject *kobj;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	platform_set_drvdata(pdev, dev);

	if (!pdev->dev.of_node) {
		/* FIXME: the driver was instantiated in traditional way */
		ret = -ENODEV;
		goto err_free_dev;
	}

	if (!of_match_device(i2s_id, &pdev->dev)) {
		ret = -ENODEV;
		goto err_free_dev;
	}

	clk_gen_node = of_find_compatible_node(NULL, NULL,
					       "xlnx,axi4-clk-gen-1.00.c");
	if (!clk_gen_node) {
		pr_err("Cannot find clock generator module\n");
		ret = -ENODEV;
		goto err_free_dev;
	}

	reg = of_get_property(pdev->dev.of_node, "ranges", NULL);
	if (!reg) {
		pr_err("No \"ranges\" property !\n");
		ret = -ENODEV;
		goto err_free_dev;
	}

	taddr = of_translate_address(pdev->dev.of_node, reg + naddr);
	if (!taddr) {
		pr_err("Can't translate address !\n");
		ret = -ENODEV;
		goto err_free_dev;
	}

	dev->i2s_base = ioremap(taddr, 0x10000);
	if (!dev->i2s_base) {
		pr_err("Failed to map I2S I/O memory\n");
		ret = -ENOMEM;
		goto err_free_dev;
	}

	ret = of_address_to_resource(clk_gen_node, 0, &res_clkgen);
	if (ret) {
		pr_err("Failed to get Clock Generator I/O resource\n");
		ret = -ENODEV;
		goto err_unmap_io_i2s;
	}

	if (!request_mem_region(res_clkgen.start,
				resource_size(&res_clkgen), "clkgen_reg")) {
		pr_err("Failed to request Clock generator mem region\n");
		ret = -EBUSY;
		goto err_unmap_io_i2s;
	}

	dev->clk_gen_base = of_iomap(clk_gen_node, 0);
	if (!dev->clk_gen_base) {
		pr_err("Failed to map Clock Generator I/O memory\n");
		ret = -ENOMEM;
		goto err_release_mem_clkgen;
	}

	dev->irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
	if (dev->irq <= 0) {
		pr_err("Failed to get IRQ\n");
		ret = -ENODEV;
		goto err_unmap_io_clkgen;
	}

	for (i = 0; i < DMA_CHANNELS; i++) {
		INIT_LIST_HEAD(&dev->ch[i].pending_list);
		dev->ch[i].is_initialized = false;
		dev->capabilites[i].direction = MOST_CH_RX | MOST_CH_TX;
		dev->capabilites[i].data_type = MOST_CH_SYNC;
		dev->capabilites[i].num_buffers_streaming = MAX_BUFFERS_STREAMING;
		dev->capabilites[i].buffer_size_streaming = MAX_BUF_SIZE_STREAMING;
	}

	dev->most_iface.interface = ITYPE_I2S;
	dev->most_iface.description = pdev->name;
	dev->most_iface.num_channels = DMA_CHANNELS;
	dev->most_iface.channel_vector = dev->capabilites;
	dev->most_iface.configure = configure_channel;
	dev->most_iface.enqueue = enqueue;
	dev->most_iface.poison_channel = poison_channel;

	kobj = most_register_interface(&dev->most_iface);
	if (IS_ERR(kobj)) {
		ret = PTR_ERR(kobj);
		pr_err("Failed to register I2S as a MOST interface\n");
		goto err_unmap_io_clkgen;
	}

	dev->bus = create_i2s_bus_obj(kobj);
	if (!dev->bus) {
		pr_err("Failed to create i2s bus object\n");
		goto err_unreg_iface;
	}

	kobject_uevent(&dev->bus->kobj, KOBJ_ADD);
	dev->bus->dev = dev;

	ret = request_irq(dev->irq, i2s_isr, 0, "i2s", dev);
	if (ret) {
		pr_err("Failed to request IRQ: %d, err: %d\n", dev->irq, ret);
		goto err_destroy_i2s_bus_obj;
	}

	/* i2s_enable(dev); */

	return 0;

err_destroy_i2s_bus_obj:
	destroy_i2s_bus_obj(dev->bus);
err_unreg_iface:
	most_deregister_interface(&dev->most_iface);
err_unmap_io_clkgen:
	iounmap(dev->clk_gen_base);
err_release_mem_clkgen:
	release_mem_region(res_clkgen.start, resource_size(&res_clkgen));
err_unmap_io_i2s:
	iounmap(dev->i2s_base);
err_free_dev:
	kfree(dev);

	return ret;
}

/*
 * i2s_remove - driver remove handler
 * @pdev - platform device
 *
 * Unregister the interface from mostcore
 */
static int i2s_remove(struct platform_device *pdev)
{
	struct hdm_i2s *dev = platform_get_drvdata(pdev);
	struct device_node *clk_gen_node;
	struct resource res_clkgen;

	clk_gen_node = of_find_compatible_node(NULL, NULL,
					       "xlnx,axi4-clk-gen-1.00.c");
	(void)of_address_to_resource(clk_gen_node, 0, &res_clkgen);

	i2s_disable(dev);
	free_irq(dev->irq, dev);
	destroy_i2s_bus_obj(dev->bus);
	most_deregister_interface(&dev->most_iface);
	iounmap(dev->clk_gen_base);
	release_mem_region(res_clkgen.start, resource_size(&res_clkgen));
	iounmap(dev->i2s_base);
	kfree(dev);
	platform_set_drvdata(pdev, NULL);

	return 0;
}

static struct platform_driver i2s_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = i2s_id,
	},
	.probe = i2s_probe,
	.remove = i2s_remove,
};

/**
 * i2s_init - Driver Registration Routine
 */
static int __init i2s_init(void)
{
	pr_info("i2s_init() %s \n", DRIVER_VERSION);

	return platform_driver_register(&i2s_driver);
}

/**
 * i2s_exit - Driver cleanup Routine
 **/
static void __exit i2s_exit(void)
{
	platform_driver_unregister(&i2s_driver);
	pr_info("i2s_exit() %s \n", DRIVER_VERSION);
}

module_init(i2s_init);
module_exit(i2s_exit);

MODULE_AUTHOR("Robert Korn <Robert.Korn@microchip.com>");
MODULE_AUTHOR("Jain Roy Ambi <JainRoy.Ambi@microchip.com>");
MODULE_DESCRIPTION("I2S Hardware Dependent Module");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);
