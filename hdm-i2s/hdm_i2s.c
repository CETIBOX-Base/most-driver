/*
 * hdm_i2s.c - Hardware Dependent Module for I2S
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/err.h>

#include <mostcore.h>

#include "hdm_i2s.h"

#define DRIVER_NAME "hdm_i2s"

/*
 * We use 4 channels per port.
 * So channels 0..3 belong to port A and channels 4..7 belong to port B.
 */
#define DMA_CHANNELS_PER_PORT 4
#define DMA_CHANNELS (DMA_CHANNELS_PER_PORT * 2)

#define QUADLETS_THRESHOLD QUADLETS_511

#define MAX_BUFFERS_STREAMING 32
#define MAX_BUF_SIZE_STREAMING (QUADLETS_THRESHOLD * 4)

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
	u32 bytes_per_frame;
	enum most_channel_direction direction;
	struct list_head pending_list;
	bool ready;
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
	u32 clk_mode;
	u32 clk_speed;
	u32 data_format;
	u32 is_enabled;
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
 * @dcm_clk_divider: dcm port divider value
 * @dcm_clk_multiplier: dcm port multiplier value
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
	u32 clk_source;
	u32 dcm_clk_divider;
	u32 dcm_clk_multiplier;
	struct list_head completed_list;
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

static DEFINE_SPINLOCK(pend_list_lock);
static DEFINE_SPINLOCK(comp_list_lock);

static void i2s_tasklet_fn(unsigned long data);
static DECLARE_TASKLET(i2s_tasklet, i2s_tasklet_fn, 0);

static void i2s_enable(struct hdm_i2s *dev);

#define I2S_BUS_ATTR(_name) \
	struct i2s_bus_attribute i2s_bus_attr_##_name = \
		__ATTR(_name, S_IRUGO | S_IWUSR, show_value, store_value)

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

/**
 * show_${attribute_name} - show attribute function
 * @bus_obj: pointer to bus
 * @attr: pointer to bus attribute
 * @buf: buffer
 *
 * This returns the value of corresponding parameter variable from struct hdm_i2s
 */
static ssize_t show_value(struct i2s_bus_obj *bus_obj,
			  struct i2s_bus_attribute *attr, char *buf)
{
	struct hdm_i2s *dev = bus_obj->dev;
	u32 tmp_val;

	if (!strcmp(attr->attr.name, "clock_source"))
		tmp_val = dev->clk_source;
	else if (!strcmp(attr->attr.name, "dcm_clock_divider"))
		tmp_val = dev->dcm_clk_divider;
	else if (!strcmp(attr->attr.name, "dcm_clock_multiplier"))
		tmp_val = dev->dcm_clk_multiplier;
	else if (!strcmp(attr->attr.name, "port_a_enable"))
		tmp_val = dev->port_a.is_enabled;
	else if (!strcmp(attr->attr.name, "port_a_clock_mode"))
		tmp_val = dev->port_a.clk_mode;
	else if (!strcmp(attr->attr.name, "port_a_clock_speed"))
		tmp_val = dev->port_a.clk_speed;
	else if (!strcmp(attr->attr.name, "port_a_data_format"))
		tmp_val = dev->port_a.data_format;
	else if (!strcmp(attr->attr.name, "port_b_enable"))
		tmp_val = dev->port_b.is_enabled;
	else if (!strcmp(attr->attr.name, "port_b_clock_mode"))
		tmp_val = dev->port_b.clk_mode;
	else if (!strcmp(attr->attr.name, "port_b_clock_speed"))
		tmp_val = dev->port_b.clk_speed;
	else if (!strcmp(attr->attr.name, "port_b_data_format"))
		tmp_val = dev->port_b.data_format;
	else if (!strcmp(attr->attr.name, "ch0_bpf"))
		tmp_val = dev->ch[0].bytes_per_frame;
	else if (!strcmp(attr->attr.name, "ch1_bpf"))
		tmp_val = dev->ch[1].bytes_per_frame;
	else if (!strcmp(attr->attr.name, "ch2_bpf"))
		tmp_val = dev->ch[2].bytes_per_frame;
	else if (!strcmp(attr->attr.name, "ch3_bpf"))
		tmp_val = dev->ch[3].bytes_per_frame;
	else if (!strcmp(attr->attr.name, "ch4_bpf"))
		tmp_val = dev->ch[4].bytes_per_frame;
	else if (!strcmp(attr->attr.name, "ch5_bpf"))
		tmp_val = dev->ch[5].bytes_per_frame;
	else if (!strcmp(attr->attr.name, "ch6_bpf"))
		tmp_val = dev->ch[6].bytes_per_frame;
	else if (!strcmp(attr->attr.name, "ch7_bpf"))
		tmp_val = dev->ch[7].bytes_per_frame;
	else
		return -EIO;

	return snprintf(buf, PAGE_SIZE, "%08x\n", tmp_val);
}

/**
 * store_${attribute_name} - store() attribute function
 * @bus_obj:
 * @attr:
 * @buf:
 * @count:
 *
 * This stores the buf content in the corresponding parameter variable in
 * struct hdm_i2s
 */
static ssize_t store_value(struct i2s_bus_obj *bus_obj,
			   struct i2s_bus_attribute *attr,
			   const char *buf, size_t count)
{
	struct hdm_i2s *dev = bus_obj->dev;
	u32 v32;
	int err;

	err = kstrtou32(buf, 16, &v32);
	if (err)
		return err;

	if (!strcmp(attr->attr.name, "clock_source"))
		dev->clk_source = v32;
	else if (!strcmp(attr->attr.name, "dcm_clock_divider"))
		dev->dcm_clk_divider = v32;
	else if (!strcmp(attr->attr.name, "dcm_clock_multiplier"))
		dev->dcm_clk_multiplier = v32;
	else if (!strcmp(attr->attr.name, "port_a_enable"))
		dev->port_a.is_enabled = v32;
	else if (!strcmp(attr->attr.name, "port_a_clock_mode"))
		dev->port_a.clk_mode = v32;
	else if (!strcmp(attr->attr.name, "port_a_clock_speed"))
		dev->port_a.clk_speed = v32;
	else if (!strcmp(attr->attr.name, "port_a_data_format"))
		dev->port_a.data_format = v32;
	else if (!strcmp(attr->attr.name, "port_b_enable"))
		dev->port_b.is_enabled = v32;
	else if (!strcmp(attr->attr.name, "port_b_clock_mode"))
		dev->port_b.clk_mode = v32;
	else if (!strcmp(attr->attr.name, "port_b_clock_speed"))
		dev->port_b.clk_speed = v32;
	else if (!strcmp(attr->attr.name, "port_b_data_format"))
		dev->port_b.data_format = v32;
	else if (!strcmp(attr->attr.name, "ch0_bpf"))
		dev->ch[0].bytes_per_frame = v32;
	else if (!strcmp(attr->attr.name, "ch1_bpf"))
		dev->ch[1].bytes_per_frame = v32;
	else if (!strcmp(attr->attr.name, "ch2_bpf"))
		dev->ch[2].bytes_per_frame = v32;
	else if (!strcmp(attr->attr.name, "ch3_bpf"))
		dev->ch[3].bytes_per_frame = v32;
	else if (!strcmp(attr->attr.name, "ch4_bpf"))
		dev->ch[4].bytes_per_frame = v32;
	else if (!strcmp(attr->attr.name, "ch5_bpf"))
		dev->ch[5].bytes_per_frame = v32;
	else if (!strcmp(attr->attr.name, "ch6_bpf"))
		dev->ch[6].bytes_per_frame = v32;
	else if (!strcmp(attr->attr.name, "ch7_bpf"))
		dev->ch[7].bytes_per_frame = v32;
	else if (!strcmp(attr->attr.name, "bus_enable"))
		i2s_enable(dev);
	else
		return -EIO;

	return count;
}

static I2S_BUS_ATTR(clock_source);
static I2S_BUS_ATTR(dcm_clock_divider);
static I2S_BUS_ATTR(dcm_clock_multiplier);
static I2S_BUS_ATTR(port_a_enable);
static I2S_BUS_ATTR(port_a_clock_mode);
static I2S_BUS_ATTR(port_a_clock_speed);
static I2S_BUS_ATTR(port_a_data_format);
static I2S_BUS_ATTR(port_b_enable);
static I2S_BUS_ATTR(port_b_clock_mode);
static I2S_BUS_ATTR(port_b_clock_speed);
static I2S_BUS_ATTR(port_b_data_format);
static I2S_BUS_ATTR(ch0_bpf);
static I2S_BUS_ATTR(ch1_bpf);
static I2S_BUS_ATTR(ch2_bpf);
static I2S_BUS_ATTR(ch3_bpf);
static I2S_BUS_ATTR(ch4_bpf);
static I2S_BUS_ATTR(ch5_bpf);
static I2S_BUS_ATTR(ch6_bpf);
static I2S_BUS_ATTR(ch7_bpf);
static I2S_BUS_ATTR(bus_enable);

/**
 * i2s_bus_def_attrs - array of default attribute files of the bus object
 */
static struct attribute *i2s_bus_def_attrs[] = {
	&i2s_bus_attr_clock_source.attr,
	&i2s_bus_attr_dcm_clock_divider.attr,
	&i2s_bus_attr_dcm_clock_multiplier.attr,
	&i2s_bus_attr_port_a_enable.attr,
	&i2s_bus_attr_port_a_clock_mode.attr,
	&i2s_bus_attr_port_a_clock_speed.attr,
	&i2s_bus_attr_port_a_data_format.attr,
	&i2s_bus_attr_port_b_enable.attr,
	&i2s_bus_attr_port_b_clock_mode.attr,
	&i2s_bus_attr_port_b_clock_speed.attr,
	&i2s_bus_attr_port_b_data_format.attr,
	&i2s_bus_attr_ch0_bpf.attr,
	&i2s_bus_attr_ch1_bpf.attr,
	&i2s_bus_attr_ch2_bpf.attr,
	&i2s_bus_attr_ch3_bpf.attr,
	&i2s_bus_attr_ch4_bpf.attr,
	&i2s_bus_attr_ch5_bpf.attr,
	&i2s_bus_attr_ch6_bpf.attr,
	&i2s_bus_attr_ch7_bpf.attr,
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

/**
 * write_reg_clkgen - write value to a register on clock generator
 * @dev: private data
 * @reg_offset: offset of the register
 * @value: value to write
 */
static inline void write_reg_clkgen(struct hdm_i2s *dev,
				    unsigned long reg_offset,
				    uint32_t value)
{
	iowrite32(value, (u32 *)(dev->clk_gen_base) + reg_offset);
}

/**
 * read_reg_clkgen - read value of a register on clock generator
 * @dev: private data
 * @reg_offset: offset of the register
 */
static inline uint32_t read_reg_clkgen(struct hdm_i2s *dev,
				       unsigned long reg_offset)
{
	return ioread32((u32 *)(dev->clk_gen_base) + reg_offset);
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

	if (!ch->ready)
		return -EAGAIN;

	spin_lock_irqsave(&pend_list_lock, flags);
	if (list_empty(head)) {
		pr_err("No MBO, ch: %d\n", ch_idx);
		spin_unlock_irqrestore(&pend_list_lock, flags);
		return -EAGAIN;
	}
	mbo = list_entry(head->next, struct mbo, list);
	spin_unlock_irqrestore(&pend_list_lock, flags);

	ch->ready = false;
	qptr = (u32 *)mbo->virt_address;
	noofquadlet = mbo->buffer_length / 4;

	if (ch->direction == MOST_CH_RX) {
		unsigned long reg = REG_CBBARn + offset;
		for (i = 0; i < noofquadlet; i++)
			qptr[i] = read_reg_i2s(dev, reg);

		/* Clear RX Service Request Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, RX_SERV_REQ_INT);

		/* Re-enable Rx Interrupts (mask interrupts again) */
		write_reg_i2s(dev, REG_CCRn + offset, (read_reg_i2s(dev,
						       REG_CCRn + offset) & RX_INT_MASK));
	} else {
		unsigned long reg = REG_NBBARn + offset;
		for (i = 0; i < noofquadlet; i++)
			write_reg_i2s(dev, reg, qptr[i]);

		/* Clear TX Service Request Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, TX_SERV_REQ_INT);

		/* Re-enable Tx Interrupts (mask interrupts again) */
		write_reg_i2s(dev, REG_CCRn + offset, (read_reg_i2s(dev,
						       REG_CCRn + offset) & TX_INT_MASK));
	}

	spin_lock_irqsave(&comp_list_lock, flags);
	list_move_tail(head->next, &dev->completed_list);
	spin_unlock_irqrestore(&comp_list_lock, flags);

	return 0;
}

static void init_i2s_channel(struct hdm_i2s *dev, int ch_idx, bool is_tx)
{
	unsigned long temp;
	unsigned long offset = ch_idx * 0x08;
	unsigned int data_dir = is_tx ? 0x400000 : 0;

	/* reset channel */
	write_reg_i2s(dev, REG_CCRn + offset, CHANNEL_RESET);

	/* release reset */
	write_reg_i2s(dev, REG_CCRn + offset, 0);

	/* Set direction and Byte Counter */
	write_reg_i2s(dev, REG_CCRn + offset,
		      (data_dir | dev->ch[ch_idx].bytes_per_frame | UNMASK_ALL));

	/* Mask interrupts */
	temp = read_reg_i2s(dev, REG_CCRn + offset);
	if (is_tx) {
		write_reg_i2s(dev, REG_CCRn + offset, (temp & TX_INT_MASK));
		dev->ch[ch_idx].ready = true;
	} else
		write_reg_i2s(dev, REG_CCRn + offset, (temp & RX_INT_MASK));

	/* Set FIFO threshold */
	write_reg_i2s(dev, REG_BFTRn + offset, QUADLETS_THRESHOLD);
	write_reg_i2s(dev, REG_BETRn + offset, QUADLETS_THRESHOLD);
}

static void enable_i2s_channel(struct hdm_i2s *dev, int ch_idx, bool is_tx)
{
	unsigned long temp;
	unsigned long offset = ch_idx * 0x08;
	unsigned int port_ch_mask;

	if (is_tx) {
		start_data_transfer(dev, ch_idx);
		dev->ch[ch_idx].ready = true;
		start_data_transfer(dev, ch_idx);
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
	write_reg_i2s(dev, REG_CCRn + offset, (temp | CHANNEL_EN));
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
	write_reg_i2s(dev, REG_CCRn + offset, (temp & ~CHANNEL_EN));
}

/**
 * i2s_enable - initialize I2S interface and configure the clock generator module
 * @dev: private data
 *
 */
static void i2s_enable(struct hdm_i2s *dev)
{
	unsigned long clk_sel_status;

	if (((dev->port_a.is_enabled) && (dev->port_a.clk_mode == OMM))
	    || ((dev->port_b.is_enabled) && (dev->port_b.clk_mode == OMM))) {
		/* Master mode */

		/* Reset the clock Generator */
		write_reg_clkgen(dev, REG_CFG, SW_RST);
		udelay(2);
		write_reg_clkgen(dev, REG_CFG, RST_CLR);

		/* Configure the clock Generator */
		write_reg_clkgen(dev, REG_CFG, dev->clk_source);
		udelay(200);

		/* Reset the clock Generator DCM0 */
		write_reg_clkgen(dev, REG_CFG, DCM0_RST | dev->clk_source);
		udelay(10);
		write_reg_clkgen(dev, REG_CFG, RST_CLR | dev->clk_source);
		udelay(200);

		/* Dynamic DCM1 multiplier configuration */
		clk_sel_status = CLK_SEL_MASK & read_reg_clkgen(dev, REG_CFG);
		write_reg_clkgen(dev, REG_CFG, clk_sel_status | DCM1_RST | DEN | DWE
				 | DADDR_MULTIPLY | dev->dcm_clk_multiplier);
		write_reg_clkgen(dev, REG_CFG, clk_sel_status | RST_CLR);

		/* Dynamic DCM1 divider configuration */
		clk_sel_status = CLK_SEL_MASK & read_reg_clkgen(dev, REG_CFG);
		write_reg_clkgen(dev, REG_CFG, clk_sel_status | DCM1_RST | DEN | DWE
				 | DADDR_DIVIDER | dev->dcm_clk_divider);
		write_reg_clkgen(dev, REG_CFG, clk_sel_status | RST_CLR);

		/* Configure the clock divider */
		write_reg_clkgen(dev, REG_DIV, 0);

		while (1) {
			clk_sel_status = CLK_SEL_MASK & read_reg_clkgen(dev, REG_CFG);
			pr_info("Reset DMC1\n");

			write_reg_clkgen(dev, REG_CFG, clk_sel_status | RST_CLR);

			if (0x20000000 & read_reg_clkgen(dev, REG_CFG)) {
				pr_info("DCM1 Locked\n");
				break;
			} else {
				pr_info("DCM1 UnLock!!!!\n");
			}
		}
	}

	if (dev->port_a.is_enabled) {

		write_reg_i2s(dev, REG_DCCRA, 0x00000000);
		write_reg_i2s(dev, REG_DCCRA, PORT_RST);
		write_reg_i2s(dev, REG_DCCRA, 0x00000000);
		write_reg_i2s(dev, REG_DCCRA, PORT_EN);
		write_reg_i2s(dev, REG_DCCRA, (PORT_EN | dev->port_a.clk_mode
					       | dev->port_a.clk_speed
					       | dev->port_a.data_format
					       | IO_MODE));
	}

	if (dev->port_b.is_enabled) {

		write_reg_i2s(dev, REG_DCCRB, 0x00000000);
		write_reg_i2s(dev, REG_DCCRB, PORT_RST);
		write_reg_i2s(dev, REG_DCCRB, 0x00000000);
		write_reg_i2s(dev, REG_DCCRB, PORT_EN);
		write_reg_i2s(dev, REG_DCCRB, (PORT_EN | dev->port_b.clk_mode
					       | dev->port_b.clk_speed
					       | dev->port_b.data_format
					       | IO_MODE));
	}
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
	struct list_head *head = &dev->completed_list;
	unsigned long flags;
	struct mbo *mbo;

	spin_lock_irqsave(&comp_list_lock, flags);
	while (!list_empty(head)) {
		mbo = list_entry(head->next, struct mbo, list);
		list_del(head->next);
		spin_unlock_irqrestore(&comp_list_lock, flags);
		mbo->processed_length = mbo->buffer_length;
		mbo->status = MBO_SUCCESS;
		mbo->complete(mbo);
		spin_lock_irqsave(&comp_list_lock, flags);
	}
	spin_unlock_irqrestore(&comp_list_lock, flags);
}

static void service_ch_irq(struct hdm_i2s *dev, int ch_idx)
{
	unsigned long offset = ch_idx * 0x08;
	unsigned int channel_status;
	unsigned int channel_control;
	unsigned int dccr = is_port_a(ch_idx) ? REG_DCCRA : REG_DCCRB;

	channel_status = read_reg_i2s(dev, REG_CSRn + offset);

	if (channel_status & FIFO_OVERFLOW_INT) {

		pr_err("FIFO_OVERFLOW_INT, ch_idx: %d\n", ch_idx);

		write_reg_i2s(dev, dccr, 0x00000000);
		write_reg_i2s(dev, REG_CCRn + offset, 0x00000000);

		/* Clear FIFO Overflow Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, FIFO_OVERFLOW_INT);
		dev->ch[ch_idx].fifo_overflow = true;
	}

	if (channel_status & FIFO_UNDERFLOW_INT) {

		pr_err("FIFO_UNDERFLOW_INT, ch_idx: %d\n", ch_idx);

		write_reg_i2s(dev, dccr, 0x00000000);
		write_reg_i2s(dev, REG_CCRn + offset, 0x00000000);

		/* Clear FIFO Underflow Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, FIFO_UNDERFLOW_INT);
		dev->ch[ch_idx].fifo_underflow = true;
	}

	if (channel_status & RX_SERV_REQ_INT) {

		/* Disable RX Interrupt to read FIFO data (unmask RX Interrupt) */
		channel_control = read_reg_i2s(dev, REG_CCRn + offset);
		write_reg_i2s(dev, REG_CCRn + offset, (channel_control | RX_INT_UNMASK));

		/* Clear RX Service Request Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, RX_SERV_REQ_INT);
		dev->ch[ch_idx].ready = true;
	}

	if (channel_status & TX_SERV_REQ_INT) {

		/* Disable TX Interrupt to transmit data to the FIFOs (unmask TX Interrupt) */
		channel_control = read_reg_i2s(dev, REG_CCRn + offset);
		write_reg_i2s(dev, REG_CCRn + offset, (channel_control | TX_INT_UNMASK));

		/* Clear TX Service Request Interrupt */
		write_reg_i2s(dev, REG_CSRn + offset, TX_SERV_REQ_INT);
		dev->ch[ch_idx].ready = true;
	}
}

static irqreturn_t i2s_isr(int irq, void *_dev)
{
	struct hdm_i2s *dev = (struct hdm_i2s *)_dev;
	unsigned int interrupt_reg;
	int ch_idx;

	/* read interrupt status */
	interrupt_reg = read_reg_i2s(dev, REG_DSCR);
	while (interrupt_reg & 0x000000FF) { /* while there is an interrupt */
		for (ch_idx = 0 ; ch_idx < DMA_CHANNELS ; ch_idx++)
			if (interrupt_reg & (1 << ch_idx)) {
				service_ch_irq(dev, ch_idx);
				(void)start_data_transfer(dev, ch_idx);
			}

		/* read interrupt status again */
		interrupt_reg = read_reg_i2s(dev, REG_DSCR);
	}

	i2s_tasklet.data = (unsigned long)dev;
	tasklet_schedule(&i2s_tasklet);

	return IRQ_HANDLED;
}

static int configure_channel(struct most_interface *most_iface, int ch_idx,
			     struct most_channel_config *channel_config)
{
	struct hdm_i2s *dev = iface_to_hdm(most_iface);
	struct i2s_channel *ch = dev->ch + ch_idx;

	if ((ch_idx < 0) || (ch_idx >= DMA_CHANNELS)) {
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

	init_i2s_channel(dev, ch_idx, channel_config->direction == MOST_CH_TX);
	ch->direction = channel_config->direction;
	ch->is_initialized = true;
	ch->mbo_count = 0;

	return 0;
}

static int enqueue(struct most_interface *most_iface, int ch_idx,
		   struct mbo *mbo)
{
	struct hdm_i2s *dev = iface_to_hdm(most_iface);
	struct i2s_channel *ch = dev->ch + ch_idx;
	unsigned long flags;

	if ((ch_idx < 0) || (ch_idx >= DMA_CHANNELS))
		return -ECHRNG;

	if (!ch->is_initialized)
		return -EPERM;

	if (mbo->bus_address == 0)
		return -EFAULT;

	spin_lock_irqsave(&pend_list_lock, flags);
	list_add_tail(&mbo->list, &ch->pending_list);
	spin_unlock_irqrestore(&pend_list_lock, flags);

	if (ch->mbo_count < 2) {
		ch->mbo_count++;
		if (ch->mbo_count == 2) {
			enable_i2s_channel(dev, ch_idx, ch->direction == MOST_CH_TX);
		}
	}

	return 0;
}

static int poison_channel(struct most_interface *most_iface, int ch_idx)
{
	struct hdm_i2s *dev = iface_to_hdm(most_iface);
	struct i2s_channel *ch = dev->ch + ch_idx;
	struct list_head *head = &ch->pending_list;
	unsigned long flags;
	struct mbo *mbo;

	if ((ch_idx < 0) || (ch_idx >= DMA_CHANNELS)) {
		pr_err("poison_channel(), bad index: %d\n", ch_idx);
		return -ECHRNG;
	}

	if (!ch->is_initialized)
		return -EPERM;

	pr_info("poison_channel(), ch_idx: %d\n", ch_idx);

	ch->is_initialized = false;
	disable_i2s_channel(dev, ch_idx);

	spin_lock_irqsave(&pend_list_lock, flags);
	while (!list_empty(head)) {
		mbo = list_entry(head->next, struct mbo, list);
		list_del(head->next);
		spin_unlock_irqrestore(&pend_list_lock, flags);
		mbo->processed_length = 0;
		mbo->status = MBO_E_CLOSE;
		mbo->complete(mbo);
		spin_lock_irqsave(&pend_list_lock, flags);
	}
	spin_unlock_irqrestore(&pend_list_lock, flags);

	return 0;
}

static struct of_device_id i2s_id[] = {
	{
		.compatible = "xlnx,axi4-i2s-1.00.b",
	},
	{},
};

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
	INIT_LIST_HEAD(&dev->completed_list);

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
	pr_info("i2s_init()\n");

	return platform_driver_register(&i2s_driver);
}

/**
 * i2s_exit - Driver Cleanup Routine
 **/
static void __exit i2s_exit(void)
{
	platform_driver_unregister(&i2s_driver);
	pr_info("i2s_exit()\n");
}

module_init(i2s_init);
module_exit(i2s_exit);

MODULE_AUTHOR("Jain Roy Ambi <JainRoy.Ambi@microchip.com>");
MODULE_DESCRIPTION("I2S Hardware Dependent Module");
MODULE_LICENSE("GPL");
