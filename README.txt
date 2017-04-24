HOW TO BUILD

export ARCH=... (i.e. "arm" or "x86_64)
export CROSS_COMPILE=... (i.e. "arm-linux-gnueabihf-")

make -C .../kernel-build-dir \
    src=.../src/most-driver \
    M=.../most-driver-build-dir \
    CONFIG_HDM_DIM2=n \
    CONFIG_HDM_USB=m \
    modules
make -C .../kernel-build-dir \
    src=.../src/most-driver \
    M=.../most-driver-build-dir \
    CONFIG_HDM_DIM2=n \
    CONFIG_HDM_USB=m \
    INSTALL_MOD_PATH=.../output/ \
    modules_install

The .ko files will be copied into the path designated by the INSTALL_MOD_PATH.
The modules must be loaded in the order below:

    mostcore.ko
    hdm_usb.ko
    aim_network.ko
    aim_cdev.ko
    aim_mlb150.ko
    aim_syncsound.ko
    aim_v4l2.ko

Loading of the modules is not enough to get a working MOST interface, this
configuration must be done separately.

