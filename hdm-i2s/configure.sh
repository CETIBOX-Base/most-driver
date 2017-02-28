#!/bin/bash

[[ $UID -ne 0 ]] && { echo "$0 must be run as root" 1>&2; exit 1; }

[[ "$1" = "" ]] && { echo "Missing Configuration Option!"; exit 1; }

# clock source
PHY1_RMCK0="0x00000000"
PHY1_RMCK1="0x04000000"
PHY2_RMCK0="0x08000000"
PHY2_RMCK1="0x0C000000"
DBG_CLK="0x10000000"
OSC1_CLK="0x14000000"
OSC2_CLK="0x18000000"
OSC3_CLK="0x1C000000"

# clock mode
PORT_MASTER="0x00008000"
PORT_SLAVE="0x00000000"

# clock speed
CLK_8FS="0x00000000"
CLK_16FS="0x00040000"
CLK_32FS="0x00080000"
CLK_64FS="0x000C0000"
CLK_128FS="0x00100000"
CLK_256FS="0x00140000"
CLK_512FS="0x00180000"

# data format
SEQ_SDF="0x00001000"
DEL_SDF="0x00000800"
DEL_SEQ_SDF="0x00001800"
LEFT_SDF="0x00000400"
RIGHT_SDF="0x00000000"

# bytes per frame
MONO_LEFT_2BYTE="0x00000800"
MONO_LEFT_4BYTE="0x00001000"
MONO_RIGHT_2BYTE="0x00020000"
MONO_RIGHT_4BYTE="0x00040000"
STEREO_2X2BYTE="0x00020800"
STEREO_2X4Byte="0x00041000"
SEQ_1BYTE="0x00000400"
SEQ_2BYTE="0x00000800"
SEQ_4BYTE="0x00001000"
SEQ_8BYTE="0x00002000"
SEQ_16BYTE="0x00004000"
SEQ_32BYTE="0x00008000"
SEQ_64BYTE="0x00010000"

DIR=/sys/devices/virtual/most/mostcore/devices/mdev1/bus

conf () {
        echo "Selected Configuration: " $1
        echo $PHY1_RMCK0 > $DIR/clock_source
        echo 1 > $DIR/dcm_clock_divider
        echo 1 > $DIR/dcm_clock_multiplier
        echo 1 > $DIR/port_a_enable
        echo $PORT_MASTER > $DIR/port_a_clock_mode
        echo $2 > $DIR/port_a_clock_speed
        echo $3 > $DIR/port_a_data_format
        echo $4 > $DIR/ch1_bpf
        echo $4 > $DIR/ch2_bpf
        echo 1 > $DIR/bus_enable
}

case $1 in
    delay_64fs_16bit)
        conf "$1" $CLK_64FS $LEFT_SDF $STEREO_2X2BYTE
        ;;
    left_64fs_16bit)
        conf "$1" $CLK_64FS $LEFT_SDF $STEREO_2X2BYTE
        ;;
    right_64fs_16bit)
        conf "$1" $CLK_64FS $RIGHT_SDF $STEREO_2X2BYTE
        ;;
    delay_64fs_seq)
        conf "$1" $CLK_64FS $DEL_SEQ_SDF $SEQ_4BYTE
        ;;
    delay_128fs_seq)
        conf "$1" $CLK_128FS $DEL_SEQ_SDF $SEQ_4BYTE
        ;;
    delay_256fs_seq)
        conf "$1" $CLK_256FS $DEL_SEQ_SDF $SEQ_4BYTE
        ;;
    delay_512fs_seq)
        conf "$1" $CLK_512FS $DEL_SEQ_SDF $SEQ_4BYTE
        ;;
    seq_64fs)
        conf "$1" $CLK_64FS $SEQ_SDF $SEQ_4BYTE
        ;;
    seq_128fs)
        conf "$1" $CLK_128FS $SEQ_SDF $SEQ_4BYTE
        ;;
    seq_256fs)
        conf "$1" $CLK_256FS $SEQ_SDF $SEQ_4BYTE
        ;;
    seq_512fs)
        conf "$1" $CLK_512FS $SEQ_SDF $SEQ_4BYTE
        ;;
    *)
        echo "Unknown Option: $1"
        ;;
esac
