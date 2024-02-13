/* --- Real board Linker Script --- */
/* Uncomment the bellow and run `cargo build` before flashing onto the MAX78000FTHR */
MEMORY {
    ROM         (rx) : ORIGIN = 0x00000000, LENGTH = 0x00010000 /* 64kB ROM */
    BOOTLOADER  (rx) : ORIGIN = 0x10000000, LENGTH = 0x0000E000 /* Bootloader flash */
    FLASH       (rx) : ORIGIN = 0x1000E000, LENGTH = 0x00038000 /* Location of team firmware */
    RESERVED    (rw) : ORIGIN = 0x10046000, LENGTH = 0x00038000 /* Reserved */
    ROM_BL_PAGE (rw) : ORIGIN = 0x1007E000, LENGTH = 0x00002000 /* Reserved */
    SRAM        (rwx): ORIGIN = 0x20000000, LENGTH = 0x00020000 /* 128kB SRAM */
}

SECTIONS {
}

/* --- QEMU Linker Script --- */
/* Uncomment the bellow and run `cargo build` before running with QEMU */

/* NOTE 1 K = 1 KiBi = 1024 bytes */
/* TODO Adjust these memory regions to match your device memory layout */
/* These values correspond to the LM3S6965, one of the few devices QEMU can emulate */
/* MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  RAM : ORIGIN = 0x20000000, LENGTH = 64K
} */
