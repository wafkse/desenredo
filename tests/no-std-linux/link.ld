SECTIONS
{
  PROVIDE(__desenredo_text_start = ADDR(.text));
  PROVIDE(__desenredo_text_end = ADDR(.text) + SIZEOF(.text));
  PROVIDE(__desenredo_eh_start = ADDR(.eh_frame));
  PROVIDE(__desenredo_eh_end = ADDR(.eh_frame) + SIZEOF(.eh_frame));

  .gcc_except_table :
  {
    __desenredo_lsda_start = .;
    KEEP(*(.gcc_except_table))
    KEEP(*(.gcc_except_table.*))
    __desenredo_lsda_end = .;
  }
}
INSERT AFTER .text;
