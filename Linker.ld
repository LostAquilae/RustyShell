/* Simple ENTRY statement to put the entry point toward the align_stack routine */
ENTRY(align_stack);

SECTIONS
{
    /* Grouping code and read onyl data, starting with .text.entry which contains the small align_stack procedure, which is the real entry point of the shellcode */
    .text  __image_base__ + ( __section_alignment__ < 0x1000 ? . : __section_alignment__ ) :
    {
        *(.text.entry)
        *(.text)
        *(.rdata*)
    }

    /* Discarding the pdata and xdata sections, which are not needed in the final binary */
    /DISCARD/ :
    {
        *(.pdata)
        *(.xdata)
    }
}