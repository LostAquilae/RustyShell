/* Simple ENTRY statement to put the entry point toward the align_stack routine */
ENTRY(align_stack);

SECTIONS
{
    .text  __image_base__ + ( __section_alignment__ < 0x1000 ? . : __section_alignment__ ) :
    {
        *(.text.entry)
        *(.text)
        *(.rdata*)
    }

    /DISCARD/ :
    {
        *(.pdata)
        *(.xdata)
    }
}