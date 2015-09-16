OUTPUT_FORMAT("elf32-littlearm", "elf32-bigarm", "elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(Vectors)

MEMORY
{
	ram (rw)  : ORIGIN = 0x00000000, LENGTH = 416K
}

SECTIONS
{
	.text 0x00000400 : AT ( 0x00000400 )
	{
		. = ALIGN (4);
		*(.vector);
		*(.*text* .rdata .constdata .rodata*);
		__text_end = . ;
	} > ram
	
	.data :
	{
		. = ALIGN (4);
		__data_start = . ;
		*(.data .data1);
		__data_end = . ;
	} > ram

	.bss :
	{
		__bss_start = . ;
		*(.dynbss)
		*(.bss .bss.* .gnu.linkonce.b.*)
		*(COMMON)
		*(.comment)
		. = ALIGN(4);
		__bss_end = . ;
		. = ALIGN(0x100);
	} > ram
	
	_end = .;
	__end__ = . ;
	PROVIDE (end = .);
	
	.stack 0x00067C00 :
	{
		_stack = .;
		*(.stack);
	} > ram

}
