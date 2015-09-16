#!/bin/gawk -f

BEGIN{
	print ARGV[0]
	print ARGV[1]
	print ARGV[2]
	ARGC = 2
	RS = "\n"
	a = 0
	b = 0
}
{	
	a = index($0,"(printf,")
	if(a > 0)
	{
		print "extern int wm_printf(const char *fmt,...);" > ARGV[2]
		print "#define printf wm_printf" > ARGV[2]
	}
	else
	{
		a = 0
	}
	b = index($0,"(sprintf,")
	if(b > 0)
	{
		print "extern int wm_sprintf(char *str, const char *fmt,...);" > ARGV[2]
		print "#define sprintf wm_sprintf" > ARGV[2]
	}
	else
	{
		b = 0
	}
	if(0 == a && 0 == b)
		print $0 > ARGV[2]
	a = 0
	b = 0
}
END{

}
