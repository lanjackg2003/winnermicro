#!/bin/awk -f

BEGIN{
	offset=0
	filelen=0
	binnum=0
	headlen=60
}
{	
	if(NR > 1 && $1 > 0)	
	{
		printf ("%c%c%c%c",offset,offset/0x100,offset/0x10000,offset/0x1000000) > ARGV[2]
		printf ("%c%c%c%c",$1,$1/0x100,$1/0x10000,$1/0x1000000) > ARGV[2]
		offset += $1
		binnum++
	}
	else if(1 == NR)
	{
		offset = $1;
	}

}
END{
	for(i = 0;i < (headlen - 4 - binnum*8);i ++)
		printf ("%c",0) > ARGV[2]
	printf ("%c",binnum) > ARGV[2]
	printf ("%c%c%c",0x11,0x11,0x11) > ARGV[2]
}
