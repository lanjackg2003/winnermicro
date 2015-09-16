#!/bin/sh
SRCBIN=WM2014_01.bin
OUTFILE=target.bin
SIZEFILE=temp/size.txt
HEADFILE=temp/head.bin
BINNUM=temp/binnum.bin
rm -rf $SIZEFILE
ls -l $SRCBIN  | awk '{if($5 > 0) print $5}' >> $SIZEFILE
ls -l bin/  | awk '{if($5 > 0) print $5}' >> $SIZEFILE
awk -f filehead.awk $SIZEFILE $HEADFILE 
cp -rf $SRCBIN $OUTFILE
filelist=$(ls bin)
cd bin
for file in $filelist
do
	cat $file >> ../$OUTFILE 
	echo $file
done
cd -
cat $HEADFILE >> $OUTFILE
