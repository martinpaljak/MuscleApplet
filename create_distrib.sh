#/bin/sh -e

# $Id$

dir=$(basename $(pwd))-$(perl -ne 'if (m/^\d.\d.\d/) { s/ .*//; print; exit;}' README)

echo -e "Using $dir as directory name\n"

rv=$(echo $dir | sed -e 's/.*-[0-9]\+\.[0-9]\+\.[0-9]\+/ok/')
if [ $rv != "ok" ]
then
	echo "ERROR: The directory name should be in the form foo-bar-x.y.z"
	exit
fi

if [ -e $dir ]
then
	echo -e "ERROR: $dir already exists\nremove it and restart"
	exit
fi

# clean
#echo -n "cleaning..."
#make clean &> /dev/null
#echo "done"

set -e

# CVS
echo -n "Generating CVS Changelog..."
rcs2log | perl -pe 's+/cvsroot/muscleplugins/MCardApplet/++g;' > Changelog.cvs
echo "done"

present_files=$(tempfile)
manifest_files=$(tempfile)
diff_result=$(tempfile)

# find files present
# remove ^debian and ^create_distrib.sh
find -type f | grep -v CVS | cut -c 3- | grep -v ^create_distrib.sh | sort > $present_files
cat MANIFEST | sort > $manifest_files

# diff the two lists
diff $present_files $manifest_files | grep '<' | cut -c 2- > $diff_result

if [ -s $diff_result ]
then
	echo -e "WARGING! some files will not be included in the archive.\nAdd them in MANIFEST"
	cat $diff_result
	echo
fi

# remove temporary files
rm $present_files $manifest_files $diff_result

# create the temporary directory
mkdir $dir

for i in $(cat MANIFEST)
do
	if [ $(echo $i | grep /) ]
	then
		idir=$dir/${i%/*}
		if [ ! -d $idir ]
		then
			echo "mkdir $idir"
			mkdir $idir
		fi
	fi
	echo "cp $i $dir/$i"
	cp -a $i $dir/$i
done

# copy src
mkdir -p $dir/src/com/musclecard/CardEdge
cp src/*.java $dir/src/com/musclecard/CardEdge

# doc
echo -n "Generating documentation..."
( cd $dir && ./DocGenerate.sh  &> /dev/null )
echo "done"

tar czvf ../$dir.tar.gz $dir
rm -r $dir

