gclocal
automake
./configure

cc -DHAVE_CONFIG_H -I.     -g -O2 -g -O0 -Wall  -c -o daemonlogger.o daemonlogger.c
if [ $? != 0 ] ; then
   echo "Error in compilation"
   exit
fi
gcc  -g -O2 -g -O0 -Wall   -ldnet -o daemonlogger daemonlogger.o -L/usr/local/lib/daq -lpcap  -lz -lpthread -ldaq -lsfbpf

sudo /usr/bin/install -c daemonlogger "/usr/local/bin"

sudo cp -p unit.daemonlogger /usr/lib/systemd/system/daemonlogger.service
sudo cp -p daemonlogger.config /etc/sysconfig/daemonlogger 
