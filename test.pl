# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..13\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::EasyTCP;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

#
# This set of tests could be VERY easily written by forking a server and having the client talk to it as 2 seperate
# processes (which is the way it would normally be), however using fork() in the test suite does not seem like
# a great idea, so this test uses alarm() to deliver signals, which tell it to move to the next part of the test.
#
# BY DEFAULT ALARM WAITS 10 SECONDS BETWEEN EACH STEP. IF THIS TESTS FAILS BECAUSE YOU HAVE AN EXTRA SLOW MACHINE
# INCREASE THE VALUE OF $ALARMVALUE RIGHT BELOW

$ALARMVALUE = 10;

$TESTNUM = 1;
sub res() {
	my $res = shift;
	my $desc = shift;
	$TESTNUM++;
	print (($res) ? "ok $TESTNUM ($desc)" : "not ok $TESTNUM ($desc: $@)");
	print "\n";
	}


$SERVER = new Net::EasyTCP(
               mode            =>      "server",
               port            =>      2345,
               );
&res($SERVER, "new server");

$temp =         $SERVER->callback(
               data            =>      \&gotdata,
               connect         =>      \&connected,
               disconnect      =>      \&disconnected,
               );
&res($temp, "set callbacks");

$SIG{ALRM} = \&testclient1;
alarm($ALARMVALUE);

$temp = $SERVER->start();
&res($temp, "start server");

sub testclient1() {
	 $CLIENT = new Net::EasyTCP(
               mode            =>      "client",
               host            =>      '127.0.0.1',
               port            =>      2345,
               );
	&res($CLIENT, "create client");
	$SIG{ALRM} = \&testclient2;
	alarm($ALARMVALUE);
	}

sub testclient2() {
	$temp = $CLIENT->receive();
	&res($temp->{"complex"} eq "data", "client receive data");
	$temp = $CLIENT->close();
	&res($temp, "client close connection");
	}

sub gotdata() {
	my $client = shift;
	my $data = $client->data();
	&res($data eq "SEND ME COMPLEX", "server receive data");
	$temp = $client->send({"complex"=>"data"});
	&res($temp, "server send complex data");
	}

sub connected() {
	my $client = shift;
	&res($client, "server received connection");
	$temp = $CLIENT->send("SEND ME COMPLEX");
	&res($temp, "client send data");
	}

sub disconnected() {
	my $client = shift;
	&res($client, "server received client disconnection");
	$temp = $SERVER->stop();
	&res($temp, "requested server stop");
	}

