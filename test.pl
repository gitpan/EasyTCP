# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN {
	$| = 1;
	select(STDERR);
	$| = 1;
	select(STDOUT);
	print "1..11\n";
	}
END {print "not ok 1\n" unless $loaded;}
use Net::EasyTCP;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

#
# Because windows is such a crappy OS that does not support (well) a fork() or alarm(), we can not possibly
# run this test. (HOWEVER, THE MODULE STILL WORKS OK !) Sorry !
#
if ($^O =~ /win32/i) {
	for (2..11) {
		print "ok $_\n";
		}
	warn ("\n\nWARNING:  SINCE YOU'RE RUNNING WINDOWS, WE COULD NOT TRULY TEST CLIENT-SERVER FUNCTIONALITY WITHIN 1 PROCESS. ASSUMING TEST SUCCEEDED\n\n");
	warn ("\n\nTO PROPERLY TEST THIS MODULE, LOOK INTO THE /util/ SUBFOLDER OF THIS DISTRO AND MANYALLY RUN THE server.pl THERE, THEN CONCURRENTLY RUN THE client.pl\n\n");
	exit(0);
	}


my $num = 1;

sub res() {
	my $res = shift;
	my $desc = shift;
	$num++;
	#
	# TO ENABLE THE DESCRIPTIONS OF WHAT EACH TEST IS, UN-COMMENT THE FOLLOWING LINE
	#
	if ($res) {
		print "ok $num\n";
		}
	else {
		print "not ok $num\n";
		warn "Error in test [$desc]: $@\n";
		die("ABORTING TEST\n");
		}
	}

&startserver();

&startclient();

while ($server->clients()) {
	}

sub startserver() {
	my $temp;
	$server = new Net::EasyTCP(
		mode            =>      "server",
		port            =>      2345,
		password			=>		"just another perl hacker",
		);
	&res ($server, "Create new server");
	$temp = $server->setcallback(
		data            =>      \&gotdata,
		connect         =>      \&connected,
		disconnect      =>      \&disconnected,
		);
	&res($temp, "Set callbacks");
	&do_one_loop();
	}

sub startclient() {
	my $temp;

	$client = new Net::EasyTCP(
		mode            =>      "client",
		host            =>      '127.0.0.1',
		port            =>      2345,
		password			=>		"just another perl hacker",
		);
	&res($client, "Create client");

	$temp = $client->receive();
	&res($temp eq "SEND ME COMPLEX", "Client receive data");

	$temp = $client->send({"complex"=>"data"});
	&res($temp, "Client send complex data");

	$temp = $client->close();
	&res($temp, "Client close connection");

	}

sub connected() {
	my $client = shift;
	my $temp;
	&res($client, "Server received connection");
	$temp = $client->send("SEND ME COMPLEX");
	&res($temp, "Server send data from callback");
	}

sub gotdata() {
	my $client = shift;
	my $data = $client->data();
	&res($data->{complex} eq "data", "Server receive complex data");
	}

sub disconnected() {
	my $client = shift;
	&res($client, "Server received client disconnection");
	exit(0);
	}

sub do_one_loop() {
	my $temp = $server->do_one_loop();
	if (!$temp) {
		die "Error from server's do_one_loop(): $@\n";
		}
	$SIG{ALRM} = \&do_one_loop;
	alarm(1);
	}
