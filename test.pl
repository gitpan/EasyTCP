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
	print "1..14\n";
	}
END {print "not ok 1\n" unless $loaded;}
use Net::EasyTCP;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

my ($client, $server, $pid);

sub res() {
	my $res = shift;
	my $num = shift;
	my $desc = shift;
	#
	# TO ENABLE THE DESCRIPTIONS OF WHAT EACH TEST IS, UN-COMMENT THE FOLLOWING LINE
	#
#	warn (($res) ? "\n$desc :\n" : "\n\nError in $desc: $@\n");
	print (($res) ? "ok $num\n" : "not ok $num\n");
	}

$pid = fork();
if (!defined $pid) {
	# Fork failed
	&res(0, 2, "Forking");
	exit(1);
	}
elsif ($pid) {
	# Fork was successful
	&res(1, 2, "Forking");
	}

if ($pid == 0) {
	# I am the child, I will be the client
	sleep (10);
	&launchclient();
	}
else {
	# I am the parent, I will be the server
	&launchserver();
	}

sub launchserver() {
	my $temp;
	$server = new Net::EasyTCP(
		mode            =>      "server",
		port            =>      2345,
		);
	&res ($server, 3, "Create new server");
	$temp = $server->setcallback(
		data            =>      \&gotdata,
		connect         =>      \&connected,
		disconnect      =>      \&disconnected,
		);
	&res($temp, 4, "Set callbacks");
	$temp = $server->start();
	&res($temp, 14, "Return of started server");
	sleep (4);
	}

sub launchclient() {
	my $temp;
	$client = new Net::EasyTCP(
		mode            =>      "client",
		host            =>      '127.0.0.1',
		port            =>      2345,
		);
	&res($client, 5, "Create client");
	$temp = $client->receive();
	&res($temp eq "SEND ME COMPLEX", 7, "Client receive data");
	$temp = $client->send({"complex"=>"data"});
	&res($temp, 9, "Client send complex data");
	$temp = $client->close();
	&res($temp, 10, "Client close connection");
	}

sub connected() {
	my $client = shift;
	my $temp;
	&res($client, 6, "Server received connection");
	$temp = $client->send("SEND ME COMPLEX");
	&res($temp, 8, "Server send data from callback");
	}

sub gotdata() {
	my $client = shift;
	my $data = $client->data();
	&res($data->{complex} eq "data", 11, "Server receive complex data");
	}

sub disconnected() {
	my $client = shift;
	&res($client, 12, "Server received client disconnection");
	$temp = $server->stop();
	&res($temp, 13, "Requested server stop");
	}
